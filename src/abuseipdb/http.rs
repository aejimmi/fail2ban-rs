//! AbuseIPDB's report endpoint and its two documented rate-limit responses.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::config::AbuseIpDbJailConfig;
use crate::error::{Error, Result};

pub(super) const ENDPOINT: &str = "https://api.abuseipdb.com/api/v2/report";
const RESPONSE_LIMIT: usize = 16 * 1024;

pub(super) struct Transport {
    client: Client,
    endpoint: String,
}

impl Transport {
    pub(super) fn new(endpoint: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(|_| Error::config("could not initialize AbuseIPDB HTTPS client"))?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
        })
    }

    pub(super) async fn post(
        &self,
        key: HeaderValue,
        ip: IpAddr,
        policy: &AbuseIpDbJailConfig,
        timestamp: Option<i64>,
    ) -> Outcome {
        let timestamp = timestamp
            .and_then(|time| chrono::DateTime::from_timestamp(time, 0))
            .map(|time| time.to_rfc3339());
        let form = ReportForm {
            ip,
            categories: policy
                .categories
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(","),
            comment: &policy.description,
            timestamp,
        };
        let response = self
            .client
            .post(self.endpoint.as_str())
            .header("Key", key)
            .header(ACCEPT, "application/json")
            .form(&form)
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(err) if err.is_timeout() => return Outcome::Timeout,
            Err(_) => return Outcome::TransportError,
        };
        let status = response.status();
        if status.is_success() {
            return Outcome::Success;
        }
        if status != StatusCode::TOO_MANY_REQUESTS {
            return Outcome::HttpError(status.as_u16());
        }
        let headers = response.headers().clone();
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if chunk.len() <= RESPONSE_LIMIT - body.len() => {
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                _ => return Outcome::Throttled,
            }
        }
        classify_limit(&headers, &body, SystemTime::now())
    }
}

#[derive(Serialize)]
struct ReportForm<'a> {
    ip: IpAddr,
    categories: String,
    comment: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) enum Outcome {
    Success,
    Timeout,
    TransportError,
    HttpError(u16),
    Throttled,
    IpLimit(Option<Duration>),
    Quota(Duration),
}

#[derive(Deserialize)]
struct ErrorResponse<'a> {
    #[serde(borrow)]
    errors: Vec<ApiError<'a>>,
}

#[derive(Deserialize)]
struct ApiError<'a> {
    #[serde(borrow)]
    detail: Option<std::borrow::Cow<'a, str>>,
    source: Option<Source>,
}

#[derive(Deserialize)]
struct Source {
    parameter: Option<String>,
}

fn classify_limit(headers: &HeaderMap, body: &[u8], now: SystemTime) -> Outcome {
    let Some(errors) = serde_json::from_slice::<ErrorResponse<'_>>(body)
        .ok()
        .map(|body| body.errors)
    else {
        return Outcome::Throttled;
    };
    let retry_after = seconds_header(headers, RETRY_AFTER.as_str()).filter(|value| *value > 0);
    if errors
        .iter()
        .any(|err| err.source.as_ref().and_then(|s| s.parameter.as_deref()) == Some("ip"))
    {
        return Outcome::IpLimit(retry_after.map(Duration::from_secs));
    }
    if errors.iter().any(|err| {
        err.detail
            .as_deref()
            .is_some_and(|text| text.starts_with("Daily rate limit of "))
    }) {
        let reset_delay = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|time| {
                seconds_header(headers, "x-ratelimit-reset")?.checked_sub(time.as_secs())
            })
            .filter(|seconds| *seconds > 0);
        return Outcome::Quota(Duration::from_secs(
            retry_after.max(reset_delay).unwrap_or(1800),
        ));
    }
    Outcome::Throttled
}

fn seconds_header(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.parse().ok()
}
