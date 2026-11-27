//! Daemon-local deduplication and background delivery of AbuseIPDB reports.

mod http;

use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use reqwest::header::HeaderValue;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::{AbuseIpDbJailConfig, Config};
use crate::error::{Error, Result};

use self::http::{Outcome, Transport};

const QUEUE_CAPACITY: usize = 64;
const IP_CAPACITY: usize = 16_384;
const COOLDOWN: Duration = Duration::from_secs(30 * 60);
const MAX_EVENT_AGE: i64 = 60 * 24 * 60 * 60;

#[derive(Default)]
pub(crate) struct Policy {
    key: Option<HeaderValue>,
    jails: HashMap<String, Arc<AbuseIpDbJailConfig>>,
}

impl Policy {
    pub(crate) fn prepare(config: &Config) -> Result<Self> {
        let jails: HashMap<_, _> = config
            .enabled_jails()
            .filter_map(|(name, jail)| Some((name.to_owned(), Arc::new(jail.abuseipdb.clone()?))))
            .collect();
        let key = if jails.is_empty() {
            None
        } else {
            let settings = config
                .global
                .abuseipdb
                .as_ref()
                .ok_or_else(|| Error::config("AbuseIPDB credentials are required"))?;
            Some(read_key(&settings.api_key_file)?)
        };
        Ok(Self { key, jails })
    }
}

fn read_key(path: &Path) -> Result<HeaderValue> {
    const KEY_LIMIT: u64 = 4096;
    let invalid = || {
        Error::config(
            "AbuseIPDB key file must be a readable, private regular file containing one API key",
        )
    };
    // Avoid blocking on a FIFO before its type can be verified. Check the
    // opened descriptor so permission checks and reading refer to one file.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| invalid())?;
    let meta = file.metadata().map_err(|_| invalid())?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || (meta.uid() != 0 && meta.uid() != nix::unistd::geteuid().as_raw())
    {
        return Err(invalid());
    }
    let mut content = String::new();
    file.take(KEY_LIMIT + 1)
        .read_to_string(&mut content)
        .map_err(|_| invalid())?;
    let key = content.trim();
    if content.len() as u64 > KEY_LIMIT
        || key.is_empty()
        || key.bytes().any(|b| !b.is_ascii_graphic())
    {
        return Err(invalid());
    }
    let mut header = HeaderValue::from_str(key).map_err(|_| invalid())?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Clone)]
pub(crate) struct Reporter {
    state: Arc<Mutex<State>>,
    queue: mpsc::Sender<Job>,
    cancel: CancellationToken,
}

struct Job {
    ip: IpAddr,
    jail: String,
    timestamp: Option<i64>,
    rules: Arc<AbuseIpDbJailConfig>,
    credential_generation: u64,
}

#[derive(Default)]
struct State {
    policy: Policy,
    credential_generation: u64,
    pending: HashMap<IpAddr, Option<Instant>>,
    expiry: BTreeSet<(Instant, IpAddr)>,
    paused_until: Option<Instant>,
    last_warning: HashMap<&'static str, Instant>,
}

impl State {
    fn prune(&mut self, now: Instant) {
        while self
            .expiry
            .first()
            .is_some_and(|&(deadline, _)| deadline <= now)
        {
            if let Some((_, ip)) = self.expiry.pop_first() {
                self.pending.remove(&ip);
            }
        }
    }

    fn cool_until(&mut self, ip: IpAddr, deadline: Instant) {
        if let Some(Some(old)) = self.pending.get(&ip).copied() {
            if old >= deadline {
                return;
            }
            self.expiry.remove(&(old, ip));
        }
        self.pending.insert(ip, Some(deadline));
        self.expiry.insert((deadline, ip));
    }

    fn dispatch(&mut self, job: &Job, now: Instant) -> Option<HeaderValue> {
        let policy_matches = job.credential_generation == self.credential_generation
            && self
                .policy
                .jails
                .get(&job.jail)
                .is_some_and(|rules| Arc::ptr_eq(rules, &job.rules));
        let key = self
            .policy
            .key
            .clone()
            .filter(|_| policy_matches && !self.is_paused(now) && fresh_event(job.timestamp));
        if key.is_some() {
            self.cool_until(job.ip, now + COOLDOWN);
        } else {
            self.pending.remove(&job.ip);
        }
        key
    }

    fn is_paused(&self, now: Instant) -> bool {
        self.paused_until.is_some_and(|until| until > now)
    }
}

impl Reporter {
    pub(crate) fn start(policy: Policy, cancel: CancellationToken) -> Result<Self> {
        Ok(Self::spawn(
            policy,
            cancel,
            Transport::new(http::ENDPOINT)?,
            QUEUE_CAPACITY,
        ))
    }

    fn spawn(
        policy: Policy,
        cancel: CancellationToken,
        transport: Transport,
        capacity: usize,
    ) -> Self {
        let (queue, rx) = mpsc::channel(capacity);
        let state = Arc::new(Mutex::new(State {
            policy,
            ..State::default()
        }));
        tokio::spawn(worker(state.clone(), rx, transport, cancel.clone()));
        Self {
            state,
            queue,
            cancel,
        }
    }

    pub(crate) fn stop(&self) {
        self.cancel.cancel();
    }

    pub(crate) fn update(&self, mut policy: Policy) {
        let mut state = lock(&self.state);
        if state.policy.key != policy.key {
            state.credential_generation = state.credential_generation.wrapping_add(1);
        }
        // Reuse identical jail policies so unrelated reloads do not discard
        // queued jobs. Re-enabling a previously removed jail gets a new Arc.
        for (name, rules) in &mut policy.jails {
            if let Some(old) = state.policy.jails.get(name).filter(|old| *old == rules) {
                *rules = old.clone();
            }
        }
        state.policy = policy;
    }

    pub(crate) fn try_enqueue(&self, ip: IpAddr, jail: &str, timestamp: Option<i64>) {
        if self.cancel.is_cancelled() {
            return;
        }
        let ip = ip.to_canonical();
        let mut state = lock(&self.state);
        let Some(rules) = state.policy.jails.get(jail).cloned() else {
            return;
        };
        if !public_address(ip) || !fresh_event(timestamp) {
            return;
        }
        let now = Instant::now();
        state.prune(now);
        if state.pending.contains_key(&ip) {
            return;
        }
        let refusal = if state.is_paused(now) {
            "quota_pause"
        } else if state.pending.len() >= IP_CAPACITY {
            "ip_capacity"
        } else if let Ok(slot) = self.queue.try_reserve() {
            state.pending.insert(ip, None);
            slot.send(Job {
                ip,
                jail: jail.to_owned(),
                timestamp,
                rules,
                credential_generation: state.credential_generation,
            });
            return;
        } else {
            "queue_unavailable"
        };
        drop(state);
        log_failure(&self.state, refusal, None);
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn worker(
    state: Arc<Mutex<State>>,
    mut queue: mpsc::Receiver<Job>,
    transport: Transport,
    cancel: CancellationToken,
) {
    let mut cleanup = tokio::time::interval(Duration::from_secs(60));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let job = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = cleanup.tick() => {
                lock(&state).prune(Instant::now());
                continue;
            }
            job = queue.recv() => job,
        };
        let Some(job) = job else { break };
        let Some(key) = lock(&state).dispatch(&job, Instant::now()) else {
            continue;
        };
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            outcome = transport.post(key, job.ip, &job.rules, job.timestamp) => outcome,
        };
        record_outcome(&state, &job, outcome);
    }
}

fn record_outcome(state: &Mutex<State>, job: &Job, outcome: Outcome) {
    let (reason, status) = match outcome {
        Outcome::Success => {
            debug!("AbuseIPDB report accepted");
            return;
        }
        Outcome::Timeout => ("timeout", None),
        Outcome::TransportError => ("transport", None),
        Outcome::HttpError(status) => ("http_error", Some(status)),
        Outcome::Throttled => ("unclassified_rate_limit", Some(429)),
        Outcome::IpLimit(delay) => {
            if let Some(deadline) = delay.and_then(|delay| Instant::now().checked_add(delay)) {
                lock(state).cool_until(job.ip, deadline);
            }
            ("ip_rate_limit", Some(429))
        }
        Outcome::Quota(delay) => {
            let now = Instant::now();
            let mut state = lock(state);
            if state.credential_generation == job.credential_generation {
                state.paused_until = Some(now.checked_add(delay).unwrap_or(now + COOLDOWN));
            }
            ("daily_quota", Some(429))
        }
    };
    log_failure(state, reason, status);
}

fn log_failure(state: &Mutex<State>, reason: &'static str, status: Option<u16>) {
    let now = Instant::now();
    let mut state = lock(state);
    if state
        .last_warning
        .get(reason)
        .is_some_and(|last| now - *last < Duration::from_secs(60))
    {
        return;
    }
    state.last_warning.insert(reason, now);
    drop(state);
    warn!(
        reason,
        status, "AbuseIPDB report dropped or delivery failed"
    );
}

fn fresh_event(timestamp: Option<i64>) -> bool {
    timestamp.is_none_or(|ts| ts >= chrono::Utc::now().timestamp() - MAX_EVENT_AGE)
}

fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
        && !matches!(
            ip.octets(),
            [0 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [192, 0, 0, _]
                | [192, 88, 99, _]
                | [198, 18 | 19, ..]
        )
}

fn public_v6(ip: Ipv6Addr) -> bool {
    match ip.segments() {
        [0x2001, 0x0db8 | 0..=0x01ff, ..] | [0x2002, ..] | [0x3fff, 0..=0x0fff, ..] => false,
        [0x2000..=0x3fff, ..] => true,
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests;
