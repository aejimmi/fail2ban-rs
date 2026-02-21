//! Tests for server-level control request handling.

use crate::control::{Request, Response};

#[test]
fn status_request_response() {
    // Verify that serde roundtrip works for all request types.
    let requests = vec![
        Request::Status,
        Request::ListBans,
        Request::Ban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        },
        Request::Unban {
            ip: "10.0.0.1".parse().unwrap(),
            jail: "nginx".to_string(),
        },
        Request::Reload,
        Request::Stats,
    ];

    for req in requests {
        let json = serde_json::to_string(&req).unwrap();
        let _parsed: Request = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn response_ok_serialization() {
    let resp = Response::ok("running");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("ok"));
    assert!(json.contains("running"));
}

#[test]
fn response_error_serialization() {
    let resp = Response::error("something went wrong");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("error"));
    assert!(json.contains("something went wrong"));
}

#[test]
fn response_ok_data_serialization() {
    let data = serde_json::json!({ "bans": [{"ip": "1.2.3.4"}] });
    let resp = Response::ok_data(data);
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("1.2.3.4"));
}

#[test]
fn stats_request_serialization() {
    let req = Request::Stats;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, Request::Stats));
}
