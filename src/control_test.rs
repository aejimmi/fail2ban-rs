//! Tests for the control socket.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::control::{self, ControlCmd, Request, Response};

#[tokio::test]
async fn request_response_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
    let cancel = CancellationToken::new();

    let sock = sock_path.clone();
    let cancel_clone = cancel.clone();
    let server = tokio::spawn(async move {
        control::run(&sock, tx, cancel_clone).await;
    });

    // Give server time to bind.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Spawn a handler that responds to Status requests.
    let handler = tokio::spawn(async move {
        if let Some(cmd) = rx.recv().await {
            match cmd.request {
                Request::Status => {
                    let _ = cmd.respond.send(Response::ok("running"));
                }
                _ => {
                    let _ = cmd.respond.send(Response::error("unexpected"));
                }
            }
        }
    });

    // Send a status request.
    let response = control::send_request(&sock_path, &Request::Status)
        .await
        .unwrap();

    match response {
        Response::Ok { message, .. } => {
            assert_eq!(message.unwrap(), "running");
        }
        Response::Error { message } => panic!("unexpected error: {message}"),
    }

    cancel.cancel();
    handler.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ban_request_serialization() {
    let req = Request::Ban {
        ip: "1.2.3.4".parse().unwrap(),
        jail: "sshd".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("ban"));
    assert!(json.contains("1.2.3.4"));

    let parsed: Request = serde_json::from_str(&json).unwrap();
    match parsed {
        Request::Ban { ip, jail } => {
            assert_eq!(ip.to_string(), "1.2.3.4");
            assert_eq!(jail, "sshd");
        }
        _ => panic!("wrong variant"),
    }
}

#[tokio::test]
async fn unban_request_serialization() {
    let req = Request::Unban {
        ip: "10.0.0.1".parse().unwrap(),
        jail: "nginx".to_string(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    match parsed {
        Request::Unban { ip, jail } => {
            assert_eq!(ip.to_string(), "10.0.0.1");
            assert_eq!(jail, "nginx");
        }
        _ => panic!("wrong variant"),
    }
}

#[tokio::test]
async fn connect_to_nonexistent_socket() {
    let result = control::send_request(
        std::path::Path::new("/tmp/nonexistent-fail2ban-rs-test.sock"),
        &Request::Status,
    )
    .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("connect"), "got: {err}");
}

#[tokio::test]
async fn all_request_variants_through_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
    let cancel = CancellationToken::new();

    let sock = sock_path.clone();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        control::run(&sock, tx, cancel_clone).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Handler that responds to everything.
    let handler = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let response = match cmd.request {
                Request::Status => Response::ok("up"),
                Request::ListBans => Response::ok_data(serde_json::json!({"bans": []})),
                Request::Ban { ip, jail } => Response::ok(format!("banned {ip} in {jail}")),
                Request::Unban { ip, jail } => Response::ok(format!("unbanned {ip} from {jail}")),
                Request::Reload => Response::ok("reloaded"),
                Request::Stats => Response::ok_data(serde_json::json!({"uptime": 42})),
            };
            let _ = cmd.respond.send(response);
        }
    });

    // Test each variant.
    let resp = control::send_request(&sock_path, &Request::Status)
        .await
        .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = control::send_request(&sock_path, &Request::ListBans)
        .await
        .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = control::send_request(
        &sock_path,
        &Request::Ban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = control::send_request(
        &sock_path,
        &Request::Unban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = control::send_request(&sock_path, &Request::Reload)
        .await
        .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    cancel.cancel();
    handler.abort();
}

#[test]
fn response_ok_data_has_no_message() {
    let data = serde_json::json!({"count": 5});
    let resp = Response::ok_data(data);
    let json = serde_json::to_string(&resp).unwrap();
    // message should be absent (skip_serializing_if).
    assert!(!json.contains("message"), "got: {json}");
    assert!(json.contains("count"));
}

#[test]
fn reload_request_serialization() {
    let req = Request::Reload;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, Request::Reload));
}

#[test]
fn list_bans_request_serialization() {
    let req = Request::ListBans;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: Request = serde_json::from_str(&json).unwrap();
    assert!(matches!(parsed, Request::ListBans));
}
