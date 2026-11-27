use super::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn client_rejects_oversized_response_length() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("big.sock");

    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Drain the client's request so it reaches the read-response phase.
        let req_len = stream.read_u32_le().await.unwrap();
        let mut req = vec![0u8; req_len as usize];
        stream.read_exact(&mut req).await.unwrap();
        // Advertise a response just over the response cap.
        stream.write_u32_le(MAX_RESPONSE_BYTES + 1).await.unwrap();
        let _ = stream.flush().await;
    });

    let result = send_request(&sock_path, &Request::Status).await;
    assert!(result.is_err(), "oversized length must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("too large"), "got: {err}");

    server.await.unwrap();
}

#[tokio::test]
async fn request_response_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("test.sock");

    let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
    let cancel = CancellationToken::new();

    let sock = sock_path.clone();
    let cancel_clone = cancel.clone();
    let server = tokio::spawn(async move {
        run(&sock, tx, cancel_clone).await;
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
    let response = send_request(&sock_path, &Request::Status).await.unwrap();

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
    let result = send_request(
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
        run(&sock, tx, cancel_clone).await;
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
                Request::BanLogs { .. } => Response::ok_data(serde_json::json!({"lines": []})),
                Request::Stats => Response::ok_data(serde_json::json!({"uptime": 42})),
            };
            let _ = cmd.respond.send(response);
        }
    });

    // Test each variant.
    let resp = send_request(&sock_path, &Request::Status).await.unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = send_request(&sock_path, &Request::ListBans).await.unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = send_request(
        &sock_path,
        &Request::Ban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = send_request(
        &sock_path,
        &Request::Unban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }));

    let resp = send_request(&sock_path, &Request::Reload).await.unwrap();
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

/// Build a list-bans response shaped exactly like the daemon's.
fn list_bans_response(count: u32) -> Response {
    let base = u128::from(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    let bans: Vec<serde_json::Value> = (0..count)
        .map(|i| {
            let ip = std::net::Ipv6Addr::from(base + u128::from(i));
            serde_json::json!({
                "ip": ip.to_string(),
                "jail": "nginx-botsearch-long-jail-name",
                "banned_at": 1_700_000_000i64 + i64::from(i),
                "expires_at": Some(1_700_003_600i64 + i64::from(i)),
            })
        })
        .collect();
    Response::ok_data(serde_json::json!({ "bans": bans }))
}

#[tokio::test]
async fn test_list_bans_roundtrip_exceeds_request_cap() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("many.sock");
    let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
    let cancel = CancellationToken::new();

    let sock = sock_path.clone();
    let cancel_clone = cancel.clone();
    let server = tokio::spawn(async move { run(&sock, tx, cancel_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let handler = tokio::spawn(async move {
        let cmd = rx.recv().await.unwrap();
        assert!(matches!(cmd.request, Request::ListBans));
        assert!(cmd.respond.send(list_bans_response(2000)).is_ok());
    });

    let size = serde_json::to_vec(&list_bans_response(2000)).unwrap().len();
    assert!(
        size > MAX_REQUEST_BYTES as usize,
        "fixture must exceed 64 KiB, got {size}"
    );

    let response = send_request(&sock_path, &Request::ListBans).await.unwrap();
    let Response::Ok {
        data: Some(data), ..
    } = response
    else {
        panic!("expected data response");
    };
    assert_eq!(data["bans"].as_array().unwrap().len(), 2000);

    cancel.cancel();
    handler.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn test_client_accepts_response_at_limit_boundary_length() {
    // A peer advertising exactly MAX_RESPONSE_BYTES passes the length check;
    // it then fails on the short read, not with "too large".
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("edge.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let req_len = stream.read_u32_le().await.unwrap();
        let mut req = vec![0u8; req_len as usize];
        stream.read_exact(&mut req).await.unwrap();
        stream.write_u32_le(MAX_RESPONSE_BYTES).await.unwrap();
        stream.flush().await.unwrap();
    });

    let err = send_request(&sock_path, &Request::Status)
        .await
        .unwrap_err()
        .to_string();
    assert!(!err.contains("too large"), "got: {err}");
    server.await.unwrap();
}

#[test]
fn test_encode_response_within_limit_unchanged() {
    let resp = list_bans_response(10);
    let encoded = encode_response(&resp).unwrap();
    assert_eq!(encoded, serde_json::to_vec(&resp).unwrap());
}

/// A response whose encoded size lands exactly on `MAX_RESPONSE_BYTES` must
/// pass through unchanged (the check is `<=`, not `<`).
#[test]
fn test_encode_response_at_exact_limit_unchanged() {
    // `Response::ok(message)` wraps the string in `{"status":"ok","message":"..."}`;
    // back out the JSON overhead so the encoded frame lands exactly at the cap.
    let overhead = serde_json::to_vec(&Response::ok(String::new()))
        .unwrap()
        .len();
    let payload = "x".repeat(MAX_RESPONSE_BYTES as usize - overhead);
    let resp = Response::ok(payload);
    let encoded = encode_response(&resp).unwrap();
    assert_eq!(encoded.len(), MAX_RESPONSE_BYTES as usize);
    assert_eq!(encoded, serde_json::to_vec(&resp).unwrap());
    let parsed: Response = serde_json::from_slice(&encoded).unwrap();
    assert!(
        matches!(parsed, Response::Ok { .. }),
        "must not be rewritten to an error at the exact boundary"
    );
}

#[test]
fn test_encode_response_over_limit_becomes_error() {
    let big = "x".repeat(MAX_RESPONSE_BYTES as usize + 1);
    let encoded = encode_response(&Response::ok(big)).unwrap();
    assert!(encoded.len() < 1024);
    let parsed: Response = serde_json::from_slice(&encoded).unwrap();
    let Response::Error { message } = parsed else {
        panic!("expected error response");
    };
    assert!(message.contains("response too large"), "got: {message}");
}
