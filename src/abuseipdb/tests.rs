use super::*;

use std::os::unix::fs::PermissionsExt;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::enforce::{FirewallBackend, FirewallCmd, ReportObservation, run_with_reporter};
use crate::track::state::BanRecord;

const FIRST: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
const SECOND: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const THIRD: IpAddr = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
const TEST_KEY: &str = "mock-key-never-for-production";

struct Request {
    headers: String,
    body: String,
    respond: oneshot::Sender<String>,
}

struct Mock {
    requests: mpsc::Receiver<Request>,
    endpoint: String,
}

impl Mock {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{addr}/api/v2/report");
        let (tx, requests) = mpsc::channel(16);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move { serve_mock(stream, tx).await });
            }
        });
        Self { requests, endpoint }
    }

    async fn receive(&mut self) -> Request {
        tokio::time::timeout(Duration::from_secs(3), self.requests.recv())
            .await
            .expect("mock did not receive a request")
            .unwrap()
    }

    fn reporter(&self, capacity: usize) -> Reporter {
        Reporter::spawn(
            policy(TEST_KEY),
            CancellationToken::new(),
            Transport::new(&self.endpoint).unwrap(),
            capacity,
        )
    }
}

async fn serve_mock(stream: TcpStream, tx: mpsc::Sender<Request>) {
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.unwrap() == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        headers.push_str(&line);
    }
    let len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await.unwrap();
    let body = String::from_utf8(body).unwrap();
    let (respond, response) = oneshot::channel();
    tx.send(Request {
        headers,
        body,
        respond,
    })
    .await
    .unwrap();
    if let Ok(response) = response.await {
        let _ = reader.get_mut().write_all(response.as_bytes()).await;
    }
}

fn reply(request: Request, status: &str, headers: &str, body: &str) {
    request
        .respond
        .send(format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len(),
        ))
        .unwrap();
}

fn policy(key: &'static str) -> Policy {
    let mut key = HeaderValue::from_static(key);
    key.set_sensitive(true);
    let jail = |categories| {
        Arc::new(AbuseIpDbJailConfig {
            categories,
            description: "Repeated failed authentication".into(),
        })
    };
    Policy {
        key: Some(key),
        jails: HashMap::from([
            ("ssh".into(), jail(vec![18, 22])),
            ("web".into(), jail(vec![21])),
            ("failing".into(), jail(vec![18])),
            ("unattached".into(), jail(vec![18])),
        ]),
    }
}

async fn until(check: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !check() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reporter state did not settle");
}

#[test]
fn private_credentials_and_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    std::fs::write(&path, TEST_KEY).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!read_key(&path).unwrap_err().to_string().contains(TEST_KEY));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = read_key(&path).unwrap();
    assert!(key.is_sensitive());
    assert!(!format!("{key:?}").contains(TEST_KEY));
    std::fs::write(&path, format!("{TEST_KEY}\ninjected")).unwrap();
    assert!(read_key(&path).is_err());
}

#[test]
fn cooldown_expires_at_the_deadline() {
    let start = Instant::now();
    let mut state = State::default();
    state.cool_until(FIRST, start + COOLDOWN);
    state.prune(start + Duration::from_secs(1799));
    assert!(state.pending.contains_key(&FIRST));
    state.prune(start + COOLDOWN);
    assert!(!state.pending.contains_key(&FIRST));
}

#[tokio::test]
async fn sends_one_form_for_an_ip_across_jails_and_address_spellings() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    let ts = chrono::Utc::now().timestamp();
    reporter.try_enqueue(FIRST, "ssh", Some(ts));
    reporter.try_enqueue("::ffff:8.8.8.8".parse().unwrap(), "web", None);
    reporter.try_enqueue(SECOND, "web", None);
    reporter.try_enqueue(Ipv4Addr::LOCALHOST.into(), "ssh", None);
    reporter.try_enqueue(THIRD, "ssh", Some(ts - MAX_EVENT_AGE - 100));

    let first = mock.receive().await;
    assert!(first.headers.starts_with("POST /api/v2/report HTTP/1.1"));
    assert!(
        first
            .headers
            .contains("content-type: application/x-www-form-urlencoded")
    );
    assert!(first.headers.contains(&format!("key: {TEST_KEY}")));
    assert!(first.body.contains(
        "ip=8.8.8.8&categories=18%2C22&comment=Repeated+failed+authentication&timestamp="
    ));
    reply(first, "200 OK", "", "{}");

    let second = mock.receive().await;
    assert_eq!(
        second.body,
        "ip=1.1.1.1&categories=21&comment=Repeated+failed+authentication"
    );
    reply(second, "200 OK", "", "{}");
    assert!(lock(&reporter.state).pending.len() == 2);
}

#[tokio::test]
async fn daily_quota_drops_queued_work_and_ip_limit_extends_only_one_ip() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    reporter.try_enqueue(FIRST, "ssh", None);
    let first = mock.receive().await;
    reporter.try_enqueue(FIRST, "web", None);
    reporter.try_enqueue(SECOND, "ssh", None);
    reply(
        first,
        "429 Too Many Requests",
        "Retry-After: 3600\r\n",
        r#"{"errors":[{"status":429,"source":{"parameter":"ip"}}]}"#,
    );
    let second = mock.receive().await;
    assert!(second.body.contains("ip=1.1.1.1"));
    let first_deadline = lock(&reporter.state).pending[&FIRST].unwrap();
    assert!(first_deadline > Instant::now() + COOLDOWN);
    reporter.try_enqueue(THIRD, "ssh", None);
    reply(
        second,
        "429 Too Many Requests",
        "Retry-After: 3600\r\n",
        r#"{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint."}]}"#,
    );
    until(|| {
        let state = lock(&reporter.state);
        state.is_paused(Instant::now()) && !state.pending.contains_key(&THIRD)
    })
    .await;
    reporter.try_enqueue(THIRD, "ssh", None);
    assert!(!lock(&reporter.state).pending.contains_key(&THIRD));
    assert_eq!(lock(&reporter.state).pending[&FIRST], Some(first_deadline));
    assert!(mock.requests.try_recv().is_err());
}

#[tokio::test]
async fn timeout_preserves_the_cooldown() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    reporter.try_enqueue(FIRST, "ssh", None);
    let stalled = mock.receive().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::time::resume();
    until(|| lock(&reporter.state).last_warning.contains_key("timeout")).await;
    reporter.try_enqueue(FIRST, "web", None);
    assert!(lock(&reporter.state).pending[&FIRST].is_some());
    assert!(mock.requests.try_recv().is_err());
    drop(stalled);
}

#[tokio::test]
async fn reload_discards_queued_work_and_preserves_prior_attempts() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(1);
    reporter.try_enqueue(FIRST, "ssh", None);
    let first = mock.receive().await;
    reporter.try_enqueue(SECOND, "web", None);
    reporter.try_enqueue(THIRD, "ssh", None);
    assert!(!lock(&reporter.state).pending.contains_key(&THIRD));
    reporter.update(policy("rotated-mock-key"));
    reply(first, "403 Forbidden", "", TEST_KEY);
    until(|| !lock(&reporter.state).pending.contains_key(&SECOND)).await;
    reporter.try_enqueue(FIRST, "web", None);
    reporter.try_enqueue(THIRD, "ssh", None);
    let third = mock.receive().await;
    assert!(third.body.contains("ip=9.9.9.9"));
    assert!(third.headers.contains("key: rotated-mock-key"));
    reply(third, "200 OK", "", "{}");
}

struct RecordingBackend {
    calls: mpsc::UnboundedSender<IpAddr>,
    fails: bool,
    attached: bool,
}

#[async_trait::async_trait]
impl FirewallBackend for RecordingBackend {
    async fn init(&self, _: &str, _: &[String], _: &str) -> Result<()> {
        Ok(())
    }
    async fn teardown(&self, _: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, ip: &IpAddr, _: &str) -> Result<()> {
        self.calls.send(*ip).unwrap();
        if self.fails {
            return Err(Error::firewall("mock failure"));
        }
        Ok(())
    }
    async fn unban(&self, _: &IpAddr, _: &str) -> Result<()> {
        Ok(())
    }
    async fn is_banned(&self, _: &IpAddr, _: &str) -> Result<bool> {
        Ok(false)
    }
    fn reportable(&self, _: IpAddr) -> bool {
        self.attached
    }
    fn name(&self) -> &'static str {
        "mock"
    }
}

#[tokio::test]
async fn only_successful_new_automatic_bans_reach_the_reporter() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    let (record, mut calls) = mpsc::unbounded_channel();
    let mut backends: HashMap<_, Box<dyn FirewallBackend>> = HashMap::new();
    for name in ["ssh", "web", "failing", "unattached", "disabled"] {
        backends.insert(
            name.to_owned(),
            Box::new(RecordingBackend {
                calls: record.clone(),
                fails: name == "failing",
                attached: name != "unattached",
            }),
        );
    }
    let (fw, rx) = mpsc::channel(16);
    let (tracker, mut results) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(run_with_reporter(
        rx,
        backends,
        tracker,
        cancel.clone(),
        Some(reporter.clone()),
    ));
    let mut ip = SECOND;
    for jail in ["failing", "unattached", "disabled", "ssh", "web"] {
        fw.send(FirewallCmd::Ban {
            ip,
            jail_id: jail.into(),
            banned_at: 1,
            expires_at: None,
            done: None,
            report: Some(ReportObservation { timestamp: None }),
        })
        .await
        .unwrap();
        if jail == "disabled" {
            ip = FIRST;
        }
    }
    let (done, ack) = oneshot::channel();
    fw.send(FirewallCmd::Ban {
        ip: THIRD,
        jail_id: "ssh".into(),
        banned_at: 1,
        expires_at: None,
        done: Some(done),
        report: None,
    })
    .await
    .unwrap();
    let first = mock.receive().await;
    assert!(first.body.contains("ip=8.8.8.8&categories=18%2C22"));
    ack.await.unwrap().unwrap();
    fw.send(FirewallCmd::Reconcile {
        bans: vec![BanRecord {
            ip: SECOND,
            jail_id: "ssh".into(),
            banned_at: 1,
            expires_at: None,
        }],
    })
    .await
    .unwrap();
    for expected in [SECOND, SECOND, SECOND, FIRST, FIRST, THIRD, SECOND] {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), calls.recv())
                .await
                .unwrap(),
            Some(expected)
        );
    }
    assert!(results.try_recv().is_ok());
    assert_eq!(lock(&reporter.state).pending.len(), 1);
    reply(first, "200 OK", "", "{}");
    cancel.cancel();
    handle.await.unwrap();
}

#[tokio::test]
async fn unknown_rate_limit_stays_per_ip_and_restart_resets_the_window() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    reporter.try_enqueue(FIRST, "ssh", None);
    let first = mock.receive().await;
    let before = lock(&reporter.state).pending[&FIRST].unwrap();
    reply(
        first,
        "429 Too Many Requests",
        "Retry-After: 3600\r\n",
        "{}",
    );
    until(|| {
        lock(&reporter.state)
            .last_warning
            .contains_key("unclassified_rate_limit")
    })
    .await;
    assert_eq!(lock(&reporter.state).pending[&FIRST], Some(before));
    reporter.try_enqueue(FIRST, "web", None);
    reporter.try_enqueue(SECOND, "web", None);
    let second = mock.receive().await;
    assert!(second.body.contains("ip=1.1.1.1"));
    reply(second, "200 OK", "", "{}");
    reporter.stop();

    let restarted = mock.reporter(64);
    restarted.try_enqueue(FIRST, "web", None);
    let after_restart = mock.receive().await;
    assert!(after_restart.body.contains("ip=8.8.8.8&categories=21"));
    reply(after_restart, "200 OK", "", "{}");
}

#[test]
fn configuration_can_be_read_without_opening_the_key() {
    let config = Config::parse(
        r#"
        [global.abuseipdb]
        api_key_file = "/nonexistent/f2b-abuseipdb.key"
        [jail.ssh]
        log_path = "/var/log/auth.log"
        filter = ['from <HOST>']
        [jail.ssh.abuseipdb]
        categories = [18, 22]
        description = "Repeated failed SSH authentication."
    "#,
    )
    .unwrap();
    assert!(Policy::prepare(&config).is_err());
}

#[tokio::test]
async fn threshold_report_runs_through_the_tracker_and_keeps_cooldown_after_unban() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    let (record, mut calls) = mpsc::unbounded_channel();
    let backends: HashMap<String, Box<dyn FirewallBackend>> = HashMap::from([(
        "ssh".to_owned(),
        Box::new(RecordingBackend {
            calls: record,
            fails: false,
            attached: true,
        }) as Box<dyn FirewallBackend>,
    )]);
    let (fw, fw_rx) = mpsc::channel(16);
    let (commands, cmd_rx) = mpsc::channel(16);
    let (failures, failure_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let executor = tokio::spawn(run_with_reporter(
        fw_rx,
        backends,
        commands.clone(),
        cancel.child_token(),
        Some(reporter.clone()),
    ));
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(crate::track::persist::open_ban_store(dir.path().into()).unwrap());
    let jail = crate::config::JailConfig {
        max_retry: 1,
        ban_time: -1,
        ..Default::default()
    };
    let tracker = tokio::spawn(crate::track::run(
        crate::config::GlobalConfig::default(),
        HashMap::from([("ssh".into(), jail)]),
        failure_rx,
        cmd_rx,
        fw,
        false,
        vec![],
        HashMap::new(),
        store,
        None,
        cancel.child_token(),
    ));

    let failure = crate::detect::watcher::Failure {
        ip: FIRST,
        jail_id: "ssh".into(),
        timestamp: chrono::Utc::now().timestamp(),
        timestamp_from_log: true,
    };
    failures.send(failure.clone()).await.unwrap();
    let request = mock.receive().await;
    assert!(request.body.contains("timestamp="));
    reply(request, "200 OK", "", "{}");
    assert_eq!(calls.recv().await, Some(FIRST));

    let (respond, unbanned) = oneshot::channel();
    commands
        .send(crate::track::TrackerCmd::ManualUnban {
            ip: FIRST,
            jail_id: "ssh".into(),
            respond,
        })
        .await
        .unwrap();
    unbanned.await.unwrap().unwrap();
    failures.send(failure).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), calls.recv())
            .await
            .unwrap(),
        Some(FIRST)
    );
    assert!(lock(&reporter.state).pending[&FIRST].is_some());
    assert!(mock.requests.try_recv().is_err());
    cancel.cancel();
    tracker.await.unwrap();
    executor.await.unwrap();
}

#[tokio::test]
async fn second_post_can_start_at_exactly_thirty_minutes() {
    let mut mock = Mock::start().await;
    let reporter = mock.reporter(64);
    tokio::time::pause();
    reporter.try_enqueue(FIRST, "ssh", None);
    let started = Instant::now();
    // Keep the runtime runnable while loopback I/O settles so the paused
    // clock cannot auto-advance to the HTTP timeout.
    let wall_deadline = std::time::Instant::now() + Duration::from_secs(3);
    let first = loop {
        assert!(
            std::time::Instant::now() < wall_deadline,
            "mock request timed out"
        );
        if let Ok(request) = mock.requests.try_recv() {
            break request;
        }
        tokio::task::yield_now().await;
    };
    reply(first, "200 OK", "", "{}");
    assert_eq!(
        lock(&reporter.state).pending[&FIRST],
        Some(started + COOLDOWN)
    );
    tokio::time::advance(Duration::from_secs(1799)).await;
    reporter.try_enqueue(FIRST, "web", None);
    assert_eq!(
        lock(&reporter.state).pending[&FIRST],
        Some(started + COOLDOWN)
    );
    assert!(mock.requests.try_recv().is_err());

    tokio::time::advance(Duration::from_secs(1)).await;
    reporter.try_enqueue(FIRST, "web", None);
    tokio::time::resume();
    let second = mock.receive().await;
    assert!(second.body.contains("ip=8.8.8.8&categories=21"));
    reply(second, "200 OK", "", "{}");
}
