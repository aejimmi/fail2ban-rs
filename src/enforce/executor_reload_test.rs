use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::ban_target::BanTarget;
use crate::enforce::test_support::{FailingInitMockBackend, MockBackend};

type Calls = Arc<Mutex<Vec<String>>>;

/// Recording backend whose individual operations can be made to fail.
#[derive(Default)]
struct ScriptedBackend {
    calls: Calls,
    fail_init: bool,
    fail_teardown: bool,
    fail_ban_ip: Option<BanTarget>,
}

impl ScriptedBackend {
    fn record(&self, entry: String) {
        self.calls.lock().expect("lock").push(entry);
    }
}

#[async_trait::async_trait]
impl FirewallBackend for ScriptedBackend {
    async fn init(&self, jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        self.record(format!("init:{jail}"));
        if self.fail_init {
            return Err(Error::firewall("scripted init failure"));
        }
        Ok(())
    }
    async fn teardown(&self, jail: &str) -> Result<()> {
        self.record(format!("teardown:{jail}"));
        if self.fail_teardown {
            return Err(Error::firewall("scripted teardown failure"));
        }
        Ok(())
    }
    async fn ban(&self, ip: &BanTarget, jail: &str) -> Result<()> {
        self.record(format!("ban:{ip}:{jail}"));
        if self.fail_ban_ip == Some(*ip) {
            return Err(Error::firewall("scripted ban failure"));
        }
        Ok(())
    }
    async fn unban(&self, _ip: &BanTarget, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn is_banned(&self, _ip: &BanTarget, _jail: &str) -> Result<bool> {
        Ok(false)
    }
    fn name(&self) -> &'static str {
        "scripted"
    }
}

fn ban(last: u8) -> BanRecord {
    BanRecord {
        ip: BanTarget::V4(Ipv4Addr::new(8, 8, 8, last)),
        jail_id: "sshd".to_string(),
        banned_at: 1000,
        expires_at: None,
    }
}

fn job(active_bans: Vec<BanRecord>) -> ReplaceJob {
    ReplaceJob {
        jail_id: "sshd".to_string(),
        old_rules: JailRules::new(vec!["22".to_string()], "tcp".to_string()),
        new_rules: JailRules::new(vec!["443".to_string()], "tcp".to_string()),
        active_bans,
    }
}

type Backends = HashMap<String, Box<dyn FirewallBackend>>;

fn backends_with(backend: impl FirewallBackend + 'static) -> Backends {
    let mut backends: Backends = HashMap::new();
    backends.insert("sshd".to_string(), Box::new(backend));
    backends
}

/// Apply an acknowledged ban through the executor's real ban path.
async fn ban_via_executor(backends: &Backends, last: u8) -> Result<()> {
    let (tracker_tx, _tracker_rx) = mpsc::channel(1);
    let (done_tx, done_rx) = oneshot::channel();
    let ip = BanTarget::V4(Ipv4Addr::new(9, 9, 9, last));
    let ban = super::super::BanApplication {
        ip,
        jail_id: "sshd",
        banned_at: 0,
        expires_at: None,
    };
    super::super::apply_ban(backends, &tracker_tx, &ban, Some(done_tx)).await;
    done_rx.await.expect("done channel dropped")
}

fn calls(c: &Calls) -> Vec<String> {
    c.lock().expect("lock").clone()
}

/// Regression for #17: if replacement initialization fails after the old
/// backend was torn down, the executor must rebuild/reseed the old backend and
/// leave it registered for subsequent enforcement.
#[tokio::test]
async fn test_replace_failed_init_restores_old_backend_and_keeps_it_functional() {
    let (old_backend, old_calls) = MockBackend::new();
    let mut backends = backends_with(old_backend);

    let replacement = Box::new(FailingInitMockBackend);
    let result = replace_jail_with_backend(&mut backends, replacement, &job(vec![ban(8)])).await;
    assert!(result.is_err(), "replacement must report its init failure");

    ban_via_executor(&backends, 9)
        .await
        .expect("old backend live");
    assert_eq!(
        calls(&old_calls),
        [
            "teardown:sshd",
            "init:sshd",
            "ban:8.8.8.8:sshd",
            "ban:9.9.9.9:sshd"
        ],
        "old backend must be fully restored and handle later bans"
    );
}

/// A successful replacement must seed stored bans on the new backend and route
/// all subsequent bans to it, without reinitializing the old backend.
#[tokio::test]
async fn test_replace_success_commits_new_backend() {
    let (old_backend, old_calls) = MockBackend::new();
    let (new_backend, new_calls) = MockBackend::new();
    let mut backends = backends_with(old_backend);

    replace_jail_with_backend(&mut backends, Box::new(new_backend), &job(vec![ban(4)]))
        .await
        .expect("replacement should succeed");
    ban_via_executor(&backends, 1)
        .await
        .expect("new backend live");

    assert_eq!(calls(&old_calls), ["teardown:sshd"]);
    assert_eq!(
        calls(&new_calls),
        ["init:sshd", "ban:8.8.8.4:sshd", "ban:9.9.9.1:sshd"]
    );
}

/// M1: when the previous backend's teardown fails, it may be half torn down;
/// it must be rebuilt (init + bans) and kept registered, and the replacement
/// is never touched.
#[tokio::test]
async fn test_replace_previous_teardown_failure_rebuilds_old_backend() {
    let old = ScriptedBackend {
        fail_teardown: true,
        ..ScriptedBackend::default()
    };
    let old_calls = Arc::clone(&old.calls);
    let (new_backend, new_calls) = MockBackend::new();
    let mut backends = backends_with(old);

    let error = replace_jail_with_backend(&mut backends, Box::new(new_backend), &job(vec![ban(1)]))
        .await
        .expect_err("teardown failure must fail the replacement");
    assert!(error.to_string().contains("scripted teardown failure"));

    ban_via_executor(&backends, 2)
        .await
        .expect("old backend live");
    assert_eq!(
        calls(&old_calls),
        [
            "teardown:sshd",
            "init:sshd",
            "ban:8.8.8.1:sshd",
            "ban:9.9.9.2:sshd"
        ]
    );
    assert!(
        calls(&new_calls).is_empty(),
        "replacement never initialized"
    );
}

/// M3: a single failed ban reapply is logged, not fatal — the replacement
/// commits and every other ban is still applied.
#[tokio::test]
async fn test_replace_single_ban_failure_does_not_abort_replacement() {
    let (old_backend, _old_calls) = MockBackend::new();
    let replacement = ScriptedBackend {
        fail_ban_ip: Some(ban(1).ip),
        ..ScriptedBackend::default()
    };
    let new_calls = Arc::clone(&replacement.calls);
    let mut backends = backends_with(old_backend);

    let bans = vec![ban(1), ban(2), ban(3)];
    replace_jail_with_backend(&mut backends, Box::new(replacement), &job(bans))
        .await
        .expect("per-ban failure must not abort the replacement");

    assert_eq!(
        calls(&new_calls),
        [
            "init:sshd",
            "ban:8.8.8.1:sshd",
            "ban:8.8.8.2:sshd",
            "ban:8.8.8.3:sshd"
        ]
    );
    assert_eq!(backends.get("sshd").map(|b| b.name()), Some("scripted"));
}

/// When both the replacement and the rollback fail, the error reports both
/// and the old backend stays registered (never a no-backend jail).
#[tokio::test]
async fn test_replace_rollback_failure_reports_both_and_keeps_old_backend() {
    let old = ScriptedBackend {
        fail_init: true,
        ..ScriptedBackend::default()
    };
    let mut backends = backends_with(old);

    let error = replace_jail_with_backend(
        &mut backends,
        Box::new(FailingInitMockBackend),
        &job(vec![]),
    )
    .await
    .expect_err("must fail");
    let msg = error.to_string();
    assert!(msg.contains("mock init failure"), "{msg}");
    assert!(msg.contains("rollback failed"), "{msg}");
    assert!(msg.contains("scripted init failure"), "{msg}");
    assert_eq!(backends.get("sshd").map(|b| b.name()), Some("scripted"));
}

/// Replacing a jail with no registered backend is an explicit error.
#[tokio::test]
async fn test_replace_without_registered_backend_errors() {
    let mut backends: Backends = HashMap::new();
    let (new_backend, new_calls) = MockBackend::new();
    let error = replace_jail_with_backend(&mut backends, Box::new(new_backend), &job(vec![]))
        .await
        .expect_err("must fail");
    assert!(error.to_string().contains("no backend is registered"));
    assert!(calls(&new_calls).is_empty());
    assert!(backends.is_empty());
}

/// If the replacement backend cannot even be constructed (binary missing),
/// the old backend is left registered and untouched, and the error is acked.
#[tokio::test]
async fn test_replace_jail_create_backend_failure_keeps_old_backend() {
    if crate::enforce::resolve_binary("ipset").is_ok() {
        eprintln!("skipping: ipset is installed, backend creation would succeed");
        return;
    }
    let (old_backend, old_calls) = MockBackend::new();
    let mut backends = backends_with(old_backend);
    let backend = crate::config::Backend::Ipset {
        maxelem: 65536,
        chain: "INPUT".to_string(),
    };
    let (done_tx, done_rx) = oneshot::channel();
    let mut running = RunningRules::new();
    replace_jail(
        &mut backends,
        &mut running,
        &backend,
        &job(vec![ban(1)]),
        done_tx,
    )
    .await;

    let error = done_rx.await.expect("acked").expect_err("must fail");
    assert!(error.to_string().contains("not found"), "{error}");
    assert!(calls(&old_calls).is_empty(), "old backend untouched");
    ban_via_executor(&backends, 3)
        .await
        .expect("old backend live");
}

/// C6: seeding an added jail tolerates a failed ban — the jail is still
/// registered and every other stored ban is applied.
#[tokio::test]
async fn test_add_jail_single_ban_failure_does_not_abort_addition() {
    let log = Calls::default();
    let backend = ScriptedBackend {
        calls: Arc::clone(&log),
        fail_ban_ip: Some(ban(1).ip),
        ..ScriptedBackend::default()
    };
    let mut backends: Backends = HashMap::new();
    let add = AddJob {
        jail_id: "sshd".to_string(),
        rules: JailRules::new(vec!["22".to_string()], "tcp".to_string()),
        active_bans: vec![ban(1), ban(2)],
    };

    register_jail(&mut backends, Box::new(backend), &add)
        .await
        .expect("a single failed ban must not fail the addition");

    assert!(backends.contains_key("sshd"), "jail must be registered");
    assert_eq!(
        calls(&log),
        ["init:sshd", "ban:8.8.8.1:sshd", "ban:8.8.8.2:sshd"]
    );
}

/// C6: a failed `init` leaves no half-registered jail and seeds nothing.
#[tokio::test]
async fn test_add_jail_init_failure_registers_nothing() {
    let log = Calls::default();
    let backend = ScriptedBackend {
        calls: Arc::clone(&log),
        fail_init: true,
        ..ScriptedBackend::default()
    };
    let mut backends: Backends = HashMap::new();
    let add = AddJob {
        jail_id: "sshd".to_string(),
        rules: JailRules::new(vec![], "tcp".to_string()),
        active_bans: vec![ban(1)],
    };

    assert!(
        register_jail(&mut backends, Box::new(backend), &add)
            .await
            .is_err()
    );
    assert!(backends.is_empty());
    assert_eq!(calls(&log), ["init:sshd"]);
}

/// Backend recording the ports each `init` was called with.
struct RulesBackend {
    inits: Arc<Mutex<Vec<Vec<String>>>>,
    fail_init: bool,
}

#[async_trait::async_trait]
impl FirewallBackend for RulesBackend {
    async fn init(&self, _jail: &str, ports: &[String], _protocol: &str) -> Result<()> {
        self.inits.lock().expect("lock").push(ports.to_vec());
        if self.fail_init {
            return Err(Error::firewall("scripted init failure"));
        }
        Ok(())
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, _ip: &BanTarget, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn unban(&self, _ip: &BanTarget, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn is_banned(&self, _ip: &BanTarget, _jail: &str) -> Result<bool> {
        Ok(false)
    }
    fn name(&self) -> &'static str {
        "rules"
    }
}

fn rules(port: &str) -> JailRules {
    JailRules::new(vec![port.to_string()], "tcp".to_string())
}

/// A reload rollback's reverse replace claims the *new* config's rules as
/// "old". When the forward replace was itself rolled back, the live backend
/// still runs the original rules, and a failed reverse replace must restore
/// it with those — not with the claimed ones.
#[tokio::test]
async fn test_reverse_replace_failure_restores_the_rules_actually_running() {
    let inits = Arc::new(Mutex::new(Vec::new()));
    let live = RulesBackend {
        inits: Arc::clone(&inits),
        fail_init: false,
    };
    let mut backends = backends_with(live);
    let mut running = RunningRules::new();
    running.insert("sshd".to_string(), rules("22"));

    // Reverse job: claims 443 is live and asks to go back to 22.
    let job = ReplaceJob {
        old_rules: running_rules(&running, "sshd", rules("443")),
        jail_id: "sshd".to_string(),
        new_rules: rules("22"),
        active_bans: vec![],
    };
    let failing = RulesBackend {
        inits: Arc::new(Mutex::new(Vec::new())),
        fail_init: true,
    };
    replace_tracked(&mut backends, &mut running, Box::new(failing), &job)
        .await
        .expect_err("replacement init fails");

    assert_eq!(*inits.lock().expect("lock"), vec![vec!["22".to_string()]]);
    assert_eq!(running.get("sshd"), Some(&rules("22")));
}

#[test]
fn test_running_rules_falls_back_to_claimed_when_unrecorded() {
    let running = RunningRules::new();
    assert_eq!(running_rules(&running, "sshd", rules("80")), rules("80"));
}

#[tokio::test]
async fn test_replace_tracked_success_records_new_rules() {
    let (old_backend, _calls) = MockBackend::new();
    let mut backends = backends_with(old_backend);
    let mut running = RunningRules::new();
    let (new_backend, _new_calls) = MockBackend::new();
    replace_tracked(
        &mut backends,
        &mut running,
        Box::new(new_backend),
        &job(vec![]),
    )
    .await
    .expect("replace succeeds");
    assert_eq!(running.get("sshd"), Some(&rules("443")));
}
