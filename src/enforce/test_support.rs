//! Shared test doubles for the enforce module's unit tests.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::enforce::FirewallBackend;
use crate::error::{Error, Result};

/// Records all ban/unban/init calls for assertion.
pub(crate) struct MockBackend {
    pub(crate) calls: Arc<Mutex<Vec<String>>>,
}

impl MockBackend {
    /// Build a mock backend, returning it alongside a shared handle to its
    /// recorded call log.
    pub(crate) fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

#[async_trait::async_trait]
impl FirewallBackend for MockBackend {
    async fn init(&self, jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("init:{jail}"));
        Ok(())
    }
    async fn teardown(&self, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("teardown:{jail}"));
        Ok(())
    }

    async fn teardown_full(&self, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("teardown_full:{jail}"));
        Ok(())
    }

    async fn ban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("ban:{ip}:{jail}"));
        Ok(())
    }

    async fn unban(&self, ip: &IpAddr, jail: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("unban:{ip}:{jail}"));
        Ok(())
    }

    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

/// Mock backend that always fails on ban/unban.
pub(crate) struct FailingMockBackend;

#[async_trait::async_trait]
impl FirewallBackend for FailingMockBackend {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Ok(())
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Err(Error::firewall("mock failure"))
    }
    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Err(Error::firewall("mock failure"))
    }
    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }
    fn name(&self) -> &'static str {
        "failing-mock"
    }
}

/// Mock backend that always fails on `init`, but otherwise succeeds. Used to
/// exercise the `FirewallCmd::InitJail` failure path through the real
/// executor loop without needing a real firewall binary.
pub(crate) struct FailingInitMockBackend;

#[async_trait::async_trait]
impl FirewallBackend for FailingInitMockBackend {
    async fn init(&self, _jail: &str, _ports: &[String], _protocol: &str) -> Result<()> {
        Err(Error::firewall("mock init failure"))
    }
    async fn teardown(&self, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn ban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn unban(&self, _ip: &IpAddr, _jail: &str) -> Result<()> {
        Ok(())
    }
    async fn is_banned(&self, _ip: &IpAddr, _jail: &str) -> Result<bool> {
        Ok(false)
    }
    fn name(&self) -> &'static str {
        "failing-init-mock"
    }
}
