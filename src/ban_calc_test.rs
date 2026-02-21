//! Tests for ban time calculation and jail parameter building.

use std::collections::HashMap;

use crate::ban_calc::{build_jail_params, calc_ban_time, JailParams};
use crate::config::JailConfig;

fn base_params() -> JailParams {
    JailParams {
        max_retry: 3,
        find_time: 600,
        ban_time: 60,
        webhook: None,
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604800,
    }
}

// ---------------------------------------------------------------------------
// calc_ban_time
// ---------------------------------------------------------------------------

#[test]
fn no_increment_returns_base() {
    let params = base_params();
    assert_eq!(calc_ban_time(60, 0, &params), 60);
    assert_eq!(calc_ban_time(60, 5, &params), 60);
    assert_eq!(calc_ban_time(60, 100, &params), 60);
}

#[test]
fn exponential_escalation() {
    let mut params = base_params();
    params.bantime_increment = true;
    assert_eq!(calc_ban_time(60, 0, &params), 60);   // 60 * 2^0
    assert_eq!(calc_ban_time(60, 1, &params), 120);  // 60 * 2^1
    assert_eq!(calc_ban_time(60, 2, &params), 240);  // 60 * 2^2
    assert_eq!(calc_ban_time(60, 3, &params), 480);  // 60 * 2^3
    assert_eq!(calc_ban_time(60, 4, &params), 960);  // 60 * 2^4
}

#[test]
fn explicit_multipliers() {
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_multipliers = vec![1, 2, 4, 8, 16];
    assert_eq!(calc_ban_time(60, 0, &params), 60);   // 60 * 1
    assert_eq!(calc_ban_time(60, 1, &params), 120);  // 60 * 2
    assert_eq!(calc_ban_time(60, 2, &params), 240);  // 60 * 4
    assert_eq!(calc_ban_time(60, 3, &params), 480);  // 60 * 8
    assert_eq!(calc_ban_time(60, 4, &params), 960);  // 60 * 16
    // Beyond list length: clamps to last multiplier.
    assert_eq!(calc_ban_time(60, 5, &params), 960);  // 60 * 16
    assert_eq!(calc_ban_time(60, 99, &params), 960); // 60 * 16
}

#[test]
fn maxtime_cap() {
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_maxtime = 300;
    assert_eq!(calc_ban_time(60, 3, &params), 300);  // 480 capped to 300
    assert_eq!(calc_ban_time(60, 10, &params), 300); // 61440 capped to 300
}

#[test]
fn factor_applied() {
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_factor = 1.5;
    assert_eq!(calc_ban_time(60, 0, &params), 90);  // 60 * 1.5
    assert_eq!(calc_ban_time(60, 1, &params), 180); // 120 * 1.5
}

#[test]
fn permanent_ban_bypasses_increment() {
    let mut params = base_params();
    params.bantime_increment = true;
    // Negative base = permanent ban, never modified.
    assert_eq!(calc_ban_time(-1, 0, &params), -1);
    assert_eq!(calc_ban_time(-1, 10, &params), -1);
}

#[test]
fn zero_maxtime_means_no_cap() {
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_maxtime = 0;
    assert_eq!(calc_ban_time(60, 10, &params), 61440);
}

// ---------------------------------------------------------------------------
// Inspired by fail2ban: permanent ban irreversibility
// ---------------------------------------------------------------------------

#[test]
fn permanent_ban_never_downgrades() {
    // Once a permanent ban (-1) is the base, escalation should never
    // produce a finite ban time, regardless of count or settings.
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_factor = 0.5; // factor < 1 should not make it finite
    params.bantime_maxtime = 300;
    for count in 0..20 {
        assert_eq!(
            calc_ban_time(-1, count, &params),
            -1,
            "permanent ban should stay permanent at count={count}"
        );
    }
}

// ---------------------------------------------------------------------------
// Inspired by fail2ban: escalation sequence simulation
// ---------------------------------------------------------------------------

#[test]
fn escalation_sequence_monotonically_increases() {
    // Each successive ban should be >= the previous one (never decreases).
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_maxtime = 0; // no cap
    let mut prev = 0i64;
    for count in 0..15 {
        let t = calc_ban_time(60, count, &params);
        assert!(
            t >= prev,
            "ban time should not decrease: count={count}, prev={prev}, got={t}"
        );
        prev = t;
    }
}

#[test]
fn multiplier_sequence_monotonically_increases() {
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_multipliers = vec![1, 2, 4, 8, 16, 32];
    params.bantime_maxtime = 0;
    let mut prev = 0i64;
    for count in 0..10 {
        let t = calc_ban_time(60, count, &params);
        assert!(
            t >= prev,
            "ban time should not decrease with multipliers: count={count}"
        );
        prev = t;
    }
}

// ---------------------------------------------------------------------------
// Exponential overflow protection
// ---------------------------------------------------------------------------

#[test]
fn high_count_does_not_panic() {
    // Exponent is capped at 20 internally, so 2^20 * 60 should not overflow.
    let mut params = base_params();
    params.bantime_increment = true;
    params.bantime_maxtime = 0;
    let result = calc_ban_time(60, 100, &params);
    // 60 * 2^20 = 62_914_560
    assert_eq!(result, 60 * (1 << 20));
}

// ---------------------------------------------------------------------------
// build_jail_params
// ---------------------------------------------------------------------------

fn test_jail_config() -> JailConfig {
    JailConfig {
        enabled: true,
        log_path: "/tmp/test.log".into(),
        date_format: crate::date::DateFormat::Syslog,
        filter: vec!["from <HOST>".to_string()],
        max_retry: 5,
        find_time: 600,
        ban_time: 3600,
        port: vec![],
        protocol: "tcp".to_string(),
        bantime_increment: false,
        bantime_factor: 1.0,
        bantime_multipliers: vec![],
        bantime_maxtime: 604800,
        backend: crate::config::Backend::Nftables,
        log_backend: crate::config::LogBackend::default(),
        journalmatch: vec![],
        ignoreregex: vec![],
        ignoreip: vec![],
        ignoreself: false,
        webhook: None,
    }
}

#[test]
fn build_params_maps_all_jails() {
    let mut configs = HashMap::new();
    configs.insert("sshd".to_string(), test_jail_config());
    let mut nginx = test_jail_config();
    nginx.max_retry = 10;
    nginx.ban_time = 7200;
    configs.insert("nginx".to_string(), nginx);

    let params = build_jail_params(&configs);
    assert_eq!(params.len(), 2);
    assert!(params.contains_key("sshd"));
    assert!(params.contains_key("nginx"));
}

#[test]
fn build_params_copies_values_correctly() {
    let mut configs = HashMap::new();
    let mut jail = test_jail_config();
    jail.max_retry = 7;
    jail.find_time = 300;
    jail.ban_time = 1800;
    jail.bantime_increment = true;
    jail.bantime_factor = 2.0;
    jail.bantime_multipliers = vec![1, 5, 10];
    jail.bantime_maxtime = 86400;
    jail.webhook = Some("https://example.com/hook".to_string());
    configs.insert("test".to_string(), jail);

    let params = build_jail_params(&configs);
    let p = &params["test"];
    assert_eq!(p.max_retry, 7);
    assert_eq!(p.find_time, 300);
    assert_eq!(p.ban_time, 1800);
    assert!(p.bantime_increment);
    assert!((p.bantime_factor - 2.0).abs() < f64::EPSILON);
    assert_eq!(p.bantime_multipliers, vec![1, 5, 10]);
    assert_eq!(p.bantime_maxtime, 86400);
    assert_eq!(p.webhook, Some("https://example.com/hook".to_string()));
}

#[test]
fn build_params_empty_configs() {
    let configs = HashMap::new();
    let params = build_jail_params(&configs);
    assert!(params.is_empty());
}

#[test]
fn build_params_preserves_defaults() {
    let mut configs = HashMap::new();
    configs.insert("default".to_string(), test_jail_config());

    let params = build_jail_params(&configs);
    let p = &params["default"];
    assert_eq!(p.max_retry, 5);
    assert_eq!(p.find_time, 600);
    assert_eq!(p.ban_time, 3600);
    assert!(!p.bantime_increment);
    assert!((p.bantime_factor - 1.0).abs() < f64::EPSILON);
    assert!(p.bantime_multipliers.is_empty());
    assert_eq!(p.bantime_maxtime, 604800);
    assert!(p.webhook.is_none());
}
