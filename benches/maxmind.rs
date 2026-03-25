//! Criterion benchmarks for MaxMind GeoIP lookups.

use std::net::IpAddr;
use std::path::PathBuf;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use fail2ban_rs::config::MaxmindField;
use fail2ban_rs::tracker_maxmind::MaxmindState;

fn test_global() -> fail2ban_rs::config::GlobalConfig {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    fail2ban_rs::config::GlobalConfig {
        maxmind_asn: Some(base.join("GeoLite2-ASN-Test.mmdb")),
        maxmind_country: Some(base.join("GeoLite2-Country-Test.mmdb")),
        maxmind_city: Some(base.join("GeoLite2-City-Test.mmdb")),
        ..fail2ban_rs::config::GlobalConfig::default()
    }
}

fn bench_lookup(c: &mut Criterion) {
    let global = test_global();
    let mut jails = std::collections::HashMap::new();
    jails.insert(
        "bench".to_string(),
        fail2ban_rs::config::JailConfig {
            maxmind: vec![MaxmindField::Asn, MaxmindField::Country, MaxmindField::City],
            ..fail2ban_rs::config::JailConfig::default()
        },
    );
    let state = MaxmindState::load(&global, &jails);

    let known_ip: IpAddr = "89.160.20.142".parse().unwrap();
    let unknown_ip: IpAddr = "0.0.0.1".parse().unwrap();
    let ipv6: IpAddr = "2a02:dd40:22::42".parse().unwrap();

    let mut group = c.benchmark_group("maxmind_lookup");

    group.bench_function("all_three_fields", |b| {
        b.iter(|| state.enrich(black_box(known_ip), "bench"));
    });

    group.bench_function("unknown_ip_miss", |b| {
        b.iter(|| state.enrich(black_box(unknown_ip), "bench"));
    });

    group.bench_function("ipv6", |b| {
        b.iter(|| state.enrich(black_box(ipv6), "bench"));
    });

    group.bench_function("unknown_jail_noop", |b| {
        b.iter(|| state.enrich(black_box(known_ip), "nonexistent"));
    });

    group.finish();
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);
