use super::*;
use crate::detect::filters::test_util::assert_filter_matches;

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "asterisk",
        "[2012-02-13 17:53:59] NOTICE[1638] chan_iax2.c: Host 1.2.3.4 failed to authenticate as 'Fail2ban'",
        "1.2.3.4",
    ),
    (
        "asterisk",
        "[2022-01-01 00:00:00] NOTICE[999] chan_sip.c: Host 2001:db8::1 failed to authenticate as 'test'",
        "2001:db8::1",
    ),
    (
        "freeswitch",
        "2013-12-31 17:39:54.767815 [WARNING] sofia_reg.c:1478 SIP auth failure (INVITE) on sofia profile 'internal' for [000972543480510@192.168.2.51] from ip 5.11.47.236",
        "5.11.47.236",
    ),
    (
        "freeswitch",
        "2013-12-31 17:39:54.767815 [WARNING] sofia_reg.c:2531 Can't find user [1001@192.168.2.51] from 5.11.47.236",
        "5.11.47.236",
    ),
    (
        "murmur",
        "<W>2015-11-29 16:38:01.818 1 => <4:testUsernameOne(-1)> Rejected connection from 192.168.0.1:29530: Invalid server password",
        "192.168.0.1",
    ),
    (
        "murmur",
        "<W>2015-11-29 17:18:20.962 1 => <8:testUsernameTwo(-1)> Rejected connection from 192.168.1.2:29761: Wrong certificate or password for existing user",
        "192.168.1.2",
    ),
];

#[test]
fn match_samples() {
    for &(name, line, ip) in MATCH_CASES {
        assert_filter_matches(name, line, ip);
    }
}

/// Every sample row targets a filter that lives in this category's table.
#[test]
fn cases_target_this_category() {
    let names: std::collections::HashSet<&str> = FILTERS.iter().map(|f| f.name).collect();
    for &(name, ..) in MATCH_CASES {
        assert!(
            names.contains(name),
            "match case for '{name}' is not in this category"
        );
    }
}
