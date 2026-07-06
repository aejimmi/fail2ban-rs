use super::*;
use crate::detect::filters::test_util::assert_filter_matches;

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "gssftpd",
        "Jan 22 18:09:46 host ftpd[132]: repeated login failures from 198.51.100.23 (example.com)",
        "198.51.100.23",
    ),
    (
        "proftpd",
        "Jan 10 00:00:00 myhost proftpd[12345] myhost.domain.com (123.123.123.123[123.123.123.123]): USER username (Login failed): User in /etc/ftpusers",
        "123.123.123.123",
    ),
    (
        "proftpd",
        "Feb 1 00:00:00 myhost proftpd[12345] myhost.domain.com (123.123.123.123[123.123.123.123]): USER username: no such user found from 123.123.123.123 [123.123.123.123] to 234.234.234.234:21",
        "123.123.123.123",
    ),
    (
        "proftpd",
        "Jun 09 07:30:58 platypus.ace-hosting.com.au proftpd[11864] platypus.ace-hosting.com.au (mail.bloodymonster.net[::ffff:67.227.224.66]): USER username (Login failed): Incorrect password.",
        "67.227.224.66",
    ),
    (
        "proftpd",
        "Jun 13 22:07:23 platypus.ace-hosting.com.au proftpd[15719] platypus.ace-hosting.com.au (::ffff:59.167.242.100[::ffff:59.167.242.100]): SECURITY VIOLATION: root login attempted.",
        "59.167.242.100",
    ),
    (
        "proftpd",
        "May 31 10:53:25 mail proftpd[15302]: xxxxxxxxxx (::ffff:1.2.3.4[::ffff:1.2.3.4]) - Maximum login attempts (3) exceeded",
        "1.2.3.4",
    ),
    (
        "proftpd",
        "Jun 14 00:09:59 platypus.ace-hosting.com.au proftpd[17839] platypus.ace-hosting.com.au (::ffff:59.167.242.100[::ffff:59.167.242.100]): USER platypus.ace-hosting.com.au proftpd[17424] platypus.ace-hosting.com.au (hihoinjection[1.2.3.44]): no such user found from ::ffff:59.167.242.100 [::ffff:59.167.242.100] to ::ffff:113.212.99.194:21",
        "59.167.242.100",
    ),
    (
        "proftpd",
        "Oct  2 15:45:44 ftp01 proftpd[5517]: 192.0.2.13 (192.0.2.13[192.0.2.13]) - SECURITY VIOLATION: Root login attempted",
        "192.0.2.13",
    ),
    (
        "pure-ftpd",
        "Jan 31 16:54:07 desktop pure-ftpd: (?@24.79.92.194) [WARNING] Authentication failed for user [Administrator]",
        "24.79.92.194",
    ),
    (
        "vsftpd",
        r#"2025-03-04T01:06:36.645577 host vsftpd[1658]: [username] FAIL LOGIN: Client "192.0.2.222""#,
        "192.0.2.222",
    ),
    (
        "vsftpd",
        r#"Thu Sep  8 00:39:49 2016 [pid 15019] vsftpd: [guest] FAIL LOGIN: Client "::ffff:192.0.2.1", "User is not in the allow user list.""#,
        "192.0.2.1",
    ),
    (
        "wuftpd",
        "Oct  6 09:59:26 myserver wu-ftpd[18760]: failed login from hj-145-173-a8.bta.net.cn [202.108.145.173]",
        "202.108.145.173",
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
