use super::*;
use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "dropbear",
        "Mar 24 15:25:51 buffalo1 dropbear[4092]: bad password attempt for 'root' from 198.51.100.87:5543",
        "198.51.100.87",
    ),
    (
        "dropbear",
        "Feb 11 15:23:17 dropbear[1252]: login attempt for nonexistent user from ::ffff:198.51.100.215:60495",
        "198.51.100.215",
    ),
    (
        "dropbear",
        "Jul 27 01:04:12 fail2ban-test dropbear[1335]: Bad password attempt for 'root' from 1.2.3.4:60588",
        "1.2.3.4",
    ),
    (
        "dropbear",
        "Jul 27 01:04:22 fail2ban-test dropbear[1335]: Exit before auth (user 'root', 10 fails): Max auth tries reached - user 'root' from 1.2.3.4:60588",
        "1.2.3.4",
    ),
    (
        "dropbear",
        "Jul 10 23:57:29 fail2ban-test dropbear[825]: [825] Jul 10 23:57:29 Exit before auth from <192.0.2.3:52289>: (user 'root', 10 fails): Max auth tries reached - user 'root'",
        "192.0.2.3",
    ),
    (
        "dropbear",
        "Jul 10 23:53:52 fail2ban-test dropbear[825]: [825] Jul 10 23:53:52 Bad password attempt for 'root' from 1.2.3.4:52289",
        "1.2.3.4",
    ),
    (
        "pam-generic",
        "Feb  7 15:10:42 example pure-ftpd: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=pure-ftpd ruser=sample-user rhost=192.168.1.1",
        "192.168.1.1",
    ),
    (
        "pam-generic",
        "May 12 09:47:54 vaio sshd[16004]: (pam_unix) authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=71.13.115.12  user=root",
        "71.13.115.12",
    ),
    (
        "pam-generic",
        "Jul 19 18:11:26 srv2 vsftpd: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=an8767 rhost=10.20.30.40",
        "10.20.30.40",
    ),
    (
        "pam-generic",
        "Nov 25 17:12:13 webmail pop(pam_unix)[4920]: authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=192.168.10.3 user=mailuser",
        "192.168.10.3",
    ),
    (
        "selinux-ssh",
        r#"type=USER_ERR msg=audit(1373330717.000:4070): user pid=12000 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:bad_ident acct="?" exe="/usr/sbin/sshd" hostname=173.242.116.187 addr=173.242.116.187 terminal=ssh res=failed'"#,
        "173.242.116.187",
    ),
    (
        "sshd",
        "Feb 25 14:34:10 belka sshd[31602]: Failed password for invalid user ROOT from 194.117.26.69 port 50273 ssh2",
        "194.117.26.69",
    ),
    (
        "sshd",
        "Feb 25 14:34:10 belka sshd[31603]: Failed password for invalid user ROOT from aaaa:bbbb:cccc:1234::1:1 port 50273 ssh2",
        "aaaa:bbbb:cccc:1234::1:1",
    ),
    (
        "sshd",
        "Jul 20 14:42:12 localhost sshd[22708]: Invalid user ftp from 192.0.2.2 port 37220",
        "192.0.2.2",
    ),
    (
        "sshd",
        "Sep 29 16:28:02 spaceman sshd[16699]: Failed password for dan from 127.0.0.1 port 45416 ssh1",
        "127.0.0.1",
    ),
    (
        "sshd",
        "Sep 29 16:28:05 spaceman sshd[16700]: Disconnected from authenticating user root 127.0.0.1 port 45416",
        "127.0.0.1",
    ),
];

/// (filter_name, log_line) rows that must NOT match.
const NO_MATCH_CASES: &[(&str, &str)] = &[
    (
        "sshd",
        "Oct 15 19:51:35 server sshd[7592]: Address 1.2.3.4 maps to 1234.bbbbbb.com, but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!",
    ),
    (
        "sshd",
        "Apr 24 01:39:19 host sshd[3719]: User root not allowed because account is locked",
    ),
    (
        "sshd",
        "Feb 12 04:09:18 localhost sshd[26713]: Connection from 115.249.163.77 port 51353",
    ),
    (
        "sshd",
        "Nov 28 09:16:03 srv sshd[32307]: Accepted publickey for git from 192.0.2.1 port 57904 ssh2: DSA 36:48:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx",
    ),
];

#[test]
fn match_samples() {
    for &(name, line, ip) in MATCH_CASES {
        assert_filter_matches(name, line, ip);
    }
}

#[test]
fn no_match_samples() {
    for &(name, line) in NO_MATCH_CASES {
        assert_filter_no_match(name, line);
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
    for &(name, ..) in NO_MATCH_CASES {
        assert!(
            names.contains(name),
            "no-match case for '{name}' is not in this category"
        );
    }
}
