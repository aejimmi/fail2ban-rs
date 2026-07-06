use super::*;
use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "courier-auth",
        "Apr 23 21:59:01 dns2 imapd: LOGIN FAILED, user=sales@example.com, ip=[::ffff:1.2.3.4]",
        "1.2.3.4",
    ),
    (
        "courier-auth",
        "Apr 23 21:59:38 dns2 pop3d: LOGIN FAILED, user=info@example.com, ip=[::ffff:198.51.100.76]",
        "198.51.100.76",
    ),
    (
        "courier-auth",
        "Nov 13 08:11:53 server imapd-ssl: LOGIN FAILED, user=user@domain.tld, ip=[::ffff:198.51.100.33]",
        "198.51.100.33",
    ),
    (
        "courier-auth",
        "Apr 17 19:17:12 server imapd-ssl: LOGIN FAILED, method=PLAIN, ip=[::ffff:192.0.2.4]",
        "192.0.2.4",
    ),
    (
        "courier-auth",
        "Apr 17 19:17:11 SERVER courierpop3login: LOGIN FAILED, user=USER@EXAMPLE.org, ip=[::ffff:1.2.3.4]",
        "1.2.3.4",
    ),
    (
        "courier-smtp",
        "Apr 10 03:47:57 web courieresmtpd: error,relay=::ffff:1.2.3.4,ident=tmf,from=<tmf@example.com>,to=<mailman-subscribe@example.com>: 550 User unknown.",
        "1.2.3.4",
    ),
    (
        "courier-smtp",
        r#"Jul  3 23:07:20 szerver courieresmtpd: error,relay=::ffff:1.2.3.4,msg="535 Authentication failed.",cmd: YWRvYmVhZG9iZQ=="#,
        "1.2.3.4",
    ),
    (
        "cyrus-imap",
        "Jan 4 21:51:05 hostname cyrus/imap[5355]: badlogin: localhost.localdomain [127.0.0.1] plaintext cyrus@localdomain SASL(-13): authentication failure: checkpass failed",
        "127.0.0.1",
    ),
    (
        "cyrus-imap",
        "Jul 17 22:55:56 derry cyrus/imaps[7568]: badlogin: serafinat.xxxxxx [1.2.3.4] plain [SASL(-13): user not found: user: pressy@derry property: cmusaslsecretPLAIN not found in sasldb]",
        "1.2.3.4",
    ),
    (
        "domino-smtp",
        "03-07-2005 23:07:20   SMTP Server: Authentication failed for user postmaster ; connecting host 1.2.3.4",
        "1.2.3.4",
    ),
    (
        "domino-smtp",
        "[28325:00010-3735542592] 22-06-2014 09:56:12   smtp: postmaster [1.2.3.4] authentication failure using internet password",
        "1.2.3.4",
    ),
    (
        "dovecot",
        "Feb 12 12:07:14 mx dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<info@example.com>, method=PLAIN, rip=80.187.101.33, lip=178.63.84.151",
        "80.187.101.33",
    ),
    (
        "dovecot",
        "Jan 05 10:00:01 mailhost dovecot: imap-login: Aborted login (tried to use disallowed plaintext auth): user=<>, rip=49.176.98.87, lip=10.0.0.2, TLS",
        "49.176.98.87",
    ),
    (
        "dovecot",
        "Jan 05 10:05:00 mailhost dovecot: pop3-login: Disconnected (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=59.167.242.100, lip=10.0.0.1, secured",
        "59.167.242.100",
    ),
    (
        "exim",
        "2013-01-04 17:03:46 login authenticator failed for rrcs-24-106-174-74.se.biz.rr.com ([192.168.2.33]) [24.106.174.74]: 535 Incorrect authentication data (set_id=brian)",
        "24.106.174.74",
    ),
    (
        "exim",
        "2013-06-12 03:57:58 login authenticator failed for (ylmf-pc) [120.196.140.45]: 535 Incorrect authentication data: 1 Time(s)",
        "120.196.140.45",
    ),
    (
        "groupoffice",
        r#"[2014-01-06 10:59:38]LOGIN FAILED for user: "asdsad" from IP: 127.0.0.1"#,
        "127.0.0.1",
    ),
    (
        "horde",
        r#"Nov 11 18:57:57 HORDE [error] [horde] FAILED LOGIN for graham [203.16.208.190] to Horde [on line 116 of "/home/ace-hosting/public_html/horde/login.php"]"#,
        "203.16.208.190",
    ),
    (
        "kerio",
        "[18/Jan/2014 06:41:25] SMTP Spam attack detected from 202.169.236.195, client closed connection before SMTP greeting",
        "202.169.236.195",
    ),
    (
        "openwebmail",
        "Sat Dec 28 19:04:03 2013 - [72926] (178.123.108.196) gsdfg - login error - no such user - loginname=gsdfg",
        "178.123.108.196",
    ),
    (
        "oracleims",
        r#"<co ts="2014-06-02T16:06:33.99" pi="72aa.17f0.25622" sc="tcp_local" dr="+" ac="U" tr="TCP|192.245.12.223|25|89.96.245.78|4299" ap="SMTP" mi="Bad password" us="nic@transcend.com" di="535 5.7.8 Bad username or password (Authentication failed)."/>"#,
        "89.96.245.78",
    ),
    (
        "perdition",
        r#"Jul 18 16:07:18 ares perdition.imaps[3194]: Auth: 192.168.8.100:2274->193.48.191.9:993 client-secure=ssl authorisation_id=NONE authentication_id="carles" server="imap.biotoul.fr:993" protocol=IMAP4S server-secure=ssl status="failed: Re-Authentication Failure""#,
        "192.168.8.100",
    ),
    (
        "perdition",
        "Jul 18 16:08:58 ares perdition.imaps[3194]: Fatal Error reading authentication information from client 192.168.8.100:2274->193.48.191.9:993: Exiting child",
        "192.168.8.100",
    ),
    (
        "postfix",
        "Jun 24 07:42:17 srv postfix/smtpd[27364]: warning: unknown[114.44.142.233]: SASL CRAM-MD5 authentication failed: PDEyMzQ1LjEzMjg5MjI5MTdAZXVyb3N0cmVhbT4=",
        "114.44.142.233",
    ),
    (
        "postfix",
        "Jun 24 08:10:01 srv postfix/smtpd[28000]: warning: unknown[1.1.1.1]: SASL LOGIN authentication failed: UGFzc3dvcmQ6",
        "1.1.1.1",
    ),
    (
        "postfix",
        "Aug  7 15:14:11 h11 postfix/smtpd[18713]: NOQUEUE: reject: RCPT from example.com[192.0.43.10]: 550 5.1.1 <admin@example.com>: Recipient address rejected: User unknown in virtual mailbox table; from=<spammer@example.net> to=<admin@example.com> proto=ESMTP helo=<test.example.com>",
        "192.0.43.10",
    ),
    (
        "postfix",
        "Sep  1 21:07:00 MAIL postfix/smtpd[6712]: NOQUEUE: reject: RCPT from unknown[93.184.216.34]: 454 4.7.1 <user@example.com>: Relay access denied; from=<some@body.com> to=<user@example.com> proto=ESMTP helo=<[93.184.216.34]>",
        "93.184.216.34",
    ),
    (
        "qmail",
        "Sep  6 07:33:33 sd6 qmail: 1157520813.485077 rblsmtpd: 198.51.100.77 pid 19597 sbl-xbl.spamhaus.org: 451 http://www.spamhaus.org/query/bl?ip=198.51.100.77",
        "198.51.100.77",
    ),
    (
        "roundcube-auth",
        "[22-Jan-2013 22:28:21 +0200]: FAILED login for user1 from 192.0.43.10",
        "192.0.43.10",
    ),
    (
        "roundcube-auth",
        "May 26 07:12:40 hamster roundcube: IMAP Error: Login failed for sales@example.com from 10.1.1.47",
        "10.1.1.47",
    ),
    (
        "roundcube-auth",
        "Jul 11 03:06:37 myhostname roundcube: IMAP Error: Login failed for admin from 1.2.3.4. AUTHENTICATE PLAIN: A0002 NO Login failed. in /usr/share/roundcube/program/include/rcube_imap.php on line 205 (POST /wmail/?_task=login&_action=login)",
        "1.2.3.4",
    ),
    (
        "roundcube-auth",
        "[10-May-2015 13:02:52 -0400]: Failed login for sampleuser from 1.2.3.4 in session 1z506z6rvddstv6k7jz08hxo27 (error: 0)",
        "1.2.3.4",
    ),
    (
        "sendmail-auth",
        "Feb 16 23:33:20 smtp1 sm-mta[5133]: s1GNXHYB005133: [190.5.230.178]: possible SMTP attack: command=AUTH, count=5",
        "190.5.230.178",
    ),
    (
        "sieve",
        "Dec 1 20:36:56 mail sieve[23713]: badlogin: example.com[1.2.3.4] PLAIN authentication failure",
        "1.2.3.4",
    ),
    (
        "sogo-auth",
        "Mar 24 08:58:32 sogod [26818]: SOGoRootPage Login from '173.194.44.31' for user 'hack0r' might not have worked - password policy: 65535  grace: -1  expire: -1  bound: 0",
        "173.194.44.31",
    ),
    (
        "sogo-auth",
        "Mar 24 19:29:32 sogod [1526]: SOGoRootPage Login from '192.0.2.16, 10.0.0.1' for user 'admin' might not have worked - password policy: 65535  grace: -1  expire: -1  bound: 0",
        "192.0.2.16",
    ),
    (
        "solid-pop3d",
        "Nov 15 00:34:53 rmc1pt2-2-35-70 solid-pop3d[3822]: authentication failed: no such user: adrian - 123.33.44.45",
        "123.33.44.45",
    ),
    (
        "squirrelmail",
        "10/06/2013 15:50:41 [LOGIN_ERROR] dadas (mydomain.org) from 151.64.44.11: Unknown user or password incorrect.",
        "151.64.44.11",
    ),
    (
        "tine20",
        "78017 00cff -- none -- - 2014-01-13T05:02:22+00:00 WARN (4): Tinebase_Controller::login::106 Login with username sdfsadf from 127.0.0.1 failed (-1)!",
        "127.0.0.1",
    ),
    (
        "uwimap-auth",
        "Jul 3 20:56:53 Linux2 imapd[666]: Login failed user=lizdy auth=lizdy host=h2066373.stratoserver.net [81.169.154.112]",
        "81.169.154.112",
    ),
];

/// (filter_name, log_line) rows that must NOT match.
const NO_MATCH_CASES: &[(&str, &str)] = &[
    (
        "oracleims",
        r#"<co ts="2014-06-02T22:02:13.94" pi="72a9.3b4.3774" sc="tcp_submit" dr="+" ac="U" tr="TCP|192.245.12.223|465|23.122.129.179|60766" ap="SMTP/TLS-128-RC4" mi="Authentication successful - switched to channel tcp_submit" us="jaugustine@example.org" di="235 2.7.0 LOGIN authentication successful."/>"#,
    ),
    (
        "postfix",
        "Jun 12 08:58:35 srv postfix/smtpd[29306]: improper command pipelining after AUTH from unknown[192.0.2.11]: QUIT",
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
