use super::*;
use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "apache-auth",
        "[Mon Dec 23 13:12:31 2013] [error] [client 194.228.20.113] user dsfasdf not found: /",
        "194.228.20.113",
    ),
    (
        "apache-auth",
        "[Mon Dec 23 13:12:31 2013] [error] [client 2001:db8::80da:af6b:8b2c] user test-ipv6 not found: /",
        "2001:db8::80da:af6b:8b2c",
    ),
    (
        "apache-auth",
        "[Mon Dec 23 13:12:31 2013] [error] [client 127.0.0.1] user username: authentication failure for \"/basic/file\": Password Mismatch",
        "127.0.0.1",
    ),
    (
        "apache-auth",
        "[Mon Dec 23 13:12:31.123456 2013] [auth_basic:error] [pid 1234:tid 5678] [client 127.0.0.1:54321] AH01617: user username: authentication failure for \"/basic/file\": Password Mismatch",
        "127.0.0.1",
    ),
    (
        "apache-botsearch",
        "[Sun Jun 09 07:57:47 2013] [error] [client 115.249.248.145] File does not exist: /var/www/phpmyadmin",
        "115.249.248.145",
    ),
    (
        "apache-botsearch",
        "[Mon Dec 23 13:12:31 2013] [error] [client 10.20.30.40] File does not exist: /var/www/html/.env",
        "10.20.30.40",
    ),
    (
        "apache-modsecurity",
        r#"[Mon Dec 23 13:12:31 2013] [error] [client 173.255.225.101] ModSecurity:  [file "/etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_21_protocol_anomalies.conf"] [line "47"] [id "960015"] Access denied with code 403 (phase 2). Operator EQ matched 0 at REQUEST_HEADERS."#,
        "173.255.225.101",
    ),
    (
        "apache-modsecurity",
        r#"[Sat Sep 28 09:18:06 2018] [error] [client 192.0.2.1:55555] [client 192.0.2.1] ModSecurity: [file "/etc/httpd/modsecurity.d/10_asl_rules.conf"] [line "635"] Access denied with code 403 (phase 2). Pattern match at REQUEST_URI."#,
        "192.0.2.1",
    ),
    (
        "apache-modsecurity",
        r"[Sat May 09 00:35:52.389262 2020] [:error] [pid 22406:tid 139985298601728] [client 192.0.2.2:47762] [client 192.0.2.2] ModSecurity: Access denied with code 401 (phase 2). Operator EQ matched 1 at IP:blocked.",
        "192.0.2.2",
    ),
    (
        "apache-nohome",
        "[Sat Jun 01 11:23:08 2013] [error] [client 1.2.3.4] File does not exist: /xxx/~",
        "1.2.3.4",
    ),
    (
        "apache-noscript",
        "[Sun Jun 09 07:57:47 2013] [error] [client 192.0.43.10] script '/usr/lib/cgi-bin/gitweb.cgiwp-login.php' not found or unable to stat",
        "192.0.43.10",
    ),
    (
        "apache-noscript",
        "[Tue Jul 22 06:48:30 2008] [error] [client 198.51.100.86] File does not exist: /home/southern/public_html/azenv.php",
        "198.51.100.86",
    ),
    (
        "apache-overflows",
        r"[Tue Mar 16 15:39:29 2010] [error] [client 58.179.109.179] Invalid URI in request \xf9h",
        "58.179.109.179",
    ),
    (
        "apache-overflows",
        "[Wed Jul 30 11:23:54 2010] [error] [client 10.85.6.69] request failed: URI too long (longer than 8190)",
        "10.85.6.69",
    ),
    (
        "apache-shellshock",
        "[Thu Sep 25 09:27:18.813902 2014] [cgi:error] [pid 16860] [client 89.207.132.76:59635] AH01215: /bin/bash: warning: HTTP_TEST: ignoring function definition attempt",
        "89.207.132.76",
    ),
    (
        "centreon",
        "2019-10-21 18:55:15|-1|0|0|[WEB] [50.97.225.132] Authentication failed for 'admin' : password mismatch",
        "50.97.225.132",
    ),
    (
        "directadmin",
        "2014:07:02-00:17:45: '3.2.1.4' 2 failed login attempts. Account 'test'",
        "3.2.1.4",
    ),
    (
        "drupal",
        "Apr 26 13:15:25 webserver example.com: https://example.com|1430068525|user|1.2.3.4|https://example.com/?q=user|https://example.com/?q=user|0||Login attempt failed for drupaladmin.",
        "1.2.3.4",
    ),
    (
        "froxlor-auth",
        "May 21 00:56:27 jomu Froxlor: [Login Action 1.2.3.4] Unknown user 'user' tried to login.",
        "1.2.3.4",
    ),
    (
        "froxlor-auth",
        "May 21 00:57:38 jomu Froxlor: [Login Action 1.2.3.4] User 'admin' tried to login with wrong password.",
        "1.2.3.4",
    ),
    (
        "gitlab",
        "Failed Login: username=admin ip=80.10.11.12",
        "80.10.11.12",
    ),
    (
        "gitlab",
        "Failed Login: username=user name ip=80.10.11.12",
        "80.10.11.12",
    ),
    (
        "grafana",
        r#"t=2020-10-19T17:44:33+0200 lvl=eror msg="Invalid username or password" logger=context userId=0 orgId=0 uname= error="Invalid Username or Password" remote_addr=182.56.23.12"#,
        "182.56.23.12",
    ),
    (
        "grafana",
        r#"t=2020-10-19T18:44:33+0200 lvl=eror msg="Invalid username or password" logger=context userId=0 orgId=0 uname= error="User not found" remote_addr=182.56.23.13"#,
        "182.56.23.13",
    ),
    (
        "haproxy",
        "Nov 14 22:45:11 test haproxy[760]: 192.168.33.1:58430 [14/Nov/2015:22:45:11.608] main main/<NOSRV> -1/-1/-1/-1/0 401 248 - - PR-- 0/0/0/0/0 0/0 \"GET / HTTP/1.1\"",
        "192.168.33.1",
    ),
    (
        "lighttpd-auth",
        "2011-12-25 17:09:20: (http_auth.c.875) password doesn't match for /gitweb/ username: francois, IP: 4.4.4.4",
        "4.4.4.4",
    ),
    (
        "lighttpd-auth",
        "2012-09-26 10:24:35: (http_auth.c.1136) digest: auth failed for  xxx : wrong password, IP: 4.4.4.4",
        "4.4.4.4",
    ),
    (
        "monitorix",
        "Wed Apr 14 08:54:22 2021 - NOTEXIST - [127.0.0.1] File does not exist: /manager/html",
        "127.0.0.1",
    ),
    (
        "monitorix",
        "Wed Apr 14 11:24:31 2021 - NOTALLOWED - [127.0.0.1] Access not allowed: /monitorix/",
        "127.0.0.1",
    ),
    (
        "monitorix",
        "Wed Apr 14 11:26:08 2021 - AUTHERR - [127.0.0.1] Authentication error: /monitorix/",
        "127.0.0.1",
    ),
    (
        "nagios",
        "Feb  3 11:22:44 valhalla nrpe[63284]: Host 50.97.225.132 is not allowed to talk to us!",
        "50.97.225.132",
    ),
    (
        "nginx-auth",
        "2012/04/09 11:53:29 [error] 2865#0: *66647 user \"xyz\" was not found in \"/var/www/.htpasswd\", client: 192.0.43.10, server: www.myhost.com, request: \"GET / HTTP/1.1\", host: \"www.myhost.com\"",
        "192.0.43.10",
    ),
    (
        "nginx-auth",
        "2012/04/09 11:53:36 [error] 2865#0: *66647 user \"xyz\": password mismatch, client: 192.0.43.10, server: www.myhost.com, request: \"GET / HTTP/1.1\", host: \"www.myhost.com\"",
        "192.0.43.10",
    ),
    (
        "nginx-bad-request",
        r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "" 400 47 "-" "-" "-""#,
        "12.34.56.78",
    ),
    (
        "nginx-bad-request",
        r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "\x03\x00\x00/*\xE0\x00\x00\x00\x00\x00Cookie: mstshash=Administr" 400 47 "-" "-" "-""#,
        "12.34.56.78",
    ),
    (
        "nginx-bad-request",
        r#"7.8.9.10 - root [20/Jan/2015:01:17:07 +0100] "CONNECT 123.123.123.123 HTTP/1.1" 400 162 "-" "-" "-""#,
        "7.8.9.10",
    ),
    (
        "nginx-botsearch",
        r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "GET /wp-login.php HTTP/1.1" 404 47 "-" "Mozilla""#,
        "12.34.56.78",
    ),
    (
        "nginx-botsearch",
        r#"12.34.56.78 - - [20/Jan/2015:19:53:28 +0100] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 47 "-" "Mozilla""#,
        "12.34.56.78",
    ),
    (
        "nginx-botsearch",
        r#"7.8.9.10 - - [20/Jan/2015:01:17:07 +0100] "POST /admin/config.php HTTP/1.1" 404 162 "-" "Mozilla""#,
        "7.8.9.10",
    ),
    (
        "nginx-botsearch",
        r#"5.6.7.8 - - [01/Feb/2020:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.64""#,
        "5.6.7.8",
    ),
    (
        "nginx-forbidden",
        r#"2018/09/14 19:03:05 [error] 2035#2035: *9134 access forbidden by rule, client: 12.34.56.78, server: www.example.net, request: "GET /wp-content/themes/evolve/js/back-end/libraries/fileuploader/upload_handler.php HTTP/1.1", host: "www.example.net""#,
        "12.34.56.78",
    ),
    (
        "nginx-forbidden",
        r#"2018/09/13 15:42:05 [error] 2035#2035: *287 access forbidden by rule, client: 12.34.56.78, server: www.example.com, request: "GET /wp-config.php~ HTTP/1.1", host: "www.example.com""#,
        "12.34.56.78",
    ),
    (
        "nginx-limit-req",
        r#"2015/10/29 20:01:02 [error] 256554#0: *99927 limiting requests, excess: 1.852 by zone "one", client: 1.2.3.4, server: example.com, request: "POST /index.htm HTTP/1.0", host: "example.com""#,
        "1.2.3.4",
    ),
    (
        "nginx-limit-req",
        r#"2016/09/30 08:36:06 [error] 22923#0: *4758725916 limiting requests, excess: 15.243 by zone "one", client: 2001:db8::80da:af6b:8b2c, server: example.com, request: "GET / HTTP/1.1", host: "example.com""#,
        "2001:db8::80da:af6b:8b2c",
    ),
    (
        "nginx-limit-req",
        r#"2025/08/01 04:24:17 [warn] 4772#4772: *68 delaying request, excess: 0.841, by zone "req_limit", client: 206.189.215.97, server: myserver.net, request: "GET /ab2h HTTP/1.1", host: "22.18.134.49""#,
        "206.189.215.97",
    ),
    (
        "nginx-limit-req",
        r#"2025/08/03 03:17:28 [error] 25808#25808: *598 limiting connections by zone "conn_limit", client: 128.199.22.141, server: myserver.net, request: "GET /favicon.ico HTTP/1.1", host: "84.108.142.49", referrer: "https://xxx.com/""#,
        "128.199.22.141",
    ),
    (
        "openhab",
        r#"175.18.15.10 -  -  [02/sept./2015:00:11:31 +0200] "GET /openhab.app HTTP/1.1" 401 1382"#,
        "175.18.15.10",
    ),
    (
        "php-url-fopen",
        r#"66.185.212.172 - - [26/Mar/2009:08:44:20 -0500] "GET /index.php?n=http://eatmyfood.hostinginfive.com/pizza.htm? HTTP/1.1" 200 114 "-" "Mozilla""#,
        "66.185.212.172",
    ),
    (
        "phpmyadmin-syslog",
        "Aug 22 14:50:22 eurostream phpMyAdmin[16358]: user denied: root (mysql-denied) from 192.0.2.1",
        "192.0.2.1",
    ),
    (
        "squid",
        "1386543323.000      4 91.188.124.227 TCP_DENIED/403 4099 GET http://www.proxy-listen.de/azenv.php - HIER_NONE/- text/html",
        "91.188.124.227",
    ),
    (
        "squid",
        "1386543500.000      5 175.44.0.184 NONE/405 3364 CONNECT error:method-not-allowed - HIER_NONE/- text/html",
        "175.44.0.184",
    ),
    (
        "suhosin",
        "Mar 11 22:52:12   lighttpd[53690]: (mod_fastcgi.c.2676) FastCGI-stderr: ALERT - configured request variable name length limit exceeded - dropped variable 'upqchi07vFfAFuBjnIKGIwiLrHo3Vt68T3yqvhQu2TqetQ78roy7Q6bpTfDUtYFR593/MA' (attacker '198.51.100.167', file '/usr/local/captiveportal/index.php')",
        "198.51.100.167",
    ),
    (
        "traefik",
        "10.0.0.2 - username [18/Nov/2018:21:34:34 +0000] \"GET /dashboard/ HTTP/2.0\" 401 17 \"-\" \"Mozilla/5.0\" 72 \"Auth\" \"/dashboard/\" 0ms",
        "10.0.0.2",
    ),
    (
        "webmin-auth",
        "Dec 13 08:15:18 sb1 webmin[25875]: Invalid login as root from 89.2.49.230",
        "89.2.49.230",
    ),
    (
        "webmin-auth",
        "Dec 12 23:14:19 sb1 webmin[22134]: Non-existent login as robert from 188.40.105.142",
        "188.40.105.142",
    ),
    (
        "zoneminder",
        r#"[Mon Mar 28 16:50:49.522240 2016] [:error] [pid 1795] [client 10.1.1.1:50700] WAR [Login denied for user "username1"], referer: https://zoneminder/"#,
        "10.1.1.1",
    ),
    (
        "zoneminder",
        "[Sun Mar 28 16:53:00.472693 2021] [php7:notice] [pid 11328] [client 10.1.1.1:39568] ERR [Could not retrieve user username1 details], referer: https://zm/zm/?view=logout",
        "10.1.1.1",
    ),
];

/// (filter_name, log_line) rows that must NOT match.
const NO_MATCH_CASES: &[(&str, &str)] = &[(
    "apache-botsearch",
    "[Sat Mar 08 02:49:57 2014] [error] [client 92.43.20.165] script '/var/www/forum/mail.php' not found or unable to stat",
)];

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
