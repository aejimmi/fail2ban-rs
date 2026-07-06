use super::*;
use crate::detect::filters::test_util::{assert_filter_matches, assert_filter_no_match};

/// (filter_name, log_line, expected_ip) rows exercised against the live registry.
const MATCH_CASES: &[(&str, &str, &str)] = &[
    (
        "3proxy",
        "11-06-2013 02:09:40 +0300 PROXY.3128 00004 - 1.2.3.4:28783 0.0.0.0:0 0 0 0 GET http://www.yandex.ua/?ncrnd=2169807731 HTTP/1.1",
        "1.2.3.4",
    ),
    (
        "3proxy",
        "11-06-2013 02:09:43 +0300 PROXY.3128 00005 ewr 1.2.3.4:28788 0.0.0.0:0 0 0 0 GET http://www.yandex.ua/?ncrnd=2169807731 HTTP/1.1",
        "1.2.3.4",
    ),
    (
        "bitwarden",
        "2019-11-26 01:04:49.008 +08:00 [WRN] Failed login attempt. 192.168.0.16",
        "192.168.0.16",
    ),
    (
        "bitwarden",
        "2019-11-25 21:39:58.464 +01:00 [WRN] Failed login attempt, 2FA invalid. 192.168.0.21",
        "192.168.0.21",
    ),
    (
        "bitwarden",
        "2019-09-24T13:16:50 e5a81dbf7fd1 Bitwarden-Identity[1]: [Bit.Core.IdentityServer.ResourceOwnerPasswordValidator] Failed login attempt. 192.168.0.23",
        "192.168.0.23",
    ),
    (
        "counter-strike",
        r#"L 01/01/2014 - 01:25:17: Bad Rcon: "rcon 1146003691 "284"  sv_contact "HLBrute 1.10"" from "31.29.29.89:57370""#,
        "31.29.29.89",
    ),
    (
        "guacamole",
        r#"WARNING: Authentication attempt from 192.0.2.0 for user "null" failed."#,
        "192.0.2.0",
    ),
    (
        "guacamole",
        r#"12:57:32.907 [http-nio-8080-exec-10] WARN  o.a.g.r.auth.AuthenticationService - Authentication attempt from 182.23.72.36 for user "guacadmin" failed."#,
        "182.23.72.36",
    ),
    (
        "monit",
        "[PDT Apr 16 20:59:33] error    : Warning: Client '97.113.189.111' supplied wrong password for user 'admin' accessing monit httpd",
        "97.113.189.111",
    ),
    (
        "monit",
        "[PDT Apr 16 21:05:29] error    : Warning: Client '69.93.127.111' supplied unknown user 'foo' accessing monit httpd",
        "69.93.127.111",
    ),
    (
        "named-refused",
        "Jul 24 14:16:55 raid5 named[3935]: client 194.145.196.18#4795: query 'ricreig.com/NS/IN' denied",
        "194.145.196.18",
    ),
    (
        "netfilter-portscan",
        "Feb  3 10:58:43 server1 kernel: [465839.855234] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:aa:bb:cc:52:54:00:dd:ee:ff:08:00 SRC=192.168.1.100 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=44356 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0",
        "192.168.1.100",
    ),
    (
        "netfilter-portscan",
        "Mar 15 14:22:07 fw01 kernel: iptables-DROP: IN=ens3 OUT= MAC=00:16:3e:aa:bb:cc:00:16:3e:dd:ee:ff:08:00 SRC=203.0.113.45 DST=198.51.100.10 LEN=44 TOS=0x00 PREC=0x00 TTL=241 ID=62233 PROTO=TCP SPT=6000 DPT=23 WINDOW=65535 RES=0x00 SYN URGP=0",
        "203.0.113.45",
    ),
    (
        "netfilter-portscan",
        "Aug  5 21:00:44 firewall kernel: nft-drop: IN=enp1s0 OUT= MAC=00:0c:29:aa:bb:cc:00:50:56:dd:ee:ff:08:00 SRC=10.20.30.40 DST=10.20.30.1 LEN=329 TOS=0x00 PREC=0x00 TTL=64 ID=48372 PROTO=UDP SPT=5353 DPT=5353 LEN=309",
        "10.20.30.40",
    ),
    (
        "netfilter-portscan",
        "Sep 17 11:22:33 router kernel: [234567.890123] DROPPED: IN=wan0 OUT= MAC=00:1a:2b:3c:4d:5e:6f:70:80:90:a0:b0:08:00 SRC=198.51.100.1 DST=203.0.113.5 LEN=84 TOS=0x00 PREC=0x00 TTL=53 ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=1234 SEQ=1",
        "198.51.100.1",
    ),
    (
        "netfilter-portscan",
        "Nov 14 16:45:22 server2 kernel: ip6-drop: IN=eth0 OUT= MAC=33:33:00:00:00:01:00:11:22:33:44:55:86:dd SRC=2001:db8::1 DST=2001:db8::2 LEN=60 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=54321 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0",
        "2001:db8::1",
    ),
    (
        "nsd",
        "[1387288694] nsd[7745]: info: ratelimit block example.com. type any target 192.0.2.0/24 query 192.0.2.105 TYPE255",
        "192.0.2.105",
    ),
    (
        "pf-portscan",
        "Feb 16 16:43:20 firewall pf: rule 0/(match) block in on ep0: 194.54.59.189.2559 > 194.54.107.19.139: [|tcp] (DF)",
        "194.54.59.189",
    ),
    (
        "pf-portscan",
        "Mar 28 09:00:01 gw pf: rule 22/0(match): block in on vlan2: 10.52.0.39.58012 > 10.55.0.131.8080: Flags [S], seq 2837144143, win 14600, length 0",
        "10.52.0.39",
    ),
    (
        "pf-portscan",
        "Feb 16 16:53:10 firewall pf: rule 0/(match) block in on ep0: 68.194.177.173 > 194.54.107.19: [|icmp]",
        "68.194.177.173",
    ),
    (
        "pf-portscan",
        "Jan 05 12:00:00 fw pf: rule 18/0(match): block in on bce0: 2a02:840:beef:1d::2.42214 > 2a02:840:1:200::2.80: Flags [S]",
        "2a02:840:beef:1d::2",
    ),
    (
        "pfsense-portscan",
        "Mar 28 12:00:00 fw filterlog[58921]: 4,,,1000000103,pppoe0,match,block,in,4,0x0,,242,26160,0,none,6,tcp,44,89.248.165.17,125.229.96.130,44961,30129,0,S,3258086147,,1025,,mss",
        "89.248.165.17",
    ),
    (
        "pfsense-portscan",
        "Oct 27 08:49:34 fw filterlog[58921]: 12,,,7ca0bdbea8e636fba2e984923ed67866,igb0,match,block,in,4,0x0,,107,19362,0,DF,6,tcp,52,177.229.216.18,125.229.96.130,51305,445,0,S,1581211380,,8192,,mss;nop;wscale;nop;nop;sackOK",
        "177.229.216.18",
    ),
    (
        "pfsense-portscan",
        "Mar 28 12:00:00 fw filterlog[1234]: 7,16777216,,1000000105,vmx1,match,block,in,6,0x00,0x00000,64,UDP,17,57,fe80::5505:5394:1ba7:b3e4,2001:db8:1:ee30:20c:29ff:fe78:6e58,54978,53,57",
        "fe80::5505:5394:1ba7:b3e4",
    ),
    (
        "portsentry",
        "1403884279 - 06/27/2014 17:51:19 Host: 192.168.56.1/192.168.56.1 Port: 1 TCP Blocked",
        "192.168.56.1",
    ),
    (
        "proxmox",
        "Jan 15 12:36:43 pve1 pvedaemon[1234]: authentication failure; rhost=192.0.2.123 user=root@pam msg=",
        "192.0.2.123",
    ),
    (
        "proxmox",
        "Mar 10 08:00:01 host pvedaemon[5678]: authentication failure; rhost=192.0.2.124 user=admin@pve",
        "192.0.2.124",
    ),
    (
        "routeros-auth",
        "Feb 15 11:25:46 gw.local system,error,critical login failure for user admin from 192.168.88.6 via web",
        "192.168.88.6",
    ),
    (
        "routeros-auth",
        "Feb 15 11:57:42 1234.hostname.cz system,error,critical login failure for user  from 2001:470:1:c84::24 via ssh",
        "2001:470:1:c84::24",
    ),
    (
        "scanlogd",
        "Mar  5 21:44:43 srv scanlogd: 192.0.2.123 to 192.0.2.1 ports 80, 81, 83, 88, 99, 443, 1080, 3128, ..., f????uxy, TOS 00, TTL 49 @20:44:43",
        "192.0.2.123",
    ),
    (
        "screensharingd",
        "Oct 27 2015 12:35:40 test1.beezwax.net screensharingd[1170]: Authentication: FAILED :: User Name: sdfsdfs () mro :: Viewer Address: 192.168.5.247 :: Type: DH",
        "192.168.5.247",
    ),
    (
        "stunnel",
        "2011.11.21 14:29:16 LOG3[28228:140093368055552]: SSL_accept from 10.7.41.61:33454 : 140890C7: error:140890C7:SSL routines:SSL3_GET_CLIENT_CERTIFICATE:peer did not return a certificate",
        "10.7.41.61",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:22.129][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 2001:db8::b6d3:95d7:1425:766d. Username: test@example.com.",
        "2001:db8::b6d3:95d7:1425:766d",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:28.562][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 80.187.85.94. Username: test@example.com.",
        "80.187.85.94",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:28.725][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 80.187.85.94",
        "80.187.85.94",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:28.725][vaultwarden::api::admin][ERROR] Invalid admin token. IP: 2001:db8::b6d3:95d7:1425:766d",
        "2001:db8::b6d3:95d7:1425:766d",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:28.892][vaultwarden::api::core::two_factor::authenticator][ERROR] Invalid TOTP code! Server time: 2024-08-31 02:11:28 UTC IP: 80.187.85.94",
        "80.187.85.94",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:28.892+0800][vaultwarden::api::core::two_factor::authenticator][ERROR] Invalid TOTP code! Server time: 2024-08-30 18:11:28 UTC IP: 80.187.85.94",
        "80.187.85.94",
    ),
    (
        "vaultwarden",
        "[2024-08-31 02:11:30.123+0800][vaultwarden::api::admin][ERROR] Invalid admin token! IP: 192.0.2.7. Username: alice",
        "192.0.2.7",
    ),
    (
        "xinetd-fail",
        "May 15 17:38:49 boo xinetd[16256]: FAIL: telnet address from=198.51.100.169",
        "198.51.100.169",
    ),
    (
        "xrdp",
        "[20220407-12:11:06] [INFO ] AUTHFAIL: user=badtypist ip=::ffff:10.171.161.151 time=1649351466",
        "10.171.161.151",
    ),
    (
        "xrdp",
        "[20220407-12:11:24] [INFO ] AUTHFAIL: user=192.168.0.1 ip=::ffff:10.171.161.151 time=1649351484",
        "10.171.161.151",
    ),
    (
        "xrdp",
        "Apr  7 12:11:06 servername xrdp-sesman[41441]: [INFO ] AUTHFAIL: user=badtypist ip=::ffff:10.171.161.151 time=1649351466",
        "10.171.161.151",
    ),
    (
        "znc-adminlog",
        "[2018-10-27 01:40:55] [girst] failed to login from 1.2.3.4",
        "1.2.3.4",
    ),
    (
        "znc-adminlog",
        "[2019-09-08 15:53:19] [admin] failed to login from 192.0.2.1:65001",
        "192.0.2.1",
    ),
];

/// (filter_name, log_line) rows that must NOT match.
const NO_MATCH_CASES: &[(&str, &str)] = &[
    (
        "netfilter-portscan",
        "Feb 12 22:10:30 myhost kernel: OUTPUT_DROP: IN= OUT=ens3 SRC=10.0.0.5 DST=1.2.3.4 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=55555 DF PROTO=TCP SPT=12345 DPT=6667 WINDOW=64240 RES=0x00 SYN URGP=0",
    ),
    (
        "pfsense-portscan",
        "Mar 28 12:00:00 fw filterlog[1234]: 4,,,1000000103,pppoe0,match,pass,in,4,0x0,,242,26160,0,none,6,tcp,44,89.248.165.17,125.229.96.130,44961,80,0,S,3258086147,,1025,,mss",
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
