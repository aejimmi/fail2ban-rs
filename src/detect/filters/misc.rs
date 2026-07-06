//! Built-in filter definitions for miscellaneous services.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "misc_test.rs"]
mod misc_test;

/// Filter templates for miscellaneous services.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "3proxy",
        description: "3proxy proxy server authentication failures",
        log_path: "/var/log/3proxy.log",
        date_format: "common",
        patterns: &[r"PROXY\.\d+ \d{3}0[1-9] \S+ <HOST>:\d+"],
    },
    FilterTemplate {
        name: "bitwarden",
        description: "Bitwarden self-hosted login failures",
        log_path: "bwdata/logs/identity/log.txt",
        date_format: "iso8601",
        patterns: &[r"Failed login attempt.* <HOST>"],
    },
    FilterTemplate {
        name: "counter-strike",
        description: "Counter-Strike game server rcon brute force",
        log_path: "/opt/cstrike/logs/L0101000.log",
        date_format: "common",
        patterns: &[r#"Bad Rcon:.*from "<HOST>:\d+""#],
    },
    FilterTemplate {
        name: "guacamole",
        description: "Apache Guacamole remote desktop gateway authentication failures",
        log_path: "/var/log/guacamole.log",
        date_format: "iso8601",
        patterns: &[r"Authentication attempt from <HOST> for user .* failed"],
    },
    FilterTemplate {
        name: "monit",
        description: "Monit process supervisor authentication failures",
        log_path: "/var/log/monit.log",
        date_format: "syslog",
        patterns: &[
            r"Client .?<HOST>.? supplied wrong password",
            r"Client .?<HOST>.? supplied unknown user",
        ],
    },
    FilterTemplate {
        name: "named-refused",
        description: "BIND/named DNS query refused",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[r"named\[\d+\].*client <HOST>#\d+.*(?:denied|REFUSED)"],
    },
    FilterTemplate {
        name: "netfilter-portscan",
        description: "Netfilter dropped packets (iptables/nftables LOG target) \u{2014} port scan detection",
        log_path: "/var/log/kern.log",
        date_format: "syslog",
        patterns: &[r"kernel: .*IN=\S+ .*SRC=<HOST> DST=\S+ .*PROTO="],
    },
    FilterTemplate {
        name: "nsd",
        description: "NSD authoritative DNS rate limit blocks and refused transfers",
        log_path: "/var/log/nsd.log",
        date_format: "epoch",
        patterns: &[
            r"nsd\[\d+\]: info: ratelimit block .* query <HOST>",
            r"nsd\[\d+\]:.*from client <HOST> refused",
        ],
    },
    FilterTemplate {
        name: "pf-portscan",
        description: "PF blocked packets (tcpdump pflog to syslog) \u{2014} port scan detection",
        log_path: "/var/log/pf.log",
        date_format: "syslog",
        patterns: &[
            r"block in on \S+:\s+<HOST>\.\d+ >",
            r"block in on \S+:\s+<HOST> >",
        ],
    },
    FilterTemplate {
        name: "pfsense-portscan",
        description: "pfSense/OPNsense filterlog blocked packets \u{2014} port scan detection",
        log_path: "/var/log/filter.log",
        date_format: "syslog",
        patterns: &[
            r"filterlog\[\d+\]: .*,block,in,4,(?:[^,]*,){9}<HOST>,",
            r"filterlog\[\d+\]: .*,block,in,6,(?:[^,]*,){6}<HOST>,",
        ],
    },
    FilterTemplate {
        name: "portsentry",
        description: "PortSentry port scan detection",
        log_path: "/var/lib/portsentry/portsentry.history",
        date_format: "epoch",
        patterns: &[r"/<HOST> Port: \d+ (?:TCP|UDP) Blocked"],
    },
    FilterTemplate {
        name: "proxmox",
        description: "Proxmox VE authentication failures",
        log_path: "/var/log/daemon.log",
        date_format: "syslog",
        patterns: &[r"pvedaemon\[.*authentication failure; rhost=<HOST>"],
    },
    FilterTemplate {
        name: "routeros-auth",
        description: "MikroTik RouterOS login failures",
        log_path: "/var/log/routeros.log",
        date_format: "syslog",
        patterns: &[r"system,error,critical login failure for user .* from <HOST> via"],
    },
    FilterTemplate {
        name: "scanlogd",
        description: "scanlogd port scan detection",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[r"scanlogd: <HOST> to"],
    },
    FilterTemplate {
        name: "screensharingd",
        description: "macOS Screen Sharing authentication failures",
        log_path: "/var/log/system.log",
        date_format: "syslog",
        patterns: &[r"screensharingd\[\d+\]: Authentication: FAILED.*Viewer Address: <HOST>"],
    },
    FilterTemplate {
        name: "stunnel",
        description: "stunnel SSL/TLS tunnel certificate authentication failures",
        log_path: "/var/log/stunnel.log",
        date_format: "iso8601",
        patterns: &[
            r"SSL_accept from <HOST>:\d+ :.*SSL routines.*peer did not return a certificate",
        ],
    },
    FilterTemplate {
        name: "vaultwarden",
        description: "Vaultwarden (Bitwarden-compatible) login failures",
        log_path: "/var/log/vaultwarden.log",
        date_format: "iso8601",
        patterns: &[
            r"Username or password is incorrect.*IP: <HOST>",
            r"Invalid admin token.*IP: <HOST>",
            r"Invalid TOTP code.*IP: <HOST>",
        ],
    },
    FilterTemplate {
        name: "xinetd-fail",
        description: "xinetd service connection failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[r"FAIL:.*from=<HOST>"],
    },
    FilterTemplate {
        name: "xrdp",
        description: "XRDP remote desktop authentication failures",
        log_path: "/var/log/xrdp-sesman.log",
        date_format: "iso8601",
        patterns: &[r"AUTHFAIL: user=\S+ ip=<HOST>"],
    },
    FilterTemplate {
        name: "znc-adminlog",
        description: "ZNC IRC bouncer login failures",
        log_path: "/var/lib/znc/moddata/adminlog/znc.log",
        date_format: "iso8601",
        patterns: &[r"failed to login from <HOST>"],
    },
];
