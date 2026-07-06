//! Built-in filter definitions for mail servers and webmail.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "mail_test.rs"]
mod mail_test;

/// Filter templates for mail servers and webmail.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "courier-auth",
        description: "Courier IMAP/POP3 authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"LOGIN FAILED,.* ip=\[<HOST>\]"],
    },
    FilterTemplate {
        name: "courier-smtp",
        description: "Courier SMTP relay and authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"courieresmtpd.*error,relay=<HOST>,"],
    },
    FilterTemplate {
        name: "cyrus-imap",
        description: "Cyrus IMAP/POP3 authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"badlogin:.*\[<HOST>\].*SASL\(-13\)"],
    },
    FilterTemplate {
        name: "domino-smtp",
        description: "IBM/HCL Domino SMTP authentication failures",
        log_path: "/local/notesdata/IBM_TECHNICAL_SUPPORT/console.log",
        date_format: "common",
        patterns: &[
            r"connecting host <HOST>",
            r"smtp.*\[<HOST>\] authentication failure",
        ],
    },
    FilterTemplate {
        name: "dovecot",
        description: "Dovecot IMAP/POP3 authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[
            r"dovecot: .*auth failed.*rip=<HOST>",
            r"dovecot: .*Aborted login.*rip=<HOST>",
        ],
    },
    FilterTemplate {
        name: "exim",
        description: "Exim MTA authentication failures",
        log_path: "/var/log/exim4/mainlog",
        date_format: "iso8601",
        patterns: &[r"authenticator failed for.*\[<HOST>\].*535 Incorrect authentication"],
    },
    FilterTemplate {
        name: "groupoffice",
        description: "Group-Office groupware authentication failures",
        log_path: "/var/log/groupoffice.log",
        date_format: "iso8601",
        patterns: &[r"LOGIN FAILED.*IP: <HOST>"],
    },
    FilterTemplate {
        name: "horde",
        description: "Horde groupware authentication failures",
        log_path: "/var/log/horde/horde.log",
        date_format: "syslog",
        patterns: &[r"HORDE.*FAILED LOGIN for \S+ \[<HOST>\]"],
    },
    FilterTemplate {
        name: "kerio",
        description: "Kerio Connect SMTP spam attack detection",
        log_path: "/var/log/kerio/mail.log",
        date_format: "common",
        patterns: &[
            r"SMTP Spam attack detected from <HOST>,",
            r"IP address <HOST>",
        ],
    },
    FilterTemplate {
        name: "openwebmail",
        description: "Open WebMail authentication failures",
        log_path: "/var/log/openwebmail.log",
        date_format: "common",
        patterns: &[r"\(<HOST>\).*(?:login error|userinfo error)"],
    },
    FilterTemplate {
        name: "oracleims",
        description: "Oracle IMS SMTP authentication failures",
        log_path: "/var/log/oracleims/mail.log",
        date_format: "iso8601",
        patterns: &[r#"\|<HOST>\|\d+".*mi="Bad password""#],
    },
    FilterTemplate {
        name: "perdition",
        description: "Perdition mail proxy authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[
            r"perdition.*Auth: <HOST>:\d+.*status=.failed",
            r"perdition.*Fatal Error reading authentication.*client <HOST>:\d+",
        ],
    },
    FilterTemplate {
        name: "postfix",
        description: "Postfix SMTP authentication and relay failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[
            r"postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL .* authentication failed",
            r"postfix/smtpd\[\d+\]: NOQUEUE: reject: RCPT from .*\[<HOST>\]",
        ],
    },
    FilterTemplate {
        name: "qmail",
        description: "Qmail RBL-blocked SMTP connections",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"rblsmtpd: <HOST>", r"badiprbl: ip <HOST>"],
    },
    FilterTemplate {
        name: "roundcube-auth",
        description: "Roundcube webmail authentication failures",
        log_path: "/var/log/roundcubemail/errors",
        date_format: "iso8601",
        patterns: &[
            r"(?i)login failed for .* from <HOST>",
            r"(?i)failed login for .* from <HOST>",
        ],
    },
    FilterTemplate {
        name: "sendmail-auth",
        description: "Sendmail SMTP AUTH brute force attempts",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"\[<HOST>\]: possible SMTP attack: command=AUTH"],
    },
    FilterTemplate {
        name: "sieve",
        description: "ManageSieve authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"badlogin:.*\[<HOST>\].*authentication failure"],
    },
    FilterTemplate {
        name: "sogo-auth",
        description: "SOGo groupware authentication failures",
        log_path: "/var/log/sogo/sogo.log",
        date_format: "syslog",
        patterns: &[r"SOGoRootPage Login from '<HOST>.*might not have worked"],
    },
    FilterTemplate {
        name: "solid-pop3d",
        description: "Solid POP3 daemon authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"solid-pop3d\[\d+\]: authentication failed:.* - <HOST>"],
    },
    FilterTemplate {
        name: "squirrelmail",
        description: "SquirrelMail webmail authentication failures",
        log_path: "/var/lib/squirrelmail/prefs/squirrelmail_access_log",
        date_format: "common",
        patterns: &[r"from <HOST>: Unknown user or password incorrect"],
    },
    FilterTemplate {
        name: "tine20",
        description: "Tine 2.0 groupware authentication failures",
        log_path: "/var/log/tine20/tine20.log",
        date_format: "iso8601",
        patterns: &[r"Login with username .* from <HOST> failed"],
    },
    FilterTemplate {
        name: "uwimap-auth",
        description: "UW-IMAP server authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[r"Login failed user=.* \[<HOST>\]"],
    },
];
