//! Built-in filter patterns for common services.
//!
//! Used by `fail2ban-rs gen-config --service <name>` to generate jail
//! configurations without manual pattern writing.

/// A built-in filter template for a service.
pub struct FilterTemplate {
    /// Service identifier (e.g. "sshd").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Default log file path.
    pub log_path: &'static str,
    /// Date format preset.
    pub date_format: &'static str,
    /// Regex patterns with `<HOST>` placeholder.
    pub patterns: &'static [&'static str],
}

/// All built-in filters.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "sshd",
        description: "OpenSSH daemon — brute force and invalid user detection",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[
            r#"sshd\[\d+\]: Failed password for .* from <HOST> port \d+"#,
            r#"sshd\[\d+\]: Invalid user .* from <HOST> port \d+"#,
            r#"sshd\[\d+\]: Connection closed by authenticating user .* <HOST> port \d+"#,
            r#"sshd\[\d+\]: Disconnected from authenticating user .* <HOST> port \d+"#,
        ],
    },
    FilterTemplate {
        name: "nginx-auth",
        description: "Nginx HTTP basic authentication failures",
        log_path: "/var/log/nginx/error.log",
        date_format: "common",
        patterns: &[
            r#"no user/password was provided for basic authentication.*client: <HOST>"#,
            r#"user .* was not found.*client: <HOST>"#,
            r#"user .* password mismatch.*client: <HOST>"#,
        ],
    },
    FilterTemplate {
        name: "nginx-botsearch",
        description: "Nginx requests for known exploit paths",
        log_path: "/var/log/nginx/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> .* "(GET|POST) /(wp-login|xmlrpc|wp-admin|\.env|phpmyadmin|admin)"#],
    },
    FilterTemplate {
        name: "postfix",
        description: "Postfix SMTP authentication and relay failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[
            r#"postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL .* authentication failed"#,
            r#"postfix/smtpd\[\d+\]: NOQUEUE: reject: RCPT from .*\[<HOST>\]"#,
        ],
    },
    FilterTemplate {
        name: "dovecot",
        description: "Dovecot IMAP/POP3 authentication failures",
        log_path: "/var/log/mail.log",
        date_format: "syslog",
        patterns: &[
            r#"dovecot: .*auth failed.*rip=<HOST>"#,
            r#"dovecot: .*Aborted login.*rip=<HOST>"#,
        ],
    },
    FilterTemplate {
        name: "vsftpd",
        description: "vsftpd FTP login failures",
        log_path: "/var/log/vsftpd.log",
        date_format: "syslog",
        patterns: &[r#"vsftpd.*FAIL LOGIN: Client "<HOST>""#],
    },
    FilterTemplate {
        name: "asterisk",
        description: "Asterisk VoIP SIP registration failures",
        log_path: "/var/log/asterisk/messages",
        date_format: "iso8601",
        patterns: &[
            r#"NOTICE.* <HOST> failed to authenticate"#,
            r#"SECURITY.* SecurityEvent="FailedACL".*RemoteAddress.*<HOST>"#,
        ],
    },
    FilterTemplate {
        name: "mysqld",
        description: "MySQL/MariaDB authentication failures",
        log_path: "/var/log/mysql/error.log",
        date_format: "iso8601",
        patterns: &[r#"Access denied for user .* from '<HOST>'"#],
    },
    FilterTemplate {
        name: "apache-auth",
        description: "Apache HTTP basic/digest authentication failures",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[
            r#"client <HOST>.*user .* authentication failure"#,
            r#"client <HOST>.*user .* not found"#,
            r#"client <HOST>.*password mismatch"#,
        ],
    },
    FilterTemplate {
        name: "apache-botsearch",
        description: "Apache requests for known exploit and scanner paths",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[
            r#"client <HOST>.*File does not exist:.*/(wp-login|xmlrpc|\.env|phpmyadmin)"#,
        ],
    },
    FilterTemplate {
        name: "vaultwarden",
        description: "Vaultwarden (Bitwarden-compatible) login failures",
        log_path: "/var/log/vaultwarden.log",
        date_format: "iso8601",
        patterns: &[r#"Username or password is incorrect.*IP: <HOST>"#],
    },
    FilterTemplate {
        name: "bitwarden",
        description: "Bitwarden self-hosted login failures",
        log_path: "bwdata/logs/identity/log.txt",
        date_format: "iso8601",
        patterns: &[r#"Failed login attempt.*<HOST>"#],
    },
    FilterTemplate {
        name: "proxmox",
        description: "Proxmox VE authentication failures",
        log_path: "/var/log/daemon.log",
        date_format: "syslog",
        patterns: &[r#"pvedaemon\[.*authentication failure; rhost=<HOST>"#],
    },
    FilterTemplate {
        name: "gitlab",
        description: "GitLab authentication failures",
        log_path: "/var/log/gitlab/gitlab-rails/application.log",
        date_format: "iso8601",
        patterns: &[r#"Failed Login:.*ip=<HOST>"#],
    },
    FilterTemplate {
        name: "grafana",
        description: "Grafana login failures",
        log_path: "/var/log/grafana/grafana.log",
        date_format: "iso8601",
        patterns: &[r#"Unauthorized.*<HOST>"#],
    },
    FilterTemplate {
        name: "haproxy",
        description: "HAProxy HTTP authentication failures",
        log_path: "/var/log/haproxy.log",
        date_format: "syslog",
        patterns: &[r#"<HOST>:\d+ .*\b401\b"#],
    },
    FilterTemplate {
        name: "drupal",
        description: "Drupal CMS authentication failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[
            r#"drupal.*Login attempt failed from <HOST>"#,
        ],
    },
    FilterTemplate {
        name: "traefik",
        description: "Traefik reverse proxy authentication failures",
        log_path: "/var/log/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> .* \d+ 401 "#],
    },
    FilterTemplate {
        name: "openvpn",
        description: "OpenVPN authentication failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[
            r#"ovpn-.*<HOST>:\d+ TLS Auth Error"#,
            r#"ovpn-.*<HOST>:\d+.*AUTH_FAILED"#,
        ],
    },
];

/// Look up a filter template by name.
pub fn find(name: &str) -> Option<&'static FilterTemplate> {
    FILTERS.iter().find(|f| f.name == name)
}

/// Generate a TOML jail configuration for a service.
pub fn gen_config(template: &FilterTemplate) -> String {
    let mut out = format!("[jail.{}]\n", template.name);
    out.push_str(&format!("# {}\n", template.description));
    out.push_str(&format!("log_path = \"{}\"\n", template.log_path));
    out.push_str(&format!("date_format = \"{}\"\n", template.date_format));
    out.push_str("filter = [\n");
    for pattern in template.patterns {
        out.push_str(&format!("    '{}',\n", pattern));
    }
    out.push_str("]\n");
    out
}
