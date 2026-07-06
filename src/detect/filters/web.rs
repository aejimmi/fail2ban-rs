//! Built-in filter definitions for web servers and web applications.

use super::FilterTemplate;

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "web_test.rs"]
mod web_test;

/// Filter templates for web servers and web applications.
pub const FILTERS: &[FilterTemplate] = &[
    FilterTemplate {
        name: "apache-auth",
        description: "Apache HTTP basic/digest authentication failures",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[
            r"client <HOST>.*user .* authentication failure",
            r"client <HOST>.*user .* not found",
            r"client <HOST>.*password mismatch",
        ],
    },
    FilterTemplate {
        name: "apache-botsearch",
        description: "Apache requests for known exploit and scanner paths",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"client <HOST>.*File does not exist:.*/(wp-login|xmlrpc|\.env|phpmyadmin)"],
    },
    FilterTemplate {
        name: "apache-modsecurity",
        description: "Apache ModSecurity WAF access denied",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"client <HOST>.*ModSecurity:.*Access denied with code [45]\d\d"],
    },
    FilterTemplate {
        name: "apache-nohome",
        description: "Apache requests for non-existent home directories",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"client <HOST>.*File does not exist:.*~"],
    },
    FilterTemplate {
        name: "apache-noscript",
        description: "Apache requests for non-existent scripts",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[
            r"client <HOST>.*script .* not found or unable to stat",
            r"client <HOST>.*File does not exist:.*\.php",
        ],
    },
    FilterTemplate {
        name: "apache-overflows",
        description: "Apache buffer overflow and invalid request attempts",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"client <HOST>.*(?:Invalid (?:method|URI)|request failed:)"],
    },
    FilterTemplate {
        name: "apache-shellshock",
        description: "Apache Shellshock (CVE-2014-6271) exploit attempts",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"client <HOST>.*AH01215:.*(?:bash|sh):.*HTTP_"],
    },
    FilterTemplate {
        name: "centreon",
        description: "Centreon IT monitoring authentication failures",
        log_path: "/var/log/centreon/login.log",
        date_format: "iso8601",
        patterns: &[r"\[<HOST>\] Authentication failed"],
    },
    FilterTemplate {
        name: "directadmin",
        description: "DirectAdmin hosting panel login failures",
        log_path: "/var/log/directadmin/login.log",
        date_format: "iso8601",
        patterns: &[r"'<HOST>' \d+ failed login attempt"],
    },
    FilterTemplate {
        name: "drupal",
        description: "Drupal CMS authentication failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[
            r"drupal.*Login attempt failed from <HOST>",
            r"(?:[^|]*\|){3}<HOST>\|.*Login attempt failed",
        ],
    },
    FilterTemplate {
        name: "froxlor-auth",
        description: "Froxlor hosting panel authentication failures",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[r"Login Action <HOST>.*(?:Unknown user|wrong password)"],
    },
    FilterTemplate {
        name: "gitlab",
        description: "GitLab authentication failures",
        log_path: "/var/log/gitlab/gitlab-rails/application.log",
        date_format: "iso8601",
        patterns: &[r"Failed Login:.*ip=<HOST>"],
    },
    FilterTemplate {
        name: "grafana",
        description: "Grafana login failures",
        log_path: "/var/log/grafana/grafana.log",
        date_format: "iso8601",
        patterns: &[
            r"Invalid username or password.*remote_addr=<HOST>",
            r"User not found.*remote_addr=<HOST>",
        ],
    },
    FilterTemplate {
        name: "haproxy",
        description: "HAProxy HTTP authentication failures",
        log_path: "/var/log/haproxy.log",
        date_format: "syslog",
        patterns: &[r"haproxy\[\d+\]: <HOST>:\d+ .*\b401\b"],
    },
    FilterTemplate {
        name: "lighttpd-auth",
        description: "Lighttpd HTTP authentication failures",
        log_path: "/var/log/lighttpd/error.log",
        date_format: "iso8601",
        patterns: &[
            r"(?:password doesn.t match|digest: auth failed|get_password failed).* IP: <HOST>",
        ],
    },
    FilterTemplate {
        name: "monitorix",
        description: "Monitorix system monitoring authentication and access failures",
        log_path: "/var/log/monitorix-httpd",
        date_format: "common",
        patterns: &[
            r"NOTEXIST - \[<HOST>\]",
            r"AUTHERR - \[<HOST>\]",
            r"NOTALLOWED - \[<HOST>\]",
        ],
    },
    FilterTemplate {
        name: "nagios",
        description: "Nagios NRPE host access denied",
        log_path: "/var/log/syslog",
        date_format: "syslog",
        patterns: &[r"Host <HOST> is not allowed to talk to us"],
    },
    FilterTemplate {
        name: "nginx-auth",
        description: "Nginx HTTP basic authentication failures",
        log_path: "/var/log/nginx/error.log",
        date_format: "common",
        patterns: &[
            r"no user/password was provided for basic authentication.*client: <HOST>",
            r"user .* was not found.*client: <HOST>",
            r"user .* password mismatch.*client: <HOST>",
        ],
    },
    FilterTemplate {
        name: "nginx-bad-request",
        description: "Nginx malformed HTTP requests (400 status)",
        log_path: "/var/log/nginx/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> - \S+ .+"[^"]*" 400 "#],
    },
    FilterTemplate {
        name: "nginx-botsearch",
        description: "Nginx requests for known exploit paths",
        log_path: "/var/log/nginx/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> .* "(GET|POST) /(wp-login|xmlrpc|wp-admin|\.env|phpmyadmin|admin)"#],
    },
    FilterTemplate {
        name: "nginx-forbidden",
        description: "Nginx access forbidden by rule",
        log_path: "/var/log/nginx/error.log",
        date_format: "common",
        patterns: &[r"access forbidden by rule, client: <HOST>,"],
    },
    FilterTemplate {
        name: "nginx-limit-req",
        description: "Nginx rate limit and connection limit violations",
        log_path: "/var/log/nginx/error.log",
        date_format: "common",
        patterns: &[
            r"limiting requests, excess: .* by zone .*, client: <HOST>,",
            r"limiting connections by zone .*, client: <HOST>,",
            r"delaying request.* by zone .*, client: <HOST>,",
        ],
    },
    FilterTemplate {
        name: "openhab",
        description: "openHAB home automation authentication failures",
        log_path: "/var/log/openhab/request.log",
        date_format: "common",
        patterns: &[r#"<HOST>\s+-\s+.+\s+"[A-Z]+ .+" 401 "#],
    },
    FilterTemplate {
        name: "php-url-fopen",
        description: "PHP remote file inclusion attempts via URL fopen",
        log_path: "/var/log/apache2/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> .*"(?:GET|POST).*\?.*=http://"#],
    },
    FilterTemplate {
        name: "phpmyadmin-syslog",
        description: "phpMyAdmin authentication failures via syslog",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"phpMyAdmin\[\d+\]: user denied: .* from <HOST>"],
    },
    FilterTemplate {
        name: "squid",
        description: "Squid proxy denied requests",
        log_path: "/var/log/squid/access.log",
        date_format: "epoch",
        patterns: &[
            r"\d\s+<HOST>\s+[A-Z_]+_DENIED/\d+",
            r"\d\s+<HOST>\s+NONE/405",
        ],
    },
    FilterTemplate {
        name: "suhosin",
        description: "Suhosin PHP security extension alerts",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[r"attacker '<HOST>'"],
    },
    FilterTemplate {
        name: "traefik",
        description: "Traefik reverse proxy authentication failures",
        log_path: "/var/log/access.log",
        date_format: "common",
        patterns: &[r#"<HOST> .*" 401 "#],
    },
    FilterTemplate {
        name: "webmin-auth",
        description: "Webmin administration panel authentication failures",
        log_path: "/var/log/auth.log",
        date_format: "syslog",
        patterns: &[r"webmin\[\d+\]: (?:Invalid|Non-existent) login as .* from <HOST>"],
    },
    FilterTemplate {
        name: "zoneminder",
        description: "ZoneMinder video surveillance authentication failures",
        log_path: "/var/log/apache2/error.log",
        date_format: "common",
        patterns: &[
            r"client <HOST>.*Login denied for user",
            r"client <HOST>.*Could not retrieve user .* details",
        ],
    },
];
