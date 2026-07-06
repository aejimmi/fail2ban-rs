//! fail2ban-rs — A pure-Rust replacement for fail2ban.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use fail2ban_rs::config::Config;
use fail2ban_rs::control::{self, Request};

mod output;
use output::{print_bans_jsonl, print_bans_table, print_response};

const HELP_TEMPLATE: &str = "\
{name} {version}
{about}

{usage-heading} {usage}

{all-args}";

#[derive(Parser)]
#[command(
    name = "fail2ban-rs",
    version,
    about = "A pure-Rust replacement for fail2ban",
    help_template = HELP_TEMPLATE
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to the configuration file
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/fail2ban-rs/config.toml"
    )]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Run the fail2ban-rs daemon
    Run,

    /// Show daemon status
    Status,

    /// List active bans
    ListBans {
        /// Output as JSONL (one JSON object per line)
        #[arg(long)]
        json: bool,
    },

    /// Show daemon statistics
    Stats,

    /// Ban an IP address
    Ban {
        /// IP address to ban
        ip: IpAddr,
        /// Jail name
        #[arg(short, long)]
        jail: String,
    },

    /// Unban an IP address
    Unban {
        /// IP address to unban
        ip: IpAddr,
        /// Jail name
        #[arg(short, long)]
        jail: String,
    },

    /// Reload daemon configuration
    Reload,

    /// Test a regex pattern against a log line
    Regex {
        /// The pattern (with <HOST> placeholder)
        #[arg(short, long)]
        pattern: String,
        /// The log line to test against
        #[arg(short, long)]
        line: String,
    },

    /// Analyze a log file without banning (dry run)
    DryRun {
        /// Log file to analyze
        log: PathBuf,
        /// Filter to specific jail
        #[arg(short, long)]
        jail: Option<String>,
    },

    /// Generate a jail configuration for a service
    GenConfig {
        /// Service name (sshd, nginx-auth, nginx-botsearch, postfix, dovecot, vsftpd, asterisk, mysqld)
        service: String,
    },

    /// List available built-in filter templates
    ListFilters,

    /// Show configured MaxMind databases
    #[cfg(feature = "maxmind")]
    ListMaxmind,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run => {
            let config_path = cli.config.clone();
            let config = Config::from_file(&cli.config).context("failed to load configuration")?;
            init_tracing(
                config.logging.level.as_deref(),
                config.logging.format.as_deref(),
            );
            fail2ban_rs::server::run(config, config_path)
                .await
                .context("daemon error")?;
        }

        Command::Status => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response = control::send_request(&config.global.socket_path, &Request::Status)
                .await
                .context("connecting to daemon")?;
            print_response(&response);
        }

        Command::ListBans { json } => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response = control::send_request(&config.global.socket_path, &Request::ListBans)
                .await
                .context("connecting to daemon")?;
            if json {
                print_bans_jsonl(&response);
            } else {
                print_bans_table(&response);
            }
        }

        Command::Stats => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response = control::send_request(&config.global.socket_path, &Request::Stats)
                .await
                .context("connecting to daemon")?;
            print_response(&response);
        }

        Command::Ban { ip, jail } => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response =
                control::send_request(&config.global.socket_path, &Request::Ban { ip, jail })
                    .await
                    .context("connecting to daemon")?;
            print_response(&response);
        }

        Command::Unban { ip, jail } => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response =
                control::send_request(&config.global.socket_path, &Request::Unban { ip, jail })
                    .await
                    .context("connecting to daemon")?;
            print_response(&response);
        }

        Command::Reload => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response = control::send_request(&config.global.socket_path, &Request::Reload)
                .await
                .context("connecting to daemon")?;
            print_response(&response);
        }

        Command::Regex { pattern, line } => {
            fail2ban_rs::regex_tool::test_pattern(&pattern, &line);
        }

        Command::DryRun { log, jail } => {
            let config = Config::from_file(&cli.config).context("loading config")?;
            dry_run(&config, &log, jail.as_deref())?;
        }

        Command::GenConfig { service } => {
            if let Some(template) = fail2ban_rs::detect::filters::find(&service) {
                print!("{}", fail2ban_rs::detect::filters::gen_config(template));
            } else {
                eprintln!("Unknown service: {service}");
                eprintln!("Available: {}", available_filters());
                std::process::exit(1);
            }
        }

        Command::ListFilters => {
            for f in fail2ban_rs::detect::filters::FILTERS {
                println!("{:20} {}", f.name, f.description);
            }
        }

        #[cfg(feature = "maxmind")]
        Command::ListMaxmind => {
            let config = Config::from_file(&cli.config).context("failed to load configuration")?;
            println!("MaxMind databases:");
            for (label, path) in [
                ("ASN", &config.global.maxmind_asn),
                ("Country", &config.global.maxmind_country),
                ("City", &config.global.maxmind_city),
            ] {
                match path {
                    Some(p) => match fail2ban_rs::track::maxmind::load_db(p, label) {
                        Some(_) => println!("  {label:8} {:<50} OK", p.display()),
                        None => println!("  {label:8} {:<50} FAILED", p.display()),
                    },
                    None => println!("  {label:8} Not configured"),
                }
            }
        }
    }

    Ok(())
}

/// Replay one IP's failure timestamps through the real sliding-window ring
/// buffer to decide whether the daemon would actually ban it.
///
/// Mirrors daemon semantics: `max_retry` failures must fall within a
/// `find_time`-second window, not merely accumulate across the whole file.
fn ip_would_ban(timestamps: &[i64], max_retry: u32, find_time: i64) -> bool {
    use fail2ban_rs::track::circular::CircularTimestamps;

    let mut ring = CircularTimestamps::new(max_retry as usize);
    for &ts in timestamps {
        ring.push(ts);
        if ring.threshold_reached(find_time) {
            return true;
        }
    }
    false
}

fn dry_run(config: &Config, log_path: &std::path::Path, jail_filter: Option<&str>) -> Result<()> {
    use fail2ban_rs::detect::date::DateParser;
    use fail2ban_rs::detect::ignore::IgnoreList;
    use fail2ban_rs::detect::matcher::JailMatcher;

    let file = std::fs::File::open(log_path)
        .with_context(|| format!("opening log file: {}", log_path.display()))?;
    let reader = BufReader::new(file);

    let mut all_lines = Vec::new();
    for chunk in reader.split(b'\n') {
        let bytes = chunk.context("reading log line")?;
        all_lines.push(String::from_utf8_lossy(&bytes).into_owned());
    }

    println!("Dry run — analyzing log without banning anyone.\n");
    println!("  Log file: {}", log_path.display());
    println!("  Lines:    {}", all_lines.len());
    println!();

    for (name, jail) in config.enabled_jails() {
        if let Some(filter) = jail_filter
            && name != filter
        {
            continue;
        }

        let matcher = match JailMatcher::new(&jail.filter) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Jail {name}: invalid filter — {e}");
                continue;
            }
        };
        let date_parser = DateParser::new(jail.date_format)?;
        let ignore_list = IgnoreList::new(&jail.ignoreip, jail.ignoreself)?;

        let mut failures: HashMap<IpAddr, Vec<i64>> = HashMap::new();
        let mut match_count = 0;

        for line in &all_lines {
            if let Some(m) = matcher.try_match(line) {
                if ignore_list.is_ignored(&m.ip) {
                    continue;
                }
                let ts = date_parser.parse_line(line).unwrap_or(0);
                failures.entry(m.ip).or_default().push(ts);
                match_count += 1;
            }
        }

        let would_ban_count = failures
            .values()
            .filter(|ts| ip_would_ban(ts, jail.max_retry, jail.find_time))
            .count();

        println!("Jail: {name}");
        println!("  Patterns:   {} loaded", jail.filter.len());
        println!(
            "  Threshold:  {} failures within {}",
            jail.max_retry, jail.find_time
        );
        println!("  Ban time:   {}", jail.ban_time);
        println!("  Matches:    {match_count}");
        println!("  Unique IPs: {}", failures.len());
        if would_ban_count > 0 {
            println!("  Would ban:  {would_ban_count}");
        }

        if !failures.is_empty() {
            println!();
            let mut sorted: Vec<_> = failures.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

            for (ip, timestamps) in &sorted {
                let count = timestamps.len();
                if ip_would_ban(timestamps, jail.max_retry, jail.find_time) {
                    println!("    {ip}: {count} failures  <- WOULD BAN");
                } else if count < jail.max_retry as usize {
                    let remaining = jail.max_retry as usize - count;
                    println!("    {ip}: {count} failures  ({remaining} more to ban)");
                } else {
                    // Enough failures overall, but never within one find_time window.
                    println!(
                        "    {ip}: {count} failures  (spread beyond {}s window)",
                        jail.find_time
                    );
                }
            }
        }
        println!();
    }

    Ok(())
}

fn available_filters() -> String {
    fail2ban_rs::detect::filters::FILTERS
        .iter()
        .map(|f| f.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn init_tracing(level: Option<&str>, format: Option<&str>) {
    let filter = level.unwrap_or("info");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    // Whole payload lands in journald MESSAGE (logfmt or JSON).
    // Under systemd, each line gets a `<N>` prefix so journald sets PRIORITY
    // per-entry (stripped before MESSAGE is stored). Service name comes from
    // the unit's SyslogIdentifier. No custom journald layer, no structured
    // journald metadata — consumers (journalctl, rsyslog, witness) read and
    // parse MESSAGE as the source of truth.
    let systemd = std::env::var_os("JOURNAL_STREAM").is_some();
    let log_format = fail2ban_rs::log_format::LogFormat::parse(format);
    let formatter = fail2ban_rs::log_format::StructuredFormatter::new(log_format, systemd);

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .event_format(formatter)
        .with_env_filter(env_filter)
        .init();
}

#[cfg(test)]
#[path = "main_test.rs"]
mod main_test;
