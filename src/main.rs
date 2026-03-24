//! fail2ban-rs — A pure-Rust replacement for fail2ban.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, IsTerminal};
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use fail2ban_rs::config::Config;
use fail2ban_rs::control::{self, Request, Response};

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
    ListMaxmind,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run => {
            init_tracing(None);
            let config_path = cli.config.clone();
            let config = Config::from_file(&cli.config).context("failed to load configuration")?;
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

        Command::GenConfig { service } => match fail2ban_rs::filters::find(&service) {
            Some(template) => print!("{}", fail2ban_rs::filters::gen_config(template)),
            None => {
                eprintln!("Unknown service: {service}");
                eprintln!("Available: {}", available_filters());
                std::process::exit(1);
            }
        },

        Command::ListFilters => {
            for f in fail2ban_rs::filters::FILTERS {
                println!("{:20} {}", f.name, f.description);
            }
        }

        Command::ListMaxmind => {
            let config = Config::from_file(&cli.config).context("failed to load configuration")?;
            println!("Available MaxMind databases (from config):");
            println!(
                "  ASN:     {}",
                config
                    .global
                    .maxmind_asn
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Not configured".to_string())
            );
            println!(
                "  Country: {}",
                config
                    .global
                    .maxmind_country
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Not configured".to_string())
            );
            println!(
                "  City:    {}",
                config
                    .global
                    .maxmind_city
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Not configured".to_string())
            );
        }
    }

    Ok(())
}

fn dry_run(config: &Config, log_path: &std::path::Path, jail_filter: Option<&str>) -> Result<()> {
    use fail2ban_rs::date::DateParser;
    use fail2ban_rs::ignore::IgnoreList;
    use fail2ban_rs::matcher::JailMatcher;

    let file = std::fs::File::open(log_path)
        .with_context(|| format!("opening log file: {}", log_path.display()))?;
    let reader = BufReader::new(file);

    let mut all_lines = Vec::new();
    for line in reader.lines() {
        all_lines.push(line.context("reading log line")?);
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
            .filter(|ts| ts.len() >= jail.max_retry as usize)
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
                let would_ban = count >= jail.max_retry as usize;
                if would_ban {
                    println!("    {ip}: {count} failures  <- WOULD BAN");
                } else {
                    let remaining = jail.max_retry as usize - count;
                    println!("    {ip}: {count} failures  ({remaining} more to ban)");
                }
            }
        }
        println!();
    }

    Ok(())
}

fn available_filters() -> String {
    fail2ban_rs::filters::FILTERS
        .iter()
        .map(|f| f.name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn init_tracing(level: Option<&str>) {
    let filter = level.unwrap_or("info");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

fn format_relative(remaining_secs: i64) -> String {
    if remaining_secs <= 0 {
        return "expired".to_string();
    }
    let hours = remaining_secs / 3600;
    let mins = (remaining_secs % 3600) / 60;
    match hours {
        0 => format!("{mins}m remaining"),
        _ => format!("{hours}h {mins}m remaining"),
    }
}

fn print_bans_table(response: &Response) {
    match response {
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        Response::Ok { data: None, .. } => {
            println!("No active bans.");
        }
        Response::Ok {
            data: Some(data), ..
        } => {
            let bans = match data.get("bans").and_then(|v| v.as_array()) {
                Some(b) => b,
                None => {
                    println!("No active bans.");
                    return;
                }
            };
            if bans.is_empty() {
                println!("No active bans.");
                return;
            }

            let now = chrono::Utc::now().timestamp();

            // Collect and sort by expires_at ascending (soonest first).
            let mut rows: Vec<_> = bans
                .iter()
                .filter_map(|b| {
                    let ip = b.get("ip")?.as_str()?;
                    let jail = b.get("jail")?.as_str()?;
                    let banned_at = b.get("banned_at")?.as_i64()?;
                    let expires_at = b.get("expires_at").and_then(|v| v.as_i64());
                    Some((ip.to_string(), jail.to_string(), banned_at, expires_at))
                })
                .collect();
            rows.sort_by_key(|r| r.3.unwrap_or(i64::MAX));

            // Compute column widths.
            let ip_width = rows.iter().map(|r| r.0.len()).max().unwrap_or(2).max(2);

            println!(
                "{:<6}  {:<ip_w$}  {:<17}  EXPIRES",
                "JAIL",
                "IP",
                "BANNED",
                ip_w = ip_width
            );

            for (ip, jail, banned_at, expires_at) in &rows {
                let banned_dt = chrono::DateTime::from_timestamp(*banned_at, 0)
                    .map(|dt| dt.format("%d %b %H:%M").to_string())
                    .unwrap_or_else(|| "-".to_string());
                let expires = match expires_at {
                    Some(exp) => format_relative(exp - now),
                    None => "permanent".to_string(),
                };
                println!(
                    "{:<6}  {:<ip_w$}  {:<17}  {}",
                    jail,
                    ip,
                    banned_dt,
                    expires,
                    ip_w = ip_width
                );
            }
            println!("\nTotal: {} active ban(s)", rows.len());
        }
    }
}

fn print_bans_jsonl(response: &Response) {
    match response {
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
        Response::Ok { data: None, .. } => {}
        Response::Ok {
            data: Some(data), ..
        } => {
            if let Some(bans) = data.get("bans").and_then(|v| v.as_array()) {
                for b in bans {
                    let jail = b.get("jail").and_then(|v| v.as_str()).unwrap_or("");
                    let ip = b.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                    let banned_at = b.get("banned_at").and_then(|v| v.as_i64()).unwrap_or(0);
                    let expires_at = b.get("expires_at").and_then(|v| v.as_i64());
                    match expires_at {
                        Some(exp) => println!(
                            r#"{{"jail":"{jail}","ip":"{ip}","banned_at":{banned_at},"expires_at":{exp}}}"#
                        ),
                        None => println!(
                            r#"{{"jail":"{jail}","ip":"{ip}","banned_at":{banned_at},"expires_at":null}}"#
                        ),
                    }
                }
            }
        }
    }
}

fn print_response(response: &Response) {
    match response {
        Response::Ok { message, data } => {
            if let Some(msg) = message {
                println!("{msg}");
            }
            if let Some(data) = data {
                println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
            }
        }
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    }
}
