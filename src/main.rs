//! fail2ban-rs — A pure-Rust replacement for fail2ban.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
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
    ListBans,

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

        Command::ListBans => {
            let config =
                Config::from_file(&cli.config).context("loading config for socket path")?;
            let response = control::send_request(&config.global.socket_path, &Request::ListBans)
                .await
                .context("connecting to daemon")?;
            print_response(&response);
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

    println!("Lines: {}\n", all_lines.len());

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

        println!("Jail: {name}");
        println!("  Matches: {match_count}");
        println!("  Unique IPs: {}", failures.len());

        if !failures.is_empty() {
            let mut sorted: Vec<_> = failures.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

            for (ip, timestamps) in sorted {
                let would_ban = timestamps.len() >= jail.max_retry as usize;
                let marker = if would_ban { " [WOULD BAN]" } else { "" };
                println!("    {ip}: {} failures{marker}", timestamps.len());
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
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
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
