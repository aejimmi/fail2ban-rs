//! Structured stderr formatter for logfmt and JSON output.
//!
//! Emits each event as a single line on stderr. Under systemd, prepends
//! `<N>` per-line so journald sets PRIORITY correctly (systemd strips the
//! prefix before storing MESSAGE). Without systemd, prepends a human
//! level tag (e.g. ` INFO`) instead.
//!
//! This replaces writing to the journald socket directly. The entire
//! structured payload — message phrase + all fields — ends up in
//! journald's MESSAGE field as one parseable string. Consumers (journalctl,
//! rsyslog, witness) read MESSAGE and parse it according to the chosen
//! format.

use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Output format for each log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// `banned ip=1.2.3.4 jail=sshd reason=threshold`
    Logfmt,
    /// `{"msg":"banned","ip":"1.2.3.4","jail":"sshd","reason":"threshold"}`
    Json,
}

impl LogFormat {
    /// Parse from config string. Defaults to `Logfmt` on unknown/missing.
    ///
    /// Unknown strings degrade to `Logfmt` here; they are rejected earlier at
    /// config validation via [`LogFormat::is_known`], so a value reaching this
    /// point is already known-good.
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(str::to_ascii_lowercase).as_deref() {
            Some("json") => Self::Json,
            _ => Self::Logfmt,
        }
    }

    /// Whether `s` names a recognized output format (case-insensitive).
    ///
    /// Used by config validation to reject typo'd `logging.format` values
    /// instead of silently degrading them to the default.
    pub fn is_known(s: &str) -> bool {
        matches!(s.to_ascii_lowercase().as_str(), "logfmt" | "json")
    }
}

/// Single-line stderr formatter.
pub struct StructuredFormatter {
    format: LogFormat,
    systemd: bool,
}

impl StructuredFormatter {
    /// Create a new formatter. `systemd` controls whether `<N>` priority
    /// prefixes are emitted (auto-detected via `JOURNAL_STREAM`).
    pub fn new(format: LogFormat, systemd: bool) -> Self {
        Self { format, systemd }
    }
}

impl<S, N> FormatEvent<S, N> for StructuredFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let level = *event.metadata().level();

        if self.systemd {
            // <N> systemd priority prefix — stripped by journald, sets PRIORITY.
            write!(writer, "<{}>", level_to_priority(level))?;
        } else {
            // Non-systemd: prepend level tag + timestamp for human readability.
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
            write!(writer, "{ts}  {:>5} ", level.as_str())?;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        match self.format {
            LogFormat::Logfmt => visitor.write_logfmt(&mut writer)?,
            LogFormat::Json => visitor.write_json(&mut writer)?,
        }

        writeln!(writer)
    }
}

/// Visitor that collects the event message and structured fields.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<(String, Value)>,
}

impl FieldVisitor {
    fn push(&mut self, name: &str, value: Value) {
        if name == "message" {
            if let Value::String(s) = value {
                self.message = s;
            } else {
                self.message = value.to_string();
            }
        } else {
            self.fields.push((name.to_string(), value));
        }
    }

    fn write_logfmt(&self, w: &mut Writer<'_>) -> fmt::Result {
        w.write_str(&self.message)?;
        for (k, v) in &self.fields {
            write!(w, " {k}=")?;
            write_logfmt_value(w, v)?;
        }
        Ok(())
    }

    fn write_json(&self, w: &mut Writer<'_>) -> fmt::Result {
        let mut obj = Map::with_capacity(self.fields.len() + 1);
        obj.insert("msg".to_string(), Value::String(self.message.clone()));
        for (k, v) in &self.fields {
            obj.insert(k.clone(), v.clone());
        }
        match serde_json::to_string(&obj) {
            Ok(s) => w.write_str(&s),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let formatted = format!("{value:?}");
        // Debug on &str adds surrounding quotes — strip for the message field.
        let clean = if field.name() == "message" {
            formatted
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .map_or(formatted.clone(), std::string::ToString::to_string)
        } else {
            formatted
        };
        self.push(field.name(), Value::String(clean));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), Value::Bool(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // serde_json::Number can fail on NaN/Inf — fall back to string.
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.push(field.name(), Value::Number(n));
        } else {
            self.push(field.name(), Value::String(value.to_string()));
        }
    }
}

/// Map tracing level to syslog priority (matches the project convention
/// where INFO shows as NOTICE in journald for operator visibility).
fn level_to_priority(level: Level) -> u8 {
    match level {
        Level::ERROR => 3, // err
        Level::WARN => 4,  // warning
        Level::INFO => 5,  // notice
        Level::DEBUG => 6, // info
        Level::TRACE => 7, // debug
    }
}

fn write_logfmt_value(w: &mut Writer<'_>, v: &Value) -> fmt::Result {
    match v {
        Value::String(s) => write_logfmt_string(w, s),
        Value::Number(n) => write!(w, "{n}"),
        Value::Bool(b) => write!(w, "{b}"),
        Value::Null => w.write_str("null"),
        other => write_logfmt_string(w, &other.to_string()),
    }
}

fn write_logfmt_string(w: &mut Writer<'_>, s: &str) -> fmt::Result {
    if needs_quoting(s) {
        w.write_char('"')?;
        for c in s.chars() {
            match c {
                '"' => w.write_str("\\\"")?,
                '\\' => w.write_str("\\\\")?,
                '\n' => w.write_str("\\n")?,
                _ => w.write_char(c)?,
            }
        }
        w.write_char('"')
    } else {
        w.write_str(s)
    }
}

fn needs_quoting(s: &str) -> bool {
    s.is_empty() || s.contains(' ') || s.contains('"') || s.contains('\n') || s.contains('=')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
#[path = "log_format_test.rs"]
mod log_format_test;
