//! Journal JSON entry decoding.
//!
//! The journal watcher runs `journalctl --output=json` so every entry carries
//! its `__CURSOR` (needed for gap-free restarts and reload handoff). Filters
//! are written against the classic `--output=short` layout, so each entry is
//! rebuilt into `"<Mon DD HH:MM:SS> <host> <ident>[<pid>]: <message>"`.

use std::borrow::Cow;

use serde_json::{Map, Value};

use crate::detect::watcher::MAX_LINE_LEN;
use crate::text::lossy;

/// One decoded journal entry.
#[derive(Debug)]
pub(crate) struct JournalEntry {
    /// Opaque journal cursor of this entry.
    pub(crate) cursor: Option<String>,
    /// Entry time as unix seconds.
    pub(crate) timestamp: Option<i64>,
    /// Short-format prefix (`"Jan 15 10:30:00 host sshd[42]: "`).
    pub(crate) prefix: String,
    /// The `MESSAGE` field (may span multiple lines).
    pub(crate) message: String,
}

impl JournalEntry {
    /// Short-format lines for this entry, laid out like `journalctl
    /// --output=short`: the first message line carries the prefix, and each
    /// continuation line is indented by the prefix width *without* the
    /// timestamp/host/ident.
    ///
    /// Continuation lines must not get the prefix: a newline embedded in an
    /// attacker-influenced message (e.g. a logged username) would otherwise
    /// forge a line such as `sshd[42]: Failed password ... from <victim>` and
    /// get an arbitrary IP banned.
    pub(crate) fn lines(&self) -> impl Iterator<Item = String> + '_ {
        let indent = self.prefix.chars().count();
        self.message.lines().enumerate().map(move |(i, msg)| {
            let msg = msg.trim_end();
            let mut line = String::with_capacity(self.prefix.len().max(indent) + msg.len());
            if i == 0 {
                line.push_str(&self.prefix);
            } else {
                line.extend(std::iter::repeat_n(' ', indent));
            }
            line.push_str(msg);
            line
        })
    }
}

/// Decode one `journalctl --output=json` line. `None` if it is not a JSON
/// object.
pub(crate) fn parse_entry(json: &str) -> Option<JournalEntry> {
    let map: Map<String, Value> = serde_json::from_str(json).ok()?;
    let micros = field(&map, "_SOURCE_REALTIME_TIMESTAMP")
        .or_else(|| field(&map, "__REALTIME_TIMESTAMP"))
        .and_then(|s| s.parse::<i64>().ok());
    Some(JournalEntry {
        cursor: field(&map, "__CURSOR").map(Cow::into_owned),
        timestamp: micros.map(|m| m.div_euclid(1_000_000)),
        prefix: build_prefix(&map, micros),
        message: field(&map, "MESSAGE")
            .map(|m| truncate_message(m).into_owned())
            .unwrap_or_default(),
    })
}

/// Cap a decoded `MESSAGE` at [`MAX_LINE_LEN`] bytes (on a char boundary).
///
/// The JSON entry may legitimately be much larger than the message (a byte-
/// array `MESSAGE` is ~4x its decoded size), so the entry cap is generous and
/// the message is truncated here rather than the whole entry being dropped —
/// the leading text, where failure lines carry their IP, is still matched.
fn truncate_message(message: Cow<'_, str>) -> Cow<'_, str> {
    if message.len() <= MAX_LINE_LEN {
        return message;
    }
    let end = message.floor_char_boundary(MAX_LINE_LEN);
    match message {
        Cow::Borrowed(s) => Cow::Borrowed(s.get(..end).unwrap_or(s)),
        Cow::Owned(mut s) => {
            s.truncate(end);
            Cow::Owned(s)
        }
    }
}

/// Text of a journal field.
fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<Cow<'a, str>> {
    value_text(map.get(key)?)
}

/// Journal JSON encodes fields as a string, a byte array (non-UTF-8 or
/// binary data), or an array of values (field set multiple times — the
/// first is used).
fn value_text(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::String(s) => Some(Cow::Borrowed(s)),
        Value::Array(items) if items.iter().all(Value::is_u64) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(Value::as_u64)
                .map(|b| b as u8)
                .collect();
            Some(Cow::Owned(lossy(&bytes).into_owned()))
        }
        Value::Array(items) => items.first().and_then(value_text),
        _ => None,
    }
}

/// Build the `--output=short` style prefix for an entry.
fn build_prefix(map: &Map<String, Value>, micros: Option<i64>) -> String {
    let mut out = String::with_capacity(64);
    if let Some(ts) = micros.and_then(format_timestamp) {
        out.push_str(&ts);
        out.push(' ');
    }
    if let Some(host) = field(map, "_HOSTNAME") {
        out.push_str(&host);
        out.push(' ');
    }
    let Some(ident) = field(map, "SYSLOG_IDENTIFIER").or_else(|| field(map, "_COMM")) else {
        return out;
    };
    out.push_str(&ident);
    if let Some(pid) = field(map, "_PID").or_else(|| field(map, "SYSLOG_PID")) {
        out.push('[');
        out.push_str(&pid);
        out.push(']');
    }
    out.push_str(": ");
    out
}

/// Format microseconds since the epoch as local syslog time.
fn format_timestamp(micros: i64) -> Option<String> {
    let utc = chrono::DateTime::from_timestamp_micros(micros)?;
    let local = utc.with_timezone(&chrono::Local);
    Some(local.format("%b %d %H:%M:%S").to_string())
}

#[cfg(test)]
#[path = "journal_entry_test.rs"]
mod journal_entry_test;
