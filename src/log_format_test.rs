use super::*;

#[test]
fn log_format_parse() {
    assert_eq!(LogFormat::parse(None), LogFormat::Logfmt);
    assert_eq!(LogFormat::parse(Some("logfmt")), LogFormat::Logfmt);
    assert_eq!(LogFormat::parse(Some("json")), LogFormat::Json);
    assert_eq!(LogFormat::parse(Some("JSON")), LogFormat::Json);
    assert_eq!(LogFormat::parse(Some("bogus")), LogFormat::Logfmt);
}

#[test]
fn log_format_is_known() {
    assert!(LogFormat::is_known("logfmt"));
    assert!(LogFormat::is_known("json"));
    assert!(LogFormat::is_known("JSON"));
    assert!(!LogFormat::is_known("bogus"));
    assert!(!LogFormat::is_known(""));
}

#[test]
fn level_priority() {
    assert_eq!(level_to_priority(Level::ERROR), 3);
    assert_eq!(level_to_priority(Level::WARN), 4);
    assert_eq!(level_to_priority(Level::INFO), 5);
    assert_eq!(level_to_priority(Level::DEBUG), 6);
    assert_eq!(level_to_priority(Level::TRACE), 7);
}

#[test]
fn needs_quoting_basic() {
    assert!(!needs_quoting("sshd"));
    assert!(!needs_quoting("1.2.3.4"));
    assert!(needs_quoting(""));
    assert!(needs_quoting("has space"));
    assert!(needs_quoting("has\"quote"));
    assert!(needs_quoting("has\nnewline"));
    assert!(needs_quoting("has=equals"));
}

fn logfmt_from_fields(fields: &[(&str, Value)], msg: &str) -> String {
    let visitor = FieldVisitor {
        message: msg.to_string(),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    };
    let mut buf = String::new();
    visitor.write_logfmt(&mut Writer::new(&mut buf)).unwrap();
    buf
}

fn json_from_fields(fields: &[(&str, Value)], msg: &str) -> String {
    let visitor = FieldVisitor {
        message: msg.to_string(),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    };
    let mut buf = String::new();
    visitor.write_json(&mut Writer::new(&mut buf)).unwrap();
    buf
}

#[test]
fn logfmt_basic() {
    let out = logfmt_from_fields(
        &[
            ("ip", Value::String("1.2.3.4".to_string())),
            ("jail", Value::String("sshd".to_string())),
        ],
        "banned",
    );
    assert_eq!(out, "banned ip=1.2.3.4 jail=sshd");
}

#[test]
fn logfmt_preserves_numbers() {
    let out = logfmt_from_fields(
        &[
            ("ban_time", Value::Number(3600.into())),
            ("ban_count", Value::Number(1.into())),
        ],
        "banned",
    );
    assert_eq!(out, "banned ban_time=3600 ban_count=1");
}

#[test]
fn logfmt_quotes_values_with_spaces() {
    let out = logfmt_from_fields(
        &[("error", Value::String("nft command failed".to_string()))],
        "ban failed",
    );
    assert_eq!(out, r#"ban failed error="nft command failed""#);
}

#[test]
fn json_basic() {
    let out = json_from_fields(
        &[
            ("ip", Value::String("1.2.3.4".to_string())),
            ("jail", Value::String("sshd".to_string())),
        ],
        "banned",
    );
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["msg"], "banned");
    assert_eq!(parsed["ip"], "1.2.3.4");
    assert_eq!(parsed["jail"], "sshd");
}

#[test]
fn json_preserves_number_types() {
    let out = json_from_fields(
        &[
            ("ban_time", Value::Number(3600.into())),
            ("ban_count", Value::Number(1.into())),
        ],
        "banned",
    );
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["ban_time"], 3600);
    assert_eq!(parsed["ban_count"], 1);
}
