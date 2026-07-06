use super::*;

use crate::config::LoggingConfig;

#[test]
fn valid_level_accepts_known() {
    for level in ["debug", "info", "warn", "warning", "error", "WARN", "Error"] {
        assert!(is_valid_level(level), "expected {level} to be valid");
    }
}

#[test]
fn valid_level_rejects_unknown() {
    assert!(!is_valid_level("verbose"));
    assert!(!is_valid_level(""));
    assert!(!is_valid_level("infoo"));
}

#[test]
fn init_none_without_destination() {
    let config = LoggingConfig {
        destination: None,
        endpoint: None,
        api_key: Some("a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()),
        level: None,
        service: None,
        format: None,
    };
    assert!(Logger::init(&config).is_none());
}

#[test]
fn init_none_without_api_key() {
    let config = LoggingConfig {
        destination: Some("tell".to_string()),
        endpoint: None,
        api_key: None,
        level: None,
        service: None,
        format: None,
    };
    assert!(Logger::init(&config).is_none());
}

#[cfg(feature = "tell")]
#[test]
fn init_none_with_invalid_key() {
    let config = LoggingConfig {
        destination: Some("tell".to_string()),
        endpoint: None,
        api_key: Some("not-a-valid-hex-key".to_string()),
        level: None,
        service: None,
        format: None,
    };
    // Invalid API key should not panic, just return None.
    assert!(Logger::init(&config).is_none());
}

#[test]
fn init_none_with_unsupported_destination() {
    let config = LoggingConfig {
        destination: Some("datadog".to_string()),
        endpoint: None,
        api_key: Some("a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()),
        level: None,
        service: None,
        format: None,
    };
    assert!(Logger::init(&config).is_none());
}

#[test]
fn default_logging_config() {
    let config = LoggingConfig::default();
    assert!(config.destination.is_none());
    assert!(config.api_key.is_none());
    assert!(config.endpoint.is_none());
    assert!(config.level.is_none());
    assert!(config.service.is_none());
}
