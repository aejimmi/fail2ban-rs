//! CLI regex testing tool — test patterns against log lines.

use crate::matcher::JailMatcher;

/// Test a single pattern against a log line and print the result.
pub fn test_pattern(pattern: &str, line: &str) {
    let matcher = match JailMatcher::new(&[pattern.to_string()]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error compiling pattern: {e}");
            std::process::exit(1);
        }
    };

    match matcher.try_match(line) {
        Some(result) => {
            println!("Match!");
            println!("  IP:      {}", result.ip);
            println!("  Pattern: {pattern}");
        }
        None => {
            println!("No match.");
            println!("  Pattern: {pattern}");
            println!("  Line:    {line}");
        }
    }
}
