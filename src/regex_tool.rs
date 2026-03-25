//! CLI regex testing tool — test patterns against log lines.

use crate::matcher::JailMatcher;

/// Test a single pattern against a log line and print the result.
pub fn test_pattern(pattern: &str, line: &str) {
    let matcher = match JailMatcher::new(&[pattern.to_string()]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error compiling pattern: {e}");
            eprintln!("  Hint: <HOST> expands to an IPv4/IPv6 capture group automatically.");
            std::process::exit(1);
        }
    };

    if let Some(result) = matcher.try_match(line) {
        println!("Match found — this line would count as a failure.");
        println!();
        println!("  Extracted IP: {}", result.ip);
        println!("  Pattern:      {pattern}");
        println!("  Line:         {line}");
        println!();
        println!(
            "In production, max_retry failures from {} within find_time triggers a ban.",
            result.ip
        );
    } else {
        println!("No match — this line would be ignored.");
        println!();
        println!("  Pattern: {pattern}");
        println!("  Line:    {line}");
        println!();
        println!("Hints:");
        println!("  - <HOST> expands to match IPv4/IPv6 addresses");
        println!("  - Escape brackets with \\[ and \\]");
        println!("  - Use .* for flexible gaps");
        println!("  - Try: fail2ban-rs list-filters  (for built-in patterns)");
    }
}
