//! Configuration loading: file reading, `config.d` overlays, TOML parsing, and
//! backward-compatibility shims applied before the typed deserialize.

use std::path::{Path, PathBuf};

use tracing::warn;

use super::types::Config;
use crate::error::{Error, Result};

impl Config {
    /// Load and validate configuration from a TOML file.
    ///
    /// After reading the main file, merges any overlays found in a sibling
    /// `config.d/` directory (sorted alphabetically).
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ConfigNotFound {
                    path: path.to_path_buf(),
                }
            } else {
                Error::io(format!("reading config: {}", path.display()), e)
            }
        })?;

        let mut base: toml::Value = content
            .parse()
            .map_err(|e| Error::config(format!("TOML parse error: {e}")))?;

        // Merge config.d/*.toml overlays if the directory exists.
        if let Some(dir) = path.parent() {
            let config_d = dir.join("config.d");
            if config_d.is_dir() {
                let mut entries: Vec<PathBuf> = std::fs::read_dir(&config_d)
                    .map_err(|e| Error::io(format!("reading {}", config_d.display()), e))?
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
                    .collect();
                entries.sort();

                for overlay_path in entries {
                    let overlay_content = std::fs::read_to_string(&overlay_path).map_err(|e| {
                        Error::io(format!("reading overlay: {}", overlay_path.display()), e)
                    })?;
                    let overlay: toml::Value = overlay_content.parse().map_err(|e| {
                        Error::config(format!(
                            "TOML parse error in {}: {e}",
                            overlay_path.display()
                        ))
                    })?;
                    deep_merge(&mut base, overlay);
                }
            }
        }

        Self::from_value(base)
    }

    /// Parse and validate configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        let base: toml::Value = content
            .parse()
            .map_err(|e| Error::config(format!("TOML parse error: {e}")))?;
        Self::from_value(base)
    }

    /// Deserialize and validate a config from an already-parsed TOML value.
    ///
    /// Applies backward-compatibility shims before the typed deserialize so
    /// deprecated keys do not trip `deny_unknown_fields`.
    fn from_value(mut base: toml::Value) -> Result<Self> {
        let legacy_level = take_legacy_log_level(&mut base);
        let mut config: Config = base
            .try_into()
            .map_err(|e| Error::config(format!("config deserialization error: {e}")))?;
        config.apply_legacy_level(legacy_level);
        config.validate()?;
        Ok(config)
    }

    /// Apply the deprecated `[global] log_level` onto `logging.level` when the
    /// latter is unset, emitting a deprecation warning either way.
    fn apply_legacy_level(&mut self, legacy_level: Option<String>) {
        let Some(level) = legacy_level else {
            return;
        };
        if self.logging.level.is_none() {
            warn!(
                level = %level,
                "global.log_level is deprecated; applying it to logging.level"
            );
            self.logging.level = Some(level);
        } else {
            warn!("global.log_level is deprecated and ignored because logging.level is set");
        }
    }
}

/// Remove and return the deprecated `[global] log_level` string, if present.
///
/// Extracting it before the typed deserialize keeps it from tripping
/// `deny_unknown_fields` on [`GlobalConfig`](super::types::GlobalConfig). A
/// non-string value is removed and treated as absent.
fn take_legacy_log_level(base: &mut toml::Value) -> Option<String> {
    let global = base.get_mut("global")?.as_table_mut()?;
    let value = global.remove("log_level")?;
    value.as_str().map(str::to_string)
}

/// Recursively merge `overlay` into `base`. Tables merge recursively;
/// all other value types are overwritten by the overlay.
fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match overlay {
        toml::Value::Table(overlay_table) => {
            if let toml::Value::Table(base_table) = base {
                for (key, overlay_val) in overlay_table {
                    let entry = base_table
                        .entry(key)
                        .or_insert(toml::Value::Table(toml::map::Map::new()));
                    deep_merge(entry, overlay_val);
                }
            } else {
                *base = toml::Value::Table(overlay_table);
            }
        }
        other => {
            *base = other;
        }
    }
}

#[cfg(test)]
#[path = "load_test.rs"]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod load_test;
