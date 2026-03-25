//! MaxMind GeoIP enrichment for ban events.
//!
//! Owns the memory-mapped database readers and per-jail field configuration.
//! Created at tracker startup via [`MaxmindState::load`], updated on
//! hot-reload via [`MaxmindState::reload`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use maxminddb::geoip2;
use tracing::{info, warn};

use crate::config::{GlobalConfig, JailConfig, MaxmindField};
use crate::watcher::Failure;

/// GeoIP enrichment results from MaxMind lookups.
#[derive(Debug, Default)]
pub struct MaxmindEnrichment {
    /// Autonomous system number and organization.
    pub asn: Option<String>,
    /// Country name (English).
    pub country: Option<String>,
    /// City name (English).
    pub city: Option<String>,
}

impl MaxmindEnrichment {
    /// True when at least one field was populated.
    pub fn has_data(&self) -> bool {
        self.asn.is_some() || self.country.is_some() || self.city.is_some()
    }
}

/// Consolidated MaxMind GeoIP state.
pub struct MaxmindState {
    asn: Option<maxminddb::Reader<maxminddb::Mmap>>,
    country: Option<maxminddb::Reader<maxminddb::Mmap>>,
    city: Option<maxminddb::Reader<maxminddb::Mmap>>,
    jail_fields: HashMap<String, Vec<MaxmindField>>,
}

impl MaxmindState {
    /// Load databases from global config, cache per-jail field lists.
    pub fn load(global: &GlobalConfig, jails: &HashMap<String, JailConfig>) -> Self {
        Self {
            asn: global
                .maxmind_asn
                .as_deref()
                .and_then(|p| load_db(p, "ASN")),
            country: global
                .maxmind_country
                .as_deref()
                .and_then(|p| load_db(p, "Country")),
            city: global
                .maxmind_city
                .as_deref()
                .and_then(|p| load_db(p, "City")),
            jail_fields: jails
                .iter()
                .map(|(k, v)| (k.clone(), v.maxmind.clone()))
                .collect(),
        }
    }

    /// Hot-reload: re-open databases and re-cache jail fields.
    pub fn reload(&mut self, global: &GlobalConfig, jails: &HashMap<String, JailConfig>) {
        self.asn = global
            .maxmind_asn
            .as_deref()
            .and_then(|p| load_db(p, "ASN"));
        self.country = global
            .maxmind_country
            .as_deref()
            .and_then(|p| load_db(p, "Country"));
        self.city = global
            .maxmind_city
            .as_deref()
            .and_then(|p| load_db(p, "City"));
        self.jail_fields = jails
            .iter()
            .map(|(k, v)| (k.clone(), v.maxmind.clone()))
            .collect();
    }

    /// Lookup enrichment for an IP based on the jail's configured fields.
    pub fn enrich(&self, ip: IpAddr, jail_id: &str) -> MaxmindEnrichment {
        let fields = match self.jail_fields.get(jail_id) {
            Some(f) => f.as_slice(),
            None => return MaxmindEnrichment::default(),
        };
        let mut result = MaxmindEnrichment::default();
        for field in fields {
            match field {
                MaxmindField::Asn => result.asn = lookup_asn(ip, self.asn.as_ref()),
                MaxmindField::Country => result.country = lookup_country(ip, self.country.as_ref()),
                MaxmindField::City => result.city = lookup_city(ip, self.city.as_ref()),
            }
        }
        result
    }
}

/// Load a MaxMind database from disk via memory-mapped I/O.
pub fn load_db(path: &Path, label: &str) -> Option<maxminddb::Reader<maxminddb::Mmap>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            warn!(path = %path.display(), db = label, error = %e, "cannot stat MaxMind database");
            return None;
        }
    };
    if !meta.is_file() {
        warn!(path = %path.display(), db = label, "MaxMind path is not a regular file");
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o002 != 0 {
            warn!(
                path = %path.display(), db = label,
                "MaxMind database is world-writable — risk of undefined behaviour if modified while mapped"
            );
        }
    }

    // SAFETY: The .mmdb file must not be modified, truncated, or replaced
    // non-atomically while this Reader (and its Mmap) exists. Operators must
    // use atomic file replacement (write to temp file + rename) when updating
    // MaxMind databases — the standard practice for geoipupdate.
    #[allow(unsafe_code)]
    let reader_result = unsafe { maxminddb::Reader::open_mmap(path) };
    match reader_result {
        Ok(reader) => {
            info!(path = %path.display(), db = label, "MaxMind database loaded");
            Some(reader)
        }
        Err(e) => {
            warn!(path = %path.display(), db = label, error = %e, "failed to load MaxMind database");
            None
        }
    }
}

/// Log a ban event, including MaxMind fields only when enrichment data exists.
pub fn log_ban_event(
    failure: &Failure,
    ban_time: i64,
    ban_count: u32,
    enrichment: &MaxmindEnrichment,
) {
    if enrichment.has_data() {
        info!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            maxmind_asn = enrichment.asn,
            maxmind_country = enrichment.country,
            maxmind_city = enrichment.city,
            ban_time,
            ban_count,
            "threshold reached, banning"
        );
    } else {
        info!(
            ip = %failure.ip,
            jail = %failure.jail_id,
            ban_time,
            ban_count,
            "threshold reached, banning"
        );
    }
}

fn lookup_asn(ip: IpAddr, reader: Option<&maxminddb::Reader<maxminddb::Mmap>>) -> Option<String> {
    let reader = reader?;
    let result = reader.lookup(ip).ok()?;
    let record = result.decode::<geoip2::Asn>().ok()??;
    match (
        record.autonomous_system_number,
        record.autonomous_system_organization,
    ) {
        (Some(num), Some(org)) => Some(format!("AS{num} ({org})")),
        (Some(num), None) => Some(format!("AS{num}")),
        (None, Some(org)) => Some(org.to_string()),
        (None, None) => None,
    }
}

fn lookup_country(
    ip: IpAddr,
    reader: Option<&maxminddb::Reader<maxminddb::Mmap>>,
) -> Option<String> {
    let reader = reader?;
    let result = reader.lookup(ip).ok()?;
    let record = result.decode::<geoip2::Country>().ok()??;
    record
        .country
        .names
        .english
        .map(std::string::ToString::to_string)
}

fn lookup_city(ip: IpAddr, reader: Option<&maxminddb::Reader<maxminddb::Mmap>>) -> Option<String> {
    let reader = reader?;
    let result = reader.lookup(ip).ok()?;
    let record = result.decode::<geoip2::City>().ok()??;
    record
        .city
        .names
        .english
        .map(std::string::ToString::to_string)
}
