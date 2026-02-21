//! State persistence — atomic snapshots of active bans.
//!
//! Format: `[magic "F2RS": 4][version: u8][crc32: 4][postcard payload]`
//! Written atomically via tmp → fsync → rename.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Magic bytes identifying a fail2ban-rs state file.
const MAGIC: &[u8; 4] = b"F2RS";

/// Current state format version.
const VERSION: u8 = 2;

/// Header size: 4 (magic) + 1 (version) + 4 (crc32) = 9 bytes.
const HEADER_SIZE: usize = 9;

/// A snapshot of all active bans at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Active bans.
    pub bans: Vec<BanRecord>,
    /// Per-IP ban counts for ban time escalation.
    pub ban_counts: Vec<(IpAddr, u32)>,
    /// Unix timestamp when the snapshot was taken.
    pub snapshot_time: i64,
}

/// V1 snapshot format (without ban_counts).
#[derive(Debug, Clone, Deserialize)]
struct StateSnapshotV1 {
    bans: Vec<BanRecord>,
    snapshot_time: i64,
}

/// A single ban record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanRecord {
    /// The banned IP address.
    pub ip: IpAddr,
    /// Which jail triggered the ban.
    pub jail_id: String,
    /// When the ban was applied (unix timestamp).
    pub banned_at: i64,
    /// When the ban expires (`None` = permanent).
    pub expires_at: Option<i64>,
}

/// Save a state snapshot atomically.
///
/// Writes to a temporary file in the same directory, fsyncs, then renames
/// over the target path.
pub fn save(path: &Path, snapshot: &StateSnapshot) -> Result<()> {
    let payload =
        postcard::to_allocvec(snapshot).map_err(|e| Error::state_corrupt(format!("{e}")))?;

    let crc = crc32fast::hash(&payload);

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&payload);

    // Write to a temp file in the same directory, then rename.
    let dir = path.parent().ok_or_else(|| {
        Error::io(
            "state file has no parent directory",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"),
        )
    })?;

    // Ensure directory exists.
    std::fs::create_dir_all(dir).map_err(|e| Error::io("creating state directory", e))?;

    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &buf).map_err(|e| Error::io("writing state temp file", e))?;

    // fsync the file.
    let f = std::fs::File::open(&tmp_path).map_err(|e| Error::io("opening state temp file", e))?;
    f.sync_all()
        .map_err(|e| Error::io("fsyncing state file", e))?;

    // Atomic rename.
    std::fs::rename(&tmp_path, path).map_err(|e| Error::io("renaming state file", e))?;

    Ok(())
}

/// Load a state snapshot, returning `None` if the file doesn't exist.
///
/// Returns an error for corrupt files (bad magic, version, or CRC).
pub fn load(path: &Path) -> Result<Option<StateSnapshot>> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io("reading state file", e)),
    };

    if data.len() < HEADER_SIZE {
        return Err(Error::state_corrupt("file too small"));
    }

    // Verify magic.
    if &data[..4] != MAGIC {
        return Err(Error::state_corrupt(format!(
            "bad magic: expected F2RS, got {:?}",
            &data[..4]
        )));
    }

    // Verify version.
    let version = data[4];
    if version != 1 && version != VERSION {
        return Err(Error::state_corrupt(format!(
            "unsupported version: {} (expected 1 or {})",
            version, VERSION
        )));
    }

    // Verify CRC32.
    let stored_crc = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
    let payload = &data[HEADER_SIZE..];
    let computed_crc = crc32fast::hash(payload);
    if stored_crc != computed_crc {
        return Err(Error::state_corrupt(format!(
            "CRC mismatch: stored={stored_crc:#x}, computed={computed_crc:#x}"
        )));
    }

    // Deserialize based on version.
    let snapshot = if version == 1 {
        let v1: StateSnapshotV1 =
            postcard::from_bytes(payload).map_err(|e| Error::state_corrupt(format!("{e}")))?;
        StateSnapshot {
            bans: v1.bans,
            ban_counts: vec![],
            snapshot_time: v1.snapshot_time,
        }
    } else {
        postcard::from_bytes(payload).map_err(|e| Error::state_corrupt(format!("{e}")))?
    };

    Ok(Some(snapshot))
}
