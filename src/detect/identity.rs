//! Log file identity and rotation detection.
//!
//! Captures a fingerprint of a log file (inode, size, first-line hash) so the
//! [`reader`](crate::detect::reader) can detect when a file has been rotated,
//! truncated, or replaced and needs reopening.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use xxhash_rust::xxh3::xxh3_64;

/// Identifies a log file for rotation detection.
#[derive(Debug)]
pub(crate) struct FileIdentity {
    /// File inode (unix only).
    #[cfg(unix)]
    inode: u64,
    /// File size in bytes.
    size: u64,
    /// Hash of the first line.
    first_line_hash: u64,
}

impl FileIdentity {
    /// Fingerprint the file at `path`, or `None` if it can't be read.
    pub(crate) fn from_file(path: &PathBuf) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let size = meta.len();

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };

        let first_line_hash = {
            let file = std::fs::File::open(path).ok()?;
            let mut reader = BufReader::new(file);
            let mut bytes = Vec::new();
            reader.read_until(b'\n', &mut bytes).ok()?;
            xxh3_64(&bytes)
        };

        Some(Self {
            #[cfg(unix)]
            inode,
            size,
            first_line_hash,
        })
    }

    /// Whether `other` represents a rotated/truncated/replaced version of `self`.
    pub(crate) fn is_rotated(&self, other: &FileIdentity) -> bool {
        #[cfg(unix)]
        if self.inode != other.inode {
            return true;
        }
        // Size shrunk → truncated/rotated.
        if other.size < self.size {
            return true;
        }
        // First line hash changed → different file.
        self.first_line_hash != other.first_line_hash
    }
}
