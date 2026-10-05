//! Bounded line reader for the journal watcher.
//!
//! Reads one `journalctl --output=json` line (a whole entry) at a time from an
//! async reader, capped at [`MAX_ENTRY_LEN`]. Oversized lines are drained and
//! skipped rather than buffered.

use memchr::memchr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tracing::warn;

use crate::text::lossy;

/// Upper bound on one `journalctl --output=json` line (a whole entry).
///
/// Deliberately far larger than the per-message
/// [`MAX_LINE_LEN`](crate::detect::watcher::MAX_LINE_LEN): the JSON object
/// carries every journal field, and a non-UTF-8 `MESSAGE` is encoded as a
/// byte array (`[97,98,...]`, ~4 bytes per byte). Capping the entry at the
/// message limit would let an attacker push a failure line past the cap —
/// and out of matching — with a modest non-UTF-8 message. The decoded
/// message is truncated to `MAX_LINE_LEN` instead (see `parse_entry`).
const MAX_ENTRY_LEN: usize = 1024 * 1024;

/// Read a single line from the async reader, bounded by [`MAX_ENTRY_LEN`].
///
/// Raw bytes are decoded into `line` once per completed line, so a UTF-8
/// sequence split across `fill_buf` chunks stays intact. Oversized lines are
/// drained and skipped; the non-zero byte count distinguishes them from EOF.
pub(super) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    raw: &mut Vec<u8>,
    line: &mut String,
    jail_id: &str,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            decode_line(raw, line); // flush a trailing partial line at EOF
            return Ok(total); // 0 if nothing was buffered
        }
        if let Some(pos) = memchr(b'\n', available) {
            let to_take = finish_line(available, pos, total, raw, line, jail_id);
            reader.consume(to_take);
            return Ok(total + to_take);
        }
        // No newline found in this chunk.
        let chunk_len = available.len();
        if total + chunk_len > MAX_ENTRY_LEN {
            return skip_oversized(reader, raw, chunk_len, jail_id).await;
        }
        raw.extend_from_slice(available);
        reader.consume(chunk_len);
        total += chunk_len;
    }
}

/// Append the line ending at `pos` to `raw` and decode it, or drop the line
/// if oversized. Returns the byte count (newline included) to consume.
fn finish_line(
    available: &[u8],
    pos: usize,
    total: usize,
    raw: &mut Vec<u8>,
    line: &mut String,
    jail_id: &str,
) -> usize {
    let to_take = pos + 1;
    if total + to_take > MAX_ENTRY_LEN {
        warn!(
            jail = %jail_id,
            limit = MAX_ENTRY_LEN,
            reason = "oversized",
            "journal line skipped"
        );
        raw.clear();
    } else if let Some(slice) = available.get(..to_take) {
        raw.extend_from_slice(slice);
        decode_line(raw, line);
    }
    to_take
}

/// Skip an oversized line: consume the current chunk and drain to the next newline.
async fn skip_oversized<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    raw: &mut Vec<u8>,
    chunk_len: usize,
    jail_id: &str,
) -> std::io::Result<usize> {
    warn!(
        jail = %jail_id,
        limit = MAX_ENTRY_LEN,
        reason = "oversized",
        "journal line skipped"
    );
    reader.consume(chunk_len);
    raw.clear();
    drain_until_newline(reader).await?;
    // Return non-zero so caller knows this is not EOF.
    Ok(MAX_ENTRY_LEN + 1)
}

/// Discard bytes from the reader until a newline or EOF is reached.
async fn drain_until_newline<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = memchr(b'\n', available) {
            reader.consume(pos + 1);
            break;
        }
        let len = available.len();
        reader.consume(len);
    }
    Ok(())
}

/// Decode `raw` into `line` (invalid UTF-8 replaced) and clear it. Per-line
/// decoding keeps UTF-8 sequences split across chunks intact.
fn decode_line(raw: &mut Vec<u8>, line: &mut String) {
    if raw.is_empty() {
        return;
    }
    line.push_str(&lossy(raw));
    raw.clear();
}

#[cfg(test)]
#[path = "journal_line_test.rs"]
mod journal_line_test;
