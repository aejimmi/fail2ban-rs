//! Fixed-size ring buffer for failure timestamps.
//!
//! Capacity equals `max_retry`. When the buffer is full and the span from
//! oldest to newest is within `find_time`, a ban threshold is reached.
//! Threshold check is O(1).

/// A fixed-capacity ring buffer of `i64` unix timestamps.
#[derive(Debug, Clone)]
pub struct CircularTimestamps {
    buf: Vec<i64>,
    /// Points to the next write position (also the oldest entry when full).
    head: usize,
    len: usize,
}

impl CircularTimestamps {
    /// Create a new buffer with the given capacity (typically `max_retry`).
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            head: 0,
            len: 0,
        }
    }

    /// Push a timestamp, overwriting the oldest if full.
    pub fn push(&mut self, ts: i64) {
        let cap = self.buf.len();
        if cap == 0 {
            return;
        }
        let write_pos = if self.len < cap {
            self.len
        } else {
            let pos = self.head;
            self.head = (self.head + 1) % cap;
            pos
        };
        if let Some(slot) = self.buf.get_mut(write_pos) {
            *slot = ts;
        }
        if self.len < cap {
            self.len += 1;
        }
    }

    /// Returns `true` when the buffer has reached its capacity.
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }

    /// Returns the oldest timestamp, or `None` if empty.
    pub fn oldest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        self.buf.get(self.head).copied()
    }

    /// Returns the newest timestamp, or `None` if empty.
    pub fn newest(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let cap = self.buf.len();
        let idx = if self.len < cap {
            self.len - 1
        } else {
            (self.head + cap - 1) % cap
        };
        self.buf.get(idx).copied()
    }

    /// Check if the failure threshold is reached: buffer is full and the
    /// time span from oldest to newest is within `find_time` seconds.
    pub fn threshold_reached(&self, find_time: i64) -> bool {
        if !self.is_full() {
            return false;
        }
        match (self.oldest(), self.newest()) {
            (Some(old), Some(new)) => (new - old) < find_time,
            _ => false,
        }
    }

    /// Number of timestamps currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The total capacity.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}
