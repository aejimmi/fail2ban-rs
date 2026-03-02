//! Etch-backed persistent ban state.
//!
//! Two collections: active bans keyed by (ip, jail), and per-IP ban counts
//! for ban time escalation.

use std::collections::HashMap;
use std::net::IpAddr;

use etchdb::{Replayable, Transactable};
use serde::{Deserialize, Serialize};

use crate::state::BanRecord;

/// Persistent ban state backed by etch WAL.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
pub struct BanState {
    #[etch(collection = 0)]
    pub bans: HashMap<(IpAddr, String), BanRecord>,
    #[etch(collection = 1)]
    pub ban_counts: HashMap<IpAddr, u32>,
}
