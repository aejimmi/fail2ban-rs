//! A firewall ban identifies a single host or an IPv6 /64.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use etchdb::EtchKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Target of a ban. IPv6 prefixes store only the upper 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BanTarget {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    V6Prefix(u64),
}

impl BanTarget {
    /// Return the enclosing /64 for an IPv6 host.
    pub fn ipv6_prefix(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() => {
                Some(Self::V6Prefix((ip.to_bits() >> 64) as u64))
            }
            _ => None,
        }
    }

    /// Return the host address or the base address of the network.
    pub fn addr(self) -> IpAddr {
        match self {
            Self::V4(ip) => ip.into(),
            Self::V6(ip) => ip.into(),
            Self::V6Prefix(prefix) => Ipv6Addr::from_bits(u128::from(prefix) << 64).into(),
        }
    }

    pub fn is_ipv6(self) -> bool {
        !matches!(self, Self::V4(_))
    }

    pub fn is_prefix(self) -> bool {
        matches!(self, Self::V6Prefix(_))
    }
}

impl From<IpAddr> for BanTarget {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => Self::V6(ip),
        }
    }
}

impl fmt::Display for BanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr().fmt(f)?;
        if self.is_prefix() {
            f.write_str("/64")?;
        }
        Ok(())
    }
}

impl FromStr for BanTarget {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(host) = value.strip_suffix("/64")
            && let Ok(ip) = host.parse()
            && let Some(prefix) = Self::ipv6_prefix(ip)
        {
            return Ok(prefix);
        }
        value
            .parse::<IpAddr>()
            .map(Self::from)
            .map_err(|_| "expected an IP address or an IPv6 /64")
    }
}

// MessagePack used by the WAL encodes these variants by name. Keep the two
// host variants identical to serde's non-human-readable IpAddr encoding.
#[derive(Serialize, Deserialize)]
#[serde(remote = "BanTarget")]
enum StoredTarget {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    V6Prefix(u64),
}

impl Serialize for BanTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            StoredTarget::serialize(self, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BanTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)?
                .parse()
                .map_err(serde::de::Error::custom)
        } else {
            StoredTarget::deserialize(deserializer)
        }
    }
}

impl EtchKey for BanTarget {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::V6Prefix(prefix) => {
                let mut key = vec![64];
                key.extend(prefix.to_be_bytes());
                key
            }
            _ => self.addr().to_bytes(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> etchdb::Result<Self> {
        if let Some((&64, prefix)) = bytes.split_first()
            && let Ok(octets) = prefix.try_into()
        {
            return Ok(Self::V6Prefix(u64::from_be_bytes(octets)));
        }
        IpAddr::from_bytes(bytes).map(Self::from)
    }
}
