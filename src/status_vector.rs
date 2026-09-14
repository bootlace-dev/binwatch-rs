// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev
//! binwatch: Status Vector Module for 12-Stage Supply-Chain Verification

use serde::{Deserialize, Serialize};
use std::fmt;

/// 12-Stage Pipeline Verification Flags (Bitmask)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    DnsResolution      = 1 << 0,  // 'D' - 0x001
    TlsHandshake       = 1 << 1,  // 'T' - 0x002
    HttpTransport      = 1 << 2,  // 'H' - 0x004
    SchemaValidation   = 1 << 3,  // 'S' - 0x008
    PgpSignatureParse  = 1 << 4,  // 'M' - 0x010 (Manifest/Sig parsing)
    KeyMatch           = 1 << 5,  // 'K' - 0x020
    KeyExpiration      = 1 << 6,  // 'E' - 0x040
    KeyRevocation      = 1 << 7,  // 'X' - 0x080 (Cross-check CRL/Revocation)
    HashMatch          = 1 << 8,  // 'H' - 0x100
    FreshnessTtl       = 1 << 9,  // 'R' - 0x200 (Recent / Non-stale TTL)
    ReproducibleFetch  = 1 << 10, // 'P' - 0x400 (Peer/Mirror fetch repro)
    ChainAnchor        = 1 << 11, // 'A' - 0x800 (Anchor to BTC block)
}

const STAGE_CHARS: [char; 12] = ['D', 'T', 'H', 'S', 'M', 'K', 'E', 'X', 'B', 'R', 'P', 'A'];


/// Granular Pipeline Status Vector Wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStatusVector {
    pub mask: u16,
    pub warn_mask: u16,
}

impl PipelineStatusVector {
    pub const ALL_PASS: u16 = 0x0FFF;

    pub fn new(mask: u16, warn_mask: u16) -> Self {
        Self {
            mask: mask & Self::ALL_PASS,
            warn_mask: warn_mask & Self::ALL_PASS,
        }
    }

    pub fn full_pass() -> Self {
        Self {
            mask: Self::ALL_PASS,
            warn_mask: 0x0000,
        }
    }

    pub fn to_ribbon(&self) -> String {
        let mut ribbon = String::with_capacity(14);
        for i in 0..12 {
            if i > 0 && i % 4 == 0 {
                ribbon.push('-');
            }
            let stage_bit = 1 << i;
            if (self.warn_mask & stage_bit) != 0 {
                ribbon.push('!');
            } else if (self.mask & stage_bit) != 0 {
                ribbon.push(STAGE_CHARS[i]);
            } else {
                ribbon.push('0');
            }
        }
        ribbon
    }

    pub fn to_hex(&self) -> String {
        format!("{:03X}", self.mask)
    }

    pub fn is_fully_verified(&self) -> bool {
        self.mask == Self::ALL_PASS && self.warn_mask == 0
    }
}

impl fmt::Display for PipelineStatusVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{})", self.to_ribbon(), self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_vector_ribbon() {
        let mut v = PipelineStatusVector::full_pass();
        assert_eq!(v.to_ribbon(), "DTHS-MKEX-BRPA");
        assert_eq!(v.to_hex(), "FFF");

        // Simulate Key Expiration warning (Stage 6)
        v.warn_mask |= PipelineStage::KeyExpiration as u16;
        assert_eq!(v.to_ribbon(), "DTHS-MK!X-BRPA");
        assert_eq!(v.to_hex(), "FFF");
        assert!(!v.is_fully_verified());

        // Simulate Hash Drift failure (Stage 8)
        v.mask &= !(PipelineStage::HashMatch as u16);
        assert_eq!(v.to_ribbon(), "DTHS-MK!X-0RPA");
        assert_eq!(v.to_hex(), "EFF");
    }
}
