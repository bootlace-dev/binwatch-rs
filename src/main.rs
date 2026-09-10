// SPDX-License-Identifier: MIT
// Copyright (c) 2026 bootlace-dev
//! binwatch: Deterministic Bitcoin Binary Integrity Auditor & Merkle Digest Engine
//! Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryArtifact {
    pub name: String,
    pub expected_sha256: String,
    pub observed_sha256: Option<String>,
    pub sig_status: String, // "OK", "FAIL", "UNVERIFIED"
    pub verified_by: String, // "pipek1:bip340", "gpg:rsa4096", "gpg:ed25519"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectHistory {
    pub first_seen_utc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_block: Option<u64>,
    pub days_stable: u64,
    pub consecutive_epochs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_release_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_primary_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_changed_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryBaseline {
    pub last_known_vulnerable_version: String,
    pub fixed_in_version: String,
    pub advisory_id: String,
    pub summary: String,
    pub status: String, // "CLEAN_BEYOND_THRESHOLD", "VULNERABLE"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectAudit {
    pub project_id: String,
    pub release_tag: String,
    pub upstream_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<ProjectHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_baseline: Option<AdvisoryBaseline>,
    pub artifacts: Vec<BinaryArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAudit {
    pub timestamp_utc: String,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub merkle_root_sha256: String,
    pub hex_seal: String, // First 6 characters of merkle_root_sha256
    pub projects: BTreeMap<String, ProjectAudit>,
}

impl ManifestAudit {
    pub fn new(timestamp_utc: String, block_height: Option<u64>, block_hash: Option<String>) -> Self {
        Self {
            timestamp_utc,
            block_height,
            block_hash,
            merkle_root_sha256: String::new(),
            hex_seal: String::new(),
            projects: BTreeMap::new(),
        }
    }

    /// Computes deterministic Merkle root over all project artifacts sorted canonically
    pub fn finalize_seal(&mut self) {
        let mut hasher = Sha256::new();

        // Feed block height if available
        if let Some(height) = self.block_height {
            hasher.update(height.to_be_bytes());
        }

        // Canonical BTreeMap iteration guarantees exact byte-for-byte reproducibility
        for (project_id, project) in &self.projects {
            hasher.update(project_id.as_bytes());
            hasher.update(project.release_tag.as_bytes());
            for art in &project.artifacts {
                hasher.update(art.name.as_bytes());
                hasher.update(art.expected_sha256.as_bytes());
                if let Some(ref obs) = art.observed_sha256 {
                    hasher.update(obs.as_bytes());
                }
                hasher.update(art.sig_status.as_bytes());
                hasher.update(art.verified_by.as_bytes());
            }
        }

        let root = hasher.finalize();
        let full_hex = hex::encode(root);
        self.hex_seal = full_hex[..6].to_uppercase();
        self.merkle_root_sha256 = full_hex;
    }

    /// Formats a single crisp, chatty-proof Nostr Kind 1 digest note
    pub fn to_nostr_digest(&self) -> String {
        let mut out = String::new();
        let height_str = self
            .block_height
            .map(|h| format!(" | BTC Block: {}", h))
            .unwrap_or_default();

        out.push_str(&format!(
            "🛡️ BINWATCH AUDIT REPORT: #{}{}\n",
            self.hex_seal, height_str
        ));
        out.push_str(&format!("UTC Timestamp: {}\n", self.timestamp_utc));
        out.push_str(&format!("Merkle Seal: #{}\n\n", self.hex_seal));

        let mut total_artifacts = 0;
        let mut passed_artifacts = 0;
        let mut expired_keys = 0;
        let mut bad_sigs = 0;
        let mut hash_drifts = 0;
        let mut missing_artifacts = 0;
        let mut vulnerable_artifacts = 0;

        let mut failed_entries = Vec::new();
        let mut passed_entries = Vec::new();

        for (project_id, project) in &self.projects {
            let mut worst_status = "OK";
            let mut failure_detail = None;

            for a in &project.artifacts {
                total_artifacts += 1;
                match a.sig_status.as_str() {
                    "OK" => {
                        passed_artifacts += 1;
                    }
                    "VULNERABLE" => {
                        vulnerable_artifacts += 1;
                        worst_status = "VULNERABLE";
                        failure_detail = a.audit_note.clone();
                    }
                    "EXPIRED" => {
                        expired_keys += 1;
                        if worst_status == "OK" {
                            worst_status = "EXPIRED";
                            failure_detail = a.audit_note.clone();
                        }
                    }
                    "HASH_DRIFT" => {
                        hash_drifts += 1;
                        if worst_status != "VULNERABLE" {
                            worst_status = "HASH_DRIFT";
                            failure_detail = a.audit_note.clone();
                        }
                    }
                    "MISSING" => {
                        missing_artifacts += 1;
                        if worst_status != "VULNERABLE" && worst_status != "BADSIG" && worst_status != "HASH_DRIFT" {
                            worst_status = "MISSING";
                            failure_detail = a.audit_note.clone();
                        }
                    }
                    _ => {
                        bad_sigs += 1;
                        if worst_status != "VULNERABLE" {
                            worst_status = "BADSIG";
                            failure_detail = a.audit_note.clone();
                        }
                    }
                }
            }

            let badge = match worst_status {
                "OK" => "✅",
                "VULNERABLE" => "🚨 VULNERABLE:",
                "EXPIRED" => "❌ EXPIRED:",
                "HASH_DRIFT" => "❌ HASH_DRIFT:",
                "MISSING" => "❌ MISSING:",
                _ => "❌ BADSIG:",
            };

            let primary_hex = project
                .artifacts
                .first()
                .map(|a| {
                    let h = if a.expected_sha256.len() >= 6 {
                        &a.expected_sha256[..6]
                    } else {
                        &a.expected_sha256
                    };
                    h.to_string()
                })
                .unwrap_or_default();

            let entry_str = if let Some(detail) = failure_detail {
                format!(
                    "{} {} ({}) [{}] - {}\n",
                    badge, project_id, project.release_tag, primary_hex, detail
                )
            } else {
                format!(
                    "{} {} ({}) [{}] - {} artifact(s)\n",
                    badge,
                    project_id,
                    project.release_tag,
                    primary_hex,
                    project.artifacts.len()
                )
            };

            if worst_status == "OK" {
                passed_entries.push(entry_str);
            } else {
                failed_entries.push(entry_str);
            }
        }

        // Output fails at the top, then a separating blank line, then passes
        for entry in &failed_entries {
            out.push_str(entry);
        }
        if !failed_entries.is_empty() && !passed_entries.is_empty() {
            out.push('\n');
        }
        for entry in &passed_entries {
            out.push_str(entry);
        }

        let total_alerts = vulnerable_artifacts + expired_keys + bad_sigs + hash_drifts + missing_artifacts;
        out.push_str(&format!(
            "\nTotal Verified: {}/{} OK",
            passed_artifacts, total_artifacts
        ));
        if total_alerts > 0 {
            let mut alert_parts = Vec::new();
            if vulnerable_artifacts > 0 {
                alert_parts.push(format!("🚨 {} Known Vulnerability", vulnerable_artifacts));
            }
            if expired_keys > 0 {
                alert_parts.push(format!("❌ {} Expired Key", expired_keys));
            }
            if bad_sigs > 0 {
                alert_parts.push(format!("❌ {} Bad Signature", bad_sigs));
            }
            if hash_drifts > 0 {
                alert_parts.push(format!("❌ {} Hash Drift", hash_drifts));
            }
            if missing_artifacts > 0 {
                alert_parts.push(format!("❌ {} Missing Artifact", missing_artifacts));
            }
            out.push_str(&format!(" | {}", alert_parts.join(", ")));
        }

        let mut advisory_tracked = 0;
        let mut clean_threshold = 0;
        for (_, project) in &self.projects {
            if let Some(ref base) = project.advisory_baseline {
                advisory_tracked += 1;
                if base.status == "CLEAN_BEYOND_THRESHOLD" {
                    clean_threshold += 1;
                }
            }
        }
        if advisory_tracked > 0 {
            out.push_str(&format!(
                "\nAdvisory Baseline: {}/{} releases clean beyond last known CVE threshold",
                clean_threshold, advisory_tracked
            ));
        }

        out.push_str("\n\nCanonical Merkle Root:\n");
        out.push_str(&format!("{}\n", self.merkle_root_sha256));

        out.push_str("\nLive Web Dashboard:\nhttps://bootlace-dev.github.io/binwatch-rs/\n");
        out.push_str("\nRaw Cryptographic Manifest:\nhttps://bootlace-dev.github.io/binwatch-rs/manifest.json\n");
        out.push_str("\nSource & Audit Logs:\nhttps://github.com/bootlace-dev/binwatch-rs\n");
        out.push_str("\n#binwatch #bitcoin #supplychain\n");

        out
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("binwatch-rs v0.0.1-rc0 - Deterministic Bitcoin Binary Integrity Auditor");
        eprintln!("Usage:");
        eprintln!("  binwatch digest <manifest.json>           # Print Nostr text digest");
        eprintln!("  binwatch seal <manifest.json>             # Compute and print 6-char Merkle seal");
        eprintln!("  binwatch demo                             # Run self-contained verification demo");
        std::process::exit(2);
    }

    match args[1].as_str() {
        "digest" => {
            if args.len() < 3 {
                eprintln!("Error: Missing manifest.json argument");
                std::process::exit(2);
            }
            let mut file = File::open(&args[2])?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            let mut manifest: ManifestAudit = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            manifest.finalize_seal();
            print!("{}", manifest.to_nostr_digest());
        }
        "seal" => {
            if args.len() < 3 {
                eprintln!("Error: Missing manifest.json argument");
                std::process::exit(2);
            }
            let mut file = File::open(&args[2])?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            let mut manifest: ManifestAudit = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            manifest.finalize_seal();
            println!("#{}", manifest.hex_seal);
        }
        "finalize" => {
            if args.len() < 3 {
                eprintln!("Error: Missing manifest.json argument");
                std::process::exit(2);
            }
            let path = &args[2];
            let mut file = File::open(path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            let mut manifest: ManifestAudit = serde_json::from_str(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            manifest.finalize_seal();
            let updated_json = serde_json::to_string_pretty(&manifest)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            std::fs::write(path, updated_json)?;
            println!("Updated manifest with seal #{} (root: {})", manifest.hex_seal, manifest.merkle_root_sha256);
        }
        "demo" => {
            let mut manifest = ManifestAudit::new("2026-09-08T18:30:00Z".to_string(), Some(965215), None);

            // Project 1: pipek1
            manifest.projects.insert(
                "pipek1".to_string(),
                ProjectAudit {
                    project_id: "pipek1".to_string(),
                    release_tag: "v0.0.1-rc0".to_string(),
                    upstream_url: "https://github.com/bootlace-dev/pipek1".to_string(),
                    trust_anchor_url: Some("https://github.com/bootlace-dev/pipek1/blob/master/SPECIFICATION.md".to_string()),
                    manifest_url: Some("https://github.com/bootlace-dev/pipek1/releases/download/v0.0.1-rc0/SHA256SUMS".to_string()),
                    key_url: None,
                    history: None,
                    advisory_baseline: None,
                    artifacts: vec![BinaryArtifact {
                        name: "pipek1-x86_64-linux-musl".to_string(),
                        expected_sha256: "7a92cebc4f91fcc103f00731292a95f9f55a706ec9a1d170754a24a79522dd5d".to_string(),
                        observed_sha256: Some("7a92cebc4f91fcc103f00731292a95f9f55a706ec9a1d170754a24a79522dd5d".to_string()),
                        sig_status: "OK".to_string(),
                        verified_by: "pipek1:bip340(npub1mvlht...)".to_string(),
                        audit_note: None,
                    }],
                },
            );

            // Project 2: SubZero-rs
            manifest.projects.insert(
                "subzero-rs".to_string(),
                ProjectAudit {
                    project_id: "subzero-rs".to_string(),
                    release_tag: "v0.3.0".to_string(),
                    upstream_url: "https://github.com/bootlace-dev/subzero-keyosk".to_string(),
                    trust_anchor_url: Some("https://github.com/bootlace-dev/subzero-keyosk".to_string()),
                    manifest_url: None,
                    key_url: None,
                    history: None,
                    advisory_baseline: None,
                    artifacts: vec![BinaryArtifact {
                        name: "subzero-x86_64-musl".to_string(),
                        expected_sha256: "01b45846718de43b7bb9ef8898be6d725bf5609790bb9dcfb729f28ccfebed9c".to_string(),
                        observed_sha256: Some("01b45846718de43b7bb9ef8898be6d725bf5609790bb9dcfb729f28ccfebed9c".to_string()),
                        sig_status: "OK".to_string(),
                        verified_by: "sha256sums:signed".to_string(),
                        audit_note: None,
                    }],
                },
            );

            // Project 3: Bitcoin Core
            manifest.projects.insert(
                "bitcoin_core".to_string(),
                ProjectAudit {
                    project_id: "bitcoin_core".to_string(),
                    release_tag: "v29.4".to_string(),
                    upstream_url: "https://bitcoincore.org/bin".to_string(),
                    trust_anchor_url: Some("https://bitcoincore.org/en/download/".to_string()),
                    manifest_url: Some("https://bitcoincore.org/bin/bitcoin-core-29.4/SHA256SUMS.asc".to_string()),
                    key_url: None,
                    history: None,
                    advisory_baseline: None,
                    artifacts: vec![
                        BinaryArtifact {
                            name: "bitcoin-29.4-x86_64-linux-gnu.tar.gz".to_string(),
                            expected_sha256: "cf54c46ae95bf13d4e71cdc22d41a2caa1e4f9202551f297c3cc8141a1320689".to_string(),
                            observed_sha256: Some("cf54c46ae95bf13d4e71cdc22d41a2caa1e4f9202551f297c3cc8141a1320689".to_string()),
                            sig_status: "OK".to_string(),
                            verified_by: "gpg:guix_signers".to_string(),
                            audit_note: None,
                        },
                    ],
                },
            );

            manifest.finalize_seal();
            println!("{}", manifest.to_nostr_digest());

            // Also output JSON manifest to stdout
            let json_manifest = serde_json::to_string_pretty(&manifest).unwrap();
            let manifest_path = "/tmp/binwatch_demo_manifest.json";
            std::fs::write(manifest_path, json_manifest)?;
            eprintln!(">> Demo manifest written to: {}", manifest_path);
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            std::process::exit(2);
        }
    }

    Ok(())
}
