# BinWatch Merkle Seal Mutation & Lineage Changelog

This document tracks the explicit architectural mutations, schema updates, upstream release discoveries, and cryptographic provenance changes that necessitated recalculation of the canonical Merkle root seal (`#HEXSEAL`) across historical evaluation epochs.

---

### **Merkle Seal Lineage & Mutation Audit Trail**

#### **1. Merkle Seal `#989299` (2026-09-16T00:42:39Z | BTC Block `#967206`)**
- **Cause**: Live Matrix Recalculation, API Rate-Limiting Hardening & Multi-Artifact Determinism Verification.
- **Mutations**: Re-ran full live audit matrix (`audit_matrix.sh`) across all 27 sovereign targets. Hardened `check_advisories.py` error handling to prevent false-positive clean passes on rate-limiting. Added multi-artifact leaf sorting tests.

#### **2. Merkle Seal `#222E65` (2026-09-15T17:57:53Z | BTC Block `#967173`)**
- **Cause**: Upstream GPG Key Expiration Sentinel Alert (`bitcoin_keeper` v2.5.13 broadcast).
- **Mutations**: Broadcast Nostr Kind 1 supply-chain mutation alert (`🟡 SUPPLY CHAIN MUTATION DETECTED`) for expired upstream GPG key (`2026-08-06`) on `bitcoin_keeper` (`#e0dcf2`). Transitioned artifact `sig_status` from `OK` to `EXPIRED`.

#### **3. Merkle Seal `#C40EB0` (2026-09-15T09:59:00Z | BTC Block `#967128`)**
- **Cause**: Nostr Telemetry Cadence & Status Vector Alignment.
- **Mutations**: Configured `NOSTR_BOT_NSEC` broadcast pipeline and 24-hour heartbeat state tracking in `scripts/nostr_broadcast.py`. Embedded 8-stage Detex status vectors (`[S1-S8]`) across all 27 audited project entries in `manifest.json`.

#### **4. Merkle Seal `#15EC8A` (2026-09-13T20:57:12Z | BTC Block `#966893`)**
- **Cause**: WalletScrutiny Build Attestation & Nostr Kind 30078 Ingestion.
- **Mutations**: Integrated WalletScrutiny reproducible build status vectors and parsed Nostr build attestations (`Kind 1` / `Kind 30078`). Updated `walletscrutiny.rs` module and matrix bindings.

#### **5. Merkle Seal `#68B733` (2026-09-13T01:15:55Z | BTC Block `#966747`)**
- **Cause**: Full Matrix Pipeline Expansion & Initial GPG Expiration Discovery (`bitcoin_keeper`).
- **Mutations**: Added `alby_hub` (v1.24.0), `pipe-k1` (v0.0.1-rc0), `noble-curves` (2.4.0), `scure-btc-signer` (2.4.1), and `subzero-rs` (v0.4.0-testnet4). Discovered expired `bitcoin_keeper` key (`2026-08-06`). Added OSV.dev vulnerability baseline queries (`check_advisories.py`).

#### **6. Merkle Seal `#D9A2F1` (2026-09-12T21:16:00Z | BTC Block `#966720`)**
- **Cause**: Composite Origin Keying (`project_id:origin`) Schema Migration.
- **Mutations**: Refactored `manifest.json` schema from plain `project_id` map keys to composite `project_id:origin` keys (e.g. `bitcoin_core:upstream_download`, `krux:github_release`) to prevent key collisions across distribution channels.

#### **7. Merkle Seal `#4F8E12` (2026-09-12T20:26:00Z | BTC Block `#966715`)**
- **Cause**: Integration of DiffWatch Upstream Zero-Day Sentinel.
- **Mutations**: Added `upstream_watcher.py` zero-day tag watcher and static diff vulnerability smell scanner (`diffwatch_sentinel.py`) to auto-detect upstream tag increments.

#### **8. Merkle Seal `#8A3D09` (2026-09-11T21:45:00Z | BTC Block `#966580`)**
- **Cause**: BIP-340 Schnorr Signature Verification (`pipe-k1`).
- **Mutations**: Added native BIP-340 Schnorr signature validation support for binary checksum manifests (`SHA256SUMS.pk1`) alongside traditional GPG OpenPGP signatures.

#### **9. Merkle Seal `#E311B4` (2026-09-10T22:29:00Z | BTC Block `#966440`)**
- **Cause**: Architectural Scope Lock & Governance Decision (ADR-001).
- **Mutations**: Formally locked scope to deterministic binary integrity verification (`DECISIONS.md`). Excluded probabilistic LLM code scanning in favor of zero-maintenance deterministic attestation.

#### **10. Merkle Seal `#0A91F5` (2026-09-08T18:24:00Z | BTC Block `#966130`)**
- **Cause**: Initial Rust Engine Release (`v0.0.1-rc0`).
- **Mutations**: Initialized `binwatch-rs` codebase, `ManifestAudit` Merkle tree calculation engine, and GitHub Pages template renderer.
