# binwatch-rs: Deterministic Bitcoin Binary Integrity Auditor

A sovereign, daemon-less replacement for legacy centralized binary monitoring services.

Instead of flooding Nostr or Twitter timelines with dozens of noisy, repetitive status messages every hour, `binwatch` summarizes full matrix integrity into a single **Deterministic 6-Character Merkle Hex Seal** (e.g. `#514DC2`).

```text
🛡️ BINWATCH AUDIT REPORT: #514DC2 | BTC Block: 965215
UTC Timestamp: 2026-09-08T18:30:00Z
Merkle Seal: #514DC2

  • ✅ bitcoin_core (v29.4) - 1 artifacts
  • ✅ pipek1 (v0.0.1-rc0) - 1 artifacts
  • ✅ subzero-rs (v0.3.0) - 1 artifacts

Total Verified: 3/3 OK

Canonical Merkle Root:
514dc23636e9bdcdd57aebe6d81a76b4427ac64f257381087468d706fcc63369
```

---

## The Problem with BinaryWatch 1.0
1. **Centralized Crawler**: Runs on a single corporate server cron; when maintainer infrastructure freezes, the entire Bitcoin ecosystem loses binary integrity visibility.
2. **Timeline Pollution**: Floods Nostr and Twitter with individual posts for every single operating system archive checked, creating spam fatigue.
3. **Legacy GnuPG Dependencies**: Relies on fragile keyserver web-of-trust and background daemons.

---

## Live Verification Endpoints & Dashboards
* **Public Web Dashboard**: https://bootlace-dev.github.io/binwatch-rs/
* **Raw Audit Manifest (JSON)**: https://bootlace-dev.github.io/binwatch-rs/manifest.json
* **Compressed Audit Manifest (GZIP)**: https://bootlace-dev.github.io/binwatch-rs/manifest.json.gz
* **Nostr Kind 1 Plaintext Digest**: https://bootlace-dev.github.io/binwatch-rs/digest.txt
* **GitHub Actions Continuous Audit Log**: https://github.com/bootlace-dev/binwatch-rs/actions/workflows/audit.yml
* **Nostr Attestation Bot Identity**: `npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm`
* **Cryptographic Delegation Proof**: [ATTESTATION.md](https://github.com/bootlace-dev/binwatch-rs/blob/master/ATTESTATION.md) (Mutual BIP-340 cross-signing with parent identity)

---

## The `binwatch-rs` Architecture
* **BIP-340 & PGP Verification**: Verifies release signatures using `pipek1` (Schnorr) and standalone detached PGP signatures without background daemons.
* **Canonical Merkle Root**: Hashes the full state of all monitored binaries into a single SHA-256 root.
* **6-Character Visual Hex Seal**: The first 6 hex characters of the Merkle root act as an immutable visual anchor. If even 1 bit of 1 binary or signature changes upstream, the hex seal immediately changes.
* **Zero Infrastructure Cost**: Runs deterministically via GitHub Actions and publishes live static dashboards to GitHub Pages.

---

## Quickstart

```bash
# Build binwatch:
cargo build --release

# Run self-contained verification demo:
./target/release/binwatch demo

# Generate 6-char Merkle seal from manifest:
./target/release/binwatch seal manifest.json

# Format clean Nostr digest:
./target/release/binwatch digest manifest.json
```

---

## License
MIT (c) 2026 bootlace-dev
