# BinWatch Architectural Decisions: Scope Lock & Strategic Doctrine

## ADR-001: Autonomous Cryptographic Sentinel vs. Dynamic Source Code Auditing

### Context
Following the deployment of Gate 1 (Cryptographic Manifest & Digital Signature Verification) and Gate 2 (Passive Upstream Advisory Mirror via OSV.dev), the project evaluated expanding into autonomous Large Language Model (LLM) source code, security, and vulnerability auditing across upstream repositories.

---

### Decision: Scope Locked at Deterministic Artifact Verification

BinWatch strictly limits its scope to **deterministic, stateless cryptographic attestation and passive third-party advisory mirroring**. The proposal to perform autonomous LLM-driven source code vulnerability scanning is rejected.

---

### Rationale

1. **Deterministic Verification over Probabilistic Inference:**
   - BinWatch's core value proposition is mathematical certainty: SHA-256 digest matching, cryptographic signature quorum verification, and Merkle root anchoring to Bitcoin block headers.
   - LLM source code auditing introduces probabilistic, non-deterministic outputs that cannot satisfy strict cryptographic verification or process repeatability standards.

2. **Legal Safe Harbor & Passive Conduit Integrity:**
   - Generating automated, subjective vulnerability claims against third-party open-source projects exposes the publisher to product disparagement and trade libel claims.
   - By acting strictly as a passive technical mirror of official upstream checksums and public database queries (OSV.dev / CVE), BinWatch maintains clear common-carrier safe harbor protections without making affirmative civil warranties.

3. **Zero-Maintenance Operational Autopilot:**
   - Deep source code auditing creates substantial triage overhead, maintainer friction, and false-positive noise.
   - Restricting BinWatch to deterministic release verification allows the engine to run fully autonomously on a scheduled cadence with zero ongoing human intervention, zero operational maintenance friction, and zero infrastructure hosting costs.

4. **Historical Continuity & Sovereign Focus:**
   - The primary objective of BinWatch is long-term binary stability tracking and supply-chain integrity attestation for the Bitcoin ecosystem.
   - The engine is complete as architected and will continue operating as a background cryptographic sentinel.

---

### Status
- **Accepted & Locked.**
- **Version:** `v0.0.1-rc0`
- **Identity:** `bootlace-dev <bootlace-dev@users.noreply.github.com>`
