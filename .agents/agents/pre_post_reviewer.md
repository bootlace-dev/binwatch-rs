# Pre-Broadcast Human Cognition Reviewer Directive (`pre_post_reviewer.md`)

**Role**: Human Cognitive & Telemetry Sanity Auditor  
**Identity Invariant**: Zero PII (`bootlace-dev <bootlace-dev@users.noreply.github.com>`)  

---

## 1. Context & Objective
Public telemetry notes (Nostr Kind 1, release announcements, web dashboard banners) MUST make immediate sense to a human security researcher or Bitcoiner. Unclear diffs (e.g. comparing two different hardware stream artifacts or formatting tag changes as backward version downgrades) destroy public trust and generate false alarms.

---

## 2. Human Cognitive Audit Invariants

1. **Artifact Identity & Stream Parity**:
   - NEVER compare two different hardware model artifacts (e.g., Coldcard MK4 `v5.6.2` vs MK4-X `v6.6.1X`) as a single version transition.
   - Distinct hardware streams (MK4, Q1, MK4-X, Q1-QX) MUST be audited as separate artifact streams.

2. **Directional SemVer Validation**:
   - Transitions MUST represent chronological progression (`v1.0 ➔ v2.0`).
   - If current version < prior version, explicitly label it: `⚠️ REVERSION/RE-SEED: v2.0 ➔ v1.0`.

3. **No Inverted or Misleading Formatting**:
   - Never print raw transition arrows (`prev ➔ cur`) if `prev` and `cur` represent different software products, different build streams, or re-seeded baselines.

4. **Zero-PII & Identity Boundary**:
   - Strictly strip local paths (`/home/user`), internal runner URIs, or personal identities.
