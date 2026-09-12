# binwatch-rs Operational Key Delegation & Mutual Cross-Attestation

This document establishes the verified cryptographic link between the primary testing root identity and the delegated `binwatch-bot` Nostr attestation publisher key.

If the bot key is rotated, compromised, or replaced in the future, a new child index (e.g. `m/83696968'/128002'/0'/2'`) can be issued and mutually cross-signed without invalidating previous root proofs.

---

## Cryptographic Identities

* **Parent Root Identity**: `npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7`
* **Bot Publisher Identity (Child Key 1)**: `npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm`
* **Derivation Standard**: BIP-85 Path `m/83696968'/128002'/0'/1'`
* **Signature Algorithm**: BIP-340 Schnorr over Tagged Hash (`pipe-k1/v1/sign`)
* **Timestamp**: `2026-09-08T23:15:40Z`

---

## Leg 1: Parent Identity Authorizes Bot Key

**Statement**:
```text
BINWATCH ATTESTATION: Parent identity npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 authorizes bot key npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm as official binwatch-rs Nostr attestation publisher under BIP-85 path m/83696968'/128002'/0'/1'.
```

**BIP-340 Schnorr Signature (Base64)**:
```text
UEtTRwFqoJce2z911dKP2J24ugG7bv5n0oavTn4R69s85RS4zrLBDnK980hFv9ArDDEun+dtcpjawytwGWqoaosDOvxaFfvzL4M4OdBrdnCuQ38RSUekXQSj4wLxivOMBOLAZO64mleZ
```

---

## Leg 2: Bot Key Acknowledges Parent Identity

**Statement**:
```text
BINWATCH ATTESTATION: Bot key npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm acknowledges derivation from parent identity npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 and serves as delegated Nostr publisher for binwatch-rs.
```

**BIP-340 Schnorr Signature (Base64)**:
```text
UEtTRwFqoJceco/uVwkBV/JLJnTY2QmPtevbp9RWe3Y7/xbiIIZo3pjvrjRuySrOlJ+qpjXnMaHh2lLLpBS/qs189LRPHTnzGm5T1R8RzVbNc7IF3tfSDisubTCfHdIxGqF9M2j/cFyk
```

---

## Independent Verification Commands

```bash
# Verify Parent -> Bot Authorization:
echo -n "BINWATCH ATTESTATION: Parent identity npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 authorizes bot key npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm as official binwatch-rs Nostr attestation publisher under BIP-85 path m/83696968'/128002'/0'/1'." | \
  pipe-k1 verify --sig <(echo "UEtTRwFqoJce2z911dKP2J24ugG7bv5n0oavTn4R69s85RS4zrLBDnK980hFv9ArDDEun+dtcpjawytwGWqoaosDOvxaFfvzL4M4OdBrdnCuQ38RSUekXQSj4wLxivOMBOLAZO64mleZ" | base64 -d) \
  --pub "npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7"

# Verify Bot -> Parent Acknowledgment:
echo -n "BINWATCH ATTESTATION: Bot key npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm acknowledges derivation from parent identity npub1mvlht4wj3lvfmw96qxakaln862r27nn7z84ak089zjuvavkppeeq79a4j7 and serves as delegated Nostr publisher for binwatch-rs." | \
  pipe-k1 verify --sig <(echo "UEtTRwFqoJceco/uVwkBV/JLJnTY2QmPtevbp9RWe3Y7/xbiIIZo3pjvrjRuySrOlJ+qpjXnMaHh2lLLpBS/qs189LRPHTnzGm5T1R8RzVbNc7IF3tfSDisubTCfHdIxGqF9M2j/cFyk" | base64 -d) \
  --pub "npub1w287u4cfq9tlyjexwnvdjzv0kh4ahf752eahvwllzm3zppngm6vqsme6cm"
```
