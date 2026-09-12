#!/usr/bin/env python3
"""
DiffWatch BinWatch Sentinel:
Scans the latest commit diffs across our 16 BinWatch sovereign targets
in passive shadow mode, asserting against the 10 Sovereign Bitcoin & Cryptographic Diff Smells.
"""

import urllib.request
import json
import re
import sys
import os
import subprocess
import time

BINWATCH_TARGETS = [
    ("bitcoin", "bitcoin", "cpp"),
    ("lightningnetwork", "lnd", "go"),
    ("ElementsProject", "lightning", "c"),
    ("getAlby", "hub", "go"),
    ("ElementsProject", "elements", "cpp"),
    ("sparrowwallet", "sparrow", "java"),
    ("selfcustody", "krux", "python"),
    ("BitHyve", "hexa", "typescript"),
    # Core Cryptographic Primitives & SubZero Dependencies
    ("bitcoin-core", "secp256k1", "c"),
    ("rust-bitcoin", "rust-bitcoin", "rust"),
    ("bitcoindevkit", "bdk", "rust"),
    # SubZero Node.js Audited Primitives (@paulmillr / Cure53)
    ("paulmillr", "noble-curves", "typescript"),
    ("paulmillr", "noble-hashes", "typescript"),
    ("paulmillr", "scure-bip39", "typescript"),
    ("paulmillr", "scure-bip32", "typescript"),
    ("paulmillr", "scure-btc-signer", "typescript"),
    ("paulmillr", "noble-secp256k1", "typescript"),
    # Pipek1 Pure-Rust Cryptographic Foundations (RustCrypto)
    ("RustCrypto", "elliptic-curves", "rust"),
    ("RustCrypto", "AEADs", "rust"),
    # New Sovereign Hardware & Mobile Wallets
    ("proto-at-block", "bitkey", "rust"),
    ("ACINQ", "phoenix", "kotlin"),
    ("cake-tech", "cake_wallet", "dart"),
    # Hardened Sovereign Mobile OS & Attestation (GrapheneOS)
    ("GrapheneOS", "hardened_malloc", "c"),
    ("GrapheneOS", "Auditor", "kotlin"),
    # Core Infrastructure Bedrock (OpenSSH)
    ("openssh", "openssh-portable", "c"),
]

# Ensure authenticated token
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    try:
        GITHUB_TOKEN = subprocess.check_output(["gh", "auth", "token"]).decode().strip()
    except Exception:
        GITHUB_TOKEN = None

HEADERS = {
    "User-Agent": "DiffWatch-Sentinel/1.0",
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

SOVEREIGN_RULES = {
    "CRYPTO.PROOF_CACHE_KEY_COLLISION_REUSE": [
        r'ProofCache', r'rangeproof', r'surjection', r'cache_key', r'proof_cache'
    ],
    "HW.TRNG_SILENT_FALLBACK_PRNG": [
        r'yasmarang', r'trng', r'prng', r'urandom', r'rng_sample', r'entropy_source', r'hw_rng'
    ],
    "BOUNDARY.EMPTY_ZERO_LENIENCY": [
        r'==\s*["\']["\']', r'len\([^\)]+\)\s*==\s*0', r'password\s*==\s*""', r'token\s*==\s*""'
    ],
    "HW.CHANGE_DESCRIPTOR_DESYNC": [
        r'is_change', r'change_path', r'internal_key', r'master_fingerprint', r'bip32_deriv'
    ],
    "LIGHTNING.DUST_HTLC_TRIMMING_EXPOSURE": [
        r'dust_limit', r'dustLimit', r'trim_htlc', r'fee_rate', r'commit_fee'
    ],
    "LIGHTNING.REPLACEMENT_CYCLING_RACE": [
        r'preimage', r'bumpfee', r'anchor', r'rbf', r'sweep'
    ],
    "CONSENSUS.POLICY_VS_CONSENSUS_DRIFT": [
        r'CheckInputs', r'StandardScript', r'IsStandardTx', r'consensus', r'policy'
    ],
    "NWC.BUDGET_ALLOWANCE_RACE": [
        r'pay_invoice', r'budget', r'allowance', r'max_amount'
    ]
}

def fetch_json(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return None

def fetch_diff(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def scan_diff(diff_text):
    hits = []
    for smell, patterns in SOVEREIGN_RULES.items():
        for p in patterns:
            if re.search(p, diff_text, re.IGNORECASE):
                hits.append(smell)
                break
    return list(set(hits))

def main():
    print("=== DiffWatch Sovereign Sentinel: Passive Shadow Mode Scan ===")
    print(f"Scanning {len(BINWATCH_TARGETS)} BinWatch targets across latest commit diffs...\n")
    
    out_dir = "/home/petjal/.gemini/antigravity-cli/brain/40aabdd4-a023-40ae-bff7-8814c083daf6/scratch"
    os.makedirs(out_dir, exist_ok=True)
    report_file = os.path.join(out_dir, "binwatch_diffwatch_scan_report.json")
    
    scan_results = []
    
    for owner, repo, lang in BINWATCH_TARGETS:
        print(f"[*] Checking {owner}/{repo} ({lang})...")
        commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=3"
        commits = fetch_json(commits_url)
        if not commits or not isinstance(commits, list):
            print(f"    [-] Failed to fetch commits for {owner}/{repo}")
            continue
            
        for c in commits:
            sha = c["sha"]
            msg = c["commit"]["message"].splitlines()[0]
            diff_url = f"https://github.com/{owner}/{repo}/commit/{sha}.diff"
            diff_text = fetch_diff(diff_url)
            
            if not diff_text:
                continue
                
            hits = scan_diff(diff_text)
            scan_results.append({
                "repo": f"{owner}/{repo}",
                "sha": sha[:8],
                "message": msg[:60],
                "diff_lines": len(diff_text.splitlines()),
                "matched_smells": hits,
                "verdict": "FLAGGED_FOR_INSPECTION" if hits else "CLEAN_PASS"
            })
            
            status_str = f"FLAGGED: {', '.join(hits)}" if hits else "PASS"
            print(f"    - [{sha[:8]}] {msg[:45]:<45} | {status_str}")
            time.sleep(0.3)
            
    with open(report_file, "w") as f:
        json.dump(scan_results, f, indent=2)
        
    print(f"\n[+] Scan Complete. Detailed report written to: {report_file}")

if __name__ == "__main__":
    main()
