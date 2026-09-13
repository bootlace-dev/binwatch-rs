#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# Upstream Release Watcher & Zero-Day Tag Detector for BinWatch & DiffWatch
# Author / Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

# Ensure clean proxy inheritance
for k in ["all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"]:
    os.environ.pop(k, None)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
PROJECTS_JSON = os.path.join(REPO_DIR, "projects.json")
EVENTS_JSON = os.path.join(REPO_DIR, "data", "upstream_events.json")

# Import Sovereign Diff Rules from DiffWatch Sentinel
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
    ],
    "COINJOIN.COORDINATOR_FEE_MANIPULATION": [
        r'coordinator_fee', r'coordinatorFee', r'mining_fee_rate', r'plebs_dont_pay_fee', r'RoundConfig'
    ],
    "COINJOIN.UNBLINDED_INPUT_DEANON": [
        r'unblinded', r'credential_issuer', r'wabisabi', r'serial_number', r'blinding_factor', r'alice_client'
    ],
    "COINJOIN.TELEMETRY_OR_TRACKING_INJECTION": [
        r'telemetry', r'analytics', r'tracker', r'backend_url', r'coordinator_url', r'onion_fallback'
    ],
}

def semver_key(tag):
    clean = re.sub(r"^refs/tags/", "", tag).lstrip("vV")
    # Matches: major.minor[.patch][-extra]
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[.-](.*))?$", clean)
    if not m:
        return (-1, -1, -1, 0, "")
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    extra = m.group(4) or ""
    # Treat architecture-specific tags and prereleases as subordinate to base release
    is_subordinate = 1 if re.search(r'(arm|aarch|x86|beta|alpha|rc|pre)', extra, re.I) else 0
    is_stable = 1 - is_subordinate
    return (major, minor, patch, is_stable, extra)

def query_upstream_tags(git_url, allow_prerelease=False):
    """Query remote git tags via git ls-remote (zero API rate limits)."""
    try:
        cmd = ["git", "ls-remote", "--tags", "--refs", git_url]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if res.returncode != 0:
            return None
        tags = []
        for line in res.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                ref = parts[1].replace("refs/tags/", "")
                tags.append(ref)
        
        valid = [t for t in tags if semver_key(t)[0] != -1]
        if not allow_prerelease:
            stable = [t for t in valid if not re.search(r'(beta|alpha|rc|pre)', t, re.I)]
            if stable:
                valid = stable
                
        if not valid:
            return None
        valid.sort(key=semver_key)
        return valid[-1]
    except Exception as e:
        return None

def fetch_compare_diff(upstream_url, old_tag, new_tag):
    """Fetch raw compare diff from GitHub."""
    diff_url = f"{upstream_url.rstrip('/')}/compare/{old_tag}...{new_tag}.diff"
    headers = {"User-Agent": "BinWatch-UpstreamWatcher/1.0"}
    try:
        req = urllib.request.Request(diff_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def scan_diff_smells(diff_text):
    """Scan diff text against sovereign vulnerability smells."""
    hits = []
    if not diff_text:
        return hits
    for smell, patterns in SOVEREIGN_RULES.items():
        for p in patterns:
            if re.search(p, diff_text, re.IGNORECASE):
                hits.append(smell)
                break
    return sorted(list(set(hits)))

def main():
    parser = argparse.ArgumentParser(description="BinWatch Upstream Release Tag Watcher")
    parser.add_argument("--auto-bump", action="store_true", help="Auto-update projects.json with new tags")
    parser.add_argument("--project", type=str, help="Specific project_id to check")
    parser.add_argument("--prerelease", action="store_true", help="Allow pre-release / beta tags")
    parser.add_argument("--nostr-out", type=str, help="Output Nostr alert note to file")
    args = parser.parse_args()

    if not os.path.exists(PROJECTS_JSON):
        print(f"[-] Error: {PROJECTS_JSON} not found", file=sys.stderr)
        sys.exit(1)

    with open(PROJECTS_JSON, "r") as f:
        projects = json.load(f)

    os.makedirs(os.path.join(REPO_DIR, "data"), exist_ok=True)
    events = []
    if os.path.exists(EVENTS_JSON):
        try:
            with open(EVENTS_JSON, "r") as f:
                events = json.load(f)
        except Exception:
            events = []

    print(f"=== BinWatch Upstream Tag Watcher: Scanning {len(projects)} Projects ===")
    detected_bumps = []

    for p in projects:
        pid = p.get("project_id", "")
        if args.project and pid != args.project:
            continue

        curr_tag = p.get("release_tag", "")
        upstream_url = p.get("upstream_url", "")
        git_url = upstream_url.rstrip("/") + ".git"

        print(f"[*] Checking {pid} (pinned: {curr_tag})...", end=" ", flush=True)
        latest_tag = query_upstream_tags(git_url, allow_prerelease=args.prerelease)

        if not latest_tag:
            print("[UNAVAILABLE]")
            continue

        if latest_tag != curr_tag and semver_key(latest_tag) > semver_key(curr_tag):
            print(f"[INCREMENT DETECTED: {curr_tag} -> {latest_tag}]")
            
            # Fetch diff and run DiffWatch smell analysis
            print(f"    -> Fetching delta diff: {curr_tag}...{latest_tag}")
            diff_text = fetch_compare_diff(upstream_url, curr_tag, latest_tag)
            diff_bytes = len(diff_text.encode("utf-8")) if diff_text else 0
            smells = scan_diff_smells(diff_text)
            
            event = {
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "project_id": pid,
                "upstream_url": upstream_url,
                "previous_tag": curr_tag,
                "detected_tag": latest_tag,
                "diff_bytes": diff_bytes,
                "detected_smells": smells,
                "status": "UNATTESTED_NEW_RELEASE"
            }
            events.append(event)
            detected_bumps.append((p, curr_tag, latest_tag, smells))
            
            if smells:
                print(f"    [!] DiffWatch Smells Detected ({len(smells)}): {', '.join(smells)}")
            else:
                print("    [+] Zero Sovereign Diff Smells Detected (Clean Delta)")
                
            if args.auto_bump:
                p["release_tag"] = latest_tag
                # Adjust manifest URL if it has the tag embedded
                if "manifest_url" in p and curr_tag in p["manifest_url"]:
                    p["manifest_url"] = p["manifest_url"].replace(curr_tag, latest_tag)
                if "signature_url" in p and curr_tag in p["signature_url"]:
                    p["signature_url"] = p["signature_url"].replace(curr_tag, latest_tag)
                print(f"    [+] BUMPED {pid} in projects.json to {latest_tag}")
        else:
            print(f"[STABLE: {curr_tag}]")

    with open(EVENTS_JSON, "w") as f:
        json.dump(events, f, indent=2)

    if args.auto_bump and detected_bumps:
        with open(PROJECTS_JSON, "w") as f:
            json.dump(projects, f, indent=2)
        print(f"\n[+] Updated {PROJECTS_JSON} with {len(detected_bumps)} new release tags.")

    if detected_bumps and args.nostr_out:
        lines = [
            "⚡ BINWATCH ZERO-DAY RELEASE ALERT ⚡\n",
            f"Autonomous upstream watcher detected {len(detected_bumps)} new release tag(s):\n"
        ]
        for p, old, new, smells in detected_bumps:
            pid = p["project_id"]
            url = p["upstream_url"]
            lines.append(f"• {pid}: {old} ➔ {new}")
            lines.append(f"  Source: {url}/releases/tag/{new}")
            if smells:
                lines.append(f"  DiffWatch Smells: {', '.join(smells)}")
            else:
                lines.append("  DiffWatch: Clean delta across sovereign smell rules")
            lines.append("")
        lines.append("Attestation manifest updating on: https://bootlace-dev.github.io/binwatch-rs/")
        
        with open(args.nostr_out, "w") as nf:
            nf.write("\n".join(lines))
        print(f"[+] Wrote Nostr alert payload to {args.nostr_out}")

    print(f"\nScan complete. Total increments detected: {len(detected_bumps)}")

if __name__ == "__main__":
    main()
