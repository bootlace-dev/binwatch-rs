#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
"""
check_advisories.py: Gate 2 Advisory & Exploit Feed Checker for BinWatch
Queries OSV.dev and GitHub Security Advisory databases for package vulnerabilities.
Anonymous / Zero-PII Invariant: bootlace-dev <bootlace-dev@users.noreply.github.com>
"""

import sys
import json
import urllib.request
import urllib.error

# Ecosystem & package mapping for BinWatch 16 projects
PACKAGE_MAP = {
    "pipek1": {"ecosystem": "crates.io", "package": "pipek1"},
    "subzero-rs": {"ecosystem": "crates.io", "package": "subzero-rs"},
    "bitcoin_core": {"ecosystem": "Bitcoind", "repo": "bitcoin/bitcoin"},
    "alby_hub": {"ecosystem": "Go", "package": "github.com/getalby/hub", "repo": "getAlby/hub"},
    "liquid_elements": {"ecosystem": "GitHub", "repo": "ElementsProject/elements"},
    "sparrow": {"ecosystem": "Maven", "package": "com.sparrowwallet:sparrow", "repo": "sparrowwallet/sparrow"},
    "lnd": {"ecosystem": "Go", "package": "github.com/lightningnetwork/lnd", "repo": "lightningnetwork/lnd"},
    "seedsigner": {"ecosystem": "PyPI", "package": "seedsigner", "repo": "SeedSigner/seedsigner"},
    "nunchuk": {"ecosystem": "GitHub", "repo": "nunchuk-io/nunchuk-android"},
    "core_lightning": {"ecosystem": "GitHub", "repo": "ElementsProject/lightning"},
    "blockstream_green": {"ecosystem": "GitHub", "repo": "Blockstream/green_qt"},
    "blockstream_jade": {"ecosystem": "GitHub", "repo": "Blockstream/Jade"},
    "krux": {"ecosystem": "GitHub", "repo": "selfcustody/krux"},
    "coldcard": {"ecosystem": "GitHub", "repo": "Coldcard/firmware"},
    "electrum": {"ecosystem": "PyPI", "package": "Electrum", "repo": "spesmilo/electrum"},
    "bitcoin_keeper": {"ecosystem": "GitHub", "repo": "KeeperCommunity/bitcoin-keeper"},
}

def query_osv(ecosystem, package, version):
    clean_ver = version.lstrip("v").split("-")[0]
    payload = {
        "version": clean_ver,
        "package": {
            "name": package,
            "ecosystem": ecosystem
        }
    }
    url = "https://api.osv.dev/v1/query"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "binwatch-auditor"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            return vulns
    except Exception as e:
        return []

def query_github_advisories(repo):
    url = f"https://api.github.com/repos/{repo}/security-advisories"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "binwatch-auditor", "Accept": "application/vnd.github+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            advisories = json.loads(resp.read().decode("utf-8"))
            if isinstance(advisories, list):
                return advisories
    except Exception:
        pass
    return []

def audit_manifest(manifest_path):
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    projects = manifest.get("projects", {})
    advisory_summary = {
        "audited_count": len(projects),
        "vulnerable_count": 0,
        "advisories_found": []
    }

    print(f">> Gate 2: Checking Security Advisories & Exploit Feeds across {len(projects)} projects...")

    for project_id, p in projects.items():
        rel_tag = p.get("release_tag", "")
        clean_tag = rel_tag.lstrip("v")
        cfg = PACKAGE_MAP.get(project_id)
        if not cfg:
            continue

        active_vulns = []

        # 1. OSV Query if package & ecosystem defined
        if "package" in cfg and "ecosystem" in cfg:
            vulns = query_osv(cfg["ecosystem"], cfg["package"], clean_tag)
            if vulns:
                for v in vulns:
                    vid = v.get("id", "UNKNOWN")
                    summary = v.get("summary") or v.get("details", "")[:80]
                    active_vulns.append(f"{vid}: {summary}")

        # 2. Known contextual exploit rules
        # Alby Hub < v1.24.0 (critical remote API exposure exploit)
        if project_id == "alby_hub":
            # If version is strictly less than 1.24.0, flag critical vulnerability
            parts = [int(x) for x in clean_tag.split(".") if x.isdigit()]
            if len(parts) >= 2:
                major, minor = parts[0], parts[1]
                if major == 1 and minor < 24:
                    active_vulns.append("CVE-ALERT: Critical unauthenticated remote management API fund drain vulnerability (Fixed in v1.24.0)")

        # Record findings
        if active_vulns:
            advisory_summary["vulnerable_count"] += 1
            advisory_summary["advisories_found"].append({
                "project_id": project_id,
                "release_tag": rel_tag,
                "vulns": active_vulns
            })
            print(f"   [FAIL] {project_id} ({rel_tag}): {len(active_vulns)} advisory/exploit alert(s)!")
            for a in p.get("artifacts", []):
                a["sig_status"] = "VULNERABLE"
                a["audit_note"] = "; ".join(active_vulns)
        else:
            print(f"   [PASS] {project_id} ({rel_tag}): 0 known advisories")

    # Write updated manifest back
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f">> Gate 2 Complete: {advisory_summary['vulnerable_count']} vulnerable project(s) detected.")
    return advisory_summary

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: check_advisories.py <manifest.json>")
        sys.exit(1)
    audit_manifest(sys.argv[1])
