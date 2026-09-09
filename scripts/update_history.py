#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
"""
update_history.py - Persistent Stability & Historical Continuity Engine for BinWatch

Tracks consecutive verification epochs, days stable, and prior state across runs.
"""

import sys
import os
import json
from datetime import datetime, timezone
import urllib.request
import urllib.error

PAGES_HISTORY_URL = "https://bootlace-dev.github.io/binwatch-rs/history.json"

def load_existing_history(history_paths):
    for path in history_paths:
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "projects" in data:
                        return data, path
            except Exception:
                pass

    # Remote fallback from GitHub Pages
    try:
        req = urllib.request.Request(PAGES_HISTORY_URL, headers={"User-Agent": "binwatch-history-bot"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, dict) and "projects" in data:
                    return data, None
    except Exception:
        pass

    return {"last_updated_utc": "", "last_block_height": None, "projects": {}}, None

def parse_iso(iso_str):
    if not iso_str:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))

def main():
    if len(sys.argv) < 2:
        print("Usage: update_history.py <manifest.json> [history.json]")
        sys.exit(1)

    manifest_path = sys.argv[1]
    custom_history_path = sys.argv[2] if len(sys.argv) > 2 else None

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(script_dir)
    default_history_path = os.path.join(repo_dir, "data", "history.json")

    history_paths = [
        custom_history_path,
        os.path.join(repo_dir, "public", "history.json"),
        default_history_path,
    ]

    history_data, loaded_from = load_existing_history(history_paths)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    now_iso = manifest.get("timestamp_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_dt = parse_iso(now_iso)
    current_block = manifest.get("block_height")

    projects = manifest.get("projects", {})
    history_projects = history_data.setdefault("projects", {})

    for proj_id, proj in projects.items():
        release_tag = proj.get("release_tag", "")
        artifacts = proj.get("artifacts", [])
        primary_hash = artifacts[0].get("expected_sha256", "") if artifacts else ""

        if proj_id in history_projects:
            prev = history_projects[proj_id]
            prev_hash = prev.get("primary_hash", "")
            prev_tag = prev.get("release_tag", "")

            if prev_hash == primary_hash and prev_tag == release_tag:
                # Hash & tag match -> increment epochs & calculate days stable
                first_seen_iso = prev.get("first_seen_utc", now_iso)
                first_seen_dt = parse_iso(first_seen_iso)
                days_stable = max(0, (now_dt.date() - first_seen_dt.date()).days)
                consecutive_epochs = prev.get("consecutive_epochs", 1) + 1

                entry = {
                    "project_id": proj_id,
                    "release_tag": release_tag,
                    "primary_hash": primary_hash,
                    "first_seen_utc": first_seen_iso,
                    "first_seen_block": prev.get("first_seen_block", current_block),
                    "days_stable": days_stable,
                    "consecutive_epochs": consecutive_epochs,
                    "previous_release_tag": prev.get("previous_release_tag"),
                    "previous_primary_hash": prev.get("previous_primary_hash"),
                    "last_changed_utc": prev.get("last_changed_utc", first_seen_iso),
                }
            else:
                # Mutation detected: release updated or hash drifted!
                entry = {
                    "project_id": proj_id,
                    "release_tag": release_tag,
                    "primary_hash": primary_hash,
                    "first_seen_utc": now_iso,
                    "first_seen_block": current_block,
                    "days_stable": 0,
                    "consecutive_epochs": 1,
                    "previous_release_tag": prev_tag or prev.get("previous_release_tag"),
                    "previous_primary_hash": prev_hash or prev.get("previous_primary_hash"),
                    "last_changed_utc": now_iso,
                }
        else:
            # First observation of this project
            entry = {
                "project_id": proj_id,
                "release_tag": release_tag,
                "primary_hash": primary_hash,
                "first_seen_utc": now_iso,
                "first_seen_block": current_block,
                "days_stable": 0,
                "consecutive_epochs": 1,
                "previous_release_tag": None,
                "previous_primary_hash": None,
                "last_changed_utc": now_iso,
            }

        history_projects[proj_id] = entry
        proj["history"] = entry

    history_data["last_updated_utc"] = now_iso
    history_data["last_block_height"] = current_block

    # Save manifest with history attached
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Save persistent history to data/history.json
    save_targets = {default_history_path}
    if custom_history_path:
        save_targets.add(custom_history_path)

    # Also save to public/history.json if public dir exists
    public_dir = os.path.join(repo_dir, "public")
    if os.path.isdir(public_dir):
        save_targets.add(os.path.join(public_dir, "history.json"))

    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    if os.path.basename(manifest_dir) == "public":
        save_targets.add(os.path.join(manifest_dir, "history.json"))

    for target in save_targets:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(history_data, f, indent=2)
        print(f">> Updated history saved to: {target}")

    print(f">> Successfully injected stability telemetry into {manifest_path}")

if __name__ == "__main__":
    main()
