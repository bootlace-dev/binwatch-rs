#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# Stateless Nostr Kind 0 profile metadata publisher for BinWatch
# Strictly Zero-PII: sets display name, about, website, and picture
# Pure standard-library BIP-340 Schnorr signing + WebSocket broadcasting

import os
import sys
import json
import time
import hashlib
import asyncio
from nostr_broadcast import (
    get_nsec_bytes, pubkey_gen, schnorr_sign, convertbits, bech32_encode, broadcast_relay
)

async def main_async():
    nsec = os.environ.get("NOSTR_BOT_NSEC")
    if not nsec:
        print("Notice: NOSTR_BOT_NSEC not set, cannot publish profile metadata.")
        sys.exit(0)

    sk_bytes = get_nsec_bytes(nsec)
    pubkey_bytes = pubkey_gen(sk_bytes)
    pubkey_x = pubkey_bytes.hex()

    # Zero-PII Profile Metadata payload
    profile = {
        "name": "binwatch",
        "display_name": "bootlace / binwatch",
        "about": "Autonomous deterministic Bitcoin & Nostr binary integrity auditor. Computes Merkle hex seals anchored to Bitcoin block headers.\n\nDashboard: https://bootlace-dev.github.io/binwatch-rs/\nManifest: https://bootlace-dev.github.io/binwatch-rs/manifest.json\nSource: https://github.com/bootlace-dev/binwatch-rs",
        "website": "https://bootlace-dev.github.io/binwatch-rs/",
        "picture": "https://raw.githubusercontent.com/bootlace-dev/binwatch-rs/master/assets/binwatch_logo.png",
        "nip05": "binwatch@bootlace-dev.github.io"
    }

    content = json.dumps(profile, separators=(',', ':'), ensure_ascii=False)
    created_at = int(time.time())
    tags = []

    # NIP-01 Kind 0 event definition
    event_data = [0, pubkey_x, created_at, 0, tags, content]
    serialized = json.dumps(event_data, separators=(',', ':'), ensure_ascii=False)
    event_id = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    msg_32 = bytes.fromhex(event_id)

    sig = schnorr_sign(msg_32, sk_bytes, os.urandom(32))
    sig_hex = sig.hex()

    event = {
        "id": event_id,
        "pubkey": pubkey_x,
        "created_at": created_at,
        "kind": 0,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    }

    data5 = convertbits(msg_32, 8, 5, True)
    npub = bech32_encode("npub", convertbits(pubkey_bytes, 8, 5, True))

    relays = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]

    req = json.dumps(["EVENT", event])
    print(f">> Broadcasting Nostr Kind 0 Profile Event:")
    print(f"   Event ID:  {event_id}")
    print(f"   Pubkey:    {pubkey_x}")
    print(f"   Npub:      {npub}")
    print(f"   Primal:    https://primal.net/p/{npub}")

    tasks = [broadcast_relay(r, req) for r in relays]
    results = await asyncio.gather(*tasks)

    success_count = 0
    for r, ok, detail in results:
        if ok:
            print(f"   ✓ Sent to {r} -> {detail}")
            success_count += 1
        else:
            print(f"   ✗ Failed {r}: {detail}")

    print(f">> Profile broadcast finished: {success_count}/{len(relays)} accepted.")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
