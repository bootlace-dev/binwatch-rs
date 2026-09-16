#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# NIP-09 Kind 5 Event Deletion Utility
import os
import sys
import json
import time
import hashlib
import asyncio

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nostr_broadcast import get_nsec_bytes, pubkey_gen, schnorr_sign, broadcast_relay

def main():
    nsec = os.environ.get("NOSTR_BOT_NSEC")
    if not nsec:
        if len(sys.argv) > 1 and sys.argv[1].startswith("nsec1"):
            nsec = sys.argv[1]
        else:
            print("Usage: NOSTR_BOT_NSEC=nsec1... python3 delete_events.py [nsec1...]")
            sys.exit(1)

    sk_bytes = get_nsec_bytes(nsec)
    pubkey_x = pubkey_gen(sk_bytes).hex()

    events_to_delete = [
        "20de7571eeca6997c1712dfafddb3ef9b0823a3139708eb05d3f8394f7cd87f8",
        "50dc1f73c31b577acccfc5820f9e2c8e3a6d7bf747d2dfa35040c1ba17388e1c"
    ]

    tags = [["e", eid] for eid in events_to_delete]
    tags.append(["k", "1"])
    content = "Requesting deletion of unpolished research test broadcasts per NIP-09"
    created_at = int(time.time())

    event_data = [0, pubkey_x, created_at, 5, tags, content]
    serialized = json.dumps(event_data, separators=(",", ":"), ensure_ascii=False)
    event_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    sig_hex = schnorr_sign(bytes.fromhex(event_id), sk_bytes, os.urandom(32)).hex()

    deletion_event = {
        "id": event_id,
        "pubkey": pubkey_x,
        "created_at": created_at,
        "kind": 5,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    }

    relays = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net",
        "wss://relay.nostr.info",
        "wss://nostr.wine"
    ]
    req = json.dumps(["EVENT", deletion_event])

    async def delete_all():
        print(f">> Broadcasting NIP-09 Kind 5 Deletion Event (ID: {event_id})...")
        tasks = [broadcast_relay(r, req) for r in relays]
        results = await asyncio.gather(*tasks)
        for r, ok, detail in results:
            status = "✓ Accepted" if ok else "✗ Failed"
            print(f"   {status} {r}: {detail}")

    asyncio.run(delete_all())

if __name__ == "__main__":
    main()
