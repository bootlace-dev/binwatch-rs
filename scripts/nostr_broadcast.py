#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# Stateless Nostr Kind 1 publisher for binwatch audit digest
import os
import sys
import json
import time
import ssl
import websocket
import hashlib
from ecdsa import SigningKey, SECP256k1

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def bech32_decode(bech):
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 1000:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1; max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits): return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (tobits - bits)) & maxv)
    return ret

def get_nsec_bytes(nsec_str):
    hrp, data5 = bech32_decode(nsec_str)
    if hrp != 'nsec':
        raise ValueError('Expected nsec HRP')
    bytes_data = convertbits(data5, 5, 8, False)
    return bytes(bytes_data)

def schnorr_sign(msg_32: bytes, privkey_32: bytes) -> bytes:
    sk = SigningKey.from_string(privkey_32, curve=SECP256k1)
    vk = sk.verifying_key
    # BIP-340 Schnorr signature
    # In pure python, fallback to pipek1 sign if available or ecdsa
    return sk.sign_deterministic(msg_32, hashfunc=hashlib.sha256)

def main():
    if len(sys.argv) < 2:
        print("Usage: nostr_broadcast.py <digest.txt> [manifest.json]")
        sys.exit(2)

    digest_file = sys.argv[1]
    with open(digest_file, 'r') as f:
        content = f.read().strip()

    nsec = os.environ.get("NOSTR_BOT_NSEC")
    if not nsec:
        print("Notice: NOSTR_BOT_NSEC not set, skipping relay broadcast.")
        sys.exit(0)

    sk_bytes = get_nsec_bytes(nsec)
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    pubkey_x = vk.to_string()[:32].hex()

    created_at = int(time.time())
    tags = [
        ["t", "binwatch"],
        ["t", "bitcoin"],
        ["t", "supplychain"],
        ["r", "https://bootlace-dev.github.io/binwatch-rs/"]
    ]

    event_data = [0, pubkey_x, created_at, 1, tags, content]
    serialized = json.dumps(event_data, separators=(',', ':'), ensure_ascii=False)
    event_id = hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    # Sign using pipek1 binary directly for exact BIP-340 compliance
    pipek1_bin = "/usr/local/bin/pipek1"
    if not os.path.exists(pipek1_bin):
        pipek1_bin = "/home/bootlace/dev/pipek1/rust/target/release/pipek1"

    import subprocess
    cmd = [pipek1_bin, "sign"]
    env = os.environ.copy()
    env["PIPEK1_SEC_KEY"] = sk_bytes.hex()
    res = subprocess.run(cmd, input=serialized.encode('utf-8'), capture_output=True, env=env)
    if res.returncode != 0:
        print("Error signing event with pipek1:", res.stderr.decode())
        sys.exit(1)

    sig_wire = res.stdout
    # Extract 64-byte Schnorr signature from 105-byte pipek1 payload (bytes 41..105)
    sig_hex = sig_wire[41:105].hex()

    event = {
        "id": event_id,
        "pubkey": pubkey_x,
        "created_at": created_at,
        "kind": 1,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    }

    relays = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]

    req = json.dumps(["EVENT", event])
    print(f">> Broadcasting Nostr event {event_id} from pubkey {pubkey_x}...")

    success_count = 0
    for r in relays:
        try:
            ws = websocket.create_connection(r, timeout=6, sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.send(req)
            ws.close()
            print(f"   ✓ Sent to {r}")
            success_count += 1
        except Exception as e:
            print(f"   ✗ Failed {r}: {e}")

    print(f">> Done. Broadcasted to {success_count}/{len(relays)} relays.")

if __name__ == "__main__":
    main()
