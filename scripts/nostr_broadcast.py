#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
# Stateless Nostr Kind 1 publisher for binwatch audit digest
# Pure standard-library BIP-340 Schnorr signing + WebSocket broadcasting

import os
import sys
import json
import time
import hashlib
import asyncio
from typing import Tuple, Optional

# --- Official BIP-340 Schnorr Reference Implementation ---
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Point = Tuple[int, int]

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None: return P2
    if P2 is None: return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)): return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n_val: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n_val >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(val: int) -> bytes:
    return val.to_bytes(32, byteorder="big")

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(b0, b1))

def lift_x(x_val: int) -> Optional[Point]:
    if x_val >= p: return None
    y_sq = (pow(x_val, 3, p) + 7) % p
    y_val = pow(y_sq, (p + 1) // 4, p)
    if pow(y_val, 2, p) != y_sq: return None
    return (x_val, y_val if y_val & 1 == 0 else p - y_val)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0

def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('Secret key out of range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('Secret key out of range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes.')
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Nonce generation failed.')
    R = point_mul(G, k0)
    assert R is not None
    k = n - k0 if not has_even_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('Created BIP-340 signature failed verification.')
    return sig

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64: return False
    P = lift_x(int_from_bytes(pubkey))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= p) or (s >= n): return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)) or (x(R) != r): return False
    return True

# --- Bech32 Helpers ---
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def bech32_decode(bech):
    if ((any(ord(c) < 33 or ord(c) > 126 for c in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 1000:
        return (None, None)
    if not all(c in CHARSET for c in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(c) for c in bech[pos+1:]]
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

def bech32_encode(hrp, data):
    def bech32_polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    def bech32_hrp_expand(s):
        return [ord(c) >> 5 for c in s] + [0] + [ord(c) & 31 for c in s]

    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    chk = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join([CHARSET[d] for d in data + chk])

def get_nsec_bytes(nsec_str):
    if len(nsec_str) == 64:
        try:
            return bytes.fromhex(nsec_str)
        except ValueError:
            pass
    hrp, data5 = bech32_decode(nsec_str)
    if hrp != 'nsec':
        raise ValueError('Expected nsec HRP')
    bytes_data = convertbits(data5, 5, 8, False)
    return bytes(bytes_data)

async def broadcast_relay(relay_url, req_str):
    try:
        import websockets
        async with asyncio.timeout(10):
            async with websockets.connect(relay_url) as ws:
                await ws.send(req_str)
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                return (relay_url, True, resp)
    except Exception as e:
        return (relay_url, False, str(e))

async def main_async():
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
    pubkey_bytes = pubkey_gen(sk_bytes)
    pubkey_x = pubkey_bytes.hex()

    import re
    seal_match = re.search(r'Merkle Seal:\s*#([A-Fa-f0-9]{6})', content)
    seal_tag = seal_match.group(1).upper() if seal_match else None

    created_at = int(time.time())
    tags = [
        ["t", "binwatch"],
        ["t", "bitcoin"],
        ["t", "supplychain"],
        ["r", "https://bootlace-dev.github.io/binwatch-rs/"]
    ]
    if seal_tag:
        tags.insert(1, ["t", seal_tag])

    event_data = [0, pubkey_x, created_at, 1, tags, content]
    serialized = json.dumps(event_data, separators=(',', ':'), ensure_ascii=False)
    event_id = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
    msg_32 = bytes.fromhex(event_id)

    # Pure standard BIP-340 Schnorr signature over exact event_id
    sig = schnorr_sign(msg_32, sk_bytes, os.urandom(32))
    sig_hex = sig.hex()

    event = {
        "id": event_id,
        "pubkey": pubkey_x,
        "created_at": created_at,
        "kind": 1,
        "tags": tags,
        "content": content,
        "sig": sig_hex
    }

    # Derive note1 bech32 identifier
    data5 = convertbits(msg_32, 8, 5, True)
    note_bech32 = bech32_encode("note", data5)

    relays = [
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.primal.net"
    ]

    req = json.dumps(["EVENT", event])
    print(f">> Broadcasting Nostr Kind 1 Event:")
    print(f"   Event ID:  {event_id}")
    print(f"   Pubkey:    {pubkey_x}")
    print(f"   Note ID:   {note_bech32}")
    print(f"   Primal:    https://primal.net/e/{note_bech32}")

    tasks = [broadcast_relay(r, req) for r in relays]
    results = await asyncio.gather(*tasks)

    success_count = 0
    for r, ok, detail in results:
        if ok:
            print(f"   ✓ Sent to {r} -> {detail}")
            success_count += 1
        else:
            print(f"   ✗ Failed {r}: {detail}")

    print(f">> Broadcast finished: {success_count}/{len(relays)} accepted.")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
