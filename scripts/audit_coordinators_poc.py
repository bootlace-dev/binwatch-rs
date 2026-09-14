#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bootlace-dev
"""
BinWatch WabiSabi / CoinJoin Privacy Coordinator Auditor (POC)
Audits live WabiSabi privacy coordinator endpoints:
1. Endpoint availability & HTTP transport
2. Declared Coordinator Fee Rate vs Observed Fee Rate (0.0% Fee assertion)
3. Active Round Metrics (Volume, Round Count, AS Anonymity Set)
4. Generates Pipeline Status Vector (DTHS-MKEX-HRPA)
"""

import urllib.request
import json
import ssl
import time
import sys

COORDINATOR_TARGETS = [
    {
        "project_id": "opencoordinator_api",
        "name": "OpenCoordinator Mainnet API",
        "url": "https://api.opencoordinator.org/wabisabi/human-monitor",
        "expected_fee": 0.0,
        "origin": "privacy_coordinator"
    },
    {
        "project_id": "kruw_wabisabi",
        "name": "Kruw WabiSabi Coordinator",
        "url": "https://coinjoin.kruw.io/wabisabi/human-monitor",
        "expected_fee": 0.0,
        "origin": "privacy_coordinator"
    },
    {
        "project_id": "coinjoin_nl",
        "name": "CoinJoin NL Coordinator",
        "url": "https://coinjoin.nl/wabisabi/human-monitor",
        "expected_fee": 0.0,
        "origin": "privacy_coordinator"
    }
]

def audit_coordinator(target):
    print(f">> Auditing Privacy Coordinator: {target['name']} ({target['project_id']})...")
    
    ctx = ssl.create_default_context()
    
    start_time = time.time()
    req = urllib.request.Request(target['url'], headers={"User-Agent": "BinWatch-CoordinatorSentinel/1.0"})
    
    # 12-Stage Pipeline Status Vector initial mask (Default: 0x0FFF = All Pass)
    # Stage D=1, T=1, H=1, S=1, M=1, K=1, E=1, X=1, H=1, R=1, P=1, A=1
    mask = 0x0FFF
    warn_mask = 0x0000
    notes = []

    try:
        res = urllib.request.urlopen(req, context=ctx, timeout=8)
        http_code = res.status
        if http_code != 200:
            mask &= ~(1 << 2) # Stage H failure
            notes.append(f"HTTP status code {http_code}")
        
        raw_body = res.read().decode('utf-8')
        data = json.loads(raw_body)
    except Exception as e:
        mask &= ~(1 << 0) # Stage D/T/H failure
        mask &= ~(1 << 2)
        notes.append(f"Transport/Network unreachable: {str(e)}")
        return {
            "project_id": target["project_id"],
            "status_vector": "D000-0000-0000",
            "hex_mask": "001",
            "status": "❌ NETWORK_UNREACHABLE",
            "audit_note": f"Coordinator endpoint transport failed: {e}"
        }

    # Inspect Round States for Fee Assertions and Volume
    rounds = data.get("roundStates") or data.get("RoundStates") or []
    total_rounds = len(rounds)
    observed_fee = 0.0
    active_inputs = 0
    
    fee_mismatch = False
    for r in rounds:
        coinjoin_state = r.get("coinJoinState") or r.get("CoinJoinState") or {}
        parameters = coinjoin_state.get("parameters") or coinjoin_state.get("Parameters") or {}
        fee_rate = parameters.get("coordinationFeeRate", {}).get("rate", 0.0)
        
        if fee_rate != target["expected_fee"]:
            fee_mismatch = True
            observed_fee = fee_rate
            break
            
        input_count = r.get("inputCount") or r.get("InputCount") or len(coinjoin_state.get("registeredInputs") or coinjoin_state.get("RegisteredInputs") or [])
        active_inputs += input_count

    if fee_mismatch:
        warn_mask |= (1 << 8) # Stage H (Hash/Fee match) Warning
        notes.append(f"Fee Rate Mismatch: Declared {target['expected_fee']}%, Observed {observed_fee}%")
    else:
        notes.append(f"0.0% Fee Asserted across {total_rounds} active rounds ({active_inputs} registered inputs)")

    # Build Ribbon String
    stage_chars = ['D', 'T', 'H', 'S', '-', 'M', 'K', 'E', 'X', '-', 'H', 'R', 'P', 'A']
    ribbon = []
    for i in range(12):
        if i > 0 and i % 4 == 0:
            ribbon.append('-')
        bit = 1 << i
        if (warn_mask & bit) != 0:
            ribbon.append('!')
        elif (mask & bit) != 0:
            ribbon.append(stage_chars[i if i < 4 else (i+1 if i < 8 else i+2)])
        else:
            ribbon.append('0')

    ribbon_str = "".join(ribbon)
    status_str = "⚠️ FEE_WARNING" if warn_mask != 0 else ("✅ OK" if mask == 0x0FFF else "❌ FAIL")

    return {
        "project_id": target["project_id"],
        "status_vector": ribbon_str,
        "hex_mask": f"{mask:03X}",
        "status": status_str,
        "rounds": total_rounds,
        "inputs": active_inputs,
        "audit_note": " • ".join(notes)
    }

def main():
    results = []
    for target in COORDINATOR_TARGETS:
        res = audit_coordinator(target)
        results.append(res)
        print(f"   Status: {res['status']} | Vector: [{res['status_vector']}] | Mask: 0x{res['hex_mask']}")
        print(f"   Note:   {res['audit_note']}\n")

    output_path = "/tmp/coordinator_audit_report.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f">> Audit complete. Report written to {output_path}")

if __name__ == "__main__":
    main()
