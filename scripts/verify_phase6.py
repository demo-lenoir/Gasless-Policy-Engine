#!/usr/bin/env python3
"""Validate the final local demo's exact accounting evidence."""

import hashlib
import json
import pathlib


root = pathlib.Path(__file__).resolve().parents[1]
result = json.loads((root / "build/local-deployment.json").read_text())
required = {
    "mode": "success",
    "execution_path": "external bundler",
    "entry_point_version": "v0.9.0",
    "target_count": "1",
    "settlement_status": "CONSUMED",
    "settlement_outcome": "FINAL",
    "unused_status": "EXPIRED_UNUSED",
    "request_count": 3,
    "reservation_count": 2,
    "actual_spend_record_count": 1,
    "account_balance_before_wei": "0",
    "account_balance_after_wei": "0",
    "budget_held_wei": "0",
}
for key, expected in required.items():
    if result.get(key) != expected:
        raise RuntimeError(f"local demo mismatch: {key}")

actual = int(result["actual_gas_cost_wei"])
before = int(result["paymaster_deposit_before_wei"])
after = int(result["paymaster_deposit_after_wei"])
reserved = int(result["reserved_upper_bound_wei"])
released = int(result["released_hold_wei"])
if actual <= 0 or before - after != actual or reserved != actual + released:
    raise RuntimeError("EntryPoint cost and original hold do not conserve Wei")

statement = result["final_accounting"]
if result["final_checksum_sha256"] != "0x" + hashlib.sha256(statement.encode()).hexdigest():
    raise RuntimeError("final checksum differs from accounting statement")
if "consumed=1;expired=1;" not in statement or not statement.endswith(";open=0"):
    raise RuntimeError("final accounting statement is incomplete")
print("phase6: HTTP, Alto, paymaster, reconciliation, and accounting demo passed")
