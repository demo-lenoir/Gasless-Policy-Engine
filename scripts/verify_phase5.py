#!/usr/bin/env python3
"""Run economic settlement scenarios against disposable local infrastructure."""

import json
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
METADATA = ROOT / "build/local-deployment.json"


def scenario(*args):
    subprocess.run(["python3", "scripts/verify_phase4.py", *args], cwd=ROOT, check=True, timeout=180)
    return json.loads(METADATA.read_text())


for mode in ("reverted", "unused", "unknown-no-inclusion"):
    result = scenario(f"--mode={mode}")
    if result["mode"] != mode or result["budget_held_wei"] != "0":
        raise RuntimeError(f"{mode}: missing settled accounting")
    reserved = int(result.get("reserved_upper_bound_wei", result.get("released_hold_wei", "0")))
    actual = int(result["actual_gas_cost_wei"])
    released = int(result["released_hold_wei"])
    if mode == "reverted":
        if result["settlement_status"] != "CONSUMED" or result["execution_success"] or actual <= 0:
            raise RuntimeError("reverted operation did not consume sponsor gas")
    elif result["settlement_status"] != "EXPIRED" or result["settlement_outcome"] != "EXPIRED_UNUSED" or actual != 0:
        raise RuntimeError(f"{mode}: unsafe unused expiry")
    if reserved and reserved != actual + released:
        raise RuntimeError(f"{mode}: accounting does not conserve reserved Wei")

result = scenario("--bundler", "--response-lost")
if result["mode"] != "response-lost" or result["settlement_status"] != "CONSUMED" or result["budget_held_wei"] != "0" or int(result["actual_gas_cost_wei"]) <= 0:
    raise RuntimeError("accepted operation with lost response was not reconciled")

print("phase5: reverted, unused, unknown, and response-loss settlement passed")
