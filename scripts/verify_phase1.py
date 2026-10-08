#!/usr/bin/env python3
"""Check that the policy package stays independent of infrastructure."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
POLICY = ROOT / "internal" / "policy"


def fail(message: str) -> None:
    print(f"phase1: {message}", file=sys.stderr)
    raise SystemExit(1)


for name in ("config/policy.example.json", "docs/policy.md", "docs/evidence.md"):
    if not (ROOT / name).is_file():
        fail(f"missing {name}")

source_files = list(POLICY.glob("*.go"))
if not source_files:
    fail("policy package has no Go source")

try:
    package = json.loads(
        subprocess.check_output(
            ["go", "list", "-json", "./internal/policy"], cwd=ROOT, text=True
        )
    )
except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
    fail(f"cannot inspect policy imports: {exc}")
for imported in package.get("Imports", []):
    first = imported.split("/", 1)[0]
    if "." in first or first in {"net", "database", "os", "syscall", "log", "context"}:
        fail(f"infrastructure import {imported} in policy package")

print("phase1: policy package boundary passed")
