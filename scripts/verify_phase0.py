#!/usr/bin/env python3
"""Validate the Phase 0 design artifacts without a runtime toolchain."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "out", "cache", "lib", "vendor", "tmp", "__pycache__"}
REQUIRED = [
    "README.md",
    "SPEC.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/failure-matrix.md",
    "docs/observability.md",
    "docs/testing.md",
    "docs/demo.md",
    "docs/adr/0001-upstream-versions.md",
    "docs/adr/0002-sponsorship-signing.md",
    "docs/adr/0003-budget-reservations.md",
    "api/openapi.yaml",
    "migrations/0001_initial.sql",
]


def fail(message: str) -> None:
    print(f"phase0: {message}", file=sys.stderr)
    raise SystemExit(1)


for name in REQUIRED:
    if not (ROOT / name).is_file():
        fail(f"missing {name}")

for path in ROOT.rglob("*.md"):
    if any(part in SKIP_PARTS for part in path.parts):
        continue
    body = path.read_text()
    for link in re.findall(r"\[[^]]+\]\(([^)]+)\)", body):
        target = link.split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        if target.startswith("/") or not (path.parent / target).exists():
            fail(f"broken local link {link} in {path.relative_to(ROOT)}")

for path in ROOT.rglob("*"):
    if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
        continue
    try:
        body = path.read_text()
    except UnicodeDecodeError:
        continue
    if re.search(r"/(?:Users|home)/[^/\s]+/", body):
        fail(f"machine-specific path in {path.relative_to(ROOT)}")
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body):
        fail(f"private key marker in {path.relative_to(ROOT)}")
    if re.search(r"(?i)(?:private[_-]?key|mnemonic|seed[_-]?phrase)\s*[:=]\s*['\"]?[a-z0-9]{32,}", body):
        fail(f"possible secret in {path.relative_to(ROOT)}")

cmd = [
    "ruby", "-ryaml", "-rjson", "-e",
    "puts JSON.generate(YAML.load_file(ARGV.fetch(0)))",
    str(ROOT / "api/openapi.yaml"),
]
try:
    spec = json.loads(subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE))
except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
    fail(f"OpenAPI YAML parse failed: {exc}")

if spec.get("openapi") != "3.1.0" or "/v1/sponsorships" not in spec.get("paths", {}):
    fail("OpenAPI version or sponsorship route missing")

schemas = spec.get("components", {}).get("schemas", {})


def check_refs(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                prefix = "#/components/schemas/"
                if not isinstance(child, str) or not child.startswith(prefix) or child[len(prefix):] not in schemas:
                    fail(f"unresolved OpenAPI reference {child}")
            else:
                check_refs(child)
    elif isinstance(value, list):
        for child in value:
            check_refs(child)


check_refs(spec)

go_files = list(ROOT.rglob("*.go"))
if go_files:
    result = subprocess.run(["gofmt", "-l", *(str(p) for p in go_files)], capture_output=True, text=True)
    if result.returncode or result.stdout.strip():
        fail("Go formatting check failed")
if (ROOT / "go.mod").exists():
    result = subprocess.run(["go", "mod", "tidy", "-diff"], cwd=ROOT, capture_output=True, text=True)
    if result.returncode or result.stdout.strip():
        fail("Go module consistency check failed")

sql = (ROOT / "migrations/0001_initial.sql").read_text()
for table in ("policy_versions", "service_controls", "sponsorship_requests", "budget_periods", "sponsorship_reservations", "audit_events"):
    if f"CREATE TABLE {table}" not in sql:
        fail(f"schema table missing: {table}")

print("phase0: design files, local links, OpenAPI YAML/refs, schema outline, and secret/path scan passed")
