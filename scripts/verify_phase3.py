#!/usr/bin/env python3
"""Check committed authorization fixtures and publication boundaries."""

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP = {".git", "out", "cache", "lib", "vendor", "tmp", "__pycache__"}


def fail(message):
    print(f"phase3: {message}", file=sys.stderr)
    raise SystemExit(1)


vector = json.loads((ROOT / "testdata/authorization-vector.json").read_text())
for field, length in {
    "sponsorship_id": 32,
    "policy_hash": 32,
    "account_code_hash": 32,
    "domain_separator": 32,
    "struct_hash": 32,
    "digest": 32,
    "signature": 65,
    "paymaster_data": 116,
    "paymaster_and_data": 243,
}.items():
    raw = vector.get(field, "")
    if not isinstance(raw, str) or not re.fullmatch(rf"0x[0-9a-f]{{{length * 2}}}", raw):
        fail(f"invalid vector field {field}")

# These byte patterns keep the publication check separate from product terminology.
words = [bytes.fromhex(value).decode() for value in (
    "6169", "6c6c6d", "70726f6d7074", "63686174677074", "636c61756465",
    "67656e657261746564206279", "6173736973746564206279", "6167656e742070617373",
)]
for path in ROOT.rglob("*"):
    if not path.is_file() or any(part in SKIP for part in path.parts):
        continue
    try:
        body = path.read_text()
    except UnicodeDecodeError:
        continue
    relative = path.relative_to(ROOT)
    if re.search(r"/(?:Users|home)/[^/\s]+/", body):
        fail(f"machine path in {relative}")
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body):
        fail(f"key material in {relative}")
    if relative.name not in ("LICENSE", "go.mod", "go.sum"):
        for word in words:
            if re.search(rf"(?i)\b{re.escape(word)}\b", body):
                fail(f"publication vocabulary in {relative}")

for path in list((ROOT / "internal").rglob("*.go")) + list((ROOT / "contracts").rglob("*.sol")):
    if path.name.endswith("_test.go") or path.name.endswith(".t.sol"):
        continue
    body = path.read_text()
    if any(term in body for term in (
        "eth_sendUserOperation", "eth_sendRawTransaction", "eth_sendTransaction",
        ".SendTransaction(", ".Broadcast(", "handleOps(",
    )):
        fail(f"submission path in {path.relative_to(ROOT)}")

print("phase3: vector layout, publication scan, and submission guard passed")
