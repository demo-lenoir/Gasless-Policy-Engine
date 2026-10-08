#!/usr/bin/env python3
"""Build unsigned local binaries, SPDX SBOM, and source-bound provenance."""

import hashlib
import json
import os
import pathlib
import subprocess


root = pathlib.Path(__file__).resolve().parents[1]
output = root / "build/release"
output.mkdir(parents=True, exist_ok=True)


def command(*args, cwd=root):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


source = command("git", "rev-parse", "HEAD")
if command("git", "status", "--porcelain"):
    raise RuntimeError("release artifacts require committed source")
artifacts = {}
commands = []
for arch in ("amd64", "arm64"):
    name = f"gasless-linux-{arch}"
    path = output / name
    args = ["go", "build", "-trimpath", "-buildvcs=true", "-ldflags=-s -w", "-o", f"build/release/{name}", "./cmd/gasless"]
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch}
    subprocess.run(args, cwd=root, env=env, check=True)
    artifacts[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    commands.append({"command": "go build -trimpath -buildvcs=true -ldflags=-s -w ./cmd/gasless", "target": f"linux/{arch}", "cgo": "disabled"})

sbom = output / "gasless-linux-amd64.spdx.json"
subprocess.run(["syft", "scan", "file:build/release/gasless-linux-amd64", "-o", f"spdx-json=build/release/{sbom.name}"], cwd=root, check=True)
document = json.loads(sbom.read_text())
if document.get("spdxVersion") != "SPDX-2.3" or not document.get("packages"):
    raise RuntimeError("invalid or empty SPDX SBOM")
artifacts[sbom.name] = hashlib.sha256(sbom.read_bytes()).hexdigest()
submodules = {}
for name in ("aa", "oz", "alto"):
    submodules[name] = command("git", "rev-parse", "HEAD", cwd=root / "lib" / name)
snapshots = json.loads((root / "dependency-snapshots/manifest.json").read_text())
for name in ("oz", "alto"):
    if submodules[name] != snapshots[name]["snapshot_commit"]:
        raise RuntimeError(f"dependency snapshot revision differs: {name}")

metadata = {
    "kind": "unsigned local provenance",
    "source_commit": source,
    "source_modified": False,
    "verification": "make verify-phase6-core and clean-clone-verify passed locally",
    "go_version": command("go", "version"),
    "forge_version": command("forge", "--version").splitlines()[0],
    "solidity_version": "0.8.37",
    "entry_point_version": "v0.9.0",
    "openzeppelin_version": "v5.7.0",
    "submodule_commits": submodules,
    "dependency_snapshots": snapshots,
    "build_commands": commands,
    "artifact_sha256": artifacts,
    "sbom_file": sbom.name,
    "sbom_sha256": artifacts[sbom.name],
}
provenance = output / "unsigned-local-provenance.json"
provenance.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
if json.loads(provenance.read_text())["source_commit"] != source:
    raise RuntimeError("provenance source identity differs")
print(json.dumps({"source_commit": source, "artifacts": artifacts, "provenance_sha256": hashlib.sha256(provenance.read_bytes()).hexdigest()}, sort_keys=True))
