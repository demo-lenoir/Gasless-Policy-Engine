#!/usr/bin/env python3
"""Populate pinned source snapshots from the committed local bundles."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SNAPSHOTS = ROOT / "dependency-snapshots"
manifest = json.loads((SNAPSHOTS / "manifest.json").read_text())

for name in ("alto", "oz"):
    bundle = SNAPSHOTS / f"{name}.bundle"
    actual = hashlib.sha256(bundle.read_bytes()).hexdigest()
    if actual != manifest[name]["bundle_sha256"]:
        raise RuntimeError(f"dependency bundle checksum differs: {name}")
    subprocess.run(
        ["git", "config", f"submodule.lib/{name}.url", str(bundle)],
        cwd=ROOT,
        check=True,
    )

subprocess.run(
    [
        "git", "-c", "protocol.file.allow=always", "submodule", "update",
        "--init", "lib/aa", "lib/alto", "lib/oz",
    ],
    cwd=ROOT,
    check=True,
)

for name in ("alto", "oz"):
    dependency = ROOT / "lib" / name
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=dependency, text=True
    ).strip()
    if actual != manifest[name]["snapshot_commit"]:
        raise RuntimeError(f"dependency revision differs: {name}")
    visible_docs = [
        path for path in subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=dependency
        ).decode().split("\0")
        if path.endswith(".md") and (dependency / path).exists()
    ]
    if visible_docs:
        raise RuntimeError(f"upstream documentation remains in {name}")
    if subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=dependency, text=True
    ).strip():
        raise RuntimeError(f"dependency checkout is modified: {name}")

alto = ROOT / "lib/alto"
root_git_dir = pathlib.Path(subprocess.check_output(
    ["git", "rev-parse", "--absolute-git-dir"], cwd=ROOT, text=True
).strip()).resolve()
entries = subprocess.check_output(
    ["git", "ls-tree", "-r", "-z", "HEAD", "contracts/lib"], cwd=alto
)
for entry in entries.split(b"\0"):
    if not entry:
        continue
    metadata, relative_path = entry.split(b"\t", 1)
    mode, kind, revision = metadata.decode().split()
    if mode != "160000" or kind != "commit":
        continue
    relative = relative_path.decode()
    target = alto / relative
    url = subprocess.check_output(
        ["git", "config", "-f", ".gitmodules", "--get", f"submodule.{relative}.url"],
        cwd=alto, text=True,
    ).strip()

    old_git_dir = None
    source = url
    if (target / ".git").exists():
        current = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=target, text=True
        ).strip()
        if current != revision or subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=target, text=True
        ).strip():
            raise RuntimeError(f"nested dependency differs or is modified: {relative}")
        shallow = subprocess.check_output(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=target, text=True,
        ).strip() == "true"
        count = subprocess.check_output(
            ["git", "rev-list", "--all", "--count"], cwd=target, text=True
        ).strip()
        if shallow and count == "1":
            continue
        if subprocess.check_output(
            ["git", "status", "--porcelain", "--ignored"], cwd=target, text=True
        ).strip():
            raise RuntimeError(f"nested dependency contains ignored files: {relative}")
        old_git_dir = pathlib.Path(subprocess.check_output(
            ["git", "rev-parse", "--absolute-git-dir"], cwd=target, text=True
        ).strip()).resolve()
        source = target.resolve().as_uri()
    elif target.exists() and any(target.iterdir()):
        raise RuntimeError(f"nested dependency contains untracked files: {relative}")

    with tempfile.TemporaryDirectory(prefix="gasless-dependency-") as temporary:
        checkout = pathlib.Path(temporary) / "checkout"
        checkout.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
        subprocess.run(
            ["git", "fetch", "-q", "--depth=1", "--no-tags", source, revision],
            cwd=checkout, check=True,
        )
        subprocess.run(
            ["git", "checkout", "-q", "--detach", revision],
            cwd=checkout, check=True,
        )
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(checkout), str(target))
    if old_git_dir and old_git_dir != target / ".git":
        if not old_git_dir.is_relative_to(root_git_dir / "modules"):
            raise RuntimeError(f"unexpected nested Git directory: {old_git_dir}")
        shutil.rmtree(old_git_dir)

print("pinned dependency sources are ready")
