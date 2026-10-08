#!/usr/bin/env python3
"""Verify committed source and pinned dependencies in an isolated checkout."""

import pathlib
import shutil
import subprocess
import tempfile


root = pathlib.Path(__file__).resolve().parents[1]
if subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip():
    raise RuntimeError("clean-clone verification requires committed source")
with tempfile.TemporaryDirectory(prefix="gasless-clean-clone-") as work:
    clone = pathlib.Path(work) / "source"
    subprocess.run(["git", "clone", "--local", str(root), str(clone)], check=True)
    subprocess.run(["python3", "scripts/prepare_dependencies.py"], cwd=clone, check=True)
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=clone, text=True).strip():
        raise RuntimeError("prepared clone is modified")
    expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clone, text=True).strip()
    if expected != actual:
        raise RuntimeError("clean clone source identity differs")
    subprocess.run(["make", "verify-phase6-core"], cwd=clone, check=True, timeout=900)
    subprocess.run(["docker", "build", "-t", f"gasless-policy-engine:clean-{expected[:12]}", "."], cwd=clone, check=True, timeout=600)
    subprocess.run(["docker", "run", "--rm", "--network", "none", f"gasless-policy-engine:clean-{expected[:12]}", "--selfcheck"], cwd=clone, check=True, timeout=30)
    if shutil.which("trivy"):
        subprocess.run(["trivy", "image", "--quiet", "--severity", "HIGH,CRITICAL", "--exit-code", "1", f"gasless-policy-engine:clean-{expected[:12]}"], cwd=clone, check=True, timeout=300)
    print(f"clean clone verified: {expected}")
