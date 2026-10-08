#!/usr/bin/env python3
"""Run the local direct EntryPoint integration against disposable infrastructure."""

import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import http.server
import threading
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CANONICAL_ENTRYPOINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
ALTO_REVISION = json.loads((ROOT / "dependency-snapshots/manifest.json").read_text())["alto"]["snapshot_commit"]


for tool in ("forge", "anvil"):
    version = subprocess.check_output([tool, "--version"], text=True).splitlines()[0]
    if not version.startswith(f"{tool} Version: 1.8.4"):
        raise RuntimeError(f"{tool} 1.8.4 is required for the pinned local integration")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args, env=None, timeout=120):
    subprocess.run(args, cwd=ROOT, env=env, timeout=timeout, check=True)


def wait_rpc(url, process):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Anvil exited before JSON-RPC became available")
        try:
            with urllib.request.urlopen(urllib.request.Request(url, payload, {"Content-Type": "application/json"}), timeout=1) as response:
                result = json.load(response)
            if result.get("result") == "0x7a69":
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Anvil JSON-RPC did not become ready")


def rpc(url, method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, payload, {"Content-Type": "application/json"}), timeout=10) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def start_external_bundler(directory, url, alto_dir):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=alto_dir, text=True).strip()
    if revision != ALTO_REVISION:
        raise RuntimeError("external bundler revision differs from the pinned integration")
    source = (alto_dir / "test/e2e/deploy-contracts/constants.ts").read_text()
    match = re.search(r'ENTRY_POINT_V09_CREATECALL: Hex\s*=\s*"(0x[0-9a-fA-F]+)"', source)
    if not match:
        raise RuntimeError("pinned Alto checkout lacks the v0.9 deployment transaction")
    account = rpc(url, "eth_accounts")[0]
    transaction = rpc(url, "eth_sendTransaction", [{
        "from": account, "to": "0x4e59b44847b379578588920ca78fbf26c0b4956c",
        "data": match.group(1), "gas": "0xe4e1c0",
    }])
    for _ in range(100):
        receipt = rpc(url, "eth_getTransactionReceipt", [transaction])
        if receipt:
            break
        time.sleep(0.1)
    if not receipt or receipt["status"] != "0x1" or rpc(url, "eth_getCode", [CANONICAL_ENTRYPOINT, "latest"]) == "0x":
        raise RuntimeError("canonical v0.9 EntryPoint deployment failed")

    alto_config = json.loads((alto_dir / "test/e2e/alto-config.json").read_text())
    alto_port = port()
    alto_config.update({
        "entrypoints": CANONICAL_ENTRYPOINT,
        "rpc-url": url,
        "port": alto_port,
        "bundle-mode": "auto",
        "safe-mode": False,
        "reorg-confirmation-depth": 0,
        "executor-private-keys": alto_config["executor-private-keys"].split(",")[0],
    })
    config_path = directory / "alto.json"
    config_path.write_text(json.dumps(alto_config))
    log = (directory / "alto.log").open("w")
    node = pathlib.Path(os.environ.get("LOCAL_NODE_BIN", "node"))
    alto = subprocess.Popen([str(node), str(alto_dir / "src/esm/cli/alto.js"), "run", "--config", str(config_path)],
                            cwd=alto_dir, stdout=log, stderr=subprocess.STDOUT)
    endpoint = f"http://127.0.0.1:{alto_port}"
    try:
        for _ in range(150):
            if alto.poll() is not None:
                raise RuntimeError(f"Alto exited: {log.name}")
            try:
                rpc(endpoint, "eth_supportedEntryPoints")
                return alto, log, endpoint, transaction
            except (OSError, RuntimeError, ValueError):
                time.sleep(0.1)
        raise RuntimeError(f"Alto did not become ready: {log.name}")
    except Exception:
        alto.terminate()
        alto.wait(timeout=5)
        log.close()
        raise


def prepare_bundler(alto_dir):
    subprocess.run([sys.executable, str(ROOT / "scripts/prepare_dependencies.py")], cwd=ROOT, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=alto_dir, text=True).strip()
    if revision != ALTO_REVISION:
        raise RuntimeError("pinned Alto snapshot has the wrong revision")
    if (alto_dir / "src/esm/cli/alto.js").is_file():
        return
    env = os.environ.copy()
    node_bin = env.get("LOCAL_NODE_BIN") or shutil.which("node")
    if node_bin and pathlib.Path(node_bin).is_file():
        env["PATH"] = str(pathlib.Path(node_bin).resolve().parent) + os.pathsep + env.get("PATH", "")
    if not node_bin or not shutil.which("node", path=env.get("PATH")) or not shutil.which("pnpm", path=env.get("PATH")):
        raise RuntimeError("Node.js and pnpm are required to build the pinned external bundler")
    subprocess.run(["pnpm", "dlx", "pnpm@8.15.4", "install", "--frozen-lockfile"], cwd=alto_dir, env=env, timeout=300, check=True)
    subprocess.run(["pnpm", "dlx", "pnpm@8.15.4", "build:all"], cwd=alto_dir, env=env, timeout=600, check=True)


def response_loss_proxy(upstream):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            with urllib.request.urlopen(urllib.request.Request(upstream, body, {"Content-Type": "application/json"}), timeout=10) as reply:
                data = reply.read()
            method = json.loads(body).get("method")
            if method == "eth_sendUserOperation":
                if "result" not in json.loads(data):
                    raise RuntimeError("bundler did not accept the operation")
                self.close_connection = True
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port()), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


with tempfile.TemporaryDirectory(prefix="gasless-phase4-") as work:
    directory = pathlib.Path(work)
    pg_port, anvil_port = port(), port()
    while anvil_port == pg_port:
        anvil_port = port()
    data = directory / "pg"
    socket_dir = pathlib.Path(work) / "socket"
    socket_dir.mkdir()
    run("initdb", "-D", str(data), "-A", "trust", "--no-instructions")
    run("pg_ctl", "-D", str(data), "-o", f"-h 127.0.0.1 -p {pg_port} -F -c unix_socket_directories={socket_dir}", "-w", "start")
    anvil_log = (directory / "anvil.log").open("w")
    anvil = subprocess.Popen(
        ["anvil", "--silent", "--host", "127.0.0.1", "--port", str(anvil_port), "--chain-id", "31337"],
        cwd=ROOT, stdout=anvil_log, stderr=subprocess.STDOUT,
    )
    alto = None
    alto_log = None
    proxy = None
    try:
        run("createdb", "-h", "127.0.0.1", "-p", str(pg_port), "gasless_phase4")
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            run("psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", str(pg_port),
                "-d", "gasless_phase4", "-f", str(migration))
        url = f"http://127.0.0.1:{anvil_port}"
        wait_rpc(url, anvil)
        alto_dir = str(ROOT / "lib/alto") if "--bundler" in sys.argv else None
        if alto_dir:
            alto_dir = pathlib.Path(alto_dir).resolve()
            prepare_bundler(alto_dir)
            alto, alto_log, alto_url, entry_tx = start_external_bundler(directory, url, alto_dir)
            if "--response-lost" in sys.argv:
                proxy, alto_url = response_loss_proxy(alto_url)
        env = os.environ.copy()
        env["LOCAL_ANVIL_RPC_URL"] = url
        env["LOCAL_PG_DSN"] = f"postgres://{os.environ.get('USER', 'postgres')}@127.0.0.1:{pg_port}/gasless_phase4?sslmode=disable"
        env["LOCAL_DEPLOYMENT_METADATA"] = str(ROOT / "build" / "local-deployment.json")
        env.pop("LOCAL_BUNDLER_RPC_URL", None)
        env.pop("LOCAL_ENTRYPOINT_DEPLOYMENT_TX", None)
        if alto:
            env["LOCAL_BUNDLER_RPC_URL"] = alto_url
            env["LOCAL_ENTRYPOINT_DEPLOYMENT_TX"] = entry_tx
        env["LOCAL_DEMO_MODE"] = next((arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--mode=")), "response-lost" if "--response-lost" in sys.argv else "success")
        run("go", "run", "./cmd/localdemo", env=env)
    finally:
        if proxy:
            proxy.shutdown()
            proxy.server_close()
        if alto:
            alto.terminate()
            alto.wait(timeout=5)
        if alto_log:
            alto_log.close()
        anvil.terminate()
        try:
            anvil.wait(timeout=5)
        except subprocess.TimeoutExpired:
            anvil.kill()
            anvil.wait(timeout=5)
        anvil_log.close()
        run("pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")
