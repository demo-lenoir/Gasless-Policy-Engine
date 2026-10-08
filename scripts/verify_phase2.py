#!/usr/bin/env python3
"""Run forward migrations and admission tests against disposable PostgreSQL databases."""

import os
import pathlib
import socket
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args, env=None):
    subprocess.run(args, cwd=ROOT, env=env, check=True)


with tempfile.TemporaryDirectory(prefix="gasless-pg-") as work:
    data = pathlib.Path(work) / "data"
    socket_dir = pathlib.Path(work) / "socket"
    socket_dir.mkdir()
    run("initdb", "-D", str(data), "-A", "trust", "--no-instructions")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    run("pg_ctl", "-D", str(data), "-o", f"-h 127.0.0.1 -p {port} -F -c unix_socket_directories={socket_dir}", "-w", "start")
    try:
        for database in ("gasless_one", "gasless_two"):
            run("createdb", "-h", "127.0.0.1", "-p", str(port), database)
            for migration in sorted((ROOT / "migrations").glob("*.sql")):
                run("psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", str(port),
                    "-d", database, "-f", str(migration))
            schema_count = subprocess.check_output(("psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", str(port),
                "-d", database, "-Atc", "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('sponsorship_requests','sponsorship_reservations','budget_periods','audit_events','policy_versions','service_controls') AND (SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN ('sponsorship_requests_client_scope_idempotency_key_key','sponsorship_reservations_expiry_idx','audit_events_sponsorship_idx'))=3 AND (SELECT count(*) FROM pg_constraint WHERE conname IN ('budget_periods_scope_identity_check','budget_periods_count_identity_check','sponsorship_requests_decision_check','audit_events_sponsorship_fk'))=4"), text=True).strip()
            if schema_count != "6":
                raise RuntimeError(f"migration schema incomplete in {database}: {schema_count}")
        env = os.environ.copy()
        env["PG_TEST_DSN"] = f"postgres://{os.environ.get('USER', 'postgres')}@127.0.0.1:{port}/gasless_one?sslmode=disable"
        run("go", "test", "-count=1", "./internal/store", env=env)
        run("go", "test", "-race", "-count=1", "./internal/store", env=env)
    finally:
        run("pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")
