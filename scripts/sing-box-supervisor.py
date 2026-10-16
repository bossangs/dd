#!/usr/bin/env python3
"""Run sing-box and apply validated config-file changes without Docker socket access."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

BINARY = Path(os.getenv("SINGBOX_BINARY", "/usr/local/bin/sing-box"))
CONFIG_FILE = Path(os.getenv("SINGBOX_CONFIG_FILE", "/etc/sing-box/config.json"))
DATA_DIR = Path(os.getenv("SINGBOX_DATA_DIR", "/var/lib/sing-box"))
STATE_FILE = Path(os.getenv("SINGBOX_STATE_FILE", "/var/lib/sing-box/supervisor.json"))
POLL_SECONDS = 0.5
START_GRACE_SECONDS = 2.0
STOP_GRACE_SECONDS = 10.0
stopping = False


def log(message: str) -> None:
    print(f"{datetime.now(timezone.utc).isoformat()} sing-box-supervisor: {message}", flush=True)


def read_config() -> bytes:
    return CONFIG_FILE.read_bytes()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_state(state: str, active_hash: str | None, requested_hash: str | None = None,
                error: str | None = None) -> None:
    payload = {
        "state": state,
        "config_sha256": active_hash,
        "requested_sha256": requested_hash,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "error": error[:1000] if error else None,
    }
    try:
        atomic_write(STATE_FILE, json.dumps(payload, ensure_ascii=False).encode("utf-8"), 0o644)
    except Exception as exc:
        log(f"failed to write state file: {exc}")


def check_config() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [str(BINARY), "-D", str(DATA_DIR), "check", "-c", str(CONFIG_FILE)],
            cwd=str(CONFIG_FILE.parent), capture_output=True, text=True, timeout=30,
            check=False,
        )
    except Exception as exc:
        return False, f"configuration check could not run: {exc}"
    output = (result.stdout + "\n" + result.stderr).strip()
    return result.returncode == 0, output or ("configuration check passed" if result.returncode == 0 else "configuration check failed")


def start_core() -> subprocess.Popen:
    return subprocess.Popen(
        [str(BINARY), "-D", str(DATA_DIR), "-c", str(CONFIG_FILE), "run"],
        cwd=str(CONFIG_FILE.parent), stdout=sys.stdout, stderr=sys.stderr,
        start_new_session=False,
    )


def stop_core(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        log("sing-box did not stop gracefully; sending SIGKILL")
        process.kill()
        process.wait(timeout=3)


def handle_signal(signum, _frame) -> None:
    global stopping
    stopping = True
    log(f"received signal {signum}; stopping")


def supervise() -> int:
    global stopping
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    process: subprocess.Popen | None = None
    active_bytes: bytes | None = None
    active_hash: str | None = None
    rejected_hash: str | None = None
    retry_after = 0.0

    while not stopping:
        try:
            requested_bytes = read_config()
            requested_hash = digest(requested_bytes)
        except Exception as exc:
            write_state("error", active_hash, error=f"cannot read config: {exc}")
            time.sleep(2)
            continue

        if (requested_hash == active_hash and rejected_hash is not None
                and process is not None and process.poll() is None):
            rejected_hash = None
            write_state("running", active_hash)

        if requested_hash != active_hash and requested_hash != rejected_hash:
            write_state("validating", active_hash, requested_hash)
            valid, message = check_config()
            if not valid:
                rejected_hash = requested_hash
                write_state("invalid", active_hash, requested_hash, message)
                log(f"config check failed: {message}")
                time.sleep(POLL_SECONDS)
                continue

            previous_bytes = active_bytes
            write_state("restarting", active_hash, requested_hash)
            stop_core(process)
            process = None
            try:
                process = start_core()
                deadline = time.monotonic() + START_GRACE_SECONDS
                while time.monotonic() < deadline and process.poll() is None and not stopping:
                    time.sleep(0.1)
                if process.poll() is not None:
                    exit_code = process.returncode
                    process = None
                    if previous_bytes is not None:
                        atomic_write(CONFIG_FILE, previous_bytes)
                        active_bytes = previous_bytes
                        active_hash = digest(previous_bytes)
                        rejected_hash = requested_hash
                        valid, rollback_message = check_config()
                        if valid:
                            process = start_core()
                            time.sleep(START_GRACE_SECONDS)
                            if process.poll() is None:
                                rejected_hash = None
                                write_state("rolled_back", active_hash, requested_hash,
                                            f"new config exited during startup (code {exit_code}); restored previous config. {message}")
                                log("new config failed at runtime; restored last active config")
                                continue
                        write_state("failed", active_hash, requested_hash,
                                    f"new config exited during startup (code {exit_code}); rollback failed: {rollback_message}")
                        retry_after = time.monotonic() + 5
                        continue
                    write_state("failed", None, requested_hash,
                                f"sing-box exited during initial startup (code {exit_code})")
                    rejected_hash = requested_hash
                    continue
                active_bytes = requested_bytes
                active_hash = requested_hash
                rejected_hash = None
                write_state("running", active_hash, requested_hash)
                log(f"sing-box running with config sha256={active_hash}")
            except Exception as exc:
                if previous_bytes is not None:
                    atomic_write(CONFIG_FILE, previous_bytes)
                    active_bytes = previous_bytes
                    active_hash = digest(previous_bytes)
                    rejected_hash = requested_hash
                    try:
                        process = start_core()
                        time.sleep(START_GRACE_SECONDS)
                    except Exception:
                        process = None
                    write_state("rolled_back", active_hash, requested_hash, str(exc))
                else:
                    write_state("failed", active_hash, requested_hash, str(exc))
                log(f"failed to start sing-box: {exc}")
                continue

        if process is None and time.monotonic() >= retry_after and requested_hash == active_hash:
            valid, message = check_config()
            if valid:
                try:
                    process = start_core()
                    time.sleep(START_GRACE_SECONDS)
                    if process.poll() is None:
                        write_state("running", active_hash)
                    else:
                        code = process.returncode
                        process = None
                        retry_after = time.monotonic() + 5
                        write_state("failed", active_hash, error=f"sing-box exited during restart (code {code})")
                except Exception as exc:
                    retry_after = time.monotonic() + 5
                    write_state("failed", active_hash, error=str(exc))
            else:
                retry_after = time.monotonic() + 5
                write_state("invalid", active_hash, requested_hash, message)

        if process is not None and process.poll() is not None:
            code = process.returncode
            process = None
            retry_after = time.monotonic() + 5
            write_state("failed", active_hash, error=f"sing-box exited unexpectedly (code {code}); retrying")
            log(f"sing-box exited unexpectedly (code {code}); retrying in 5 seconds")

        time.sleep(POLL_SECONDS)

    stop_core(process)
    write_state("stopped", active_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(supervise())
