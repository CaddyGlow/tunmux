#!/usr/bin/env python3
"""Exercise reconnect and durable manual suspension with an isolated local proxy.

Uses the prepared AirVPN WGConf file; no login agent or privileged tunnel is created.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from macos_native_validation import command


def wait_state(path, previous=None, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            state = json.loads(path.read_text())
            if state.get("session_id") and state["session_id"] != previous:
                return state
        time.sleep(.1)
    raise RuntimeError("controller did not establish the expected session")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/tunmux"))
    parser.add_argument("--profile-file", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, default=Path("target/native-validation"))
    args = parser.parse_args()
    directory = args.evidence_dir.resolve() / f"autoconnect-{int(time.time())}"
    directory.mkdir(parents=True, mode=0o700)
    config = directory / "config"
    config.mkdir(mode=0o700)
    os.environ["XDG_CONFIG_HOME"] = str(config)
    binary = args.binary.resolve(strict=True)
    profile = args.profile_file.resolve(strict=True)
    base = [binary, "autoconnect"]
    report = {"result": "failed"}
    controller = None
    log = (directory / "controller.log").open("w")
    state_path = config / "tunmux/connections/auto-levua.json"
    try:
        command([*base, "enable", "levua", "--no-login-agent", "--", "connect", "wgconf", "--file", profile, "--local-proxy", "--backend", "userspace"])
        controller = subprocess.Popen([*base, "run"], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        first = wait_state(state_path)
        report["initial_session"] = first["session_id"]
        command([binary, "disconnect", first["instance_name"]])
        desired_path = config / "tunmux/desired.json"
        if not json.loads(desired_path.read_text())["entries"]["levua"]["suspended"]:
            raise RuntimeError("manual disconnect did not persist suspension")
        controller.terminate()
        controller.wait(timeout=10)
        controller = subprocess.Popen([*base, "run"], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        time.sleep(3)
        if state_path.exists():
            raise RuntimeError("controller restart ignored manual suppression")
        command([*base, "resume", "levua"])
        second = wait_state(state_path, first["session_id"])
        report["resumed_session"] = second["session_id"]
        # This PID belongs to the daemon just created by this isolated controller.
        os.kill(second["proxy_pid"], signal.SIGKILL)
        recovered = wait_state(state_path, second["session_id"])
        report["recovered_session"] = recovered["session_id"]
        if (first["socks_port"], first["http_port"]) != (recovered["socks_port"], recovered["http_port"]):
            raise RuntimeError("proxy ports changed during reconnect")
        command([binary, "disconnect", recovered["instance_name"]])
        report["result"] = "passed"
    finally:
        command([*base, "disable", "--all"], check=False)
        if controller is not None:
            controller.terminate()
            controller.wait(timeout=10)
        cleanup = command([binary, "disconnect", "--all"], check=False)
        report["cleanup_returncode"] = cleanup.returncode
        log.close()
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        for path in directory.iterdir():
            if path.is_file():
                path.chmod(0o600)
        print(f"Evidence: {directory}", flush=True)


if __name__ == "__main__":
    main()
