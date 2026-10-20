#!/usr/bin/env python3
"""Native macOS evidence collection and supervised VPN lifecycle checks.

Never records the supplied WireGuard configuration or credentials. Run as the login
user; --admin-dialog authorizes only explicit administrator operations via macOS.
"""
import argparse
import datetime
import json
import os
import pwd
import re
from pathlib import Path
import shlex
import signal
import subprocess
import time


LOGIN_USER = None
CLI_BINARY = None
CLI_CONFIG_PARENT = None


def command(argv, timeout=180, check=True, as_login_user=False):
    argv = [str(a) for a in argv]
    if LOGIN_USER is not None and CLI_BINARY is not None and (argv[0] == str(CLI_BINARY) or as_login_user):
        argv = ["/usr/bin/sudo", "-H", "-u", f"#{LOGIN_USER}", "--", "/usr/bin/env", f"XDG_CONFIG_HOME={CLI_CONFIG_PARENT}", *argv]
    result = subprocess.run([str(a) for a in argv], text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{shlex.join([str(a) for a in argv])}: {result.stderr.strip()}")
    return result


def administrator(argv, dialog):
    if os.geteuid() == 0:
        return command(argv)
    if not dialog:
        return command(["/usr/bin/sudo", "-n", "--", *argv])
    shell = shlex.join([str(a) for a in argv])
    literal = '"' + shell.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return command(["/usr/bin/osascript", "-e", f"do shell script {literal} with administrator privileges"], timeout=300)


def dns_snapshot():
    listing = command(["/usr/sbin/networksetup", "-listallnetworkservices"]).stdout
    if not listing.strip() or "AuthorizationCreate" in listing:
        raise RuntimeError("networksetup could not enumerate services; run outside the sandbox or under sudo")
    result = {}
    for service in listing.splitlines()[1:]:
        if not service or service.startswith("*"):
            continue
        result[service] = {kind: command(["/usr/sbin/networksetup", option, service]).stdout.strip()
                           for kind, option in [("dns", "-getdnsservers"), ("search", "-getsearchdomains")]}
    return result


def snapshot(directory, label, binary):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "dns": dns_snapshot()}
    for name, args in {
        "routes": ["/usr/sbin/netstat", "-rn"],
        "default_ipv4": ["/sbin/route", "-n", "get", "default"],
        "default_ipv6": ["/sbin/route", "-n", "get", "-inet6", "default"],
        "interfaces": ["/sbin/ifconfig", "-a"],
        "status": [binary, "status"],
    }.items():
        observed = command(args, check=False)
        result[name] = {"returncode": observed.returncode, "stdout": observed.stdout, "stderr": observed.stderr}
    path = directory / f"{label}.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    path.chmod(0o600)
    return result


def wait_for_network(directory, timeout=60):
    """Wait for physical routing and tunnel traffic after an operator transition."""
    started = time.monotonic()
    deadline = started + timeout
    previous = None
    consecutive = 0
    attempts = []
    try:
        while time.monotonic() < deadline:
            route = command(["/sbin/route", "-n", "get", "default"], timeout=3, check=False)
            gateway = re.search(r"^\s*gateway:\s*(\S+)", route.stdout, re.MULTILINE)
            interface = re.search(r"^\s*interface:\s*(\S+)", route.stdout, re.MULTILINE)
            current = (gateway.group(1), interface.group(1)) if gateway and interface else None
            attempt = {"elapsed_seconds": time.monotonic() - started, "default": current,
                       "route_stderr": route.stderr}
            attempts.append(attempt)
            if current is not None and current == previous:
                ping = command(["/sbin/ping", "-c", "1", "-W", "1000", "1.1.1.1"], timeout=3, check=False, as_login_user=True)
                attempt["ping"] = {"returncode": ping.returncode, "stdout": ping.stdout, "stderr": ping.stderr}
                consecutive = consecutive + 1 if ping.returncode == 0 else 0
                if consecutive >= 3:
                    return time.monotonic() - started
            else:
                consecutive = 0
            previous = current
            time.sleep(1)
        raise RuntimeError("network did not recover within 60 seconds: no stable IPv4 default route with successful tunnel ping; see transition-wait.json")
    finally:
        (directory / "transition-wait.json").write_text(json.dumps(attempts, indent=2) + "\n")


def wait_state(path, previous=None, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            state = json.loads(path.read_text())
            if state.get("session_id") and state["session_id"] != previous:
                return state
        time.sleep(.1)
    raise RuntimeError("controller did not establish the expected session")


def autoconnect(args):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/tunmux"))
    parser.add_argument("--profile-file", type=Path)
    parser.add_argument("--scenario", choices=["snapshot", "disconnect", "sigterm", "crash", "dns-conflict", "network-switch", "sleep-resume", "lan", "local-proxy", "autoconnect", "suite"], default="snapshot")
    parser.add_argument("--evidence-dir", type=Path, default=Path("target/native-validation/evidence"))
    parser.add_argument("--admin-dialog", action="store_true")
    parser.add_argument("--login-user", type=int, help="when running under sudo, run tunmux as this login UID")
    parser.add_argument("--install", action="store_true", help="root only: install the supplied build before running tests")
    parser.add_argument("--with-transitions", action="store_true", help="include supervised network switching and sleep/resume in the suite")
    parser.add_argument("--dns-service", help="explicit active service for the DNS conflict scenario")
    parser.add_argument("--conflict-dns", help="operator-selected DNS address to install as an external change")
    args = parser.parse_args()
    if os.uname().sysname != "Darwin":
        parser.error("native macOS host required")
    if args.scenario == "autoconnect":
        if os.geteuid() == 0 or args.install or args.login_user is not None:
            parser.error("autoconnect must run as the login user without --install or --login-user")
        if args.profile_file is None:
            parser.error("autoconnect requires --profile-file")
        autoconnect(args)
        return
    global LOGIN_USER, CLI_BINARY, CLI_CONFIG_PARENT
    binary = args.binary.resolve(strict=True)
    source_binary = binary
    if os.geteuid() == 0:
        if args.login_user is None:
            parser.error("root execution requires --login-user to preserve user-owned connection state")
        LOGIN_USER = args.login_user
        CLI_BINARY = binary
        CLI_CONFIG_PARENT = Path(pwd.getpwuid(LOGIN_USER).pw_dir) / ".config"
    if args.install:
        if os.geteuid() != 0:
            parser.error("--install requires running under sudo with --login-user")
        subprocess.run([str(binary), "service", "install", "--user", str(LOGIN_USER)], check=True, timeout=240)
        binary = Path("/usr/local/libexec/tunmux")
        CLI_BINARY = binary
    if args.scenario == "suite":
        if os.geteuid() != 0:
            parser.error("suite requires sudo and --login-user, so signals and DNS changes need no additional dialog")
        if args.profile_file is None:
            parser.error("suite requires --profile-file")
        unauthorized_probe = "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect('/var/run/tunmux/ctl.sock')\nexcept PermissionError:\n sys.exit(0)\nexcept OSError as e:\n print(e);sys.exit(2)\nelse:\n print('unauthorized socket connection succeeded');sys.exit(1)"
        # The unprivileged account cannot traverse the operator's private checkout.
        # Start in a public directory so Python reaches the socket permission probe.
        subprocess.run(["/usr/bin/sudo", "-H", "-u", "nobody", "--", "/usr/bin/python3", "-I", "-c", unauthorized_probe], cwd="/", check=True, timeout=10)
        scenarios = ["disconnect", "sigterm", "crash", "lan"]
        if args.dns_service and args.conflict_dns:
            scenarios.append("dns-conflict")
        if args.with_transitions:
            scenarios.extend(["network-switch", "sleep-resume"])
        for scenario in scenarios:
            argv = ["/usr/bin/python3", str(Path(__file__).resolve()), "--binary", str(binary), "--profile-file", str(args.profile_file.resolve()), "--scenario", scenario, "--login-user", str(LOGIN_USER), "--evidence-dir", str(args.evidence_dir)]
            if args.dns_service:
                argv.extend(["--dns-service", args.dns_service])
            if args.conflict_dns:
                argv.extend(["--conflict-dns", args.conflict_dns])
            subprocess.run(argv, check=True)
        if args.install and source_binary != binary:
            # Exercise teardown before maintenance while retaining the source build
            # so the service can be restored immediately after uninstall.
            base_connect = [binary, "connect", "wgconf", "--file", args.profile_file.resolve(), "--backend", "userspace"]
            command(base_connect)
            try:
                subprocess.run([str(binary), "service", "reload"], check=True, timeout=180)
            finally:
                command([binary, "disconnect", "--all"], check=False)
            command(base_connect)
            try:
                subprocess.run([str(binary), "service", "uninstall"], check=True, timeout=180)
            finally:
                # Restore the installation even when an uninstall check fails.
                subprocess.run([str(source_binary), "service", "install", "--user", str(LOGIN_USER)], check=True, timeout=240)
                command([binary, "disconnect", "--all"], check=False)
            scenarios.extend(["live-reload", "live-uninstall-and-reinstall"])
        summary = args.evidence_dir / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-suite.json")
        summary.parent.mkdir(parents=True, exist_ok=True)
        summary.write_text(json.dumps({"result": "passed", "scenarios": ["unauthorized-socket-access", *scenarios]}, indent=2) + "\n")
        summary.chmod(0o600)
        os.chown(summary, LOGIN_USER, pwd.getpwuid(LOGIN_USER).pw_gid)
        print("Native suite passed: " + ", ".join(scenarios), flush=True)
        print(f"Suite summary: {summary}", flush=True)
        return
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = args.evidence_dir / f"{stamp}-{args.scenario}"
    before = snapshot(directory, "before", binary)
    if args.scenario == "snapshot":
        print(f"Snapshot: {directory}")
        return
    if args.profile_file is None:
        parser.error("--profile-file is required for live scenarios")
    if args.scenario == "dns-conflict" and not (args.dns_service and args.conflict_dns):
        parser.error("DNS conflict requires --dns-service and --conflict-dns")
    status = before["status"]["stdout"]
    if "No active connections." not in status:
        raise RuntimeError("existing connection state must be resolved before native validation")
    config_root = (CLI_CONFIG_PARENT if LOGIN_USER is not None else Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))) / "tunmux"
    if (config_root / "desired.json").exists():
        desired = json.loads((config_root / "desired.json").read_text())
        if any(not entry["suspended"] for entry in desired.get("entries", {}).values()):
            raise RuntimeError("suspend existing autoconnect entries before validation")
    connect = [binary, "connect", "wgconf", "--file", args.profile_file.resolve(strict=True), "--backend", "userspace"]
    if args.scenario == "local-proxy":
        connect += ["--local-proxy"]
    if args.scenario == "lan":
        connect += ["--allow-lan"]
    connected = False
    dns_changed = False
    report = {"scenario": args.scenario, "result": "failed"}
    try:
        start = time.monotonic()
        output = command(connect)
        connected = True
        report["connect_seconds"] = time.monotonic() - start
        (directory / "connect.log").write_text(output.stdout + output.stderr)
        state = json.loads(next((config_root / "connections").glob("*.json")).read_text())
        instance = state["instance_name"]
        initial = state["session_id"]
        repeated = command([*connect, "--if-missing"])
        if json.loads((config_root / "connections" / f"{instance}.json").read_text())["session_id"] != initial:
            raise RuntimeError("--if-missing replaced the active session")
        report["if_missing"] = repeated.stdout.strip()
        connected_snapshot = snapshot(directory, "connected", binary)
        if args.scenario != "local-proxy":
            before_interfaces = set(re.findall(r"^([^\s:]+): flags=", before["interfaces"]["stdout"], re.MULTILINE))
            new_interfaces = {name: int(mtu) for name, mtu in re.findall(r"^([^\s:]+): flags=.*?mtu (\d+)", connected_snapshot["interfaces"]["stdout"], re.MULTILINE) if name not in before_interfaces}
            mtu_match = re.search(r"(?im)^\s*MTU\s*=\s*(\d+)", args.profile_file.read_text())
            if mtu_match:
                expected_mtu = int(mtu_match.group(1))
                if expected_mtu not in new_interfaces.values():
                    raise RuntimeError("actual tunnel interface MTU does not match the profile")
                report["interface_mtu"] = expected_mtu
        if args.scenario in ("sigterm", "crash"):
            socket = Path("/var/run/wireguard") / (state["interface_name"] + ".sock")
            pids = administrator(["/usr/sbin/lsof", "-t", "--", socket], args.admin_dialog).stdout.split()
            if len(set(pids)) != 1 or not pids[0].isdigit():
                raise RuntimeError("could not uniquely identify the helper owning its UAPI socket")
            administrator(["/bin/kill", "-TERM" if args.scenario == "sigterm" else "-KILL", pids[0]], args.admin_dialog)
            deadline = time.monotonic() + 70
            while time.monotonic() < deadline:
                observed = command([binary, "status"]).stdout
                if "inactive" in observed:
                    break
                time.sleep(.25)
            else:
                raise RuntimeError("helper did not become confirmed inactive")
            snapshot(directory, "after-signal", binary)
            journal = Path("/var/run/wireguard") / (state["interface_name"] + ".recovery.json")
            report["journal_after_signal"] = journal.exists()
            if args.scenario == "crash" and not journal.exists():
                raise RuntimeError("crash did not retain its recovery journal")
            command(connect)
            recovered = json.loads((config_root / "connections" / f"{instance}.json").read_text())
            if recovered["session_id"] == initial:
                raise RuntimeError("recovery did not establish a fresh session")
        elif args.scenario == "dns-conflict":
            administrator(["/usr/sbin/networksetup", "-setdnsservers", args.dns_service, args.conflict_dns], args.admin_dialog)
            dns_changed = True
            result = command([binary, "disconnect", instance], check=False)
            current = command(["/usr/sbin/networksetup", "-getdnsservers", args.dns_service]).stdout.strip()
            if current != args.conflict_dns or result.returncode == 0:
                raise RuntimeError("DNS conflict was overwritten or reported as successful cleanup")
            report["conflict_preserved"] = True
            snapshot(directory, "dns-conflict-preserved", binary)
            # Restore the helper-owned DNS so the retained journal can safely retry cleanup.
            administrator(["/usr/sbin/networksetup", "-setdnsservers", args.dns_service, *state["dns_servers"]], args.admin_dialog)
        elif args.scenario in ("network-switch", "sleep-resume"):
            transition = "Switch between Wi-Fi and Ethernet" if args.scenario == "network-switch" else "Put the Mac to sleep, then wake it"
            print(f"{transition} now, then press Enter when the network has settled.", flush=True)
            input()
            print("Waiting up to 60 seconds for routing and tunnel connectivity...", flush=True)
            report["transition_wait_seconds"] = wait_for_network(directory)
            snapshot(directory, "after-transition", binary)
            connectivity = command([binary, "hook", "run", "connectivity"], check=False)
            (directory / "connectivity.log").write_text(connectivity.stdout + connectivity.stderr)
            report["connectivity_returncode"] = connectivity.returncode
            if connectivity.returncode:
                # Retain independent login-user probes while the failing session
                # still exists, before the finally block performs cleanup.
                probes = {}
                for name, argv in [
                    ("ping", ["/sbin/ping", "-c", "5", "-W", "1000", "1.1.1.1"]),
                    ("https", ["/usr/bin/curl", "-4", "--silent", "--show-error", "--max-time", "10", "https://1.1.1.1/cdn-cgi/trace"]),
                ]:
                    observed = command(argv, timeout=15, check=False, as_login_user=True)
                    probes[name] = {"returncode": observed.returncode, "stdout": observed.stdout, "stderr": observed.stderr}
                (directory / "connectivity-failure.json").write_text(json.dumps(probes, indent=2) + "\n")
                snapshot(directory, "connectivity-failed", binary)
                raise RuntimeError("post-transition connectivity hook failed; see connectivity.log and connectivity-failure.json")
        start = time.monotonic()
        command([binary, "disconnect", instance], timeout=75)
        report["disconnect_seconds"] = time.monotonic() - start
        if report["disconnect_seconds"] > 70:
            raise RuntimeError("disconnect exceeded the documented bound")
        connected = False
        if args.scenario != "local-proxy" and (Path("/var/run/wireguard") / (state["interface_name"] + ".recovery.json")).exists():
            raise RuntimeError("disconnect left an unfinished recovery journal")
        after = snapshot(directory, "after", binary)
        if args.scenario not in ("network-switch", "sleep-resume") and before["dns"] != after["dns"]:
            raise RuntimeError("DNS/search-domain state differs from baseline")
        report["result"] = "passed"
    finally:
        if connected:
            cleanup = command([binary, "disconnect", "--provider", "wgconf", "--all"], timeout=75, check=False)
            report["cleanup_returncode"] = cleanup.returncode
        if dns_changed:
            baseline = before["dns"][args.dns_service]["dns"]
            values = ["Empty"] if baseline.startswith("There aren't any") else baseline.splitlines()
            administrator(["/usr/sbin/networksetup", "-setdnsservers", args.dns_service, *values], args.admin_dialog)
        (directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        for path in directory.iterdir():
            path.chmod(0o600)
            if LOGIN_USER is not None:
                os.chown(path, LOGIN_USER, pwd.getpwuid(LOGIN_USER).pw_gid)
        if LOGIN_USER is not None:
            os.chown(directory, LOGIN_USER, pwd.getpwuid(LOGIN_USER).pw_gid)
        print(f"Evidence: {directory}", flush=True)


if __name__ == "__main__":
    main()
