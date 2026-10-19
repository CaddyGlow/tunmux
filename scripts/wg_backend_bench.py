#!/usr/bin/env python3
"""Compare kernel WireGuard and tunmux's GotaTun dataplane without internet traffic."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(*args, **kwargs):
    return subprocess.run(
        args, check=True, text=True, capture_output=True, **kwargs
    ).stdout


def net(namespace, *args, **kwargs):
    return run("ip", "netns", "exec", namespace, *args, **kwargs)


def cpu_ticks(pid=None):
    if pid is not None:
        # comm can contain spaces and parentheses.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])
    fields = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:]))
    # guest time is already included in user/nice. Exclude idle and iowait.
    return sum(fields[:3]) + sum(fields[5:8])


def ping_result(output):
    match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output)
    if not match:
        raise RuntimeError(f"missing ping timing summary: {output}")
    return dict(
        zip(("min_ms", "mean_ms", "max_ms", "mdev_ms"), map(float, match.groups()))
    )


def ping_command(namespace):
    return [
        "ip",
        "netns",
        "exec",
        namespace,
        "ping",
        "-n",
        "-c",
        "10",
        "-i",
        "0.1",
        "-W",
        "1",
        "10.77.0.2",
    ]


def benchmark(args):
    # Private /run isolates ip-netns mount points and the production helper's UAPI sockets.
    run("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run")
    Path("/run/netns").mkdir()
    client, server, interface = "wgbench-client", "wgbench-server", "wgbench0"
    children = []
    rows = []
    hz = os.sysconf("SC_CLK_TCK")
    try:
        for ns in (client, server):
            run("ip", "netns", "add", ns)
            net(ns, "ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "bench-a", "type", "veth", "peer", "name", "bench-b")
        for ns, dev, address in (
            (client, "bench-a", "192.0.2.1/24"),
            (server, "bench-b", "192.0.2.2/24"),
        ):
            run("ip", "link", "set", dev, "netns", ns)
            net(ns, "ip", "addr", "add", address, "dev", dev)
            net(ns, "ip", "link", "set", dev, "up")

        with tempfile.TemporaryDirectory(prefix="tunmux-wg-keys-") as secrets:
            keys = []
            for name in ("client", "server"):
                private = run("wg", "genkey")
                path = Path(secrets) / name
                path.write_text(private)
                path.chmod(0o600)
                keys.append((str(path), run("wg", "pubkey", input=private).strip()))

            net(server, "ip", "link", "add", interface, "type", "wireguard")
            net(
                server,
                "wg",
                "set",
                interface,
                "private-key",
                keys[1][0],
                "listen-port",
                "51820",
                "peer",
                keys[0][1],
                "allowed-ips",
                "10.77.0.1/32",
            )
            net(server, "ip", "addr", "add", "10.77.0.2/24", "dev", interface)
            net(server, "ip", "link", "set", interface, "mtu", str(args.mtu), "up")
            iperf = subprocess.Popen(
                ["ip", "netns", "exec", server, "iperf3", "-s", "-B", "10.77.0.2"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            children.append(iperf)

            # Alternate order each round to reduce bias from heat and background load.
            for repeat in range(args.repeats):
                order = (
                    ("kernel", "userspace")
                    if repeat % 2 == 0
                    else ("userspace", "kernel")
                )
                for backend in order:
                    # A fresh client must not inherit the server's previous
                    # session keys and remembered UDP endpoint.
                    net(server, "wg", "set", interface, "peer", keys[0][1], "remove")
                    net(
                        server,
                        "wg",
                        "set",
                        interface,
                        "peer",
                        keys[0][1],
                        "allowed-ips",
                        "10.77.0.1/32",
                    )
                    helper_pid = None
                    if backend == "kernel":
                        net(client, "ip", "link", "add", interface, "type", "wireguard")
                    else:
                        env = os.environ.copy()
                        env.pop("TUNMUX_GOTATUN_CONFIG_B64", None)
                        env["TUNMUX_GOTATUN_HELPER"] = "1"
                        net(client, str(args.bin), interface, env=env, timeout=65)
                        helper_pid = int(run("ip", "netns", "pids", client).strip())
                    net(
                        client,
                        "wg",
                        "set",
                        interface,
                        "private-key",
                        keys[0][0],
                        "peer",
                        keys[1][1],
                        "allowed-ips",
                        "10.77.0.2/32",
                        "endpoint",
                        "192.0.2.2:51820",
                    )
                    net(client, "ip", "addr", "add", "10.77.0.1/24", "dev", interface)
                    net(
                        client,
                        "ip",
                        "link",
                        "set",
                        interface,
                        "mtu",
                        str(args.mtu),
                        "up",
                    )
                    # Trigger the handshake before collecting measurements.
                    for attempt in range(10):
                        try:
                            net(client, "ping", "-n", "-c", "1", "-W", "1", "10.77.0.2")
                            break
                        except subprocess.CalledProcessError:
                            if attempt == 9:
                                raise
                    idle = ping_result(run(*ping_command(client)))
                    for direction in ("upload", "download"):
                        command = [
                            "ip",
                            "netns",
                            "exec",
                            client,
                            "iperf3",
                            "-c",
                            "10.77.0.2",
                            "-J",
                            "-t",
                            str(args.seconds),
                            "-P",
                            str(args.streams),
                        ]
                        if direction == "download":
                            command.append("-R")
                        loaded_ping = subprocess.Popen(
                            ping_command(client),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        children.append(loaded_ping)
                        start_cpu = cpu_ticks()
                        start_helper = cpu_ticks(helper_pid) if helper_pid else 0
                        start = time.monotonic()
                        result = json.loads(run(*command, timeout=args.seconds + 20))
                        elapsed = time.monotonic() - start
                        host_cpu = (cpu_ticks() - start_cpu) / hz / elapsed * 100
                        helper_cpu = (
                            (cpu_ticks(helper_pid) - start_helper) / hz / elapsed * 100
                            if helper_pid
                            else None
                        )
                        ping_out, ping_err = loaded_ping.communicate(timeout=15)
                        if loaded_ping.returncode:
                            raise RuntimeError(
                                f"loaded ping failed: {ping_out} {ping_err}"
                            )
                        if "error" in result:
                            raise RuntimeError(result["error"])
                        row = {
                            "backend": backend,
                            "round": repeat + 1,
                            "direction": direction,
                            "mbps": result["end"]["sum_received"]["bits_per_second"]
                            / 1e6,
                            "host_busy_cpu_pct": host_cpu,
                            "helper_cpu_pct": helper_cpu,
                            "idle_ping": idle,
                            "loaded_ping": ping_result(ping_out),
                            "iperf": result,
                        }
                        rows.append(row)
                        print(
                            f"{backend:9} {direction:8} round={repeat + 1} {row['mbps']:9.1f} Mbps idle={idle['mean_ms']:.3f} ms loaded={row['loaded_ping']['mean_ms']:.3f} ms host_cpu={host_cpu:.1f}% helper_cpu={helper_cpu}",
                            flush=True,
                        )
                    if helper_pid:
                        os.kill(helper_pid, signal.SIGTERM)
                        for _ in range(100):
                            if not Path(f"/proc/{helper_pid}").exists():
                                break
                            time.sleep(0.05)
                        else:
                            raise RuntimeError(
                                "userspace helper did not stop within 5 seconds"
                            )
                    else:
                        net(client, "ip", "link", "del", interface)
    finally:
        for ns in (client, server):
            pids = (
                run("ip", "netns", "pids", ns).split()
                if run("ip", "netns", "list").find(ns) >= 0
                else []
            )
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            subprocess.run(["ip", "netns", "del", ns], capture_output=True, check=False)
        for child in children:
            child.wait(timeout=5)
        report = {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "binary_sha256": hashlib.sha256(args.bin.read_bytes()).hexdigest(),
            "seconds": args.seconds,
            "streams": args.streams,
            "mtu": args.mtu,
            "requested_repeats": args.repeats,
            "complete": len(rows) == 4 * args.repeats,
            "cpu_note": "One core = 100%. Host busy CPU includes both peers and unrelated host activity; helper CPU is client GotaTun only.",
            "samples": rows,
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Raw results: {args.output}", flush=True)

    print("\nMedian throughput:")
    for direction in ("upload", "download"):
        values = {
            backend: statistics.median(
                row["mbps"]
                for row in rows
                if row["backend"] == backend and row["direction"] == direction
            )
            for backend in ("kernel", "userspace")
        }
        print(
            f"{direction}: kernel={values['kernel']:.1f} Mbps userspace={values['userspace']:.1f} Mbps ratio={values['userspace'] / values['kernel']:.2f}x"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True, help="Release tunmux binary")
    parser.add_argument(
        "--seconds",
        type=int,
        default=5,
        help="Seconds per throughput sample (default: 5)",
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--mtu", type=int, default=1420)
    parser.add_argument("--output", type=Path, default=Path("wg-backend-results.json"))
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.seconds, args.repeats, args.streams) < 1 or not 576 <= args.mtu <= 1500:
        parser.error("seconds/repeats/streams must be positive; MTU must be 576..1500")
    args.bin = args.bin.resolve()
    args.output = args.output.resolve()
    if not args.bin.is_file() or not os.access(args.bin, os.X_OK):
        parser.error("--bin must be an executable release tunmux binary")
    if not args.inside:
        if platform.system() != "Linux" or not Path("/dev/net/tun").exists():
            parser.error("requires Linux with /dev/net/tun")
        paths = []
        for tool in ("ip", "wg", "iperf3", "ping", "mount", "unshare"):
            path = shutil.which(tool)
            if path is None:
                parser.error(f"missing required tool: {tool}")
            paths.append(str(Path(path).resolve().parent))
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        env["PATH"] = os.pathsep.join(paths + [env.get("PATH", "")])
        env["TUNMUX_BENCH_OUTER_MNT_NS"] = os.readlink("/proc/self/ns/mnt")
        command = ["unshare", "--mount", "--net", "--fork"]
        if os.geteuid() != 0:
            command += ["--user", "--map-root-user"]
        command += [
            str(Path(sys.executable).resolve()),
            str(Path(__file__).resolve()),
            *sys.argv[1:],
            "--inside",
        ]
        os.execvpe(command[0], command, env)
    if os.environ.get("TUNMUX_BENCH_OUTER_MNT_NS") in (
        None,
        os.readlink("/proc/self/ns/mnt"),
    ):
        parser.error("internal runner requires its own mount namespace")
    benchmark(args)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.SubprocessError, OSError, RuntimeError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
