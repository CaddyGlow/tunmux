//! Explicit, isolated Linux dataplane benchmark; never part of normal CI.
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{sysconf, Pid, SysconfVar, Uid};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CLIENT: &str = "wgbench-client";
const SERVER: &str = "wgbench-server";
const IFACE: &str = "wgbench0";
const OUTER_NS: &str = "TUNMUX_BENCH_OUTER_MNT_NS";

struct Options {
    binary: PathBuf,
    output: PathBuf,
    seconds: u32,
    repeats: u32,
    streams: u32,
    mtu: u32,
    inside: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Self {
            binary: PathBuf::new(),
            output: "wg-backend-results.json".into(),
            seconds: 5,
            repeats: 3,
            streams: 1,
            mtu: 1420,
            inside: false,
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg == "--inside" {
                opts.inside = true;
                continue;
            }
            let value = args
                .next()
                .with_context(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--bin" => opts.binary = value.into(),
                "--output" => opts.output = value.into(),
                "--seconds" => opts.seconds = value.parse()?,
                "--repeats" => opts.repeats = value.parse()?,
                "--streams" => opts.streams = value.parse()?,
                "--mtu" => opts.mtu = value.parse()?,
                _ => bail!("unknown option {arg}"),
            }
        }
        ensure!(!opts.binary.as_os_str().is_empty(), "--bin is required");
        ensure!(opts.seconds > 0 && opts.seconds <= u32::MAX - 20 && opts.repeats > 0 && opts.streams > 0, "seconds/repeats/streams must be positive and seconds must allow a 20-second timeout margin");
        ensure!((576..=1500).contains(&opts.mtu), "MTU must be 576..1500");
        Ok(opts)
    }
}

pub fn main(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: cargo xtask bench-wg --bin <release-tunmux> [OPTIONS]\n\nCompare kernel WireGuard and GotaTun using isolated local peers (no VPN account).\nRequires Linux, /dev/net/tun, ip, wg, iperf3, ping, mount and unshare.\nRun as a user with unprivileged namespaces enabled, or as root.\n\n  --seconds N   Seconds per sample (default: 5)\n  --repeats N   Rounds, alternating backend order (default: 3)\n  --streams N   Parallel iperf streams (default: 1)\n  --mtu N       Interface MTU, 576..1500 (default: 1420)\n  --output PATH JSON evidence (default: wg-backend-results.json)");
        return Ok(());
    }
    let mut opts = Options::parse(args)?;
    opts.binary = opts.binary.canonicalize().context("resolve --bin")?;
    ensure!(
        opts.binary.is_file() && fs::metadata(&opts.binary)?.permissions().mode() & 0o111 != 0,
        "--bin must be executable"
    );
    opts.output = std::path::absolute(&opts.output)?;
    if !opts.inside {
        ensure!(Path::new("/dev/net/tun").exists(), "requires /dev/net/tun");
        let mut paths = Vec::new();
        for tool in ["ip", "wg", "iperf3", "ping", "mount", "unshare"] {
            let found = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|p| p.join(tool))
                .find(|p| {
                    fs::metadata(p)
                        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                })
                .with_context(|| format!("missing required tool: {tool}"))?
                .canonicalize()?;
            if let Some(parent) = found.parent() {
                paths.push(parent.to_owned());
            }
        }
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let mut command = Command::new("unshare");
        // PID namespace teardown also contains daemonized helpers after interruption.
        command.args([
            "--mount",
            "--net",
            "--pid",
            "--mount-proc",
            "--fork",
            "--kill-child",
        ]);
        if !Uid::effective().is_root() {
            command.args(["--user", "--map-root-user"]);
        }
        let status = command
            .arg(std::env::current_exe()?)
            .arg("bench-wg")
            .args(args)
            .arg("--inside")
            .env("LC_ALL", "C")
            .env("PATH", std::env::join_paths(paths)?)
            .env(OUTER_NS, fs::read_link("/proc/self/ns/mnt")?)
            .status()
            .context("start isolated benchmark")?;
        ensure!(status.success(), "isolated benchmark failed: {status}");
        return Ok(());
    }
    let outer =
        std::env::var_os(OUTER_NS).context("internal runner requires namespace isolation")?;
    ensure!(
        outer != fs::read_link("/proc/self/ns/mnt")?,
        "internal runner requires its own mount namespace"
    );
    ensure!(
        std::process::id() == 1,
        "internal runner requires its own PID namespace"
    );
    run(&mut cmd(
        "mount",
        &["-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run"],
    ))?;
    fs::create_dir("/run/netns")?;
    let mut rows = Vec::new();
    let result = benchmark(&opts, &mut rows);
    let cleanup = cleanup();
    let report = json!({
        "kernel": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "machine": std::env::consts::ARCH,
        "binary_sha256": format!("{:x}", Sha256::digest(fs::read(&opts.binary)?)),
        "seconds": opts.seconds, "streams": opts.streams, "mtu": opts.mtu,
        "requested_repeats": opts.repeats,
        "complete": result.is_ok() && cleanup.is_ok() && rows.len() as u64 == 4 * u64::from(opts.repeats),
        "error": result.as_ref().err().map(|e| format!("{e:#}")),
        "cleanup_error": cleanup.as_ref().err().map(|e| format!("{e:#}")),
        "cpu_note": "One core = 100%. Host busy CPU includes both peers and unrelated host activity; helper CPU is client GotaTun only.",
        "samples": rows,
    });
    fs::write(
        &opts.output,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;
    println!("Raw results: {}", opts.output.display());
    result?;
    cleanup?;
    for direction in ["upload", "download"] {
        let mut medians = Vec::new();
        for backend in ["kernel", "userspace"] {
            let values = rows
                .iter()
                .filter(|r| r["direction"] == direction && r["backend"] == backend)
                .filter_map(|r| r["mbps"].as_f64())
                .collect();
            medians.push(median(values)?);
        }
        println!(
            "{direction}: kernel={:.1} Mbps userspace={:.1} Mbps ratio={:.2}x",
            medians[0],
            medians[1],
            medians[1] / medians[0]
        );
    }
    Ok(())
}

fn cmd(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    command
}
fn net(namespace: &str, args: &[&str]) -> Command {
    let mut command = cmd("ip", &["netns", "exec", namespace]);
    command.args(args);
    command
}

// Files avoid pipe-buffer deadlocks while polling a bounded child lifetime.
struct Process {
    child: Child,
    stdout: fs::File,
    stderr: fs::File,
}
impl Process {
    fn spawn(command: &mut Command) -> Result<Self> {
        let stdout = tempfile::tempfile()?;
        let stderr = tempfile::tempfile()?;
        let child = command
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()
            .context("spawn benchmark command")?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }
    fn finish(mut self, seconds: u64) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(status) = self.child.try_wait()? {
                let mut output = String::new();
                self.stdout.seek(SeekFrom::Start(0))?;
                self.stdout.read_to_string(&mut output)?;
                let mut error = String::new();
                self.stderr.seek(SeekFrom::Start(0))?;
                self.stderr.read_to_string(&mut error)?;
                ensure!(
                    status.success(),
                    "benchmark command failed ({status}): {error}"
                );
                return Ok(output);
            }
            ensure!(
                Instant::now() < deadline,
                "benchmark command timed out after {seconds}s"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn run(command: &mut Command) -> Result<String> {
    Process::spawn(command)?.finish(65)
}

fn ticks(pid: Option<i32>) -> Result<u64> {
    let path = pid.map_or_else(|| "/proc/stat".into(), |p| format!("/proc/{p}/stat"));
    parse_ticks(&fs::read_to_string(path)?, pid.is_some())
}
fn parse_ticks(text: &str, process: bool) -> Result<u64> {
    let fields: Vec<_> = if process {
        text.rsplit_once(')')
            .context("invalid process stat")?
            .1
            .split_whitespace()
            .collect()
    } else {
        text.lines()
            .next()
            .context("empty CPU stat")?
            .split_whitespace()
            .skip(1)
            .collect()
    };
    let indices: &[usize] = if process {
        &[11, 12]
    } else {
        &[0, 1, 2, 5, 6, 7]
    };
    indices.iter().try_fold(0, |sum, &i| {
        Ok(sum
            + fields
                .get(i)
                .context("incomplete CPU stat")?
                .parse::<u64>()?)
    })
}
fn ping_result(output: &str) -> Result<Value> {
    let timing = output
        .lines()
        .find_map(|l| l.split_once(" = ").map(|(_, v)| v))
        .context("missing ping timing summary")?;
    let values = timing
        .split_whitespace()
        .next()
        .context("empty ping summary")?
        .split('/')
        .map(str::parse::<f64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 4 && values.iter().all(|v| v.is_finite() && *v >= 0.0),
        "invalid ping timing summary"
    );
    Ok(
        json!({"min_ms": values[0], "mean_ms": values[1], "max_ms": values[2], "mdev_ms": values[3]}),
    )
}
fn ping() -> Command {
    net(
        CLIENT,
        &[
            "ping",
            "-n",
            "-c",
            "10",
            "-i",
            "0.1",
            "-W",
            "1",
            "10.77.0.2",
        ],
    )
}
fn median(mut values: Vec<f64>) -> Result<f64> {
    ensure!(!values.is_empty(), "no throughput samples");
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Ok(if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

fn benchmark(opts: &Options, rows: &mut Vec<Value>) -> Result<()> {
    let hz = sysconf(SysconfVar::CLK_TCK)?.context("clock tick frequency unavailable")? as f64;
    for ns in [CLIENT, SERVER] {
        run(&mut cmd("ip", &["netns", "add", ns]))?;
        run(&mut net(ns, &["ip", "link", "set", "lo", "up"]))?;
    }
    run(&mut cmd(
        "ip",
        &[
            "link", "add", "bench-a", "type", "veth", "peer", "name", "bench-b",
        ],
    ))?;
    for (ns, dev, address) in [
        (CLIENT, "bench-a", "192.0.2.1/24"),
        (SERVER, "bench-b", "192.0.2.2/24"),
    ] {
        run(&mut cmd("ip", &["link", "set", dev, "netns", ns]))?;
        run(&mut net(ns, &["ip", "addr", "add", address, "dev", dev]))?;
        run(&mut net(ns, &["ip", "link", "set", dev, "up"]))?;
    }
    let secrets = tempfile::tempdir()?;
    let mut keys = Vec::new();
    for name in ["client", "server"] {
        let private = run(&mut cmd("wg", &["genkey"]))?;
        let path = secrets.path().join(name);
        // The containing directory is private before key material is written.
        fs::write(&path, private)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let mut public = cmd("wg", &["pubkey"]);
        public.stdin(fs::File::open(&path)?);
        let output = run(&mut public)?;
        keys.push((
            path.to_string_lossy().into_owned(),
            output.trim().to_owned(),
        ));
    }
    run(&mut net(
        SERVER,
        &["ip", "link", "add", IFACE, "type", "wireguard"],
    ))?;
    run(&mut net(
        SERVER,
        &[
            "wg",
            "set",
            IFACE,
            "private-key",
            &keys[1].0,
            "listen-port",
            "51820",
            "peer",
            &keys[0].1,
            "allowed-ips",
            "10.77.0.1/32",
        ],
    ))?;
    let mtu = opts.mtu.to_string();
    run(&mut net(
        SERVER,
        &["ip", "addr", "add", "10.77.0.2/24", "dev", IFACE],
    ))?;
    run(&mut net(
        SERVER,
        &["ip", "link", "set", IFACE, "mtu", &mtu, "up"],
    ))?;
    let _server = Process::spawn(&mut net(SERVER, &["iperf3", "-s", "-B", "10.77.0.2"]))?;
    for round in 0..opts.repeats {
        let order = if round % 2 == 0 {
            ["kernel", "userspace"]
        } else {
            ["userspace", "kernel"]
        };
        for backend in order {
            run(&mut net(
                SERVER,
                &["wg", "set", IFACE, "peer", &keys[0].1, "remove"],
            ))?;
            run(&mut net(
                SERVER,
                &[
                    "wg",
                    "set",
                    IFACE,
                    "peer",
                    &keys[0].1,
                    "allowed-ips",
                    "10.77.0.1/32",
                ],
            ))?;
            let helper = if backend == "kernel" {
                run(&mut net(
                    CLIENT,
                    &["ip", "link", "add", IFACE, "type", "wireguard"],
                ))?;
                None
            } else {
                let mut command = net(CLIENT, &[]);
                command
                    .arg(&opts.binary)
                    .arg(IFACE)
                    .env_remove("TUNMUX_GOTATUN_CONFIG_B64")
                    .env("TUNMUX_GOTATUN_HELPER", "1");
                run(&mut command)?;
                let pids = run(&mut cmd("ip", &["netns", "pids", CLIENT]))?;
                Some(
                    pids.trim()
                        .parse::<i32>()
                        .context("expected exactly one userspace helper")?,
                )
            };
            run(&mut net(
                CLIENT,
                &[
                    "wg",
                    "set",
                    IFACE,
                    "private-key",
                    &keys[0].0,
                    "peer",
                    &keys[1].1,
                    "allowed-ips",
                    "10.77.0.2/32",
                    "endpoint",
                    "192.0.2.2:51820",
                ],
            ))?;
            run(&mut net(
                CLIENT,
                &["ip", "addr", "add", "10.77.0.1/24", "dev", IFACE],
            ))?;
            run(&mut net(
                CLIENT,
                &["ip", "link", "set", IFACE, "mtu", &mtu, "up"],
            ))?;
            for attempt in 0..10 {
                let result = run(&mut net(
                    CLIENT,
                    &["ping", "-n", "-c", "1", "-W", "1", "10.77.0.2"],
                ));
                if result.is_ok() {
                    break;
                }
                if attempt == 9 {
                    result?;
                }
            }
            let idle = ping_result(&run(&mut ping())?)?;
            for direction in ["upload", "download"] {
                let loaded = Process::spawn(&mut ping())?;
                let host_start = ticks(None)?;
                let helper_start = helper.map(|p| ticks(Some(p))).transpose()?;
                let start = Instant::now();
                let mut command = net(
                    CLIENT,
                    &[
                        "iperf3",
                        "-c",
                        "10.77.0.2",
                        "-J",
                        "-t",
                        &opts.seconds.to_string(),
                        "-P",
                        &opts.streams.to_string(),
                    ],
                );
                if direction == "download" {
                    command.arg("-R");
                }
                let result: Value = serde_json::from_str(
                    &Process::spawn(&mut command)?.finish(u64::from(opts.seconds) + 20)?,
                )?;
                let elapsed = start.elapsed().as_secs_f64();
                let host_cpu = (ticks(None)? - host_start) as f64 / hz / elapsed * 100.0;
                let helper_cpu = helper
                    .zip(helper_start)
                    .map(|(p, before)| {
                        ticks(Some(p)).map(|after| (after - before) as f64 / hz / elapsed * 100.0)
                    })
                    .transpose()?;
                let loaded = ping_result(&loaded.finish(15)?)?;
                ensure!(
                    result.get("error").is_none(),
                    "iperf failed: {}",
                    result["error"]
                );
                let mbps = result["end"]["sum_received"]["bits_per_second"]
                    .as_f64()
                    .context("missing iperf throughput")?
                    / 1e6;
                println!("{backend:9} {direction:8} round={} {mbps:.1} Mbps host_cpu={host_cpu:.1}% helper_cpu={helper_cpu:?}", round + 1);
                rows.push(json!({"backend": backend, "round": round + 1, "direction": direction, "mbps": mbps, "host_busy_cpu_pct": host_cpu, "helper_cpu_pct": helper_cpu, "idle_ping": idle, "loaded_ping": loaded, "iperf": result}));
            }
            if let Some(pid) = helper {
                kill(Pid::from_raw(pid), Signal::SIGTERM)?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while let nix::sys::wait::WaitStatus::StillAlive = nix::sys::wait::waitpid(
                    Pid::from_raw(pid),
                    Some(nix::sys::wait::WaitPidFlag::WNOHANG),
                )? {
                    ensure!(
                        Instant::now() < deadline,
                        "userspace helper did not stop within 5 seconds"
                    );
                    thread::sleep(Duration::from_millis(50));
                }
            } else {
                run(&mut net(CLIENT, &["ip", "link", "del", IFACE]))?;
            }
        }
    }
    Ok(())
}

fn cleanup() -> Result<()> {
    let mut errors = Vec::new();
    let namespaces = run(&mut cmd("ip", &["netns", "list"]))?;
    for ns in [CLIENT, SERVER] {
        if !namespaces
            .lines()
            .any(|line| line.split_whitespace().next() == Some(ns))
        {
            continue;
        }
        match run(&mut cmd("ip", &["netns", "pids", ns])) {
            Ok(pids) => {
                for pid in pids.split_whitespace() {
                    if let Ok(pid) = pid.parse::<i32>() {
                        if let Err(error) = kill(Pid::from_raw(pid), Signal::SIGKILL) {
                            if error != nix::errno::Errno::ESRCH {
                                errors.push(error.to_string());
                            }
                        }
                    }
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
        if let Err(error) = run(&mut cmd("ip", &["netns", "del", ns])) {
            errors.push(error.to_string());
        }
    }
    ensure!(
        errors.is_empty(),
        "namespace cleanup failed: {}",
        errors.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_command_timeout_kills_and_reaps_child() {
        let process = Process::spawn(&mut cmd("sleep", &["30"])).unwrap();
        let pid = process.child.id() as i32;
        assert!(process
            .finish(0)
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert_eq!(
            nix::sys::wait::waitpid(Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ECHILD)
        );
    }

    #[test]
    fn test_command_failure_includes_stderr() {
        let error = run(&mut cmd(
            "sh",
            &["-c", "echo deliberate-failure >&2; exit 7"],
        ))
        .unwrap_err();
        assert!(error.to_string().contains("deliberate-failure"));
        assert_eq!(run(&mut cmd("printf", &["success"])).unwrap(), "success");
    }

    #[test]
    fn test_cpu_ticks_exclude_idle_and_guest() {
        assert_eq!(
            parse_ticks("cpu 10 20 30 400 500 6 7 8 900 1000\n", false).unwrap(),
            81
        );
        assert_eq!(
            parse_ticks("123 (helper (name)) S 0 0 0 0 0 0 0 0 0 0 17 23", true).unwrap(),
            40
        );
    }
    #[test]
    fn test_ping_summary_and_missing_measurements() {
        assert_eq!(
            ping_result("rtt min/avg/max/mdev = 0.1/0.2/0.3/0.04 ms\n").unwrap()["mean_ms"],
            0.2
        );
        assert!(ping_result("100% packet loss").is_err());
        assert!(ping_result("rtt = 1/2/3 ms").is_err());
    }
    #[test]
    fn test_median_even_and_odd_rounds() {
        assert_eq!(median(vec![3.0, 1.0, 2.0]).unwrap(), 2.0);
        assert_eq!(median(vec![4.0, 1.0, 3.0, 2.0]).unwrap(), 2.5);
        assert!(median(vec![]).is_err());
    }
    #[test]
    fn test_options_reject_invalid_measurement_parameters() {
        for args in [
            vec!["--bin", "/unused", "--seconds", "0"],
            vec!["--bin", "/unused", "--mtu", "575"],
            vec!["--bin"],
            vec!["--wat", "1"],
        ] {
            assert!(
                Options::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
    }
}
