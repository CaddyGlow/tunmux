//! Explicit, isolated Linux dataplane benchmark; never part of normal CI.
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use nix::sys::signal::{kill, Signal};
use nix::unistd::{sysconf, Pid, SysconfVar, Uid};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CLIENT: &str = "wgbench-client";
const SERVER: &str = "wgbench-server";
const IFACE: &str = "wgbench0";
const OUTER_NS: &str = "TUNMUX_BENCH_OUTER_MNT_NS";
const BACKENDS: &[&str] = &["kernel", "userspace", "local-proxy"];
const TRAFFIC_PORT: u16 = 5202;
const SOCKS_PORT: u16 = 1080;
const CHUNK: usize = 128 * 1024;

struct Options {
    binary: PathBuf,
    output: PathBuf,
    seconds: u32,
    repeats: u32,
    streams: u32,
    mtu: u32,
    delay_ms: u32,
    backends: Vec<String>,
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
            delay_ms: 0,
            backends: BACKENDS.iter().map(|b| (*b).to_owned()).collect(),
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
                "--delay-ms" => opts.delay_ms = value.parse()?,
                "--backends" => {
                    opts.backends = value.split(',').map(str::to_owned).collect();
                }
                _ => bail!("unknown option {arg}"),
            }
        }
        ensure!(!opts.binary.as_os_str().is_empty(), "--bin is required");
        ensure!(opts.seconds > 0 && opts.seconds <= u32::MAX - 20 && opts.repeats > 0 && opts.streams > 0, "seconds/repeats/streams must be positive and seconds must allow a 20-second timeout margin");
        ensure!((576..=1500).contains(&opts.mtu), "MTU must be 576..1500");
        ensure!(opts.delay_ms <= 1000, "delay must be 0..1000 ms");
        for backend in &opts.backends {
            ensure!(
                BACKENDS.contains(&backend.as_str()),
                "unknown backend {backend}; expected one of {}",
                BACKENDS.join(",")
            );
        }
        ensure!(!opts.backends.is_empty(), "--backends must name a backend");
        Ok(opts)
    }
}

pub fn main(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: cargo xtask bench-wg --bin <release-tunmux> [OPTIONS]\n\nCompare kernel WireGuard, GotaTun and the rootless local proxy using isolated\nlocal peers (no VPN account). Requires Linux, /dev/net/tun, ip, wg, iperf3,\nping, mount and unshare, plus tc with --delay-ms. Run as a user with\nunprivileged namespaces enabled, or as root.\n\n  --seconds N      Seconds per sample (default: 5)\n  --repeats N      Rounds, rotating backend order (default: 3)\n  --streams N      Parallel TCP streams (default: 1)\n  --mtu N          Interface MTU, 576..1500 (default: 1420)\n  --delay-ms N     One-way delay added on each veth end (default: 0)\n  --backends LIST  Comma list of kernel,userspace,local-proxy (default: all)\n  --output PATH    JSON evidence (default: wg-backend-results.json)\n\nlocal-proxy traffic runs through its SOCKS5 port with a built-in generator;\nthe TUN backends use iperf3.");
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("--serve-traffic") => return serve_traffic(args.get(1).context("missing address")?),
        Some("--socks-load") => return socks_load(&args[1..]),
        Some("--socks-half-close") => return socks_half_close(&args[1..]),
        _ => {}
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
        let tc: &[&str] = if opts.delay_ms > 0 { &["tc"] } else { &[] };
        for &tool in ["ip", "wg", "iperf3", "ping", "mount", "unshare"]
            .iter()
            .chain(tc)
        {
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
        "delay_ms_each_way": opts.delay_ms, "backends": opts.backends,
        "requested_repeats": opts.repeats,
        "complete": result.is_ok() && cleanup.is_ok() && rows.len() as u64 == 2 * opts.backends.len() as u64 * u64::from(opts.repeats),
        "error": result.as_ref().err().map(|e| format!("{e:#}")),
        "cleanup_error": cleanup.as_ref().err().map(|e| format!("{e:#}")),
        "cpu_note": "One core = 100%. Host busy CPU includes both peers and unrelated host activity; helper CPU is the client GotaTun helper or local-proxy daemon only.",
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
        let mut line = format!("{direction}:");
        let mut kernel = None;
        for backend in &opts.backends {
            let pick = |key: &str| -> Vec<f64> {
                rows.iter()
                    .filter(|r| r["direction"] == direction && r["backend"] == backend.as_str())
                    .filter_map(|r| r[key].as_f64())
                    .collect()
            };
            let mbps = median(pick("mbps"))?;
            line.push_str(&format!(" {backend}={mbps:.1} Mbps"));
            if backend == "kernel" {
                kernel = Some(mbps);
            } else if let Some(kernel) = kernel {
                line.push_str(&format!(" ({:.2}x)", mbps / kernel));
            }
            if let Ok(cpu) = median(pick("helper_cpu_pct")) {
                line.push_str(&format!(" helper_cpu={cpu:.0}%"));
            }
        }
        println!("{line}");
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
        if opts.delay_ms > 0 {
            let delay = format!("{}ms", opts.delay_ms);
            run(&mut net(
                ns,
                &[
                    "tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", &delay, "limit",
                    "100000",
                ],
            ))?;
        }
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
    let traffic_addr = format!("10.77.0.2:{TRAFFIC_PORT}");
    let mut traffic = net(SERVER, &[]);
    traffic
        .arg(std::env::current_exe()?)
        .args(["bench-wg", "--serve-traffic", &traffic_addr]);
    let _traffic = Process::spawn(&mut traffic)?;
    let proxy_dir = tempfile::tempdir()?;
    for round in 0..opts.repeats {
        let mut order: Vec<&str> = opts.backends.iter().map(String::as_str).collect();
        let shift = round as usize % order.len();
        order.rotate_left(shift);
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
            let mut proxy = None;
            let helper = if backend == "kernel" {
                run(&mut net(
                    CLIENT,
                    &["ip", "link", "add", IFACE, "type", "wireguard"],
                ))?;
                None
            } else if backend == "local-proxy" {
                let (process, pid) = start_local_proxy(opts, &keys, proxy_dir.path())?;
                proxy = Some(process);
                Some(pid)
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
            let half_close = if proxy.is_some() {
                let mut command = net(CLIENT, &[]);
                command.arg(std::env::current_exe()?).args([
                    "bench-wg",
                    "--socks-half-close",
                    &format!("127.0.0.1:{SOCKS_PORT}"),
                    &traffic_addr,
                ]);
                let check = Process::spawn(&mut command)?.finish(20);
                if let Err(error) = &check {
                    println!("{backend:11} half-close check failed: {error:#}");
                }
                Some(check.is_ok())
            } else {
                None
            };
            let idle = if proxy.is_some() {
                Value::Null
            } else {
                tun_up(&keys, &mtu)?
            };
            for direction in ["upload", "download"] {
                let loaded = proxy
                    .is_none()
                    .then(|| Process::spawn(&mut ping()))
                    .transpose()?;
                let host_start = ticks(None)?;
                let helper_start = helper.map(|p| ticks(Some(p))).transpose()?;
                let counters_start = counters()?;
                let start = Instant::now();
                let (mbps, raw) = if proxy.is_some() {
                    let mut command = net(CLIENT, &[]);
                    command.arg(std::env::current_exe()?).args([
                        "bench-wg",
                        "--socks-load",
                        &format!("127.0.0.1:{SOCKS_PORT}"),
                        &traffic_addr,
                        direction,
                        &opts.seconds.to_string(),
                        &opts.streams.to_string(),
                    ]);
                    let result: Value = serde_json::from_str(
                        &Process::spawn(&mut command)?.finish(u64::from(opts.seconds) + 20)?,
                    )?;
                    let mbps = result["mbps"].as_f64().context("missing load throughput")?;
                    (mbps, result)
                } else {
                    iperf(opts, direction)?
                };
                let elapsed = start.elapsed().as_secs_f64();
                let net_counters = counter_delta(&counters_start, &counters()?);
                let host_cpu = (ticks(None)? - host_start) as f64 / hz / elapsed * 100.0;
                let helper_cpu = helper
                    .zip(helper_start)
                    .map(|(p, before)| {
                        ticks(Some(p)).map(|after| (after - before) as f64 / hz / elapsed * 100.0)
                    })
                    .transpose()?;
                let loaded = loaded
                    .map(|p| p.finish(15).and_then(|out| ping_result(&out)))
                    .transpose()?;
                println!("{backend:11} {direction:8} round={} {mbps:.1} Mbps host_cpu={host_cpu:.1}% helper_cpu={helper_cpu:?}", round + 1);
                rows.push(json!({"backend": backend, "round": round + 1, "direction": direction, "mbps": mbps, "host_busy_cpu_pct": host_cpu, "helper_cpu_pct": helper_cpu, "half_close_ok": half_close, "idle_ping": idle, "loaded_ping": loaded, "net_counters": net_counters, "raw": raw}));
            }
            if let Some(mut process) = proxy {
                let log = opts
                    .output
                    .with_extension(format!("local-proxy-r{}.log", round + 1));
                process.stderr.seek(SeekFrom::Start(0))?;
                std::io::copy(&mut process.stderr, &mut fs::File::create(&log)?)?;
            } else if let Some(pid) = helper {
                stop_helper(pid)?;
            } else {
                run(&mut net(CLIENT, &["ip", "link", "del", IFACE]))?;
            }
        }
    }
    Ok(())
}

fn tun_up(keys: &[(String, String)], mtu: &str) -> Result<Value> {
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
        &["ip", "link", "set", IFACE, "mtu", mtu, "up"],
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
    ping_result(&run(&mut ping())?)
}

fn iperf(opts: &Options, direction: &str) -> Result<(f64, Value)> {
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
    let result: Value =
        serde_json::from_str(&Process::spawn(&mut command)?.finish(u64::from(opts.seconds) + 20)?)?;
    ensure!(
        result.get("error").is_none(),
        "iperf failed: {}",
        result["error"]
    );
    let mbps = result["end"]["sum_received"]["bits_per_second"]
        .as_f64()
        .context("missing iperf throughput")?
        / 1e6;
    Ok((mbps, result))
}

fn stop_helper(pid: i32) -> Result<()> {
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
    Ok(())
}

/// SNMP counters that explain a throughput drop: datagrams the UDP sockets
/// discarded and TCP segments the senders had to resend.
const COUNTERS: &[(&str, &str)] = &[
    ("Udp", "RcvbufErrors"),
    ("Udp", "SndbufErrors"),
    ("Tcp", "RetransSegs"),
];

fn counters() -> Result<Vec<u64>> {
    let mut values = Vec::new();
    for ns in [CLIENT, SERVER] {
        let snmp = run(&mut net(ns, &["cat", "/proc/net/snmp"]))?;
        for &(table, name) in COUNTERS {
            values.push(snmp_counter(&snmp, table, name)?);
        }
    }
    Ok(values)
}

fn counter_delta(before: &[u64], after: &[u64]) -> Value {
    let mut out = serde_json::Map::new();
    for (i, ns) in [CLIENT, SERVER].iter().enumerate() {
        for (j, &(table, name)) in COUNTERS.iter().enumerate() {
            let k = i * COUNTERS.len() + j;
            out.insert(
                format!("{ns}.{table}.{name}"),
                json!(after[k].saturating_sub(before[k])),
            );
        }
    }
    Value::Object(out)
}

fn snmp_counter(snmp: &str, table: &str, name: &str) -> Result<u64> {
    let prefix = format!("{table}:");
    let mut rows = snmp.lines().filter(|line| line.starts_with(&prefix));
    let (header, values) = rows.next().zip(rows.next()).context("missing SNMP table")?;
    let column = header
        .split_whitespace()
        .position(|field| field == name)
        .with_context(|| format!("missing SNMP counter {table}.{name}"))?;
    Ok(values
        .split_whitespace()
        .nth(column)
        .context("short SNMP row")?
        .parse()?)
}

fn decode_key(text: &str) -> Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())?
        .try_into()
        .ok()
        .context("WireGuard key must be 32 bytes")
}

/// Start the local-proxy daemon in the foreground and wait for its handshake.
fn start_local_proxy(
    opts: &Options,
    keys: &[(String, String)],
    dir: &Path,
) -> Result<(Process, i32)> {
    let config = json!({
        "private_key": decode_key(&fs::read_to_string(&keys[0].0)?)?,
        "peer_public_key": decode_key(&keys[1].1)?,
        "preshared_key": null,
        "endpoint": "192.0.2.2:51820",
        "virtual_ips": ["10.77.0.1/32"],
        "keepalive": null,
        "socks_port": SOCKS_PORT,
        "http_port": SOCKS_PORT + 1,
        "dns_servers": [],
    });
    let pid_file = dir.join("bench.pid");
    let status_file = dir.join("bench.pid.status");
    let _ = fs::remove_file(&status_file);
    let mut command = net(CLIENT, &[]);
    command
        .arg(&opts.binary)
        .arg("local-proxy-daemon")
        .args(["--socks-port", &SOCKS_PORT.to_string()])
        .args(["--http-port", &(SOCKS_PORT + 1).to_string()])
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--log-file")
        .arg(dir.join("bench.log"))
        .stdin(Stdio::piped())
        .env("TUNMUX_LOCAL_PROXY_FOREGROUND", "1")
        .env("XDG_CONFIG_HOME", dir);
    let mut process = Process::spawn(&mut command)?;
    // The daemon reads its config from stdin; closing it signals EOF.
    if let Some(mut stdin) = process.child.stdin.take() {
        stdin.write_all(config.to_string().as_bytes())?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fs::read_to_string(&status_file).is_ok_and(|s| s.trim() == "ready") {
            let pid = fs::read_to_string(&pid_file)?.trim().parse()?;
            return Ok((process, pid));
        }
        if process.child.try_wait()?.is_some() {
            return process
                .finish(0)
                .map(|_| bail!("local proxy exited before its handshake"))?;
        }
        if Instant::now() >= deadline {
            let mut log = String::new();
            process.stderr.seek(SeekFrom::Start(0))?;
            process.stderr.read_to_string(&mut log)?;
            let tail: Vec<&str> = log.lines().rev().take(20).collect();
            bail!(
                "local proxy did not complete a handshake within 10 seconds; log tail:\n{}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Traffic peer for the SOCKS load. `u<secs>` counts what arrives in a window
/// that opens with the first byte, reports bytes and microseconds, then drains
/// until the client hangs up (the proxy has no TCP half-close). `d` streams
/// zeros until the client hangs up.
fn serve_traffic(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("bind {addr}"))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        thread::spawn(move || -> std::io::Result<()> {
            let mut mode = [0u8; 5];
            stream.read_exact(&mut mode)?;
            let mut buf = vec![0u8; CHUNK];
            if mode[0] == b'u' {
                let seconds = u32::from_be_bytes([mode[1], mode[2], mode[3], mode[4]]);
                let mut total = stream.read(&mut buf)? as u64;
                let start = Instant::now();
                let deadline = start + Duration::from_secs(seconds.into());
                while Instant::now() < deadline {
                    match stream.read(&mut buf)? {
                        0 => return Ok(()),
                        n => total += n as u64,
                    }
                }
                let micros = start.elapsed().as_micros() as u64;
                let mut report = total.to_be_bytes().to_vec();
                report.extend(micros.to_be_bytes());
                stream.write_all(&report)?;
                while stream.read(&mut buf)? > 0 {}
            } else if mode[0] == b'e' {
                let mut total = 0u64;
                loop {
                    match stream.read(&mut buf)? {
                        0 => break,
                        n => total += n as u64,
                    }
                }
                stream.write_all(&total.to_be_bytes())?;
            } else {
                loop {
                    stream.write_all(&buf)?;
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream> {
    let SocketAddr::V4(target) = target else {
        bail!("SOCKS load target must be IPv4");
    };
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_nodelay(true)?;
    stream.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    ensure!(reply == [5, 0], "SOCKS5 method rejected: {reply:?}");
    let mut request = vec![5, 1, 0, 1];
    request.extend(target.ip().octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    ensure!(
        reply[1] == 0,
        "SOCKS5 connect failed with code {}",
        reply[1]
    );
    Ok(stream)
}

/// One stream's goodput: bytes the far end received in its window (upload) or
/// the client read (download), with the window length.
fn socks_stream(
    proxy: SocketAddr,
    target: SocketAddr,
    upload: bool,
    seconds: u64,
) -> Result<(u64, f64)> {
    let mut stream = socks_connect(proxy, target)?;
    let mut mode = vec![if upload { b'u' } else { b'd' }];
    mode.extend(u32::try_from(seconds)?.to_be_bytes());
    stream.write_all(&mode)?;
    let mut buf = vec![0u8; CHUNK];
    if upload {
        let mut writer = stream.try_clone()?;
        let feeder = thread::spawn(move || while writer.write_all(&buf).is_ok() {});
        let mut report = [0u8; 16];
        let read = stream.read_exact(&mut report);
        let _ = stream.shutdown(Shutdown::Both);
        let _ = feeder.join();
        read.context("read upload report")?;
        let (bytes, micros) = report.split_at(8);
        let bytes = u64::from_be_bytes(bytes.try_into()?);
        let micros = u64::from_be_bytes(micros.try_into()?);
        return Ok((bytes, micros as f64 / 1e6));
    }
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let mut total = 0u64;
    while Instant::now() < deadline {
        match stream.read(&mut buf)? {
            0 => bail!("traffic peer closed the download early"),
            n => total += n as u64,
        }
    }
    Ok((total, start.elapsed().as_secs_f64()))
}

/// Send a payload, close the sending side, and expect the server's byte count
/// back: the reply only arrives if the proxy keeps the other direction open.
fn socks_half_close(args: &[String]) -> Result<()> {
    let [proxy, target] = args else {
        bail!("usage: --socks-half-close PROXY TARGET");
    };
    let mut stream = socks_connect(proxy.parse()?, target.parse()?)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let payload = vec![7u8; 3 * CHUNK + 5];
    stream.write_all(&[b'e', 0, 0, 0, 0])?;
    stream.write_all(&payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = [0u8; 8];
    stream
        .read_exact(&mut reply)
        .context("no reply after half-close")?;
    let echoed = u64::from_be_bytes(reply);
    ensure!(
        echoed == payload.len() as u64,
        "server counted {echoed} of {} bytes",
        payload.len()
    );
    ensure!(
        stream.read(&mut reply)? == 0,
        "expected EOF after the reply"
    );
    Ok(())
}

fn socks_load(args: &[String]) -> Result<()> {
    let [proxy, target, direction, seconds, streams] = args else {
        bail!("usage: --socks-load PROXY TARGET upload|download SECONDS STREAMS");
    };
    let (proxy, target): (SocketAddr, SocketAddr) = (proxy.parse()?, target.parse()?);
    let upload = direction == "upload";
    let seconds: u64 = seconds.parse()?;
    let workers: Vec<_> = (0..streams.parse::<u32>()?)
        .map(|_| thread::spawn(move || socks_stream(proxy, target, upload, seconds)))
        .collect();
    let (mut bytes, mut elapsed) = (0u64, 0f64);
    for worker in workers {
        let (n, secs) = worker
            .join()
            .map_err(|_| anyhow::anyhow!("load thread panicked"))??;
        bytes += n;
        elapsed = elapsed.max(secs);
    }
    let mbps = bytes as f64 * 8.0 / elapsed / 1e6;
    println!(
        "{}",
        json!({"generator": "socks-load", "bytes": bytes, "seconds": elapsed, "mbps": mbps})
    );
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
    fn test_snmp_counter_reads_named_column() {
        let snmp =
            "Tcp: RtoAlgorithm RetransSegs\nTcp: 1 42\nUdp: InDatagrams RcvbufErrors\nUdp: 9 7\n";
        assert_eq!(snmp_counter(snmp, "Tcp", "RetransSegs").unwrap(), 42);
        assert_eq!(snmp_counter(snmp, "Udp", "RcvbufErrors").unwrap(), 7);
        assert!(snmp_counter(snmp, "Udp", "Missing").is_err());
        assert!(snmp_counter("Ip: 1\n", "Tcp", "RetransSegs").is_err());
    }

    #[test]
    fn test_options_accept_known_backends_only() {
        let parse = |list: &str| {
            Options::parse(&["--bin", "/unused", "--backends", list].map(str::to_owned))
        };
        assert_eq!(
            parse("local-proxy,kernel").unwrap().backends,
            ["local-proxy", "kernel"]
        );
        assert!(parse("kernel,tap").is_err());
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
