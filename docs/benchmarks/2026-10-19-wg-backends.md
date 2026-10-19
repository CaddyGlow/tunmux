# Kernel versus GotaTun WireGuard — 2026-10-19

On this machine, the kernel client reached median TCP throughput of **7.18 Gbit/s
upload and 7.24 Gbit/s download**, compared with **2.24 and 2.56 Gbit/s** for
tunmux's embedded GotaTun client. These are local dataplane measurements with
both peers on the same host. Host load varied during the run.

The complete [raw results](2026-10-19-wg-backends.json) include all 12 samples,
iperf3 output, CPU measurements, and ping summaries. The benchmark completed
without sudo using unprivileged user namespaces.

## Setup

- CPU: Intel Core i7-13700K, x86_64.
- Linux kernel: 6.18.53.
- Release build: `cargo build --release --locked --no-default-features`.
- Source base: `e8697617a7191802c4f86e7cd0647f1a19a6f837`, with the working-tree
  benchmark and helper logging fix applied; this was not a clean commit build.
- Binary SHA-256:
  `c3049f7d4536a1b8fe2ac5cc7e427a2da671d03d95b500f617a62d006986496c`.
- Two temporary network namespaces connected by a veth pair. The server always
  used kernel WireGuard; the client alternated between kernel WireGuard and
  tunmux's production GotaTun helper.
- One TCP stream, MTU 1420, five seconds per throughput sample, three rounds.
- Order: kernel/userspace, userspace/kernel, kernel/userspace. Each client ran
  upload followed by download. Server peer state was reset before each case,
  and a successful ping established readiness before measurement.
- Idle ping: ten probes at 100 ms intervals before each backend's traffic tests.
  Loaded ping: ten probes at 100 ms intervals at the start of each throughput
  sample. These measurements do not describe the entire five-second load window.
- No provider account, external VPN server, or internet traffic.

## Results

Throughput uses iperf3 receiver-reported rates. Gbit/s is decimal.

| Metric | Kernel client | GotaTun client |
| --- | ---: | ---: |
| Median upload | 7.181 Gbit/s | 2.241 Gbit/s |
| Median download | 7.243 Gbit/s | 2.557 Gbit/s |
| Median idle ping mean RTT | 0.301 ms | 0.279 ms |
| Median loaded ping mean RTT | 0.394 ms | 0.954 ms |

GotaTun achieved approximately 31% of kernel upload throughput and 35% of kernel
download throughput in this run. Ping figures are medians of per-sample means,
not latency percentiles; loaded ping aggregates both traffic directions.

| Round | Kernel upload | Kernel download | GotaTun upload | GotaTun download |
| --- | ---: | ---: | ---: | ---: |
| 1 | 9.088 Gbit/s | 9.173 Gbit/s | 2.241 Gbit/s | 2.601 Gbit/s |
| 2 | 7.181 Gbit/s | 7.243 Gbit/s | 2.270 Gbit/s | 2.557 Gbit/s |
| 3 | 7.013 Gbit/s | 7.226 Gbit/s | 2.207 Gbit/s | 2.528 Gbit/s |

The GotaTun client process used approximately 77–78% of one CPU core during
upload and 86–87% during download. Host busy CPU includes both peers and
unrelated host activity, so it cannot establish a per-backend CPU efficiency
comparison. One occupied logical core is 100% in the raw CPU measurements.

## Limits and follow-up

Both peers share host CPU resources. The samples are short, the CPU was not
pinned, and kernel throughput varied appreciably between rounds. Treat these
figures as an initial local baseline rather than an internet VPN speed estimate.
This run covers IPv4 tunnel traffic with one TCP stream; it does not measure
SOCKS/HTTP proxy performance, UDP throughput, multiple streams, or a remote peer.

The run also verified that the fixed helper launcher returns with stdout/stderr
captured while its daemon continues running. Daemon output now goes to
`/var/run/wireguard/<interface>.log`; the benchmark's private mount namespace
makes these logs disposable.

## Reproduce

From the repository root, inside the development shell, with the tools listed
in the [README](../../README.md#kernel-versus-userspace-wireguard-benchmark):

```sh
cargo build --release --locked --no-default-features
python3 scripts/wg_backend_bench.py --bin target/release/tunmux \
  --seconds 5 --repeats 3 --output /tmp/tunmux-wg-backends.json
```

Use Cargo's actual target directory for `--bin` if it is configured elsewhere.
The saved JSON should report `complete: true` and contain 12 samples.
