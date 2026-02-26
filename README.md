# tunmux

`tunmux` is a multi-provider VPN CLI written in Rust.

Supported platforms:
- Linux: direct mode, `--proxy` mode, and `--local-proxy` mode
- macOS: direct mode and `--local-proxy` mode (`--proxy` is not available)

It supports Proton VPN, AirVPN, Mullvad, IVPN, and local WireGuard config profiles (`wgconf`) with WireGuard connectivity in:
- direct mode (system-wide routing)
- Linux namespace proxy mode (`--proxy`, isolated per-connection namespace)
- local-proxy mode (`--local-proxy`, userspace SOCKS5/HTTP proxy without root)

## What It Does

- Connect/disconnect VPN sessions across multiple providers
- Run multiple VPN exits side-by-side in proxy mode
- In proxy mode, keep host traffic unchanged unless an app explicitly uses a proxy
- Run rootless userspace local-proxy mode with `--local-proxy` (no `sudo` required)
- Manage provider-specific account and utility commands from one CLI
- Support multiple WireGuard backends: `wg-quick`, `userspace`, `kernel`

## Platform And Requirements

- Rust (stable, edition 2021)
- Linux for full feature set (kernel backend + `--proxy` namespace isolation)
- macOS for direct mode and `--local-proxy` mode (`--proxy` is Linux-only)
- `sudo` access for privileged operations (`tunmux privileged --serve`) used by direct mode and `--proxy`

`userspace` mode uses the embedded `gotatun` library through a built-in helper; no separate `gotatun` CLI install is required.
`--local-proxy` uses that userspace engine to run a SOCKS5/HTTP proxy without root.

Optional:
- systemd socket activation via `systemd/tunmux-privileged.socket`
- keyring storage via `cargo build --features keyring`

## Build

```bash
cargo build
cargo build --features keyring
```

## Release CI (Tag-Based)

Pushing a `v*` tag (for example `v1.2.3`) triggers `.github/workflows/release.yml` to:
- run `cargo test --locked`
- build release binaries for Linux, macOS, and Android targets via `.github/workflows/manual-build.yml`
- build an Android app APK from `android/` via `.github/workflows/manual-build-android.yml`
- upload tarballs and SHA256 files to a GitHub Release for that tag

Publishing that GitHub Release then triggers `.github/workflows/docker.yml` (which calls `.github/workflows/docker-publish.yml`) to build and publish a multi-arch Docker image to GHCR.

Binary version output follows the tag in CI builds:

```bash
tunmux --version
```

Container tags:
- `ghcr.io/<owner>/tunmux:<tag>`
- `ghcr.io/<owner>/tunmux:latest` (only for non-prerelease tags)

## Quick Start

### 1) Sign in and connect (direct mode)

```bash
tunmux proton login <username>
tunmux connect proton --country CH --backend wg-quick
tunmux status
tunmux disconnect --provider proton
```

### 2) Start isolated proxy exits (proxy mode)

```bash
# First proxy instance (typically SOCKS5 1080, HTTP 8118)
tunmux connect proton --proxy --country US

# Second proxy instance (next available ports)
tunmux connect proton --proxy --country CH

# Use a specific proxy
curl --socks5 127.0.0.1:1080 https://api.ipify.org

# Host traffic remains unchanged unless using proxy
curl https://api.ipify.org
```

### 3) Start local-proxy mode (no root)

```bash
# No sudo required; app traffic goes through SOCKS5/HTTP proxy
tunmux connect proton --local-proxy --country US

# Use the proxy from an app/tool
curl --socks5 127.0.0.1:1080 https://api.ipify.org

# Stop local-proxy instance(s)
tunmux disconnect --provider proton
```

## Command Map

Top-level commands:

```bash
tunmux status
tunmux connect <provider> [provider connect flags]
tunmux disconnect [instance] [--provider <provider>] [--all]
tunmux hook run <connectivity|external-ip|dns-detection>
tunmux hook debug [instance] [--provider <provider>] [--event ifup|ifdown]
tunmux proton <...>
tunmux airvpn <...>
tunmux mullvad <...>
tunmux ivpn <...>
tunmux wgconf <...>
```

Common provider flows:

```bash
tunmux <provider> login ...
tunmux <provider> info
tunmux <provider> servers [--country XX] [--tag ...] [--sort ...]
tunmux connect <provider> [server] [--country XX] [--sort ...] [--backend ...] [--mtu N] [--proxy|--local-proxy]
tunmux disconnect [instance] [--provider <provider>] [--all]
tunmux <provider> logout
```

`wgconf` provider flow:

```bash
tunmux connect wgconf --file ./my-tunnel.conf
tunmux connect wgconf --file ./my-tunnel.conf --save-as work
tunmux connect wgconf --profile work
tunmux wgconf list
tunmux wgconf remove work
```

Legacy provider-prefixed forms (`tunmux <provider> connect ...`, `tunmux <provider> disconnect ...`) remain supported for compatibility.

Disconnect semantics:

```bash
tunmux disconnect --all                     # all providers
tunmux disconnect --provider proton --all   # proton only
tunmux disconnect --provider wgconf --all   # wgconf only
tunmux disconnect <instance>                # exact instance
tunmux disconnect --provider proton         # provider-scoped single/list behavior

# short forms
tunmux disconnect -a
tunmux disconnect -p proton -a
```

Common short forms:
- `connect`: `-c` (country), `-s` (sort), `-b` (backend)
- `disconnect`: `-p` (provider), `-a` (all)
- `servers`: `-c` (country), `-t` (tag), `-s` (sort)

Use verbose logs when needed:

```bash
tunmux -v connect proton --country CH
RUST_LOG=debug tunmux disconnect --all
```

## Provider Examples

### Proton VPN

```bash
tunmux proton login <username>
tunmux proton info
tunmux proton servers --country US --free
tunmux proton servers --country CH --tag p2p --sort latency
tunmux connect proton US#1
tunmux connect proton --country CH --p2p
tunmux connect proton --country CH --p2p --port-forwarding
tunmux connect proton --country CH --sort latency
tunmux connect proton FR#183 --mtu 1280
tunmux proton ports request --protocol both
tunmux proton ports request --protocol both --no-daemon
tunmux proton ports list
tunmux proton ports list --current
tunmux proton ports list --current --json
tunmux proton ports renew --lifetime 60
tunmux proton ports daemon --protocol both --lifetime 60 --renew-every 45
tunmux proton ports release
tunmux disconnect --provider proton --all
tunmux proton logout
```

Proton NAT-PMP notes:
- `tunmux proton ports request ...` now starts the background renew daemon by default.
- Use `--no-daemon` for a one-shot mapping request.
- Default daemon renew interval is `lifetime - 15s` (minimum `1s`).
- `tunmux proton ports list` shows saved mappings (including expired ones).
- `tunmux proton ports list --current` shows only active mappings for the current direct Proton connection.
- `tunmux proton ports list --current --json` returns the same filtered view as JSON.
- `tunmux proton ports release` stops the renew daemon and sends NAT-PMP unmap (lifetime `0`) for saved mappings on the active direct connection.
- Daemon state files:
  - PID: `~/.config/tunmux/proton/port_forward_daemon.pid`
  - Log: `~/.config/tunmux/proton/port_forward_daemon.log`

Typical lifecycle:

```bash
tunmux connect proton --country DE --port-forwarding
tunmux proton ports request --protocol both   # request + auto-start renew daemon
tunmux proton ports list --current --json     # inspect currently active mapping(s)
tunmux proton ports release                   # stop daemon + release mapping(s)
```

### AirVPN

```bash
tunmux airvpn login <username>
tunmux airvpn info
tunmux airvpn servers --country NL --tag nl
tunmux airvpn servers --sort latency
tunmux connect airvpn Castor
tunmux connect airvpn --country DE --key "my device"
tunmux connect airvpn --country DE --sort latency
tunmux airvpn sessions
tunmux airvpn generate -s nl -s be -p wg-1637 -o config.conf
tunmux airvpn ports list
tunmux airvpn ports add 8080 --protocol tcp --ddns myhost
tunmux airvpn devices list
tunmux airvpn api list
tunmux disconnect --provider airvpn --all
tunmux airvpn logout
```

### Mullvad

```bash
tunmux mullvad login <account_number>
tunmux mullvad create-account
tunmux mullvad payment monero --json
tunmux mullvad info
tunmux mullvad servers --country US --tag us-nyc
tunmux mullvad servers --sort latency
tunmux connect mullvad us-nyc-wg-401
tunmux connect mullvad --country SE --sort latency
tunmux disconnect --provider mullvad
tunmux mullvad logout
```

### IVPN

```bash
tunmux ivpn create-account
tunmux ivpn create-account --product pro
tunmux ivpn payment monero --duration 1m
tunmux ivpn login <account_id>
tunmux ivpn info
tunmux ivpn servers --country US --tag us1
tunmux ivpn servers --sort latency
tunmux connect ivpn us-ny4.wg.ivpn.net
tunmux connect ivpn --country US --sort latency
tunmux disconnect --provider ivpn
tunmux ivpn logout
```

### WGConf (local WireGuard config/profile provider)

```bash
tunmux connect wgconf --file ./my-tunnel.conf --backend wg-quick
tunmux connect wgconf --file ./my-tunnel.conf --save-as office
tunmux connect wgconf --profile office --local-proxy
tunmux connect wgconf --file ./ipv4-only.conf --backend kernel --disable-ipv6
tunmux connect wgconf --file ./my-tunnel.conf --backend kernel --mtu 1280
tunmux wgconf save --file ./my-tunnel.conf --name backup
tunmux wgconf list
tunmux wgconf remove backup
tunmux disconnect --provider wgconf
```

`--disable-ipv6` is supported by `connect` for `proton`, `airvpn`, `mullvad`,
`ivpn`, and `wgconf`. It is accepted only for direct kernel mode (no
`--proxy`/`--local-proxy`) and only when the selected WireGuard config has no
IPv6 interface address.

`--mtu` is supported by provider `connect` commands. For most providers it
applies to direct and proxy kernel tunnels, as well as generated wg-quick and
userspace configs. For `wgconf`, `--mtu` is supported in kernel mode (direct
or `--proxy`) and is not supported with `--local-proxy`.

## Linux Namespace Proxy Mode (`--proxy`)

Each `--proxy` connection creates:
- a dedicated Linux network namespace
- a dedicated WireGuard interface in that namespace
- a local SOCKS5 and HTTP proxy bound on localhost

Multiple instances can run at once, each with different exits and ports.

## Local Proxy Mode (`--local-proxy`)

`--local-proxy` starts a userspace WireGuard tunnel and local SOCKS5/HTTP proxy without `sudo`.

- no root/privileged daemon required
- no host routing changes (only apps configured to use the proxy are tunneled)
- available on Linux and macOS
- supports multiple instances with the same auto-port behavior as `--proxy`
- hostname resolution for proxy requests prefers the VPN-pushed DNS servers
- set `TUNMUX_LOCAL_PROXY_DNS_SERVERS` (or `TUNMUX_DNS_SERVERS`) to override local-proxy DNS resolver servers (comma or whitespace separated)

Port behavior:
- default scan starts at `1080` (SOCKS5) and `8118` (HTTP)
- each new instance picks the next available localhost ports
- override with `--socks-port` and `--http-port`

Instance naming is derived from the selected server and used in status/disconnect commands.

## Direct Mode Details

Direct mode is the default when neither `--proxy` nor `--local-proxy` is used.
- one direct connection is active at a time
- host traffic is routed through that WireGuard tunnel
- stored internally as `_direct` connection state

Direct, `--proxy`, and `--local-proxy` sessions can coexist.

## Multi-Instance Disconnect

If multiple instances exist for a provider, running disconnect without an instance will prompt selection:

```bash
tunmux disconnect --provider proton
```

Disconnect all for one provider:

```bash
tunmux disconnect --provider proton --all
```

Disconnect all active connections across all providers:

```bash
tunmux disconnect --all
```

## Configuration

`tunmux` reads optional defaults from:

`~/.config/tunmux/config.toml`

Example:

```toml
[general]
backend = "kernel"                # default: kernel on unix (except macOS), wg-quick on macOS
credential_store = "keyring"      # keyring or file
proxy_access_log = false
hooks = { ifup = ["builtin:connectivity", "builtin:external-ip"], ifdown = [] }
privileged_transport = "socket"   # socket or stdio
privileged_autostart = true
privileged_autostart_timeout_ms = 5000
privileged_authorized_group = "tunmux"
privileged_autostop_mode = "never"      # never, command, timeout
privileged_autostop_timeout_ms = 30000

[proton]
default_country = "CH"
hooks = { ifup = ["/usr/local/bin/proton-ifup.sh"], ifdown = ["/usr/local/bin/proton-ifdown.sh"] }

[airvpn]
default_country = "NL"
default_device = "laptop"
hooks = { ifup = [], ifdown = [] }

[mullvad]
default_country = "SE"
hooks = { ifup = [], ifdown = [] }

[ivpn]
default_country = "CH"
hooks = { ifup = [], ifdown = [] }

[wgconf]
hooks = { ifup = [], ifdown = [] }
```

CLI flags override config values.

Hook behavior:
- `general.hooks` runs for every provider, then provider-specific hooks run after it.
- `ifup` runs after successful connect; `ifdown` runs after successful disconnect.
- Built-ins are opt-in via hook entries:
  - `builtin:connectivity`: ping IPv4 (`1.1.1.1`) and IPv6 (`2606:4700:4700::1111`)
  - `builtin:external-ip`: fetch external IP via `https://ipinfo.io` and `https://v6.ipinfo.io`
  - `builtin:dns-detection`: query `https://<random>-<n>.ipleak.net/dnsdetection/`
    with a 40-char random host label and incrementing probe number (`-1` to `-10`),
    then run reverse DNS lookup for each recovered resolver IP
- Hook commands run with env vars such as `TUNMUX_HOOK_EVENT`, `TUNMUX_PROVIDER`,
  `TUNMUX_INSTANCE`, `TUNMUX_BACKEND`, `TUNMUX_INTERFACE`, `TUNMUX_SERVER`,
  `TUNMUX_ENDPOINT`, plus optional proxy fields (`TUNMUX_NAMESPACE`, `TUNMUX_SOCKS_PORT`,
  `TUNMUX_HTTP_PORT`, `TUNMUX_PROXY_PID`).
- Hook env also includes `TUNMUX_DNS_SERVERS` when VPN DNS servers are known.
- When proxy ports are present, hook commands also receive standard proxy vars:
  `HTTP_PROXY`/`HTTPS_PROXY` and `ALL_PROXY` (plus lowercase variants).
- Builtin HTTP checks (`external-ip`, `dns-detection`, and proxy-mode `connectivity`) use
  the active connection proxy automatically when available.
- `dns-detection` reverse DNS lookup prefers VPN-configured DNS servers first.
- Manual builtin checks: `tunmux hook run connectivity`, `tunmux hook run external-ip`,
  or `tunmux hook run dns-detection`.
- Debug helper: `tunmux hook debug <instance>` prints the exact env payload used for hooks
  (`--event ifup|ifdown`, default `ifup`).

## Privileged Service

Privileged operations are handled by:

```bash
sudo tunmux privileged --serve --authorized-group <group>
```

Supported transports:
- `socket` (default): Unix socket control channel (`/var/run/tunmux/ctl.sock`, typically `/run/tunmux/ctl.sock`)
- `stdio`: one-shot helper process over stdin/stdout

Autostart can launch the privileged service when needed (if enabled in config).

Example sudoers entries (adjust binary path for your install):

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --autostarted --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --autostarted --authorized-group tunmux --idle-timeout-ms *
```

For stdio mode:

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --stdio --autostarted --authorized-group tunmux
```

## Data Layout

User data under `~/.config/tunmux/`:

```text
~/.config/tunmux/
  config.toml
  connections/
    _direct.json
    <instance>.json
  proton/
    session.json
    manifest.json
  airvpn/
    session.json
    manifest.json
    web_session.json
  mullvad/
    account_id.json
    session.json
    manifest.json
  ivpn/
    account_id.json
    session.json
    manifest.json
  wgconf/
    profiles/
      <name>.conf
```

Runtime state (Linux):

```text
/var/run/tunmux/
  ctl.sock
  managed-pids/
    <pid>.start

/var/lib/tunmux/
  proxy/
    <instance>.pid
    <instance>.log
  wg/
    <provider>/<iface>.conf
```

Runtime state (macOS):

```text
/var/db/tunmux/
  proxy/
  wg/
```

## License

MIT

Copyright (c) 2026 Contributors to tunmux
