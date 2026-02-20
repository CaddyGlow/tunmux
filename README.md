# tunmux

`tunmux` is a multi-provider VPN CLI written in Rust.

Supported platforms:
- Linux: direct mode and proxy mode
- macOS: direct mode only (proxy mode is not available)

It supports Proton VPN, AirVPN, Mullvad, and IVPN with WireGuard connectivity in:
- direct mode (system-wide routing)
- proxy mode (isolated per-connection namespace with local SOCKS5/HTTP proxies)

## What It Does

- Connect/disconnect VPN sessions across multiple providers
- Run multiple VPN exits side-by-side in proxy mode
- In proxy mode, keep host traffic unchanged unless an app explicitly uses a proxy
- Manage provider-specific account and utility commands from one CLI
- Support multiple WireGuard backends: `wg-quick`, `userspace`, `kernel`

## Platform And Requirements

- Rust (stable, edition 2021)
- Linux for full feature set (kernel backend + network namespace proxy isolation)
- macOS for direct mode (`--proxy` is Linux-only; use `--backend userspace` or `--backend wg-quick`)
- `sudo` access for privileged operations (`tunmux privileged --serve`)

`userspace` mode uses the embedded `gotatun` library through a built-in helper; no separate `gotatun` CLI install is required.

Optional:
- systemd socket activation via `systemd/tunmux-privileged.socket`
- keyring storage via `cargo build --features keyring`

## Build

```bash
cargo build
cargo build --features keyring
```

## Release CI (Tag-Based)

Pushing a git tag (for example `v1.2.3`) triggers `.github/workflows/release.yml` to:
- build release binaries for Linux, macOS, and Android targets
- upload tarballs and SHA256 files to a GitHub Release for that tag
- build and publish a multi-arch Docker image to GHCR

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
tunmux proton connect --country CH --backend wg-quick
tunmux status
tunmux proton disconnect
```

### 2) Start isolated proxy exits (proxy mode)

```bash
# First proxy instance (typically SOCKS5 1080, HTTP 8118)
tunmux proton connect --proxy --country US

# Second proxy instance (next available ports)
tunmux proton connect --proxy --country CH

# Use a specific proxy
curl --socks5 127.0.0.1:1080 https://api.ipify.org

# Host traffic remains unchanged unless using proxy
curl https://api.ipify.org
```

## Command Map

Top-level commands:

```bash
tunmux status
tunmux proton <...>
tunmux airvpn <...>
tunmux mullvad <...>
tunmux ivpn <...>
```

Common provider flows:

```bash
tunmux <provider> login ...
tunmux <provider> info
tunmux <provider> servers [--country XX]
tunmux <provider> connect [server] [--country XX] [--backend ...] [--proxy]
tunmux <provider> disconnect [instance] [--all]
tunmux <provider> logout
```

Use verbose logs when needed:

```bash
tunmux -v <provider> <command>
RUST_LOG=debug tunmux <provider> <command>
```

## Provider Examples

### Proton VPN

```bash
tunmux proton login <username>
tunmux proton info
tunmux proton servers --country US --free
tunmux proton connect US#1
tunmux proton connect --country CH --p2p
tunmux proton disconnect --all
tunmux proton logout
```

### AirVPN

```bash
tunmux airvpn login <username>
tunmux airvpn info
tunmux airvpn servers --country NL
tunmux airvpn connect Castor
tunmux airvpn connect --country DE --key "my device"
tunmux airvpn sessions
tunmux airvpn generate -s nl -s be -p wg-1637 -o config.conf
tunmux airvpn ports list
tunmux airvpn ports add 8080 --protocol tcp --ddns myhost
tunmux airvpn devices list
tunmux airvpn api list
tunmux airvpn disconnect --all
tunmux airvpn logout
```

### Mullvad

```bash
tunmux mullvad login <account_number>
tunmux mullvad create-account
tunmux mullvad payment monero --json
tunmux mullvad info
tunmux mullvad servers --country US
tunmux mullvad connect us-nyc-wg-401
tunmux mullvad disconnect
tunmux mullvad logout
```

### IVPN

```bash
tunmux ivpn create-account
tunmux ivpn create-account --product pro
tunmux ivpn payment monero --duration 1m
tunmux ivpn login <account_id>
tunmux ivpn info
tunmux ivpn servers --country US
tunmux ivpn connect us-ny4.wg.ivpn.net
tunmux ivpn disconnect
tunmux ivpn logout
```

## Proxy Mode Details

Each `--proxy` connection creates:
- a dedicated Linux network namespace
- a dedicated WireGuard interface in that namespace
- a local SOCKS5 and HTTP proxy bound on localhost

Multiple instances can run at once, each with different exits and ports.

Port behavior:
- default scan starts at `1080` (SOCKS5) and `8118` (HTTP)
- each new instance picks the next available localhost ports
- override with `--socks-port` and `--http-port`

Instance naming is derived from the selected server and used in status/disconnect commands.

## Direct Mode Details

Direct mode is the default when `--proxy` is not used.
- one direct connection is active at a time
- host traffic is routed through that WireGuard tunnel
- stored internally as `_direct` connection state

Direct and proxy sessions can coexist.

## Multi-Instance Disconnect

If multiple instances exist for a provider, running disconnect without an instance will prompt selection:

```bash
tunmux proton disconnect
```

Disconnect all for one provider:

```bash
tunmux proton disconnect --all
```

## Configuration

`tunmux` reads optional defaults from:

`~/.config/tunmux/config.toml`

Example:

```toml
[general]
backend = "wg-quick"              # wg-quick, userspace, kernel
credential_store = "keyring"      # keyring or file
proxy_access_log = false
privileged_transport = "socket"   # socket or stdio
privileged_autostart = true
privileged_autostart_timeout_ms = 5000
privileged_authorized_group = "tunmux"
privileged_autostop_mode = "never"      # never, command, timeout
privileged_autostop_timeout_ms = 30000

[proton]
default_country = "CH"

[airvpn]
default_country = "NL"
default_device = "laptop"

[mullvad]
default_country = "SE"

[ivpn]
default_country = "CH"
```

CLI flags override config values.

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
