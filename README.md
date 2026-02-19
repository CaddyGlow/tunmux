# tunmux

Multi-provider VPN CLI written in Rust. Supports Proton VPN and AirVPN with
WireGuard connectivity, dual backends (wg-quick and kernel), and full account
management.

## Features

### Proxy mode (network namespace isolation)

Connect to multiple VPN exits simultaneously without routing all host traffic
through the VPN. Each `--proxy` connection creates:

- A dedicated Linux network namespace with its own WireGuard interface
- A SOCKS5 and HTTP proxy on localhost that routes traffic through that namespace
- Full isolation: only applications using the proxy go through the VPN

Multiple proxy instances can run side-by-side, each with a different exit
location and its own port pair. Host traffic is unaffected.

### Proton VPN
- SRP authentication with 2FA (TOTP)
- Ed25519/X25519 key generation and VPN certificate provisioning
- Server listing with filters (country, free tier, P2P)
- WireGuard connect/disconnect (direct or proxy mode)

### AirVPN
- Encrypted XML API authentication
- Web session management (cookie-based, with session reuse)
- Server listing from cached manifest
- WireGuard connect/disconnect with key selection (direct or proxy mode)
- Port forwarding management (add, remove, edit, check reachability, DDNS)
- Device (WireGuard key) management (add, rename, delete)
- API key management (add, rename, delete)
- Config file generation (WireGuard and OpenVPN, single or archive)
- Active session viewing with traffic stats

### WireGuard
- Two backends: wg-quick (default) and kernel (ip/wg commands)
- Auto-detection: uses wg-quick when available, falls back to kernel
- Connection state tracking across providers
- Kernel backend handles routing, DNS, and clean teardown
- Namespace-aware kernel backend for proxy mode (no host route changes)

## Requirements

- Rust 2021 edition (latest stable)
- Linux (uses ip/wg-quick commands and network namespaces)
- `sudo` access to run `tunmux privileged --serve` for privileged WireGuard/namespace operations
- Optional: systemd socket activation via `tunmux-privileged.socket`

## Build

    cargo build
    cargo build --features keyring   # enable OS keyring credential storage

## Usage

    tunmux <command>

### Status

    tunmux status

Shows all active connections with instance names, providers, servers, backends,
and proxy ports.

### Proton VPN

    tunmux proton login <username>
    tunmux proton info
    tunmux proton servers --country US --free
    tunmux proton connect --country CH --p2p --backend auto
    tunmux proton connect US#1
    tunmux proton disconnect
    tunmux proton logout

#### Proxy mode

    # First proxy instance (auto-assigns ports 1080/8118)
    tunmux proton connect --proxy --country US

    # Second proxy instance (auto-assigns ports 1081/8119)
    tunmux proton connect --proxy --country CH

    # Explicit ports
    tunmux proton connect --proxy --country JP --socks-port 9050 --http-port 3128

    # Use the proxy
    curl --socks5 127.0.0.1:1080 https://api.ipify.org    # US exit
    curl --socks5 127.0.0.1:1081 https://api.ipify.org    # CH exit
    curl https://api.ipify.org                              # real IP (no proxy)

    # Disconnect one instance
    tunmux proton disconnect us-1

    # Disconnect all proton connections
    tunmux proton disconnect --all

### AirVPN

    tunmux airvpn login <username>
    tunmux airvpn info
    tunmux airvpn servers --country NL
    tunmux airvpn connect --country DE --key "my device"
    tunmux airvpn connect Castor
    tunmux airvpn disconnect
    tunmux airvpn sessions
    tunmux airvpn ports list
    tunmux airvpn ports add 8080 --protocol tcp --ddns myhost
    tunmux airvpn ports info 8080
    tunmux airvpn ports check 8080
    tunmux airvpn ports set 8080 --local 9090
    tunmux airvpn ports remove 8080
    tunmux airvpn devices list
    tunmux airvpn devices add --name "laptop"
    tunmux airvpn devices rename "laptop" "desktop"
    tunmux airvpn devices delete "old-device"
    tunmux airvpn api list
    tunmux airvpn api add --name "scripts"
    tunmux airvpn api rename "scripts" "deploy"
    tunmux airvpn api delete "old-key"
    tunmux airvpn generate -s nl -s be -p wg-1637 -o config.conf
    tunmux airvpn logout

#### Proxy mode

    tunmux airvpn connect --proxy --country IT
    tunmux airvpn connect --proxy Castor --socks-port 9060 --http-port 3129
    tunmux airvpn disconnect castor
    tunmux airvpn disconnect --all

### Multi-instance disconnect

When multiple connections are active for a provider, `disconnect` without
arguments lists them:

    $ tunmux proton disconnect
    Multiple active connections. Specify which to disconnect:

      us-1  US#1  SOCKS5 :1080, HTTP :8118
      ch-3  CH#3  SOCKS5 :1081, HTTP :8119

    Usage: tunmux proton disconnect <instance>
           tunmux proton disconnect --all

## Architecture

### Proxy mode

```
Host namespace             Namespace: tunmux_us-1         Namespace: tunmux_ch-3
+------------------+      +---------------------+       +---------------------+
| App A            |      | wg-us-1 interface   |       | wg-ch-3 interface   |
|  socks5 :1080 ---|----->| US VPN exit         |       | CH VPN exit         |
|                  |      +---------------------+       +---------------------+
| App B            |             ^                             ^
|  socks5 :1081 ---|-------------|-----------------------------+
|                  |
| Normal traffic   |
|  (no proxy)      |--- direct internet (no VPN) --->
+------------------+
```

Each proxy daemon binds listeners on the host, then calls `setns()` to enter
its VPN namespace. All outbound connections from the daemon route through that
namespace's WireGuard tunnel. A single-threaded tokio runtime ensures all I/O
stays on the thread that entered the namespace.

### Instance naming

Auto-derived from the server name:
- Proton `US#1` -> instance `us-1`, interface `wg-us-1`, namespace `tunmux_us-1`
- AirVPN `Castor` -> instance `castor`, interface `wg-castor`, namespace `tunmux_castor`

### Port assignment

- First instance: SOCKS5 `1080`, HTTP `8118`
- Subsequent instances auto-increment: `1081`/`8119`, `1082`/`8120`, etc.
- Override with `--socks-port` / `--http-port`

### Direct mode

Traditional all-traffic VPN (the default, without `--proxy`). Captures all host
traffic through the WireGuard tunnel. Only one direct connection can be active
at a time. Stored as the `_direct` instance.

Direct and proxy connections can coexist: a direct connection routes all host
traffic through one VPN, while proxy instances provide opt-in access to
additional exits.

## Configuration

### Config file

tunmux reads `~/.config/tunmux/config.toml` for default preferences. All fields
are optional; a missing file means all defaults apply.

    [general]
    backend = "auto"              # default WireGuard backend: auto, wg-quick, kernel
    credential_store = "keyring"  # "keyring" or "file" (requires --features keyring)
    privileged_autostart = true
    privileged_autostart_timeout_ms = 5000
    privileged_authorized_group = "tunmux"
    privileged_autostop_mode = "never"      # never, command, timeout
    privileged_autostop_timeout_ms = 30000  # used when mode = "timeout"

    [proton]
    default_country = "CH"

    [airvpn]
    default_country = "NL"
    default_device = "laptop"

CLI flags always override config values. For example, `--backend wg-quick` takes
precedence over `backend = "kernel"` in the config file, and `--country US`
overrides `default_country`.

### Privileged daemon autostart

When a privileged command is issued and `/run/tunmux/ctl.sock` is missing or not
accepting connections, `tunmux` can autostart the daemon with:

```bash
sudo /usr/bin/tunmux privileged --serve --authorized-group <group>
```

Autostart behavior:
- Uses `sudo -n -b` first (non-interactive).
- If sudo needs a password and a TTY is available, runs `sudo -v` once, then retries background start.
- Uses a per-user startup lock (`$XDG_RUNTIME_DIR/tunmux` or `/tmp/tunmux-$UID`) to avoid race-starting multiple daemons.
- Optional autostop modes for autostarted daemons:
  - `privileged_autostop_mode = "command"`: uses command-scope lease refcount and explicit `shutdown-if-idle` when the command exits.
  - `privileged_autostop_mode = "timeout"`: exits after `privileged_autostop_timeout_ms` of idle time.

Recommended sudoers entry (example):

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --authorized-group tunmux
```

Typical failures:
- `autostart disabled and privileged socket unavailable`
- `sudo not found in PATH`
- `sudo password required but no TTY available`
- `startup timeout waiting for privileged daemon readiness`
- `authorization denied by privileged daemon`

### Keyring support

When built with `--features keyring` and `credential_store = "keyring"` is set
in the config file, session credentials are stored in the OS secret service
(e.g., GNOME Keyring, KDE Wallet, macOS Keychain) instead of plaintext JSON
files. No automatic migration -- after enabling keyring, run
`tunmux <provider> login` again to store credentials in the keyring.

### Data directory

Session and connection state stored in `~/.config/tunmux/`:

    ~/.config/tunmux/
      config.toml              # user preferences (optional)
      connections/             # multi-instance connection state
        us-1.json              # proxy instance state
        us-1.pid               # proxy daemon PID
        us-1.log               # proxy daemon log
        _direct.json           # direct (non-proxy) connection state
      proton/
        session.json           # Proton VPN credentials and keys
      airvpn/
        session.json           # AirVPN credentials and WG keys
        manifest.json          # cached server list
        web_session.json       # web session cookies and CSRF tokens

## Verbose logging

    tunmux -v <provider> <command>
    RUST_LOG=debug tunmux <provider> <command>

## License

[to be determined by owner]
