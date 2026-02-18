# tunmux

Multi-provider VPN CLI written in Rust. Supports Proton VPN and AirVPN with
WireGuard connectivity, dual backends (wg-quick and kernel), and full account
management.

## Features

### Proton VPN
- SRP authentication with 2FA (TOTP)
- Ed25519/X25519 key generation and VPN certificate provisioning
- Server listing with filters (country, free tier, P2P)
- WireGuard connect/disconnect

### AirVPN
- Encrypted XML API authentication
- Web session management (cookie-based, with session reuse)
- Server listing from cached manifest
- WireGuard connect/disconnect with key selection
- Port forwarding management (add, remove, edit, check reachability, DDNS)
- Device (WireGuard key) management (add, rename, delete)
- API key management (add, rename, delete)
- Config file generation (WireGuard and OpenVPN, single or archive)
- Active session viewing with traffic stats

### WireGuard
- Two backends: wg-quick (default) and kernel (ip/wg commands)
- Auto-detection: uses wg-quick when available, falls back to kernel
- Connection state tracking across providers (prevents dual connections)
- Kernel backend handles routing, DNS, and clean teardown

## Requirements

- Rust 2021 edition (latest stable)
- Linux (uses ip/wg-quick commands)
- sudo access for WireGuard operations

## Build

    cargo build
    cargo build --features keyring   # enable OS keyring credential storage

## Usage

    tunmux <provider> <command>

### Proton VPN

    tunmux proton login <username>
    tunmux proton info
    tunmux proton servers --country US --free
    tunmux proton connect --country CH --p2p --backend auto
    tunmux proton connect US#1
    tunmux proton disconnect
    tunmux proton logout

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

## Configuration

### Config file

tunmux reads `~/.config/tunmux/config.toml` for default preferences. All fields
are optional; a missing file means all defaults apply.

    [general]
    backend = "auto"              # default WireGuard backend: auto, wg-quick, kernel
    credential_store = "keyring"  # "keyring" or "file" (requires --features keyring)

    [proton]
    default_country = "CH"

    [airvpn]
    default_country = "NL"
    default_device = "laptop"

CLI flags always override config values. For example, `--backend wg-quick` takes
precedence over `backend = "kernel"` in the config file, and `--country US`
overrides `default_country`.

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
      connection.json          # active connection state (provider-neutral)
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
