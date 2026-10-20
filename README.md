<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/tunmux-lockup-on-dark.svg">
    <img src="assets/logo/tunmux-lockup-on-light.svg" alt="tunmux" width="360">
  </picture>
</p>

# tunmux

A Rust CLI for WireGuard connections through **Proton VPN, AirVPN, Mullvad,
IVPN**, or your own **WireGuard configuration files** (`wgconf`). Use it for a
direct VPN connection or run separate VPN exits as local SOCKS5/HTTP proxies.

## Build

Use the Rust toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml).
Install a C compiler and make for native dependencies (on macOS, install the
Xcode command-line tools). The optional AWS-LC backend also needs CMake and a C++
compiler. AirVPN's default RustCrypto backend requires no native crypto library.
Initialize the bundled `smoltcp` submodule before building:

```sh
git submodule update --init --recursive
cargo build --release --locked
cargo run -- --help
```

The executable is normally `target/release/tunmux` (or under your configured Cargo
target directory). Put it on your `PATH` to use the commands below.

| Mode | Platforms | Requirements |
| --- | --- | --- |
| Direct VPN | Linux, macOS | Privileged helper; changes host routing according to the tunnel configuration |
| `--proxy` | Linux | `proxy` Cargo feature, kernel backend, privileged helper; isolated network namespace |
| `--local-proxy` | Linux, macOS | No root; only applications using the proxy send traffic through the VPN |

Direct mode defaults to `kernel` on Linux and `userspace` on macOS. Linux kernel
mode needs WireGuard kernel support, `ip`, and `wg`; DNS setup uses `resolvectl`.
The `userspace` backend embeds GotaTun. Selecting `--backend wg-quick` requires
an installed `wg-quick` and its platform dependencies. Privileged operations can
start a helper through the system's elevation tools, such as `sudo`.

Android uses the shared Rust library. The app and JNI adapter live in the sibling
`tunmux-android` repository, where APKs are built.

## Usage

### Sign in and connect

Choose your provider's login command. Proton, AirVPN, and IVPN can prompt for
additional credentials when needed.

```sh
tunmux proton login <username>
tunmux airvpn login <username>
tunmux mullvad login <account-number>
tunmux ivpn login <account-id>
```

Then list servers and connect, for example:

```sh
tunmux proton servers --country CH
tunmux connect proton --country CH
tunmux status
tunmux wg
tunmux disconnect --provider proton
```

The account providers also have `info`, `logout`, and `servers` commands.
Select a server by name or use `--country` and `--sort latency`.
Provider-specific options,
including port forwarding, devices, and account creation, are listed in help:

```sh
tunmux --help
tunmux airvpn --help
tunmux connect proton --help
tunmux proton ports --help
```

### Use a WireGuard file

No provider login is needed for `wgconf`:

```sh
tunmux connect wgconf --file ./tunnel.conf
# Save a profile for reuse without connecting:
tunmux wgconf save --file ./tunnel.conf --name work
tunmux wgconf list
tunmux disconnect --provider wgconf
tunmux connect wgconf --profile work
```

`--save-as work` on a file-based connect also saves the profile.
`tunmux wgconf remove work` deletes a saved profile.

### Use a proxy

Start a rootless proxy, then point an application at its assigned port:

```sh
tunmux connect proton --country US --local-proxy
tunmux status
curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
curl --proxy http://127.0.0.1:8118 https://api.ipify.org
```

Ports start at **1080** for SOCKS5 and **8118** for HTTP. Each instance selects
available ports; check `status` or choose `--socks-port` and `--http-port` explicitly.
Use `socks5h://` so hostname resolution happens through the proxy.

On Linux, use `--proxy` instead for an isolated network namespace with a kernel
WireGuard tunnel. Both proxy modes support multiple exits at once and leave host
routing unchanged. One direct connection can coexist with proxy instances.

### Disconnect and inspect

```sh
tunmux status
tunmux disconnect <instance>                 # name shown by status
tunmux disconnect --provider proton --all    # every Proton connection
tunmux disconnect --all                      # every connection
```

Without an instance or `--all`, disconnect handles a single matching connection
or lists the candidates when the choice is ambiguous.

Useful connection options:

- `--if-missing`: succeed without reconnecting when the same source and options
  are already active.
- `--backend kernel|userspace|wg-quick`: override the platform/configured backend.
- `--mtu N`: override the interface MTU (576–65535);
  unavailable in local-proxy mode.
- `--disable-ipv6`: block host IPv6 egress for an IPv4-only direct kernel tunnel.
- `--allow-lan`: bypass directly attached LANs in macOS helper-backed direct mode.

## Configuration and diagnostics

Optional defaults live in `~/.config/tunmux/config.toml`:

```toml
[general]
credential_store = "file"
proxy_access_log = false
hooks = { ifup = ["builtin:connectivity"], ifdown = [] }

[proton]
default_country = "CH"

[airvpn]
default_country = "NL"
default_device = "laptop"

[mullvad]
default_country = "SE"
```

Set `general.backend` to override the platform default. Credentials, cached provider
data, connection state, and saved WireGuard profiles also live under
`~/.config/tunmux/`. Desktop credentials default to file storage;
`credential_store = "keyring"` selects the optional native backend when compiled
in: Secret Service on Linux (requires an unlocked desktop keyring and session
D-Bus), or Keychain on macOS.
See [src/config.rs](src/config.rs) for the complete configuration schema.

```sh
tunmux -v status
RUST_LOG=tunmux=debug,gotatun=warn tunmux status
tunmux hook run connectivity
tunmux hook run external-ip
tunmux hook debug <instance>
```

`RUST_LOG` takes precedence over `-v`. Existing daemons retain their startup log
filter until restarted. Hooks accept built-in checks or executable paths and run
on connection up/down events. Local-proxy DNS prefers the tunnel's DNS servers;
`TUNMUX_LOCAL_PROXY_DNS_SERVERS` overrides them with a comma-separated list.

Status distinguishes observed health from saved metadata. If cleanup fails,
resolve the reported problem and retry disconnect; recovery journals retain
unfinished route/DNS restoration work.

## Service setup

Installing a service is optional; rootless local-proxy mode does not need one.

On **Linux with systemd**, first create or choose a group containing the users
allowed to access the helper, then install:

```sh
sudo tunmux service install --authorized-group tunmux
systemctl status tunmux-privileged.socket
journalctl -u tunmux-privileged.service
```

The installer does not create groups or change memberships. It copies the binary
to `/usr/local/libexec/tunmux`, installs the units, and enables socket activation.
Disconnect all sessions before `sudo tunmux service uninstall`. Linux does not
support `service reload` or `service diagnose`; use systemd tools.

On **macOS**, install the privileged LaunchDaemon with:

```sh
sudo tunmux service install
tunmux service diagnose
sudo tunmux service reload
sudo tunmux service uninstall
```

Both platforms accept `service install --binary-path /absolute/path` for a custom
installation location. The binary and its ancestors must be root-owned and
protected from writes by other users; Linux service hardening excludes paths
under `/home`, `/root`, and `/run/user`. Linux upgrades must reuse the installed
binary path. Profiles and credentials are preserved on uninstall.

### Automatic connections on macOS

After saving a profile and installing the service:

```sh
tunmux autoconnect enable work -- connect wgconf --profile work
tunmux autoconnect status
tunmux autoconnect disable work
tunmux autoconnect resume work
```

Enabling installs a user login agent. One direct tunnel and multiple local proxies
are supported. Manual disconnect suspends the matching entry until explicitly
resumed. Background attempts never prompt for elevation. Use `--no-login-agent`
on `enable` and run `tunmux autoconnect run` for foreground operation.
Logs are in
`~/.config/tunmux/autoconnect.log`.

## Rust features

Default builds enable **`all-providers`, `proxy`, and `crypto-rustcrypto`**.
Features are additive; use
`--no-default-features` to build a smaller selection.

| Cargo feature | Enables |
| --- | --- |
| `proton`, `airvpn`, `mullvad`, `ivpn` | The named provider, its CLI commands, and provider-specific dependencies |
| `wgconf` | Local WireGuard files and saved profiles |
| `all-providers` | All five providers |
| `proxy` | Linux network-namespace proxy support; not required for rootless local-proxy mode |
| `keyring` | Optional credential storage through the keyring crate |
| `crypto-rustcrypto` | Pure Rust RSA encryption for AirVPN (default) |
| `crypto-aws-lc` | AWS-LC RSA encryption for AirVPN; takes precedence when both crypto features are enabled |

```sh
cargo build --locked --no-default-features --features wgconf
cargo build --locked --no-default-features --features proton,mullvad,proxy
cargo build --locked --features keyring
cargo build --locked --features crypto-aws-lc
# AWS-LC only, excluding the rsa crate from the build:
cargo build --locked --no-default-features --features all-providers,proxy,crypto-aws-lc
# AirVPN with pure Rust RSA:
cargo build --locked --no-default-features --features airvpn,crypto-rustcrypto
```

A build with `--no-default-features` alone retains shared infrastructure without
provider commands. Library consumers using `default-features = false` must choose
providers explicitly. AirVPN requires one of the two crypto features. Android
consumers can enable `all-providers,crypto-rustcrypto` without `proxy`.

These flags select AirVPN's RSA implementation; they do not replace the TLS or
WireGuard crypto stacks. RustCrypto avoids AWS-LC's native build, but other
dependencies still require a C compiler.

[`.cargo/audit.toml`](.cargo/audit.toml) contains one exception for
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071). The advisory
concerns private-key operations; production code only encrypts with AirVPN's
public key. Private-key decryption is limited to offline tests. Review this
exception if RSA usage changes and remove it when a patched version is available.
Cargo audits the entire lockfile, including optional dependencies, so selecting
AWS-LC alone does not remove the lockfile finding.

## Codebase and contributions

The Rust 2021 package provides a library and CLI binary:

| Location | Responsibility |
| --- | --- |
| [src/main.rs](src/main.rs), [src/cli.rs](src/cli.rs), [src/lib.rs](src/lib.rs) | Command entry point, Clap arguments, library exports |
| `src/{proton,airvpn,mullvad,ivpn,wgconf}/` | Provider APIs, models, and command handlers |
| [src/wireguard/](src/wireguard/) | Configuration, backends, connection state, health, and rootless proxy tunnel |
| [src/shared/](src/shared/) | Credentials, hooks, persistence, and common connection operations |
| `src/privileged*`, `src/userspace_helper*` | Privileged requests, embedded GotaTun helper, network setup and recovery |
| [src/proxy/](src/proxy/), [src/netns.rs](src/netns.rs) | Linux namespace proxies |
| [src/service.rs](src/service.rs), [src/automation.rs](src/automation.rs) | Service installation and automatic connections |
| [tests/](tests/), [benches/](benches/), [scripts/](scripts/) | Integration tests, offline benchmarks, and validation tools |
| [third_party/smoltcp/](third_party/smoltcp/) | Patched TCP/IP stack used with BoringTun for rootless proxies |

Keep changes focused, preserve platform and feature gates, and add behavior tests
for fixes. Follow rustfmt, use structured `tracing` logs, and propagate errors with
`Result` and useful context. Never include credentials or private keys in logs,
fixtures, or bug reports. Agent-specific guidance is in [AGENTS.md](AGENTS.md).

Before submitting a contribution, run the repository checks:

```sh
bash scripts/ci.sh
# Optional offline CPU benchmarks (no VPN account or root needed):
cargo bench --locked --bench offline
```

The CI script checks formatting, runs Clippy across all targets/features with
warnings denied, and tests both default and all-feature builds. Keyring tests use
isolated in-memory credentials and never access your account entries.
For feature-gated changes, also
check the affected `--no-default-features --features ...` configuration. Changes
to routes, DNS, privileges, or recovery need live validation on the affected OS;
[scripts/macos_native_validation.py](scripts/macos_native_validation.py) provides
macOS scenarios (`--help` lists its options).

Privileged tests are explicitly ignored by the default suite. Run them only in a
prepared disposable environment after inspecting their requirements. Live VPN
validation scripts under `scripts/` are manual tools: they may change connections,
routes, and DNS. The offline benchmark needs no credentials or privileges.

Lint project Markdown with `rumdl check README.md AGENTS.md` (CI pins version
0.2.77). CI also builds the Docker image and smoke-tests its CLI.

On the maintainer's Linux setup, `.envrc` selects the shared Nix Android shell.
Run checks there with:

```sh
nix develop --no-write-lock-file \
  "path:$HOME/projects-caddy/nix-dev-shells/android" -c bash scripts/ci.sh
```

Other environments can run the same Cargo commands with the pinned toolchain.
Include reproduction steps, OS, backend, enabled features, and validation results
in issues and pull requests.

## Releases and containers

Pushing a `v*` tag runs the checks and `cargo audit`, builds Linux x86-64 and
macOS x86-64/ARM64 archives, and publishes a GitHub Release.
Archives include the binary, README,
license, and an accompanying SHA-256 checksum file. Versions containing `-` are
marked as prereleases. The release workflow then publishes the container image;
the Docker workflow also supports manual publication.

Build a container locally with `docker build -t tunmux .`. It runs as an
unprivileged user and is intended for rootless `--local-proxy` connections.
Provider login and proxy startup must run in the same container with persistent
configuration storage. The proxy listens on container localhost, so consumers
must share its network namespace; publishing a Docker port alone is insufficient.
Direct/kernel modes need additional privileges and host networking integration.
`tunmux status` reports connection state; it is not a container health guarantee.

## License

[MIT](LICENSE).
