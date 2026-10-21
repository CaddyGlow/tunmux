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
Build and run:

```sh
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

### Desktop app

`tunmux-gui` is a window and system tray for the same accounts and connections.
On Linux the tray uses StatusNotifierItem (KDE, waybar, GNOME with the
AppIndicator extension). It is the `tunmux-gui` workspace package; build it
together with `tunmux` so the GUI finds the CLI next to it, otherwise on
`PATH`:

```sh
cargo build --release --locked -p tunmux -p tunmux-gui
target/release/tunmux-gui            # --hidden: start in the tray only
```

The tray shows connection status, quick connect, recent servers, and
disconnect. The window logs in, browses and connects to servers in each mode,
and has provider tools for AirVPN ports, devices and API keys, Proton port
forwarding and certificate renewal, and `wgconf` profiles. Settings save the
backend and proxy access log to `config.toml`; GUI-only options go to
`~/.config/tunmux/gui.toml`, and "Start at login" writes an XDG autostart entry.
Started without a terminal, the privileged helper asks for elevation through
`run0` or `pkexec`. `--mock` shows sample data without touching any account.

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
See [crates/tunmux-core/src/config.rs](crates/tunmux-core/src/config.rs) for the complete configuration schema.

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
`--no-default-features` to build a smaller selection. The `tunmux` CLI package
and the `tunmux-core` library share these feature names; the CLI forwards each
one to the library.

| Cargo feature | Enables |
| --- | --- |
| `proton`, `airvpn`, `mullvad`, `ivpn` | The named provider, its CLI commands, and provider-specific dependencies (in the CLI, also password prompts) |
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
provider commands. Library consumers depend on `tunmux-core`, which has no
clap or terminal prompts; with `default-features = false` they must choose
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

The Cargo workspace keeps its packages under `crates/`: `crates/tunmux-core` is
the library, `crates/tunmux-cli` the `tunmux` CLI package, `crates/tunmux-gui` the
desktop app,
`crates/tunmux-build-version` derives version strings from git, and `xtask/`
holds the build and CI automation.

| Location | Responsibility |
| --- | --- |
| [crates/tunmux-cli/src/main.rs](crates/tunmux-cli/src/main.rs), [crates/tunmux-cli/src/cli/](crates/tunmux-cli/src/cli/) | Command entry point, Clap arguments, provider subcommands, prompts and output, autoconnect controller |
| [crates/tunmux-core/src/lib.rs](crates/tunmux-core/src/lib.rs), [crates/tunmux-core/src/api.rs](crates/tunmux-core/src/api.rs) | Library exports and the data-returning API used by the GUI |
| `crates/tunmux-core/src/{proton,airvpn,mullvad,ivpn,wgconf}/` | Provider APIs, models, connect, disconnect and logout |
| [crates/tunmux-core/src/wireguard/](crates/tunmux-core/src/wireguard/) | Configuration, backends, connection state, health, and rootless proxy tunnel |
| [crates/tunmux-core/src/shared/](crates/tunmux-core/src/shared/) | Credentials, hooks, persistence, progress reporting, and common connection operations |
| `crates/tunmux-core/src/privileged*`, `crates/tunmux-core/src/userspace_helper*` | Privileged requests, embedded GotaTun helper, network setup and recovery |
| [crates/tunmux-core/src/proxy/](crates/tunmux-core/src/proxy/), [crates/tunmux-core/src/netns.rs](crates/tunmux-core/src/netns.rs) | Linux namespace proxies |
| [crates/tunmux-core/src/service.rs](crates/tunmux-core/src/service.rs), [crates/tunmux-core/src/automation.rs](crates/tunmux-core/src/automation.rs) | Service installation and connection identity for automatic connections |
| [crates/tunmux-cli/tests/](crates/tunmux-cli/tests/), [crates/tunmux-core/tests/](crates/tunmux-core/tests/), `crates/*/benches/`, [scripts/](scripts/) | Integration tests, offline benchmarks, and validation tools |
| [CaddyGlow/smoltcp](https://github.com/CaddyGlow/smoltcp) | Patched TCP/IP stack used with BoringTun for rootless proxies (Cargo git patch) |

Keep changes focused, preserve platform and feature gates, and add behavior tests
for fixes. Follow rustfmt, use structured `tracing` logs, and propagate errors with
`Result` and useful context. Never include credentials or private keys in logs,
fixtures, or bug reports. Agent-specific guidance is in [AGENTS.md](AGENTS.md).

Before submitting a contribution, run the repository checks:

```sh
cargo xtask ci
# Optional offline CPU benchmarks (no VPN account or root needed):
cargo bench --locked --bench offline
```

`cargo xtask ci` is what GitHub Actions runs: formatting, Clippy across all
targets/features with warnings denied, default and all-feature tests, the
per-provider feature matrix, Markdown lint and `cargo audit` (`cargo xtask ci
--help` lists the steps; `docker` builds and smoke-tests both images). Enable the
matching git hooks with `git config core.hooksPath .githooks`: pre-commit runs
`cargo xtask ci --quick`, pre-push runs `fmt clippy test markdown`. Keyring tests
use isolated in-memory credentials and never access your account entries.
Changes to routes, DNS, privileges, or recovery need live validation on the
affected OS;
[scripts/macos_native_validation.py](scripts/macos_native_validation.py) provides
macOS scenarios (`--help` lists its options), including `--scenario autoconnect`
for isolated local-proxy reconnect and manual-suspension checks. Run that scenario
as the login user with `--binary` and `--profile-file`; it creates no login agent.

For Linux dataplane comparisons, run `cargo xtask bench-wg --bin /path/to/release/tunmux`.
This compares kernel WireGuard, GotaTun, and the rootless local proxy with local
peers, rotating backend order and recording throughput, idle/loaded latency, CPU
usage, UDP drop and TCP retransmit counters, and raw iperf JSON. Local-proxy
traffic goes through its SOCKS5 port using a built-in generator, each round first
checks that a client's half-close still gets the reply, and each round's daemon log
is saved next to the JSON. `--help` lists duration, repeat, stream,
MTU, added delay (`--delay-ms`), backend selection (`--backends`), and output
options. It requires `ip`, `wg`, `iperf3`, `ping`, `mount`, `unshare`, and
`/dev/net/tun` (plus `tc` with `--delay-ms`), and either unprivileged user
namespaces or root. Private mount, network, and PID namespaces
contain the benchmark; no VPN account or internet traffic is needed. This manual
benchmark is separate from CI and the offline CPU benchmark.

Privileged tests are explicitly ignored by the default suite. Run them only in a
prepared disposable environment after inspecting their requirements. Live VPN
validation scripts under `scripts/` are manual tools: they may change connections,
routes, and DNS. The offline benchmark needs no credentials or privileges.

On the maintainer's Linux setup, `.envrc` selects the shared Nix Android shell.
Run checks there with:

```sh
nix develop --no-write-lock-file \
  "path:$HOME/projects-caddy/nix-dev-shells/android" -c cargo xtask ci
```

Other environments can run the same command with the pinned toolchain; CI pins
cargo-audit and rumdl, and `cargo xtask ci` warns when local versions differ.
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

`Dockerfile.distroless` builds a static musl binary on
`gcr.io/distroless/static-debian13:nonroot` (no shell or networking tools), which
only suits `--local-proxy` mode:
`docker build -f Dockerfile.distroless -t tunmux:distroless .`. Its configuration
lives under `/home/nonroot/.config/tunmux`.

### Local cross-builds

`cargo run -p xtask -- dist` builds and packages every supported target into
`dist/` with the same archive and checksum layout as the release workflow:
Linux gnu (glibc 2.28 floor) and static musl for x86-64 and ARM64,
macOS x86-64/ARM64, and a Flatpak bundle. Select subsets with `linux`, `gnu`,
`musl`, `macos`, `flatpak`, `flatpak-aarch64` or a target triple;
`cargo run -p xtask -- targets` lists them. Run it in the Nix dev shell: Linux
targets use `cargo-zigbuild`, macOS cross-linking needs clang, lld and `SDKROOT`
pointing at a MacOSX SDK, and targets without an installed Rust standard library
are skipped. Linux binaries are checked for a distribution loader, no rpath and
the glibc floor (musl: fully static).

The Flatpak bundle wraps the static musl binary for rootless local-proxy use and
needs the Flathub `org.freedesktop.Sdk` 25.08 (`--install-flatpak-deps` installs
it for the current user). Windows (`x86_64-pc-windows-msvc`, via `cargo-xwin`) is
selectable but does not build yet: the crate is Unix-only.

## License

[MIT](LICENSE).
