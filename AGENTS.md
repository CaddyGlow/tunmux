# AGENTS.md

Guidance for coding agents working in `tunmux`.

## 1) Project Snapshot

- Language: Rust (edition 2021); use the toolchain pinned in `rust-toolchain.toml`.
- Crate layout: single package with library + binary (`src/lib.rs`, `src/main.rs`).
- Domain: multi-provider VPN CLI (`proton`, `airvpn`, `mullvad`, `ivpn`, `wgconf`).
- Platforms:
  - Linux: direct, namespace proxy, rootless local-proxy, and systemd service installation.
  - macOS: direct, rootless local-proxy, launchd service installation,
    and login-agent autoconnect.
  - Android: shared-library support; app and JNI adapter live in `../tunmux-android`.
- Default Cargo features: `all-providers` and `proxy`. Each provider is independently
  gated; `keyring` is optional. `proxy` enables Linux namespace proxies, not rootless
  local-proxy mode.
- Direct backend defaults: `kernel` on Linux, embedded GotaTun `userspace` on macOS.
  Rootless proxies use BoringTun and the patched `smoltcp` stack.
- User-facing documentation is consolidated in `README.md`; keep usage there.

## 2) Build, Run, Lint, and Test Commands

### Environment

- Initialize `third_party/smoltcp` with `git submodule update --init --recursive`.
  See README for the public-URL override if the maintainer SSH alias is unavailable.
- On the maintainer's Linux setup, `.envrc` selects the shared Nix Android shell.
  Run development tools through it, for example:

  ```sh
  nix develop --no-write-lock-file \
    "path:$HOME/projects-caddy/nix-dev-shells/android" -c bash scripts/ci.sh
  ```

- Commands below assume the development shell is active. Preserve toolchain pins,
  lockfiles, Cargo cache settings, and the configured target directory.

### Core local commands

- Build: `cargo build --locked`
- Build with optional keyring: `cargo build --locked --features keyring`
- Run CLI: `cargo run -- --help`
- Example login: `cargo run -- proton login <username>`
- Example connect: `cargo run -- connect proton --country CH`
- WGConf-only build: `cargo build --locked --no-default-features --features wgconf`

### Formatting and lint

- Format code: `cargo fmt --all`
- Check formatting (CI style): `cargo fmt --all --check`
- Clippy (strict, CI style):
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
- Quick clippy during development:
  - `cargo clippy -- -D warnings`

### Tests

- Run full test suite: `cargo test --locked`
- Run full test suite (dev quick): `cargo test`
- Run a single test by name:
  - `cargo test test_select_relay_by_name`
- Run a single test by full path filter:
  - `cargo test mullvad::handlers::tests::test_select_relay_by_name`
- Run one async tokio test:
  - `cargo test test_session_new_with_confirmation_and_manifest_fetch`
- Show test output:
  - `cargo test test_select_host_by_hostname -- --nocapture`

### Repo CI helper

- CI script used by GitHub Actions: `bash ./scripts/ci.sh`
- What it runs:
  - `cargo fmt --all --check`
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
  - `cargo test --locked`
- For feature-gated changes, also run Clippy and `cli::tests` with
  `--no-default-features --features <selection>`. CI covers no features, each
  individual provider, `proxy`, and `proxy,wgconf`.
- Offline CPU benchmarks: `cargo bench --locked --bench offline`.

### Android build (when needed)

- This repository checks the shared Rust library for Android in CI.
- Shared-library check (Android SDK/NDK and cargo-ndk required):

  ```sh
  cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 check --locked --lib \
    --no-default-features --features all-providers
  ```

- App builds and APK release workflows live in `../tunmux-android`.
- Follow that repository's instructions for app builds.

## 3) Source Layout and Architectural Conventions

- Keep modules fairly flat; avoid unnecessary deep nesting.
- Provider modules live under:
  - `src/proton/`
  - `src/airvpn/`
  - `src/mullvad/`
  - `src/ivpn/`
  - `src/wgconf/`
- Shared/system modules include:
  - `src/config.rs`, `src/error.rs`, `src/logging.rs`
  - `src/wireguard/`, `src/privileged*.rs`, `src/proxy/`
  - `src/shared/` for credential storage, hooks, persistence, and connection operations
  - `src/userspace_helper*` for the embedded tunnel helper and network recovery
  - `src/local_proxy*` and `src/wireguard/proxy_tunnel/` for rootless proxies
  - `src/service.rs`, `src/automation.rs`, `src/network_changes.rs`
    for services and reconnects
- Preserve both platform and Cargo feature gates. Non-Android does not imply Linux.

## 4) Code Style Rules

### Formatting and structure

- Always follow `rustfmt` output; do not hand-format against it.
- Prefer short, composable functions over large monolithic blocks.
- Use early returns for error branches and guard conditions.
- Keep comments minimal and focused on non-obvious intent.

### Imports

- Group imports in this order when practical:
  1. `std` imports
  2. third-party crate imports
  3. `crate::...` imports
  4. `super::...` imports
- Use explicit imports where readability improves.
- Avoid unused imports; clippy is run with `-D warnings` in CI.

### Naming

- Types/traits/enums: `UpperCamelCase`.
- Functions/variables/modules: `snake_case`.
- Constants/statics: `SCREAMING_SNAKE_CASE`.
- Tests are named with `test_...` prefixes and descriptive intent.

### Types and ownership

- Prefer borrowed params in APIs:
  - `&str` over `&String`
  - `&[T]` over `&Vec<T>`
- Prefer enums to encode state over loosely-related booleans.
- Add `#[must_use]` to return values that should not be ignored.
- Avoid unnecessary `.clone()`; borrow when possible.

### Error handling

- In shared/library-style code, prefer `crate::error::Result<T>` / `AppError`.
- In command orchestration / CLI flows, `anyhow::Result<T>` is common.
- Use `?` for propagation.
- Avoid `.unwrap()`/`.expect()` in non-test code unless failure is truly
  unrecoverable and intentional.
- Prefer specific context in error messages (`what failed` + relevant value).

### Logging

- Use `tracing` macros (`trace!`, `debug!`, `info!`, `warn!`, `error!`).
- Keep event names short and structured (for example `command_failed`).
- Put dynamic values in structured fields, not only in formatted strings.
- Initialize logging through `src/logging.rs` helpers (`init_terminal`, `init_file`).
- Keep the returned logging guard alive until shutdown so buffered logs flush.
- Never log credentials, private keys, or complete privileged request payloads.

### Serde and models

- Use `serde` derives (`Serialize`, `Deserialize`) for persisted/API structs.
- Prefer struct-level `#[serde(rename_all = "...")]` when API casing is consistent.
- Keep model naming aligned with provider/API terms.

### Async and runtime

- `tokio` is the async runtime in use.
- Keep async boundaries explicit (`async fn` returning `Result`).
- Do not block in async code unless explicitly isolated/intentional.

### Platform-specific code

- Linux-only code paths must be cfg-gated.
- Non-Linux fallbacks/stubs exist (`netns_stub.rs`, `proxy_stub.rs`);
  keep behavior consistent.

### Unsafe code

- Some existing low-level paths use `unsafe` (fork/fd boundaries).
- Do not add new `unsafe` unless necessary.
- If adding/changing `unsafe`, keep scope minimal and document invariants.

## 5) Testing Conventions

- Prefer integration-like behavior tests over brittle implementation-detail tests.
- Keep tests near code in `#[cfg(test)] mod tests` blocks.
- CLI integration tests also live in `tests/`.
- Use descriptive test names that encode behavior and expectation.
- For network/API logic, existing tests use local mock servers; follow that pattern.

## 6) Agent Workflow Expectations

- Before finishing substantial changes, run:
  - `cargo fmt --all --check`
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
  - `cargo test --locked` (or targeted tests while iterating)
- If time is limited, run the most targeted tests first, then broader checks.
- Keep changes scoped; avoid unrelated refactors.
- Route, DNS, privilege, and recovery changes require native validation on affected
  platforms; compilation and unit tests do not establish live network behavior.
  See `scripts/macos_native_validation.py --help` for macOS scenarios.
- Preserve session identity and ownership checks. Unknown health is not proof a
  session is inactive; incomplete cleanup must retain recovery information.

## 7) Cursor/Copilot Rule Files

- Checked for Cursor rules:
  - `.cursorrules`
  - `.cursor/rules/**`
  - None found in this repository at time of writing.
- Checked for Copilot rules:
  - `.github/copilot-instructions.md`
  - None found in this repository at time of writing.
- If any of these files are added later, treat them as higher-priority agent
  instructions and update this document.
