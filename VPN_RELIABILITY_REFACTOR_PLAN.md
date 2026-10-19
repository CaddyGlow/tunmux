# VPN reliability and macOS integration plan

## Objective

Implement the useful reliability improvements proposed in PRs [#1](https://github.com/CaddyGlow/tunmux/pull/1) and [#3](https://github.com/CaddyGlow/tunmux/pull/3) through incremental changes to the current codebase. Preserve provider integrations, Linux functionality, Android support, and existing proxy modes.

This plan follows a read-only source review using three agents for lifecycle/state, macOS networking, and tracing. Findings have not been confirmed through native macOS execution. Source locations below refer to the code at review time and may move.

## Scope decisions

| Proposal | Decision |
| --- | --- |
| Diagnostic deadlock | Fix first; replace the self-querying subprocess with direct async device statistics. |
| SIGTERM/SIGINT handling | Preserve existing handlers; make them reachable during diagnostics and shutdown. |
| Probe and device-stop deadlines | Add deadlines with explicit cancellation/resource handling. |
| Stale/corrupt state | Centralize health inspection and recovery; preserve unfinished restoration data. |
| Status | Improve existing shared status; an optional `wgconf status` alias delegates to it. |
| Debug flag | Keep existing verbosity semantics; optionally alias `--debug` to `--verbose`. |
| Forwarded logs | Separate optional change using structured, negotiated frames. |
| Userspace MTU | Add shared parsing, validation, override resolution, and helper propagation. |
| DNS and LAN reconciliation | Implement ownership-aware recovery first, then network-change reconciliation with explicit LAN policy. |
| macOS launchd | Add as an optional activation backend after lifecycle reliability. |
| Login connection/reconnect | Opt-in feature after reliable health and recovery exist. |
| Installation tooling | Separate packaging change with explicit install, reload, diagnostic, and uninstall behavior. |
| gotatun upgrade | No upgrade to the PR's 0.7.1: current Cargo.toml already requests 0.10. |

Do not import either branch wholesale. In particular, do not adopt PR #4's removal of providers, platforms, or proxy functionality.

## Phase 1: responsive helper lifecycle and acknowledged disconnect

### Findings

- `src/userspace_helper.rs:195` creates a current-thread runtime.
- The shutdown ticker calls diagnostics synchronously, ultimately reaching `Command::output()` for `wg show` at line 400. The command queries the helper's own UAPI, whose work needs that same runtime.
- Signal handlers already exist; runtime starvation prevents their polling.
- `wait_for_shutdown(...)?` at line 209 can return before network cleanup. Parent readiness notification failure can also bypass teardown after device startup.
- Device stops at lines 212, 255, and 265 have no deadline.
- `src/privileged/commands.rs:354` removes the control socket and reports success before the helper completes restoration.

### Implementation

1. Establish one explicit helper lifecycle owning the device, network recovery state, and shutdown coordination.
2. Replace `wg show` diagnostics with async `device.peers()` statistics available in the installed gotatun 0.10.1 API. Keep diagnostic futures cancellable/selectable against shutdown and bounded by deadlines.
3. Separate passive statistics from active connectivity probes. Emit passive statistics at debug/trace level; make outbound diagnostic traffic explicit and opt-in.
4. Route every outcome after resource acquisition through teardown, including setup failure, readiness-notification failure, shutdown-listener failure, and normal stop.
5. Bound device stop. Network restoration must proceed independently of stop success. Review gotatun stop cancellation behavior before choosing whether to retain, await, or abandon the stop task on timeout.
6. Track helper identity and add a bounded stop acknowledgment. Return successful disconnect only after cleanup completes; report incomplete cleanup and retain recovery data otherwise.
7. For external OS commands that remain necessary, use a small bounded command runner. Async commands need explicit child termination and reaping on timeout/cancellation, bounded output collection, and contextual errors.

Do not use a timeout around `spawn_blocking` as the sole cancellation mechanism: started blocking work is not cancelled and can prevent runtime shutdown.

### Validation

- A stalled diagnostic operation does not prevent shutdown processing.
- Stop deadline expiry still attempts network restoration.
- Failures after startup always reach teardown.
- Disconnect acknowledgment follows cleanup completion and reports timeout/failure accurately.
- Repeat stop/cleanup requests are safe.
- Native macOS test: SIGTERM during a live tunnel restores routes and DNS and exits within the documented bound.

## Phase 2: transactional network recovery and shared health

### Findings

- `src/userspace_helper.rs:996` installs routes before DNS setup succeeds; an error can discard accumulated cleanup state.
- DNS snapshots are appended after DNS/search-domain writes at line 1044, leaving partial mutations without recorded rollback state.
- Cleanup at line 1023 discards restoration errors.
- Original macOS DNS/search-domain state exists only in helper memory.
- `src/wireguard/connection.rs:106` treats JSON existence as connection existence; userspace liveness at `src/wireguard/userspace.rs:50` checks socket presence.
- Connect guards and status use saved state without a shared authoritative health inspection.
- Connection-state writes are not atomic; corrupt entries may block a single load or be skipped by bulk loading.

### Implementation

1. Extract a small platform network interface with plan, apply, rollback/recover, and later reconcile operations. Keep route planning pure where practical.
2. Create a privileged, versioned recovery journal recording session ownership, original state, intended/applied values, and pending cleanup actions. Store no private keys or credentials.
3. Persist recovery information before each mutation. Handle crashes between the mutation and completion recording through idempotent inspection and recovery.
4. Roll back partial setup in reverse order. Attempt all independent cleanup actions, record errors, and retain unfinished actions for retry.
5. Restore DNS only while current values still match those owned by the session. Preserve later changes made by the user or another VPN and report ownership conflicts.
6. Introduce a backend-aware health result distinguishing active, inactive, and unknown, with reasons. Classify saved records as stale only when backend evidence supports it.
7. Probe through privileged operations where permissions require it. Socket existence, PID existence, or interface existence alone must not establish session ownership; account for stale sockets and reused identifiers.
8. Share health inspection across connect guards, status, recovery, and future autoconnect. Probe deadlines and permission errors remain unknown, never proof that cleanup/deletion is safe.
9. Write connection state atomically with restrictive permissions. Quarantine corrupt records with a warning; do not discard independent network recovery records.
10. Recover owned network changes before retiring stale state. Keep recovery state separate from display-oriented connection metadata.

### Validation

- Inject failures after each route/DNS/search-domain mutation and verify rollback.
- Recover from journals representing crashes before and after mutation completion.
- Preserve user-modified DNS and settings owned by another session.
- Test stale sockets, missing interfaces, reused PIDs, permission errors, and timeout/unknown results.
- Test corrupt state, atomic replacement, repeated recovery, and incomplete cleanup retry.
- Native macOS test: crash helper and recover DNS without rebooting or overwriting later user changes.

## Phase 3: idiomatic tracing and reliable log lifecycle

### Findings

- Tracing already exists, and `--verbose` already selects debug output.
- `src/logging.rs:12` parses RUST_LOG by substring, losing target-level directives.
- Subscriber-installation failures are suppressed at line 50.
- The static WorkerGuard at line 86 does not drop during normal process teardown.
- CLI verbosity is not explicitly propagated across privileged helper process boundaries.
- PR #1 captures formatted text in thread-local buffers, tails helper files, sorts second-resolution timestamps, and returns logs after dispatch completes. This loses structure, risks unbounded buffering, and is not live streaming.

### Implementation

1. Use one tracing registry per process with appropriately filtered formatting layers. Enable tracing-subscriber's `env-filter` feature and use EnvFilter instead of custom parsing.
2. Define clear configuration precedence for explicit RUST_LOG directives and CLI verbosity. Keep dependencies quiet by default while allowing targeted filters such as `tunmux=debug,gotatun=warn`.
3. Return an owned logging guard held in the main/daemon scope and initialize worker-backed logging after daemonization. Make initialization failures observable.
4. Pass typed logging configuration to newly spawned privileged/helper processes. Persistent daemons retain an explicit startup filter; request verbosity cannot recover events already disabled by that filter.
5. Add request/connection/operation spans with request_id, instance, interface, backend, and operation. Instrument async futures rather than holding entered-span guards across awaits.
6. Use `#[instrument(skip_all, fields(...))]` where appropriate and explicitly select safe fields. Never record full configuration objects, credentials, private keys, or raw privileged request payloads.
7. Use structured fields for errors and dynamic values. Log cleanup outcomes and deadlines; log failures once at the layer that handles them.
8. Optionally add `--debug` as an alias for existing verbosity, without a separate environment-variable mechanism.

### Validation

- Target filters and CLI defaults resolve as documented.
- Normal process shutdown flushes queued file logs.
- Spawned helpers receive intended log configuration.
- Representative error paths retain operation/session context and exclude secrets.
- Logging does not delay teardown under backpressure or output failure.

## Phase 4: reconciliation, status, and userspace MTU

### Network reconciliation

- Reconcile gateway, endpoint routes, owned VPN routes, and DNS against current network observations.
- Compute and apply a delta rather than re-running full setup each tick.
- Debounce network-change events; use bounded polling only where required.
- Handle Wi-Fi/Ethernet transitions, suspend/resume, and periods with no settled primary network.
- Make LAN access an explicit routing policy. Do not silently override configured AllowedIPs or create unintended bypasses.
- Serialize reconciliation with setup and teardown; shutdown takes priority.

### Status

- Improve `tunmux status` using the shared health API rather than saved JSON alone.
- Keep existing `tunmux wg` functionality for detailed WireGuard information.
- If added, `wgconf status` delegates to shared inspection and rendering rather than duplicating it.
- Report unknown/unavailable observations honestly and avoid making status a destructive cleanup operation.

### MTU

- Parse `[Interface] MTU` once in shared configuration and validate centrally.
- Resolve precedence as CLI override, then config value, then existing backend default.
- Pass the resolved typed value through the privileged request/helper boundary.
- Set TUN MTU before activation, preserving existing backend and proxy-mode constraints.

### Validation

- Fixture-test route deltas for gateway changes, LAN overlap, IPv4/IPv6, and no-primary-network states.
- Verify reconciliation is idempotent and stops before teardown.
- Test MTU parsing, invalid values, override precedence, and backend propagation.
- Native macOS tests cover roaming, suspend/resume, DNS ownership conflicts, and actual interface MTU.

## Phase 5: optional launchd, installation, and autoconnect

1. Add launchd listener acquisition alongside systemd activation in the privileged service. Reuse authentication, request dispatch, and socket authorization.
2. Track whether the listener/socket is service-owned or activation-manager-owned; do not unlink a launchd-owned socket during normal service shutdown.
3. Provide a privileged LaunchDaemon for socket activation and a separate opt-in user LaunchAgent for login connection.
4. Implement idempotent `connect --if-missing` through the shared health/identity API. A matching active source is a no-op; a different active source remains an error; unknown health does not trigger replacement.
5. Persist desired autoconnect state separately from observed connection state so manual disconnect can suspend automatic reconnect explicitly.
6. Serialize competing connects, apply bounded retries/backoff, and avoid reconnect storms.
7. Add explicit install, reload, diagnostics, and uninstall targets. Parameterize binary/profile paths; avoid hard-coded personal profiles or test IPs.
8. Uninstall first disables reconnect, requests acknowledged teardown/recovery, and only then removes binaries and owned artifacts. Preserve unresolved recovery information and user profiles.

Validate plist generation and installation logic independently. Native macOS validation must cover activation, authorization, login connection, manual disconnect, concurrent invocation, reload, and uninstall with a live VPN.

## Phase 6: optional structured live log forwarding

Only implement this after reliable daemon logs and tracing configuration are available.

- Negotiate protocol capabilities before sending additional frames; current clients expect one response line.
- Use typed log/progress/result frames with request ID, origin, sequence, original timestamp, level, target, and structured fields.
- Use a tracing forwarding layer and bounded queues, with dropped-event accounting. A slow/disconnected client must never block VPN operation or cleanup.
- Scope events to the authenticated request or authorized connection. Preserve context across spawned tasks and process boundaries explicitly.
- Render events at the CLI without treating remote formatted text as local structured telemetry or creating forwarding loops.
- Keep operation results independent from optional log delivery.

Test old/new client compatibility, concurrent request isolation, ordering, disconnects, overflow, redaction, and teardown under a stalled log consumer.

## Delivery and verification

Deliver each phase as a focused change, splitting larger phases when necessary. Extract modules only where they establish an ownership or platform boundary; avoid a broad generic framework or unrelated provider rewrites.

Suggested initial boundaries:

- helper lifecycle and passive diagnostics;
- platform network planning/effects and recovery journal;
- shared backend health inspection;
- logging configuration and optional protocol forwarding.

Use meaningful failure-injection and behavior tests near the code. Before completing substantial changes, run the repository checks:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

Preserve platform cfg guards and validate supported non-Linux builds where toolchains are available. Linux tests and cross-compilation do not establish native macOS routing, DNS, signal, or launchd behavior. Report native macOS validation separately, including before/after network settings and recovery results.

## Reference documentation

- [Tokio spawn_blocking cancellation and runtime shutdown](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)
- [Tokio process management](https://docs.rs/tokio/latest/tokio/process/struct.Command.html)
- [tracing-subscriber EnvFilter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
- [tracing instrumentation and field exclusion](https://docs.rs/tracing/latest/tracing/attr.instrument.html)
- [tracing-appender WorkerGuard](https://docs.rs/tracing-appender/latest/tracing_appender/non_blocking/struct.WorkerGuard.html)
