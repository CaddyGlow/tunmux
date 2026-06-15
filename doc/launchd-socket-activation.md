# launchd socket activation for the privileged service

**Status:** proposed
**Scope:** macOS privileged control service (`tunmux privileged --serve`)
**Author:** design note

## Problem

The privileged service is installed as a macOS LaunchDaemon (`make install/privileged`)
that runs at boot as root. Today that daemon **binds the control socket itself**:

```rust
// src/privileged/mod.rs  (self-bind branch)
let listener = UnixListener::bind(&socket_path)?;
let perms = Permissions::from_mode(0o660);
set_permissions(&socket_path, perms)?;
if let Some(gid) = group_gid { chown(&socket_path, None, Some(gid))?; }
```

The socket is created **as root**, then the mode and group are patched afterward.
That sequence has a window — and several failure modes — in which the socket is
left `root:wheel`/root-only, so an unprivileged client in the `tunmux` group cannot
connect after boot.

macOS `launchd` supports **socket activation** (the equivalent of systemd socket
activation): `launchd` creates the socket with a declared mode and group **before**
the process starts and passes it in as an inherited file descriptor. This removes the
chown-after-bind window entirely and is the recommended fix.

## Current architecture (what exists today)

### Socket contract — `src/config.rs`

| Property | Value |
|---|---|
| Socket path | `/var/run/tunmux/ctl.sock` (`privileged_socket_path()`) |
| Socket dir | `/var/run/tunmux` (`privileged_socket_dir()`), mode `0750` |
| Socket file mode | `0660` |
| Owner / group | `root` / `tunmux` |

Both the dir and the file are chowned to group `tunmux` inside `serve()`.

### Server — `src/privileged/mod.rs` `serve()`

`serve()` already chooses between an **activation-provided** listener and a
**self-bound** listener:

```rust
let listener = match systemd_activated_listener()? {
    Some(listener) => listener,          // Linux: fd 3 via LISTEN_PID / LISTEN_FDS
    None => {                            // everything else: bind + chmod + chown
        let listener = UnixListener::bind(&socket_path)?;
        set_permissions(&socket_path, 0o660)?;
        chown(&socket_path, group_gid)?;
        listener
    }
};
```

- `systemd_activated_listener()` is keyed on the systemd protocol (`LISTEN_PID`,
  `LISTEN_FDS`, first fd at 3). **launchd does not set these**, so on macOS it
  always returns `None` and falls through to the self-bind branch — the path that
  produces the root-only socket.
- There is **no `launch_activate_socket` path** yet.

### Authorization boundary — `src/privileged/mod.rs` `handle_client()`

```rust
let peer = {
    #[cfg(target_os = "linux")]
    { /* SO_PEERCRED → is_authorized(uid, gid, group) or reject */ }

    #[cfg(not(target_os = "linux"))]
    { let _ = authorized_group; (0u32, 0u32) }   // no check on macOS
};
```

**On macOS there is no peer-credential check.** The socket's filesystem permissions
(`0660` + group `tunmux`) are the *entire* access-control boundary. This makes getting
the socket mode/group right not just a usability fix but the security boundary itself.

### Client — `src/privileged_client/transport.rs` `connect_or_autostart()`

```
try_connect_socket()
  └─ Ok        → use it
  └─ NotFound / ConnectionRefused / PermissionDenied
       └─ autostart: sudo -n -b tunmux privileged --serve --autostarted
                          --authorized-group tunmux [--idle-timeout-ms N]
```

The client is **transport-agnostic**: it only knows the socket path. It does not care
who created the socket.

### Current plist — `etc/me.pansen.tunmux.privileged.plist`

```xml
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/tunmux</string>
  <string>--debug</string>
  <string>privileged</string>
  <string>--serve</string>
  <string>--authorized-group</string>
  <string>tunmux</string>
</array>
<key>RunAtLoad</key>  <true/>
<key>KeepAlive</key>  <true/>   <!-- always-on root process -->
```

A persistent (`KeepAlive`) root daemon that self-binds the socket.

---

## Design

### Goal

`launchd` creates `/var/run/tunmux/ctl.sock` with `SockMode=0660` and
`SockGroup=tunmux` **atomically at creation**, and hands the listening fd to the
daemon via `launch_activate_socket("Listeners", …)`. The daemon never chmods/chowns
the socket in the activation path. The unprivileged client is unchanged.

### Why this is the right fix

- **Perms set at creation, not patched.** No window where the socket is root-only.
- **It is the whole boundary on macOS.** With no `SO_PEERCRED` check, launchd-declared
  group/mode is the authorization; declaring it in the plist is more trustworthy than
  a runtime chown that can partially fail.
- **Unifies boot-start and on-demand.** launchd can spawn the daemon lazily on first
  connect and let it exit when idle — no always-on root process.
- **No runtime `sudo` on installed machines.** Once the LaunchDaemon is loaded, the
  client's connect succeeds (launchd spawns the daemon transparently), so the sudo
  autostart branch never fires — no password prompts, no TTY dependency.
- **Low blast radius.** `serve()` already branches activation vs self-bind; we add the
  macOS arm. The client is untouched.

### The two creation paths and how they stay compatible

Both paths must converge on **one socket contract**: path `/var/run/tunmux/ctl.sock`,
mode `0660`, group `tunmux`. They already share `config::privileged_socket_path()`;
the plist's `SockPathName` / `SockMode` / `SockGroup` must match it exactly.

| | **launchd (installed)** | **sudo (fallback)** |
|---|---|---|
| Who creates the socket | launchd, before process start | the daemon, via `bind()` |
| Perms/group source | `SockMode` / `SockGroup` in plist | `set_permissions` + `chown` in `serve()` |
| How daemon gets the listener | `launch_activate_socket("Listeners")` returns fd | self-bind branch |
| Trigger | first client connect (or boot) | client's `sudo -n -b` autostart |

**Detection is self-selecting.** `serve()` calls `launch_activate_socket` first:

- A **launchd job** receives the fd → activation branch.
- A **sudo-spawned process** is not a launchd job → the call fails (e.g. `ESRCH`) →
  returns `None` → falls through to the existing self-bind+chown branch.

The same binary with the same flags picks the right path automatically. No extra
config to keep in sync.

**Mutual exclusion in practice.** With on-demand activation the socket file always
exists (launchd creates it at load), so the client's `try_connect_socket()` succeeds
and `connect_or_autostart()` never enters the sudo branch on an installed machine. The
sudo path remains the fallback for (a) dev machines where `make install` was not run,
and (b) Linux.

**Race to guard.** If the LaunchDaemon is installed *and* the client still reaches the
sudo branch (e.g. the socket file was manually deleted), a sudo-spawned daemon would
`remove_file` launchd's socket and `bind()` its own, orphaning launchd's fd.
Mitigations, in order of preference:

1. Rely on on-demand activation keeping the socket present (covers the normal case).
2. Optional: on macOS, if the LaunchDaemon plist exists, have the client
   `launchctl kickstart` the job instead of `sudo`-spawning.

**Flag consistency.** Pass `--autostarted --idle-timeout-ms N` in *both* the plist and
the sudo command so the daemon behaves identically regardless of who spawned it
(idle-exit + lease-based `ShutdownIfIdle`).

### Lifecycle: on-demand instead of always-on

Switch from `KeepAlive=true` (always-on root process) to **socket activation +
idle-timeout**:

- launchd holds the socket; the daemon is spawned on first connect.
- The daemon exits after `--idle-timeout-ms` of inactivity (lease-aware, via the
  existing `ControlState`/`ShutdownIfIdle` machinery).
- launchd re-spawns on the next connection.

This fits the existing login-time autoconnect LaunchAgent (`install/autostart`): at
login the autoconnect agent connects → launchd spawns the privileged daemon → after
disconnect/idle the daemon exits → the socket persists for next time.

---

## Implementation

### 1. `src/privileged/mod.rs` — add the macOS activation branch

Add a macOS-gated `launchd_activated_listener()` paralleling
`systemd_activated_listener()`, and select it first in `serve()`.

```rust
/// On macOS, retrieve a launchd socket-activation listener for the `Listeners`
/// socket declared in the LaunchDaemon plist. Returns `Ok(None)` when this process
/// was not launched by launchd with that socket (e.g. a sudo-spawned daemon), so the
/// caller falls through to the self-bind path.
#[cfg(target_os = "macos")]
fn launchd_activated_listener() -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let name = CString::new("Listeners").unwrap();
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count: libc::size_t = 0;

    // SAFETY: launch_activate_socket writes a heap-allocated fd array we must free.
    let ret = unsafe { libc::launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
    if ret != 0 || fds.is_null() || count == 0 {
        if !fds.is_null() {
            unsafe { libc::free(fds as *mut libc::c_void) };
        }
        // Non-zero (commonly ESRCH when not launchd-managed) → not activated.
        return Ok(None);
    }

    // We declare exactly one listener socket in the plist; take the first fd.
    let fd = unsafe { *fds };
    unsafe { libc::free(fds as *mut libc::c_void) };

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    Ok(Some(listener))
}
```

Wire it into the `match` in `serve()` (currently at `src/privileged/mod.rs:87`) so the
detection order is **launchd (macOS) → systemd (Linux) → self-bind**:

```rust
let activated = {
    #[cfg(target_os = "macos")]
    { launchd_activated_listener()? }
    #[cfg(not(target_os = "macos"))]
    { systemd_activated_listener()? }
};

let listener = match activated {
    Some(listener) => {
        info!("privileged_service_socket_activation");
        listener
    }
    None => {
        // existing self-bind + chmod 0660 + chown(group) branch, unchanged
    }
};
```

Notes:

- **launchd does not use fd 3 / `LISTEN_FDS`.** It uses the `launch_activate_socket`
  C API keyed by the socket name (`"Listeners"`) from the plist. Do not try to reuse
  the systemd fd-3 logic.
- **`libc::launch_activate_socket` availability.** Verify it is exposed for the macOS
  target via the already-present `nix::libc`. If it is not, add a minimal declaration:

  ```rust
  extern "C" {
      fn launch_activate_socket(
          name: *const libc::c_char,
          fds: *mut *mut libc::c_int,
          cnt: *mut libc::size_t,
      ) -> libc::c_int;
  }
  ```

- The dir chown earlier in `serve()` (lines ~79–85) is harmless and can remain; it is
  redundant under activation (dir is pre-created `root:tunmux` by the installer) and
  still needed for the sudo self-bind path.
- `launch_activate_socket` must be called **exactly once**; calling it again returns
  the same fd already consumed.

### 2. `etc/me.pansen.tunmux.privileged.plist` — convert to socket activation

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>me.pansen.tunmux.privileged</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/tunmux</string>
        <string>--debug</string>
        <string>privileged</string>
        <string>--serve</string>
        <string>--authorized-group</string>
        <string>tunmux</string>
        <string>--autostarted</string>
        <string>--idle-timeout-ms</string>
        <string>60000</string>
    </array>

    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <key>SockPathName</key>
            <string>/var/run/tunmux/ctl.sock</string>
            <key>SockType</key>
            <string>stream</string>
            <key>SockFamily</key>
            <string>Unix</string>
            <!-- 0660 octal = 432 decimal; plist <integer> is base-10. See gotchas. -->
            <key>SockPathMode</key>
            <integer>432</integer>
            <key>SockPathGroup</key>
            <string>tunmux</string>
        </dict>
    </dict>

    <!-- On-demand: launchd spawns on first connect, daemon exits on idle, launchd re-spawns. -->
    <key>RunAtLoad</key>
    <false/>

    <key>StandardOutPath</key>
    <string>/var/log/tunmux/privileged.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/tunmux/privileged.err.log</string>
</dict>
</plist>
```

Changes from current:

- **Add the `Sockets` → `Listeners` dict** matching the socket contract exactly.
- **Drop `KeepAlive`** and set `RunAtLoad=false` → pure on-demand. (Alternatively keep
  `RunAtLoad=true` for boot warm-start; on-demand is recommended given the login-time
  autoconnect agent.)
- **Add `--autostarted --idle-timeout-ms 60000`** so the launchd-spawned daemon
  matches the sudo-spawned daemon's idle-exit / lease behavior.

> **Verify the key names and mode encoding on the target macOS version.** Apple's
> `launchd.plist(5)` historically documents both `SockPathMode`/`SockPathGroup` and the
> shorter `SockMode`/`SockGroup`. Confirm which the running launchd honors (see gotchas);
> the value must end up `0660 root:tunmux` on the created socket.

### 3. `Makefile` — pre-create the socket directory

Under on-demand activation the daemon may not be running to create
`/var/run/tunmux`; launchd needs the parent directory to exist to create the socket
file. Add to `install/privileged` (the `tunmux` group already exists by this point):

```make
sudo mkdir -p /var/run/tunmux
sudo chgrp tunmux /var/run/tunmux
sudo chmod 0750 /var/run/tunmux
```

The rest of `install/privileged` (group creation, binary install, log dir, plist
copy/chown, `bootout`/`bootstrap`) is unchanged.

### 4. Unprivileged client — no change

`src/privileged_client/transport.rs` connects to the same path. When launchd manages
the socket, the connect succeeds and the sudo autostart branch is never reached.

### 5. (Optional, follow-up) macOS peer-credential hardening

Today macOS trusts any connector that can open the socket. As a separate change, add a
peer check in `handle_client()` for macOS using `getpeereid()` / `LOCAL_PEERCRED`, so
socket permissions are not the *only* boundary. Not required for this change; track
separately.

---

## Gotchas / verification checklist

- [ ] **`SockMode` is decimal in plist XML.** `<integer>` is base-10, so `0660` octal =
      `432`. Writing `<integer>0660</integer>` is wrong. After load, confirm with
      `stat -f '%Sp %Sg %Su' /var/run/tunmux/ctl.sock` → expect `srw-rw---- tunmux root`.
- [ ] **Key names.** Confirm `SockPathMode`/`SockPathGroup` vs `SockMode`/`SockGroup`
      against `man launchd.plist` on the target OS; the effective result must be
      `0660 root:tunmux`.
- [ ] **launchd respawn throttle (~10s minimum).** Too-short `--idle-timeout-ms` makes a
      disconnect-then-reconnect within the throttle window add latency. Use ≥30–60s
      (spec uses 60000ms).
- [ ] **`/var/run/tunmux` exists before first activation** (Makefile step 3).
- [ ] **`launch_activate_socket` returns `None` cleanly** in a sudo-spawned daemon →
      self-bind fallback still works.
- [ ] **`libc::launch_activate_socket` links** on macOS (else add the `extern "C"`).

## Test plan

1. **Fresh install, on-demand:** `make install`. Confirm no daemon is running
   (`launchctl print system/me.pansen.tunmux.privileged` shows loaded, not running).
   Run a client op that needs privilege → daemon spawns → op succeeds with no sudo
   prompt. After `--idle-timeout-ms`, confirm the daemon exits and the socket persists.
2. **Permissions:** `stat -f '%Sp %Sg %Su' /var/run/tunmux/ctl.sock` → `srw-rw----`,
   group `tunmux`, owner `root`.
3. **Group gating:** as a user **in** `tunmux`, a client connects; a user **not** in
   `tunmux` is denied at connect (`PermissionDenied`).
4. **sudo fallback intact:** `launchctl bootout system/me.pansen.tunmux.privileged`,
   remove the socket, run a client op from a TTY → sudo autostart self-binds the socket
   `0660 root:tunmux` → op succeeds. Confirms the activation `None` path.
5. **Reboot:** reboot, log in (autoconnect agent fires) → privileged op works with no
   manual sudo. This is the original bug; confirm it is fixed.
6. **Linux unaffected:** build/run on Linux; `systemd_activated_listener()` /
   self-bind paths behave as before (the new code is `#[cfg(target_os = "macos")]`).
