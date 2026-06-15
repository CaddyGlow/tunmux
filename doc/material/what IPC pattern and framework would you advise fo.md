# what IPC pattern and framework would you advise for a desktop service in rust, which needs to have differently privileged subservices.

I’d advise a **brokered capability** design: keep one tiny privileged root service, push almost all logic into unprivileged workers, and use a narrow RPC-style IPC boundary between them over Unix domain sockets; use D-Bus only if you also need desktop integration or external clients to talk to the service.[^1_1][^1_2]

## Recommended pattern

For a desktop service with differently privileged subservices, the safest pattern is privilege separation with a single privileged parent or helper that owns the sensitive operations, while child processes run with dropped privileges and communicate only through a strict internal message protocol. The `privsep` crate is explicitly built around this model: a privileged parent forks child processes, children drop privileges and run sandboxed, and communication happens over async socket pairs using `imsg` channels.[^1_1]

Architecturally, that means:

- Privileged broker: minimal code, owns root-only capabilities.
- Unprivileged workers: business logic, parsing, UI-facing logic, network handling.
- Explicit capability RPC: workers ask the broker for narrowly defined actions, not arbitrary command execution.[^1_1]


## IPC choice

On Linux desktop systems, D-Bus gives you a bus topology with discoverable services, well-known names, object paths, interfaces, methods, properties, and signals, and `zbus` provides Rust APIs plus service introspection helpers. That makes it a strong fit when your service must be callable by other apps, desktop components, or system/session-level tooling.[^1_2]

For **internal** communication among your own privilege-separated processes, Unix domain sockets are the better default because they are simpler, tighter, and better aligned with least-privilege boundaries; the `privsep` crate itself uses async socket pairs for that internal messaging model. I would avoid making internal privileged edges depend on the public bus unless external interoperability is a real requirement.[^1_1]

## Framework advice

If this is a Linux-first desktop daemon, my recommendation is:


| Need | Best fit | Why |
| :-- | :-- | :-- |
| Internal privileged helper IPC | `privsep`-style model or plain UDS + Tokio codec | Built specifically for privilege separation; small, explicit boundary with sandboxed children and async socket-based messaging. [^1_1] |
| External desktop/system API | `zbus` | Natural fit for system or session bus APIs, introspection, and stable service interfaces. [^1_2][^1_2] |
| Cross-platform desktop app IPC | UDS abstraction first, add Windows named pipes later | D-Bus is strongest on Linux; a socket-based internal RPC layer ports more cleanly. [^1_1][^1_3] |

In practice, a very solid stack is **Tokio + Unix domain sockets + serde/bincode or postcard for the internal protocol**, with a separate `zbus` façade only if you need a public bus-facing API. If you want an opinionated privilege-separation framework and you are comfortable with its experimental status, `privsep` is worth studying, but I would treat it cautiously for production because its docs label it experimental and WIP.[^1_1]

## Design rules

Keep the privileged process extremely small: no parsing of complex untrusted inputs, no plugin loading, and no general filesystem or shell surface beyond narrowly scoped operations. The whole point of privilege separation is that compromise of a worker should only grant access to the broker’s exposed capabilities, not broad system authority.[^1_1]

A good request model is capability-oriented rather than command-oriented. For example, prefer `InstallSystemProfile(profile_id)` or `BindPrivilegedPort(port)` over generic operations like `Run(cmd)` or `WriteFile(path, bytes)`, because narrow methods preserve the security boundary and make auditing much easier.[^1_1]

## Practical pick

If you’re targeting Linux desktop and want my concrete recommendation: use **Unix domain sockets for the internal privileged boundary, one root broker, multiple unprivileged Rust workers, and `zbus` only as an outer API layer when desktop integration is needed**. That gives you a clean security model, avoids overcomplicating internal IPC, and still lets you expose a polished Linux-native interface if required.[^1_2][^1_1]

Would you like a concrete Rust crate stack and message schema for Linux-only versus cross-platform desktop?
<span style="display:none">[^1_10][^1_4][^1_5][^1_6][^1_7][^1_8][^1_9]</span>

<div align="center">⁂</div>

[^1_1]: https://docs.rs/privsep/latest/privsep/

[^1_2]: https://docs.rs/zbus/2.0.0-beta.6/zbus/

[^1_3]: https://lib.rs/crates/kode-bridge

[^1_4]: https://lib.rs/crates/ipc-broker

[^1_5]: https://elitedev.in/rust/how-to-build-memory-safe-system-services-with-rust/

[^1_6]: https://elmarco.pages.freedesktop.org/zbus/concepts.html

[^1_7]: https://crates.io/crates/ipc-broker

[^1_8]: https://users.rust-lang.org/t/recommended-way-of-ipc-in-rust/31116

[^1_9]: https://stackoverflow.com/questions/74824809/how-to-create-a-d-bus-server-with-zbus-in-rust

[^1_10]: https://lib.rs/crates/sandbox-ipc


---

# currently my application spawns the privileged part via `sudo`, if it does is not started yet. that works, as all the wiring and tracing of "did the unprivileged service already _start_ the privileged service" happens from the unprivileged side.

if i intend to start the privileged service during boot, to have the `sudo` part already done, my problem is, that the communication socket is owned by root and the entire low-privilege thing seems to fall apart.

do you have advise for that?

You're running into the classic privilege-separation boot problem: when the privileged helper starts at boot as root, it creates the socket file as root with root-only permissions, so your unprivileged service can't connect.

The core fix is to **decouple socket ownership/permissions from the process that binds**. You have three solid options:

## Option 1: Use systemd socket activation (best for Linux desktop)

Instead of your privileged service creating the socket itself, let systemd create it with the right permissions and pass it as a file descriptor:

```ini
# /etc/systemd/system/yourapp-privileged.socket
[Unit]
Description=YourApp privileged service socket

[Socket]
ListenStream=/run/yourapp/privileged.sock
SocketMode=0660
SocketGroup=youruser
RemoveOnStop=no

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/yourapp-privileged.service
[Unit]
Description=YourApp privileged service
Requires=yourapp-privileged.socket

[Service]
ExecStart=/usr/bin/yourapp-privileged
# systemd passes the socket FD; yourapp uses listenfd
```

Your privileged Rust code then:

```rust
use listenfd::{ListenFd, ListenFdResult};
use tokio::net::UnixListener;

let lf = ListenFd::from_env();
let fd = lf.take_tcp_listener(0)?; // or UnixListener for AF_UNIX
let listener = UnixListener::from(fd);
```

This gives you:

- Socket created by systemd with `SocketMode=0660` and `SocketGroup=youruser`
- Your unprivileged service can connect as `youruser`
- No `sudo` needed at runtime; root service started via systemd at boot[^2_1][^2_2][^2_3]


## Option 2: Create the socket in a dedicated directory with group permissions

If you don't want systemd socket activation, create the socket in a directory owned by a group that includes your unprivileged user:

```bash
# Setup (run once as root)
mkdir -p /run/yourapp
chown root:yourapp-group /run/yourapp
chmod 0750 /run/yourapp
```

Then in your privileged Rust code, set permissions **before** `bind()` using `fchmod()` on the socket FD:

```rust
use std::os::unix::io::AsRawFd;
use nix::sys::stat::fchmod;
use nix::unistd::Uid;

let socket = std::net::UnixSocket::new_stream()?;
let fd = socket.as_raw_fd();

// Set permissions before bind (Linux-specific)
fchmod(fd, 0o660)?;  // rw for owner+group

// Bind to path in group-accessible directory
socket.bind("/run/yourapp/privileged.sock")?;
```

On Linux, `fchmod()` **before** `bind()` is required; `fchmod()` after `bind()` doesn't work for new socket files.[^2_4][^2_5]

You also need to ensure the socket's group is set correctly. If the directory is `root:yourapp-group` with `0750`, the socket will inherit that group.

## Option 3: Two-phase startup with a bootstrap socket

Keep your current `sudo`-based approach but add a small bootstrap phase:

1. Unprivileged service starts first
2. It creates a temporary bootstrap socket in `$XDG_RUNTIME_DIR` (user-owned)
3. Unprivileged service spawns privileged helper via `sudo`, passing the bootstrap socket path
4. Privileged helper creates the permanent socket with correct permissions (`fchmod()` before `bind()`)
5. Privileged helper sends the permanent socket path back via bootstrap
6. Both sides switch to the permanent socket

This preserves your current wiring/tracing logic while fixing the permission problem.

## Recommended approach for your case

Since you're on Linux desktop and want boot-time startup:

**Use systemd socket activation** with `SocketMode=0660` and `SocketGroup=youruser`. This:

- Eliminates the `sudo` runtime entirely
- Gives you clean boot-time startup via systemd
- Solves the permission problem at the source
- Keeps your unprivileged-side wiring logic intact

You'd still spawn the privileged service via `sudo` only during initial setup (installing the systemd units), not at runtime.

Would you like a concrete Rust example using `listenfd` + `tokio::net::UnixListener` for the systemd-activated privileged service?
<span style="display:none">[^2_10][^2_11][^2_12][^2_13][^2_14][^2_15][^2_16][^2_17][^2_18][^2_19][^2_6][^2_7][^2_8][^2_9]</span>

<div align="center">⁂</div>

[^2_1]: https://github.com/Ralith/sd-listen-fds

[^2_2]: https://www.reddit.com/r/rust/comments/ny9w57/issue_with_server_daemonization_wondering_about/

[^2_3]: https://lucumr.pocoo.org/2025/1/19/what-is-systemfd/

[^2_4]: https://stackoverflow.com/questions/11781134/change-linux-socket-file-permissions

[^2_5]: https://www.uwsg.indiana.edu/hypermail/linux/kernel/0505.2/0008.html

[^2_6]: https://www.unix.com/man_page/suse/8/wpa_priv/

[^2_7]: https://users.rust-lang.org/t/tokio-daemonize-w-privileged-ports/81603

[^2_8]: https://www.oreilly.com/library/view/secure-programming-cookbook/0596003943/ch01s04.html

[^2_9]: https://postgresqlco.nf/doc/en/param/unix_socket_permissions/

[^2_10]: https://stackoverflow.com/questions/35424970/unix-socket-permissions-linux

[^2_11]: https://users.rust-lang.org/t/enter-cli-of-a-systemd-service/87155

[^2_12]: https://mutagen.io/documentation/forwarding/unix-domain-sockets/

[^2_13]: https://discourse.nixos.org/t/dynamicuser-and-socket-permission/76442

[^2_14]: https://www.mail-archive.com/ovs-dev@openvswitch.org/msg73211.html

[^2_15]: https://manpages.debian.org/testing/systemd/systemd.socket.5.en.html

[^2_16]: https://access.redhat.com/solutions/7127175

[^2_17]: https://cd.uxsino.com:53222/优炫数据库管理系统用户手册/user_manual

[^2_18]: https://github.com/dotnet/runtime/issues/58689

[^2_19]: https://github.com/systemd/systemd/issues/23067


---

# Do you know of a systemd equivalent in macOS, which also lets us abstract the socket permissions away?

Yes: **`launchd`** is the macOS equivalent of systemd, and it **does support socket activation** that abstracts socket permissions away from your process.

## How launchd socket activation works

Instead of your privileged service creating the socket itself, `launchd`:

1. Creates the socket (TCP or Unix) with your specified permissions
2. Passes it as a file descriptor to your process via `launch_activate_socket()`
3. Handles boot-time startup automatically

This is the same pattern as systemd's socket activation, just with a different API and plist format.[^3_1][^3_3][^3_4][^3_5]

## launchd plist example for Unix socket

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.yourapp.privileged</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/yourapp-privileged</string>
    </array>
    
    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <!-- For Unix domain socket: -->
            <key>SockPathName</key>
            <string>/var/run/yourapp/privileged.sock</string>
            <key>SockType</key>
            <string>stream</string>
            <key>SockFamily</key>
            <string>Unix</string>
            <!-- Permissions: -->
            <key>SockMode</key>
            <integer>0660</integer>
            <key>SockGroup</key>
            <string>youruser</string>
        </dict>
    </dict>
    
    <key>UserName</key>
    <string>root</string>
    
    <key>GroupName</key>
    <string>wheel</string>
    
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Install it as `/Library/LaunchDaemons/com.yourapp.privileged.plist` and load with:

```bash
sudo launchctl load /Library/LaunchDaemons/com.yourapp.privileged.plist
```


## Using the socket in Rust

Your privileged Rust code receives the socket via `launch_activate_socket()`:

```rust
use std::os::unix::io::AsRawFd;
use libc::launch_activate_socket;
use tokio::net::UnixListener;
use std::ffi::CString;

let sock_name = CString::new("Listeners").unwrap();
let mut fds: *mut libc::c_int = std::ptr::null_mut();
let mut count: libc::c_int = 0;

let ret = launch_activate_socket(sock_name.as_ptr(), &mut fds, &mut count);
if ret != 0 {
    panic!("launch_activate_socket failed");
}

// fds[^3_0] is your socket FD
let fd = fds[^3_0];
let listener = UnixListener::from(fd);
```

You'll need the `libc` crate and to link against the system's `launchd` library (which is automatic on macOS).

## Key differences from systemd

| Aspect | systemd | launchd |
| :-- | :-- | :-- |
| Config format | `.socket` unit (INI-like) | `.plist` (XML) |
| Socket activation API | `listenfd` env var | `launch_activate_socket()` call |
| Socket naming | File path in unit | Hardcoded name in plist + env var |
| Installation path | `/etc/systemd/system/` | `/Library/LaunchDaemons/` |
| Load command | `systemctl enable/start` | `launchctl load` |

The widget says: "On macOS launchd socket activation is also available although the socket needs to be explicitly named through the fd://socket-name syntax". The socket name you define in the plist (e.g., `"Listeners"`) becomes the environment variable name passed to your process.[^3_1]

## Cross-platform approach

For a truly cross-platform desktop service (Linux + macOS), you can:

1. **Use the same Rust IPC logic** (Unix sockets + Tokio codec)
2. **Conditionally compile the activation layer**:

```rust
#[cfg(target_os = "linux")]
use listenfd::ListenFd;  // systemd

#[cfg(target_os = "macos")]
use launch_activate_socket;  // launchd
```

3. **Keep the unprivileged service's wiring logic identical** — it just connects to the socket path regardless of which OS created it

This gives you:

- Boot-time startup on both platforms without `sudo` at runtime
- Socket permissions controlled by the OS, not your process
- Same IPC protocol and security model across platforms

Would you like a complete cross-platform Rust example with both `listenfd` (systemd) and `launch_activate_socket` (launchd) support?
<span style="display:none">[^3_10][^3_2][^3_6][^3_7][^3_8][^3_9]</span>

<div align="center">⁂</div>

[^3_1]: https://github.com/wiktor-k/service-binding

[^3_2]: https://www.picussecurity.com/resource/blog/securing-macos-a-closer-look-at-built-in-macos-application-security

[^3_3]: https://github.com/sorccu/node-socket-activation

[^3_4]: https://zameermanji.com/blog/2024/1/5/binding-to-privileged-ports-without-root-on-macos/

[^3_5]: https://en.wikipedia.org/wiki/Launchd

[^3_6]: https://www.applivery.com/docs/mobile-device-management/apple-mdm/macos/managing-app-permissions-on-macos/

[^3_7]: https://fossil-scm.org/home/doc/tip/www/server/macos/service.md

[^3_8]: https://github.com/kotauskas/interprocess/discussions/65

[^3_9]: https://snarfed.org/2021-07-05_socket-activation

[^3_10]: https://stackoverflow.com/questions/55190472/docker-socket-permissions-within-container
