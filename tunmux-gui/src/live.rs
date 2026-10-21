//! Live connection status from the saved state files.
//!
//! Status is refreshed on events instead of a fixed poll, because a health
//! probe of a kernel or userspace tunnel connects to the privileged helper
//! socket and would keep the socket-activated root helper alive:
//!
//! - inotify on the connections directory: connect, disconnect, replace;
//! - a pidfd per proxy daemon: the daemon exited;
//! - rtnetlink link and address events: an interface vanished or the
//!   network changed;
//! - an explicit wake (tray menu opened, window action);
//! - a slow timer for silent peers, only while the window is shown.
//!
//! Only startup and state-file changes may run probes that need the helper.
//! Every other refresh probes helper-backed tunnels only when the helper is
//! already running, and otherwise keeps their last observation.

use std::collections::{HashMap, HashSet};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tunmux::wireguard::backend::WgBackend;
use tunmux::wireguard::connection::ConnectionState;
use tunmux::wireguard::health::{self, HealthKind};

use crate::model::{ConnectionView, Health, Mode, Provider};

/// Interval of the silent-peer check while the window is shown.
const SLOW_CHECK: Duration = Duration::from_secs(60);
/// Coalesces bursts: a connect writes files and adds links and routes.
#[cfg(target_os = "linux")]
const SETTLE: Duration = Duration::from_millis(200);

pub type Notify = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub connections: Vec<ConnectionView>,
    pub corrupt: Vec<String>,
}

/// Outcome of a CLI action, shown as a toast.
pub type Message = Result<String, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refresh {
    /// Startup or state files changed: probe everything.
    Full,
    /// Network, process or timer event: never wake the helper.
    Light,
}

pub struct Live {
    snapshot: Arc<Mutex<Snapshot>>,
    window_open: Arc<AtomicBool>,
    waker: Waker,
    notify: Notify,
    messages_tx: Sender<Message>,
    messages: Receiver<Message>,
}

impl Live {
    /// Start the watcher thread. `on_change` runs on that thread after each
    /// refresh, also while the window is closed.
    pub fn start(notify: Notify, on_change: impl Fn(&Snapshot) + Send + 'static) -> Self {
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let window_open = Arc::new(AtomicBool::new(false));
        let (waker, wait) = waker();
        let (messages_tx, messages) = mpsc::channel();
        {
            let snapshot = snapshot.clone();
            let window_open = window_open.clone();
            std::thread::Builder::new()
                .name("tunmux-gui-status".into())
                .spawn(move || watch(snapshot, window_open, wait, on_change))
                .expect("spawn status thread");
        }
        Self {
            snapshot,
            window_open,
            waker,
            notify,
            messages_tx,
            messages,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn set_window_open(&self, open: bool) {
        self.window_open.store(open, Ordering::Relaxed);
        self.waker.wake();
    }

    /// Wakes the watcher for a refresh that never wakes the privileged
    /// helper.
    pub fn waker(&self) -> Waker {
        self.waker.clone()
    }

    pub fn take_messages(&self) -> Vec<Message> {
        self.messages.try_iter().collect()
    }

    /// Disconnect one instance, or all of them, through the tunmux CLI.
    /// Interim until the library exposes a disconnect API.
    pub fn disconnect(&self, instance: Option<&str>) {
        let mut args = vec!["disconnect".to_string()];
        match instance {
            Some(i) => args.push(i.to_string()),
            None => args.push("--all".into()),
        }
        let tx = self.messages_tx.clone();
        let waker = self.waker.clone();
        let notify = self.notify.clone();
        std::thread::spawn(move || {
            let _ = tx.send(run_cli(&args));
            waker.wake();
            notify();
        });
    }
}

fn run_cli(args: &[String]) -> Message {
    let bin = tunmux_bin();
    let output = Command::new(&bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
    let text = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    if output.status.success() {
        let line = text(&output.stdout);
        Ok(if line.is_empty() {
            format!("tunmux {} done", args.join(" "))
        } else {
            line
        })
    } else {
        let line = text(&output.stderr);
        Err(if line.is_empty() {
            format!("tunmux {} failed ({})", args.join(" "), output.status)
        } else {
            line
        })
    }
}

/// `TUNMUX_BIN`, else a `tunmux` next to this executable, else `PATH`.
fn tunmux_bin() -> std::path::PathBuf {
    if let Some(bin) = std::env::var_os("TUNMUX_BIN") {
        return bin.into();
    }
    std::env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name("tunmux"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| "tunmux".into())
}

/// Saved state plus the last observation for each instance.
struct Tracked {
    state: ConnectionState,
    since: SystemTime,
    health: Health,
    reason: String,
}

fn needs_helper(state: &ConnectionState) -> bool {
    state.backend != WgBackend::LocalProxy && state.namespace_name.is_none()
}

fn refresh(
    kind: Refresh,
    tracked: &mut HashMap<String, Tracked>,
    exited: &HashSet<String>,
) -> Vec<String> {
    let (states, corrupt) = match ConnectionState::load_all_with_corrupt() {
        Ok(v) => v,
        Err(error) => {
            tracing::warn!(%error, "gui_status_load_failed");
            return Vec::new();
        }
    };
    let dir = tunmux::config::connections_dir();
    let helper_up = kind == Refresh::Full || helper_running();
    let mut next = HashMap::new();
    for state in states {
        let name = state.instance_name.clone();
        let since = std::fs::metadata(dir.join(format!("{name}.json")))
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let previous = tracked.remove(&name);
        let (health, reason) = if exited.contains(&name) {
            (
                Health::Inactive,
                format!("proxy daemon pid {} exited", state.proxy_pid.unwrap_or(0)),
            )
        } else if !needs_helper(&state) || helper_up || interface_missing(&state) {
            // Local-proxy and namespace checks never contact the helper, and
            // a missing kernel interface is detected before any probe.
            let h = health::inspect(&state);
            (map_health(h.kind), h.reason)
        } else if let Some(p) = previous {
            (p.health, p.reason)
        } else {
            (
                Health::Unknown,
                "not checked: privileged helper is not running".into(),
            )
        };
        next.insert(
            name,
            Tracked {
                state,
                since,
                health,
                reason,
            },
        );
    }
    *tracked = next;
    corrupt
        .iter()
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect()
}

#[cfg(target_os = "linux")]
fn interface_missing(state: &ConnectionState) -> bool {
    matches!(state.backend, WgBackend::Kernel | WgBackend::WgQuick)
        && std::fs::metadata(format!("/sys/class/net/{}", state.interface_name))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(not(target_os = "linux"))]
fn interface_missing(_state: &ConnectionState) -> bool {
    false
}

/// Whether a `tunmux privileged --serve` process exists, read from /proc
/// so the check itself never activates the helper socket.
#[cfg(target_os = "linux")]
fn helper_running() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            return false;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        args.first().is_some_and(|a| a.ends_with(b"tunmux"))
            && args.iter().any(|a| *a == b"privileged")
            && args.iter().any(|a| *a == b"--serve")
    })
}

#[cfg(not(target_os = "linux"))]
fn helper_running() -> bool {
    false
}

fn map_health(kind: HealthKind) -> Health {
    match kind {
        HealthKind::Active => Health::Active,
        HealthKind::Inactive => Health::Inactive,
        HealthKind::Unknown => Health::Unknown,
    }
}

fn to_view(t: &Tracked) -> Option<ConnectionView> {
    let s = &t.state;
    let Some(provider) = Provider::from_dir_name(&s.provider) else {
        tracing::warn!(provider = %s.provider, "gui_unknown_provider_in_state");
        return None;
    };
    let mode = if s.backend == WgBackend::LocalProxy {
        Mode::LocalProxy
    } else if s.namespace_name.is_some() {
        Mode::NetnsProxy
    } else {
        Mode::Direct
    };
    // Proton names carry the exit country ("CH#12"); others do not.
    let country_code = s
        .server_display_name
        .split_once('#')
        .map(|(cc, _)| cc.chars().filter(char::is_ascii_alphabetic).collect())
        .unwrap_or_default();
    Some(ConnectionView {
        instance: s.instance_name.clone(),
        provider,
        server: s.server_display_name.clone(),
        country_code,
        city: String::new(),
        mode,
        backend: s.backend.to_string(),
        virtual_ip: s
            .virtual_ips
            .first()
            .cloned()
            .unwrap_or_else(|| s.interface_name.clone()),
        socks_port: s.socks_port,
        http_port: s.http_port,
        health: t.health,
        health_reason: Some(t.reason.clone()),
        since: t.since,
        rx_bytes: None,
        tx_bytes: None,
    })
}

fn publish(
    shared: &Mutex<Snapshot>,
    tracked: &HashMap<String, Tracked>,
    corrupt: Vec<String>,
    on_change: &dyn Fn(&Snapshot),
) {
    let mut connections: Vec<ConnectionView> = tracked.values().filter_map(to_view).collect();
    connections.sort_by(|a, b| (!a.is_direct(), &a.instance).cmp(&(!b.is_direct(), &b.instance)));
    let snap = Snapshot {
        connections,
        corrupt,
    };
    for c in &snap.connections {
        tracing::debug!(
            instance = %c.instance,
            health = c.health.label(),
            reason = c.health_reason.as_deref().unwrap_or(""),
            "gui_status"
        );
    }
    tracing::debug!(
        connections = snap.connections.len(),
        corrupt = snap.corrupt.len(),
        "gui_status_published"
    );
    if let Ok(mut s) = shared.lock() {
        *s = snap.clone();
    }
    on_change(&snap);
}

// --- Linux: block in poll(2) on all event sources --------------------------

#[cfg(target_os = "linux")]
pub use linux::Waker;
#[cfg(target_os = "linux")]
use linux::{waker, watch};

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, HashSet};
    use std::os::fd::OwnedFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use rustix::event::{eventfd, poll, EventfdFlags, PollFd, PollFlags, Timespec};
    use rustix::fs::inotify;
    use rustix::io::Errno;
    use rustix::net::netlink::SocketAddrNetlink;
    use rustix::net::{bind, recv, socket_with, AddressFamily, RecvFlags, SocketFlags, SocketType};
    use rustix::process::{pidfd_open, Pid, PidfdFlags};

    use super::{publish, refresh, Refresh, Snapshot, Tracked, SETTLE, SLOW_CHECK};
    use crate::model::Health;

    // rtnetlink multicast groups (linux/rtnetlink.h).
    const RTMGRP_LINK: u32 = 0x1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;

    /// Wakes the watcher through an eventfd.
    #[derive(Clone)]
    pub struct Waker(Arc<OwnedFd>);

    impl Waker {
        pub fn wake(&self) {
            let _ = rustix::io::write(&*self.0, &1u64.to_ne_bytes());
        }
    }

    pub fn waker() -> (Waker, Arc<OwnedFd>) {
        let fd = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
            .expect("eventfd is available on supported kernels");
        let fd = Arc::new(fd);
        (Waker(fd.clone()), fd)
    }

    fn open_inotify() -> rustix::io::Result<OwnedFd> {
        let dir = tunmux::config::connections_dir();
        if let Err(error) = tunmux::config::ensure_connections_dir() {
            tracing::warn!(%error, "gui_connections_dir_unavailable");
        }
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)?;
        inotify::add_watch(
            &fd,
            &dir,
            inotify::WatchFlags::CREATE
                | inotify::WatchFlags::DELETE
                | inotify::WatchFlags::MOVED_TO
                | inotify::WatchFlags::MOVED_FROM
                | inotify::WatchFlags::CLOSE_WRITE
                | inotify::WatchFlags::ONLYDIR,
        )?;
        Ok(fd)
    }

    fn open_netlink() -> rustix::io::Result<OwnedFd> {
        let fd = socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None, // NETLINK_ROUTE
        )?;
        bind(
            &fd,
            &SocketAddrNetlink::new(0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR),
        )?;
        Ok(fd)
    }

    fn drain(fd: &OwnedFd) {
        let mut buf = [0u8; 8192];
        while matches!(recv(fd, &mut buf, RecvFlags::DONTWAIT), Ok((_, n)) if n > 0) {}
    }

    fn drain_read(fd: &OwnedFd) {
        let mut buf = [0u8; 4096];
        while matches!(rustix::io::read(fd, &mut buf), Ok(n) if n > 0) {}
    }

    /// pidfds for proxy daemons; a missing process is recorded as exited.
    fn pidfds(
        tracked: &HashMap<String, Tracked>,
        exited: &mut HashSet<String>,
    ) -> Vec<(String, OwnedFd)> {
        let mut out = Vec::new();
        for (name, t) in tracked {
            let Some(pid) = t.state.proxy_pid.and_then(|p| Pid::from_raw(p as i32)) else {
                continue;
            };
            if t.health == Health::Inactive {
                continue;
            }
            match pidfd_open(pid, PidfdFlags::empty()) {
                Ok(fd) => out.push((name.clone(), fd)),
                // No process has the saved pid, so the daemon is gone.
                Err(Errno::SRCH) => {
                    exited.insert(name.clone());
                }
                Err(error) => tracing::debug!(%error, instance = %name, "gui_pidfd_unavailable"),
            }
        }
        out
    }

    pub fn watch(
        shared: Arc<Mutex<Snapshot>>,
        window_open: Arc<AtomicBool>,
        wake: Arc<OwnedFd>,
        on_change: impl Fn(&Snapshot),
    ) {
        let inotify = open_inotify()
            .inspect_err(|error| tracing::warn!(%error, "gui_inotify_unavailable"))
            .ok();
        let netlink = open_netlink()
            .inspect_err(|error| tracing::warn!(%error, "gui_netlink_unavailable"))
            .ok();
        let mut tracked = HashMap::new();
        let mut exited = HashSet::new();
        let mut kind = Refresh::Full;
        loop {
            let corrupt = refresh(kind, &mut tracked, &exited);
            let procs = pidfds(&tracked, &mut exited);
            if exited
                .iter()
                .any(|n| tracked.get(n).is_some_and(|t| t.health != Health::Inactive))
            {
                // A daemon vanished between load and pidfd_open.
                let corrupt = refresh(Refresh::Light, &mut tracked, &exited);
                publish(&shared, &tracked, corrupt, &on_change);
            } else {
                publish(&shared, &tracked, corrupt, &on_change);
            }

            let slow = window_open.load(Ordering::Relaxed)
                && tracked.values().any(|t| t.health == Health::Active);
            let timeout = slow.then(|| Timespec {
                tv_sec: SLOW_CHECK.as_secs() as _,
                tv_nsec: 0,
            });

            let mut fds = vec![PollFd::new(&*wake, PollFlags::IN)];
            if let Some(fd) = &inotify {
                fds.push(PollFd::new(fd, PollFlags::IN));
            }
            if let Some(fd) = &netlink {
                fds.push(PollFd::new(fd, PollFlags::IN));
            }
            let first_proc = fds.len();
            for (_, fd) in &procs {
                fds.push(PollFd::new(fd, PollFlags::IN));
            }
            match poll(&mut fds, timeout.as_ref()) {
                Ok(0) => {
                    kind = Refresh::Light;
                    continue;
                }
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(error) => {
                    tracing::warn!(%error, "gui_status_poll_failed");
                    std::thread::sleep(SLOW_CHECK);
                    kind = Refresh::Full;
                    continue;
                }
            }
            let fired: Vec<bool> = fds.iter().map(|f| !f.revents().is_empty()).collect();
            drop(fds);
            let files_changed = inotify.is_some() && fired[1];
            for (i, (name, _)) in procs.iter().enumerate() {
                if fired[first_proc + i] {
                    exited.insert(name.clone());
                }
            }

            std::thread::sleep(SETTLE);
            drain_read(&wake);
            if let Some(fd) = &inotify {
                drain_read(fd);
            }
            if let Some(fd) = &netlink {
                drain(fd);
            }
            tracing::debug!(files_changed, "gui_status_event");
            if files_changed {
                // New or rewritten state files start with fresh evidence.
                exited.clear();
                kind = Refresh::Full;
            } else {
                kind = Refresh::Light;
            }
        }
    }
}

// --- elsewhere: timer and explicit wakes only ------------------------------

#[cfg(not(target_os = "linux"))]
#[derive(Clone)]
pub struct Waker(Sender<()>);

#[cfg(not(target_os = "linux"))]
impl Waker {
    pub fn wake(&self) {
        let _ = self.0.send(());
    }
}

#[cfg(not(target_os = "linux"))]
fn waker() -> (Waker, Receiver<()>) {
    let (tx, rx) = mpsc::channel();
    (Waker(tx), rx)
}

#[cfg(not(target_os = "linux"))]
fn watch(
    shared: Arc<Mutex<Snapshot>>,
    window_open: Arc<AtomicBool>,
    wake: Receiver<()>,
    on_change: impl Fn(&Snapshot),
) {
    let mut tracked = HashMap::new();
    let exited = HashSet::new();
    let mut kind = Refresh::Full;
    loop {
        let corrupt = refresh(kind, &mut tracked, &exited);
        publish(&shared, &tracked, corrupt, &on_change);
        let timeout = if window_open.load(Ordering::Relaxed) {
            SLOW_CHECK
        } else {
            Duration::from_secs(3600)
        };
        kind = match wake.recv_timeout(timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => Refresh::Light,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
    }
}
