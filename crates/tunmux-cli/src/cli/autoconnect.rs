//! Desired state is user-owned and separate from observations and root recovery journals.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::CommandFactory;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::{AutoconnectCommand, Cli};
use tunmux_core::automation::ConnectionSpec;
use tunmux_core::wireguard::{
    connection::ConnectionState,
    health::{self, HealthKind},
};

fn entry_instance(name: &str, proxy: bool) -> String {
    if proxy {
        tunmux_core::proxy::instance_name(&format!("auto-{name}"))
    } else {
        "_direct".into()
    }
}
fn path() -> PathBuf {
    tunmux_core::config::app_config_dir().join("desired.json")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    spec: ConnectionSpec,
    suspended: bool,
    generation: u64,
    #[serde(default)]
    instance: Option<String>,
    #[serde(default)]
    failure: Option<String>,
    #[serde(default)]
    failures: usize,
    #[serde(default)]
    blocked: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Desired {
    #[serde(default = "version")]
    version: u32,
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
}
fn version() -> u32 {
    1
}
fn load() -> anyhow::Result<Desired> {
    match std::fs::read(path()) {
        Ok(bytes) => {
            let state: Desired =
                serde_json::from_slice(&bytes).context("invalid desired state; preserving file")?;
            anyhow::ensure!(state.version == 1, "unsupported desired-state version");
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Desired {
            version: 1,
            ..Default::default()
        }),
        Err(e) => Err(e.into()),
    }
}
fn save(state: &Desired) -> anyhow::Result<()> {
    tunmux_core::shared::persistence::write_private_atomic(
        &path(),
        &serde_json::to_vec_pretty(state)?,
    )?;
    Ok(())
}
pub struct OperationGuard(nix::fcntl::Flock<std::fs::File>);
pub fn lock() -> anyhow::Result<OperationGuard> {
    lock_named("command.lock", Duration::from_secs(180))
}
fn lock_named(name: &str, budget: Duration) -> anyhow::Result<OperationGuard> {
    use std::os::unix::fs::OpenOptionsExt;
    tunmux_core::config::ensure_connections_dir()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(tunmux_core::config::app_config_dir().join(name))?;
    let start = Instant::now();
    let mut file = file;
    loop {
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(OperationGuard(lock)),
            Err((returned, error)) => {
                anyhow::ensure!(
                    error == nix::errno::Errno::EWOULDBLOCK && start.elapsed() < budget,
                    "operation lock {name}: {error}"
                );
                file = returned;
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        let _ = &self.0;
    }
}

/// Canonicalize parsed options, independent of spelling or argument order.
pub fn connection_spec(args: &[String]) -> anyhow::Result<ConnectionSpec> {
    let mut argv = vec!["tunmux".to_string()];
    argv.extend_from_slice(args);
    let matches = Cli::command().try_get_matches_from(&argv)?;
    let (top, sub) = matches.subcommand().context("expected connect command")?;
    let (provider, leaf) = if top == "connect" {
        sub.subcommand().context("expected provider")?
    } else {
        let (op, leaf) = sub.subcommand().context("expected provider connect")?;
        anyhow::ensure!(op == "connect", "expected connect command");
        (top, leaf)
    };
    anyhow::ensure!(
        matches!(
            provider,
            "proton" | "airvpn" | "mullvad" | "ivpn" | "wgconf"
        ),
        "expected VPN provider"
    );
    let definition = Cli::command();
    let provider_definition = definition
        .find_subcommand("connect")
        .and_then(|c| c.find_subcommand(provider))
        .context("provider is disabled")?;
    let argument_ids: std::collections::HashSet<_> = provider_definition
        .get_arguments()
        .map(|arg| arg.get_id().as_str())
        .collect();
    let mut options = BTreeMap::new();
    for id in leaf.ids() {
        let key = id.as_str();
        if !argument_ids.contains(key) {
            continue;
        }
        if matches!(key, "if_missing" | "verbose" | "log_filter" | "save_as") {
            continue;
        }
        if let Some(values) = leaf.get_raw(key) {
            options.insert(
                key.to_owned(),
                values.map(|s| s.to_string_lossy().into_owned()).collect(),
            );
        }
    }
    let config = tunmux_core::config::load_config();
    options
        .entry("backend".into())
        .or_insert_with(|| vec![config.general.backend.clone()]);
    if !options.contains_key("country") {
        if let Some(provider) = tunmux_core::config::Provider::from_dir_name(provider) {
            if let Some(country) = config.default_country_for(provider) {
                options.insert("country".into(), vec![country.into()]);
            }
        }
    }
    if provider == "airvpn" && !options.contains_key("key") {
        if let Some(key) = &config.airvpn.default_device {
            options.insert("key".into(), vec![key.clone()]);
        }
    }
    if config.general.proxy_access_log && options.contains_key("proxy_access_log") {
        options.insert("proxy_access_log".into(), vec!["true".into()]);
    }
    if let Some(file) = options.get_mut("file") {
        file[0] = std::fs::canonicalize(&file[0])?
            .to_string_lossy()
            .into_owned();
    }
    let source = options
        .get("file")
        .map(|v| PathBuf::from(&v[0]))
        .or_else(|| {
            options.get("profile").map(|v| {
                tunmux_core::config::config_dir(tunmux_core::config::Provider::Wgconf)
                    .join("profiles")
                    .join(format!("{}.conf", v[0]))
            })
        });
    if let Some(source) = source {
        options.insert(
            "source_digest".into(),
            vec![format!("{:x}", Sha256::digest(std::fs::read(source)?))],
        );
    }
    // Retain a replayable argv; effective defaults and absolute source paths are frozen.
    let mut replay = vec!["connect".into(), provider.into()];
    for (key, values) in &options {
        if key == "source_digest" {
            continue;
        }
        if key == "server" {
            replay.extend(values.clone());
            continue;
        }
        if values == &["false"] {
            continue;
        }
        replay.push(format!("--{}", key.replace('_', "-")));
        if values != &["true"] {
            replay.extend(values.clone());
        }
    }
    Ok(ConnectionSpec {
        provider: provider.into(),
        args: replay,
        options,
    })
}

/// Called before provider requests; the guard lives through startup and metadata save.
pub fn prepare(args: &[String]) -> anyhow::Result<Option<OperationGuard>> {
    let mut argv = vec!["tunmux".to_string()];
    argv.extend_from_slice(args);
    let matches = Cli::command().try_get_matches_from(&argv)?;
    let Some((top, sub)) = matches.subcommand() else {
        return Ok(None);
    };
    let operation = if top == "connect" || top == "disconnect" {
        top
    } else {
        sub.subcommand_name().unwrap_or("")
    };
    if !matches!(operation, "connect" | "disconnect") {
        return Ok(None);
    }
    let guard = lock()?;
    if operation == "disconnect" {
        let leaf = if top == "disconnect" {
            sub
        } else {
            sub.subcommand().unwrap().1
        };
        let instance = leaf.get_one::<String>("instance").map(String::as_str);
        let provider = if top == "disconnect" {
            leaf.get_raw("provider")
                .and_then(|mut v| v.next())
                .and_then(|v| v.to_str())
        } else {
            Some(top)
        };
        let all = leaf.get_flag("all");
        let observed = ConnectionState::load_all()?;
        let targets: Vec<_> = observed
            .iter()
            .filter(|s| {
                provider.is_none_or(|p| p == s.provider)
                    && instance.is_none_or(|i| i == s.instance_name)
            })
            .collect();
        if all || instance.is_some() || targets.len() <= 1 {
            suspend_matching(instance, provider, all, &targets)?;
        }
        return Ok(Some(guard));
    }
    // A controller child must recheck desired state while holding the command lock.
    if let Some(token) = std::env::var_os("TUNMUX_DESIRED_ENTRY") {
        let (name, generation): (String, u64) = serde_json::from_str(&token.to_string_lossy())?;
        let state = load()?;
        anyhow::ensure!(
            state
                .entries
                .get(&name)
                .is_some_and(|e| !e.suspended && e.generation == generation),
            "desired connection suspended or changed"
        );
    }
    let spec = connection_spec(args)?;
    anyhow::ensure!(
        !spec.allow_lan()
            || (cfg!(target_os = "macos")
                && !spec.is_proxy()
                && spec
                    .options
                    .get("backend")
                    .is_some_and(|v| matches!(v[0].as_str(), "kernel" | "userspace"))),
        "--allow-lan requires a macOS helper-backed direct connection"
    );
    let leaf = sub.subcommand().unwrap().1;
    if leaf.get_flag("if_missing") {
        for state in ConnectionState::load_all()? {
            let same = state.source_spec.as_ref().is_some_and(|s| spec.matches(s));
            if same || (!spec.is_proxy() && state.instance_name == "_direct") {
                let health = health::inspect_for_connect(&state);
                match health.kind {
                    HealthKind::Active if same => {
                        println!("Already connected: {}", state.instance_name);
                        std::process::exit(0);
                    }
                    HealthKind::Inactive => {}
                    _ => anyhow::bail!(
                        "{} is {}: {}",
                        state.instance_name,
                        health.kind,
                        health.reason
                    ),
                }
            }
        }
    }
    if let Some(token) = std::env::var_os("TUNMUX_DESIRED_ENTRY") {
        let (name, _): (String, u64) = serde_json::from_str(&token.to_string_lossy())?;
        if spec.is_proxy() {
            tunmux_core::automation::set_managed_instance(entry_instance(&name, true));
        }
    }
    tunmux_core::automation::set_active(spec);
    Ok(Some(guard))
}
fn suspend_matching(
    instance: Option<&str>,
    provider: Option<&str>,
    all: bool,
    targets: &[&ConnectionState],
) -> anyhow::Result<()> {
    let mut state = load()?;
    let single_pending =
        targets.is_empty() && instance.is_none() && provider.is_none() && state.entries.len() == 1;
    for entry in state.entries.values_mut() {
        if provider.is_some_and(|p| p != entry.spec.provider) {
            continue;
        }
        let selected = instance.is_some_and(|i| entry.instance.as_deref() == Some(i))
            || targets.iter().any(|s| {
                entry.instance.as_deref() == Some(s.instance_name.as_str())
                    || s.source_spec
                        .as_ref()
                        .is_some_and(|spec| spec.matches(&entry.spec))
            });
        if all
            || selected
            || single_pending
            || (instance.is_none() && targets.is_empty() && provider.is_some())
        {
            entry.suspended = true;
            entry.generation += 1;
        }
    }
    save(&state)
}
pub fn suspend_all() -> anyhow::Result<()> {
    let _guard = lock()?;
    let mut state = load()?;
    for entry in state.entries.values_mut() {
        entry.suspended = true;
        entry.generation += 1;
    }
    save(&state)
}

pub fn dispatch(command: AutoconnectCommand) -> anyhow::Result<()> {
    if matches!(command, AutoconnectCommand::Run) {
        return controller();
    }
    let _guard = lock()?;
    let mut state = load()?;
    let suspended = matches!(command, AutoconnectCommand::Disable { .. });
    match command {
        AutoconnectCommand::Enable {
            name,
            args,
            no_login_agent,
        } => {
            anyhow::ensure!(
                cfg!(target_os = "macos"),
                "login autoconnect installation is available only on macOS"
            );
            anyhow::ensure!(
                !nix::unistd::Uid::effective().is_root(),
                "enable autoconnect as the login user"
            );
            anyhow::ensure!(
                !args
                    .iter()
                    .any(|a| a == "--save-as" || a.starts_with("--save-as=")),
                "save profiles before enabling autoconnect"
            );
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
                "invalid desired connection name"
            );
            let mut spec = connection_spec(&args)?;
            anyhow::ensure!(
                !spec.options.contains_key("save_as"),
                "save profiles before enabling autoconnect"
            );
            if !spec.is_proxy() {
                anyhow::ensure!(
                    !state
                        .entries
                        .iter()
                        .any(|(n, e)| n != &name && !e.spec.is_proxy()),
                    "only one desired direct connection is supported"
                );
            }
            if spec.is_proxy() && !spec.options.contains_key("socks_port") {
                let ports =
                    tunmux_core::shared::connection_ops::resolve_proxy_config(None, None, false)?;
                // Reserve stable ports across desired entries, including entries not yet running.
                let mut socks = ports.socks_port;
                let mut http = ports.http_port;
                while state.entries.iter().any(|(n, e)| {
                    n != &name
                        && (e
                            .spec
                            .options
                            .get("socks_port")
                            .is_some_and(|v| v[0] == socks.to_string())
                            || e.spec
                                .options
                                .get("http_port")
                                .is_some_and(|v| v[0] == http.to_string()))
                }) {
                    socks = socks.checked_add(1).context("proxy port range exhausted")?;
                    http = http.checked_add(1).context("proxy port range exhausted")?;
                }
                let mut args = spec.args.clone();
                args.extend([
                    "--socks-port".into(),
                    socks.to_string(),
                    "--http-port".into(),
                    http.to_string(),
                ]);
                spec = connection_spec(&args)?;
            }
            anyhow::ensure!(
                !state
                    .entries
                    .iter()
                    .any(|(n, e)| n != &name && e.spec.matches(&spec)),
                "connection is already managed under another name"
            );
            let generation = state.entries.get(&name).map_or(1, |e| e.generation + 1);
            let desired_instance = entry_instance(&name, spec.is_proxy());
            anyhow::ensure!(!state.entries.iter().any(|(other,entry)|other != &name && entry.instance.as_deref() == Some(desired_instance.as_str())), "desired name collides with an existing instance after normalization; choose another name");
            let entry_name = name.clone();
            let previous = state.entries.insert(
                name,
                Entry {
                    spec,
                    suspended: false,
                    generation,
                    instance: Some(desired_instance),
                    failure: None,
                    failures: 0,
                    blocked: false,
                },
            );
            save(&state)?;
            if let Err(error) = if no_login_agent {
                Ok(())
            } else {
                tunmux_core::service::install_agent()
            } {
                if let Some(previous) = previous {
                    state.entries.insert(entry_name, previous);
                } else {
                    state.entries.remove(&entry_name);
                }
                save(&state)?;
                return Err(error);
            }
        }
        AutoconnectCommand::Disable { name, all } | AutoconnectCommand::Resume { name, all } => {
            anyhow::ensure!(
                all || name.as_ref().is_some_and(|n| state.entries.contains_key(n)),
                "unknown desired connection"
            );
            for (n, e) in &mut state.entries {
                if all || Some(n) == name.as_ref() {
                    e.suspended = suspended;
                    e.generation += 1;
                    e.failure = None;
                    e.failures = 0;
                    e.blocked = false;
                }
            }
            save(&state)?;
        }
        AutoconnectCommand::Status => {
            for (name, e) in state.entries {
                println!(
                    "{name}: {} {} {}",
                    if e.suspended { "suspended" } else { "enabled" },
                    e.instance.as_deref().unwrap_or("unobserved"),
                    e.failure.as_deref().unwrap_or("")
                );
            }
        }
        AutoconnectCommand::Run => unreachable!(),
    }
    Ok(())
}
#[derive(Default)]
struct Retry {
    generation: u64,
    failures: usize,
    permanent: bool,
    next: Option<Instant>,
}
fn retry_delay(failures: usize) -> Option<Duration> {
    [1, 2, 4, 8, 16, 30]
        .get(failures.saturating_sub(1))
        .map(|s| Duration::from_millis(s * 1000 + u64::from(rand::random::<u8>()) * 2))
}
fn controller() -> anyhow::Result<()> {
    let _controller = lock_named("controller.lock", Duration::ZERO)?;
    let changes = tunmux_core::network_changes::NetworkChanges::start();
    let mut observed_generation = changes.generation();
    let mut retries: BTreeMap<String, Retry> = BTreeMap::new();
    loop {
        let state = load()?;
        let network = changes.generation();
        if network != observed_generation {
            retries.retain(|_, retry| retry.permanent);
            let _guard = lock()?;
            let mut state = load()?;
            for entry in state.entries.values_mut().filter(|e| !e.blocked) {
                entry.failures = 0;
            }
            save(&state)?;
            observed_generation = network;
            continue;
        }
        for (name, entry) in state.entries {
            if entry.suspended || entry.blocked {
                continue;
            }
            let retry = retries.entry(name.clone()).or_insert_with(|| Retry {
                generation: entry.generation,
                failures: entry.failures,
                permanent: entry.blocked,
                next: if entry.failures > 0 {
                    Some(Instant::now() + Duration::from_secs(30))
                } else {
                    None
                },
            });
            if retry.generation != entry.generation {
                *retry = Retry {
                    generation: entry.generation,
                    ..Default::default()
                };
            }
            if retry.failures > 6 || retry.next.is_some_and(|at| at > Instant::now()) {
                continue;
            }
            let observed = ConnectionState::load_all()?;
            if let Some(existing) = observed.iter().find(|s| {
                s.source_spec
                    .as_ref()
                    .is_some_and(|spec| spec.matches(&entry.spec))
            }) {
                let health = health::inspect(existing);
                if health.kind == HealthKind::Active {
                    retry.failures = 0;
                    retry.next = Some(Instant::now() + Duration::from_secs(10));
                    continue;
                }
                if health.kind == HealthKind::Unknown {
                    record(
                        &name,
                        entry.generation,
                        Some(existing.instance_name.clone()),
                        Some(health.reason),
                        Some((7, true)),
                    )?;
                    retry.failures = 7;
                    retry.permanent = true;
                    continue;
                }
            }
            let current = connection_spec(&entry.spec.args);
            if !current.as_ref().is_ok_and(|s| s.matches(&entry.spec)) {
                record(
                    &name,
                    entry.generation,
                    None,
                    Some("source or defaults changed; enable again to accept changes".into()),
                    Some((7, true)),
                )?;
                retry.failures = 7;
                retry.permanent = true;
                continue;
            }
            let result =
                std::process::Command::new(tunmux_core::shared::executable::cli_executable()?)
                    .args(&entry.spec.args)
                    .arg("--if-missing")
                    .env(
                        "TUNMUX_DESIRED_ENTRY",
                        serde_json::to_string(&(name.clone(), entry.generation))?,
                    )
                    .env("TUNMUX_NONINTERACTIVE", "1")
                    .stdin(std::process::Stdio::null())
                    .spawn()
                    .and_then(wait_child);
            if result.as_ref().is_ok_and(|s| s.success()) {
                let observed = ConnectionState::load_all()?;
                let instance = observed
                    .iter()
                    .find(|s| {
                        s.source_spec
                            .as_ref()
                            .is_some_and(|spec| spec.matches(&entry.spec))
                    })
                    .map(|s| s.instance_name.clone());
                record(&name, entry.generation, instance, None, Some((0, false)))?;
                retry.failures = 0;
                retry.next = Some(Instant::now() + Duration::from_secs(10));
            } else {
                if !result.as_ref().is_ok_and(|s| s.code() == Some(75)) {
                    retry.permanent = true;
                    retry.failures = 7;
                    record(&name, entry.generation, None, Some("connect requires intervention; inspect autoconnect.log and resume explicitly".into()), Some((7,true)))?;
                    continue;
                }
                retry.failures += 1;
                retry.next = retry_delay(retry.failures).map(|d| Instant::now() + d);
                record(
                    &name,
                    entry.generation,
                    None,
                    Some(
                        if retry.failures > 6 {
                            "retry limit reached; resume explicitly"
                        } else {
                            "connect failed; retry scheduled"
                        }
                        .into(),
                    ),
                    Some((retry.failures, false)),
                )?;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
fn record(
    name: &str,
    generation: u64,
    instance: Option<String>,
    failure: Option<String>,
    retry: Option<(usize, bool)>,
) -> anyhow::Result<()> {
    let _guard = lock()?;
    let mut state = load()?;
    if let Some(e) = state
        .entries
        .get_mut(name)
        .filter(|e| e.generation == generation)
    {
        if instance.is_some() {
            e.instance = instance;
        }
        e.failure = failure;
        if let Some((failures, blocked)) = retry {
            e.failures = failures;
            e.blocked = blocked;
        }
        save(&state)?;
    }
    Ok(())
}

fn wait_child(mut child: std::process::Child) -> std::io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect deadline exceeded; inspect and recover before resuming",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
/// Background callers retry only errors known to be transient; uncertain errors stop.
pub fn failure_exit_code(error: &anyhow::Error) -> std::process::ExitCode {
    if std::env::var_os("TUNMUX_DESIRED_ENTRY").is_none() {
        return std::process::ExitCode::FAILURE;
    }
    let transient = tunmux_core::automation::is_transient(error);
    std::process::ExitCode::from(if transient { 75 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_retry_schedule() {
        for n in 1..=6 {
            assert!(retry_delay(n).unwrap() <= Duration::from_millis(30510));
        }
        assert!(retry_delay(7).is_none());
    }
    #[cfg(feature = "proton")]
    #[test]
    fn equivalent_cli_spelling_has_same_identity() {
        let a =
            connection_spec(&["connect", "proton", "FR#1", "-b", "userspace"].map(String::from))
                .unwrap();
        let b = connection_spec(
            &[
                "proton",
                "connect",
                "--backend",
                "userspace",
                "--if-missing",
                "FR#1",
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(a.matches(&b), "a={a:?} b={b:?}");
        assert!(a.matches(&connection_spec(&a.args).unwrap()));
    }
    #[test]
    fn suspension_survives_serialization() {
        let mut state = Desired {
            version: 1,
            ..Default::default()
        };
        state.entries.insert(
            "work".into(),
            Entry {
                spec: ConnectionSpec {
                    provider: "wgconf".into(),
                    args: vec![],
                    options: BTreeMap::new(),
                },
                suspended: true,
                generation: 3,
                instance: None,
                failure: None,
                failures: 0,
                blocked: false,
            },
        );
        let loaded: Desired = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(loaded.entries["work"].suspended);
        assert_eq!(loaded.entries["work"].generation, 3);
    }
}
