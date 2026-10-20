//! Explicit platform service installation.
//! No installation is performed during ordinary connects.
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::cli::ServiceCommand;

pub const DAEMON_LABEL: &str = "io.tunmux.privileged";
const AGENT_LABEL: &str = "io.tunmux.autoconnect";
const PLIST: &str = "/Library/LaunchDaemons/io.tunmux.privileged.plist";
const MANIFEST: &str = "/Library/Application Support/tunmux/install.json";
#[derive(Serialize, Deserialize)]
struct Installation {
    version: u32,
    binary: PathBuf,
    authorized_group: String,
    uid: u32,
    config_dir: PathBuf,
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn render_plist(template: &str, values: &[(&str, String)]) -> String {
    let mut rendered = String::new();
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        rendered.push_str(&remaining[..start]);
        let Some((name, rest)) = remaining[start + 2..].split_once("}}") else {
            rendered.push_str(&remaining[start..]);
            return rendered;
        };
        if let Some((_, value)) = values.iter().find(|(key, _)| *key == name) {
            rendered.push_str(value);
        } else {
            rendered.push_str(&remaining[start..start + name.len() + 4]);
        }
        remaining = rest;
    }
    rendered.push_str(remaining);
    rendered
}
fn daemon_plist(binary: &Path, group: &str, gid: u32) -> String {
    render_plist(
        include_str!("../launchd/io.tunmux.privileged.plist"),
        &[
            ("BINARY", xml(&binary.to_string_lossy())),
            ("GROUP", xml(group)),
            ("GID", gid.to_string()),
            (
                "SOCKET",
                xml(&crate::config::privileged_socket_path().to_string_lossy()),
            ),
        ],
    )
}
fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("cannot execute {program}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
fn installation() -> anyhow::Result<Installation> {
    let state: Installation = serde_json::from_slice(&std::fs::read(MANIFEST)?)?;
    anyhow::ensure!(
        state.version == 1 && state.binary.is_absolute(),
        "invalid install manifest"
    );
    Ok(state)
}
pub fn installed() -> bool {
    cfg!(target_os = "macos") && Path::new(PLIST).exists()
}
fn dispatch_macos(command: ServiceCommand) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "macos"),
        "service installation is available only on Linux and macOS"
    );
    match command {
        ServiceCommand::Install {
            binary_path,
            authorized_group,
            user,
            config_dir,
        } => {
            require_root()?;
            install_macos(binary_path, &authorized_group, user, config_dir)
        }
        ServiceCommand::Reload => {
            require_root()?;
            reload_macos()
        }
        ServiceCommand::Uninstall => {
            require_root()?;
            uninstall_macos()
        }
        ServiceCommand::Diagnose => diagnose(),
    }
}
fn install_macos(
    binary_path: PathBuf,
    authorized_group: &str,
    user: Option<u32>,
    config_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    anyhow::ensure!(binary_path.is_absolute(), "binary path must be absolute");
    let group = nix::unistd::Group::from_name(authorized_group)?
        .context("authorized group does not exist")?;
    let source = std::env::current_exe()?;
    let uid = user
        .or(std::env::var("SUDO_UID")
            .ok()
            .map(|s| s.parse())
            .transpose()?)
        .unwrap_or_else(|| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata("/dev/console")
                .map(|m| m.uid())
                .unwrap_or(0)
        });
    let login = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
        .context("installation user does not exist")?;
    let config_dir = config_dir.unwrap_or_else(|| login.dir.join(".config/tunmux"));
    anyhow::ensure!(
        config_dir.is_absolute()
            && config_dir.parent().is_some()
            && config_dir.file_name().is_some_and(|name| name == "tunmux"),
        "configuration directory must be absolute and end in tunmux"
    );
    // Validate every ancestor; launchd must never execute a user-replaceable binary.
    secure_directory(binary_path.parent().context("binary path has no parent")?)?;
    secure_directory(Path::new("/Library/LaunchDaemons"))?;
    secure_directory(Path::new("/Library/Application Support/tunmux"))?;
    secure_directory(Path::new("/var/log/tunmux"))?;
    crate::config::ensure_privileged_socket_dir()?;
    nix::unistd::chown(
        &crate::config::privileged_socket_dir(),
        Some(nix::unistd::Uid::from_raw(0)),
        Some(group.gid),
    )?;
    let mut resume = Vec::new();
    if installed() {
        let previous = installation()?;
        anyhow::ensure!(
            previous.binary == binary_path,
            "use the existing binary path when upgrading"
        );
        resume = teardown(&previous)?;
        bootout()?;
    }
    let previous_binary = std::fs::read(&binary_path).ok();
    let previous_plist = std::fs::read(PLIST).ok();
    let previous_manifest = std::fs::read(MANIFEST).ok();
    let state = Installation {
        version: 1,
        binary: binary_path.clone(),
        authorized_group: authorized_group.to_owned(),
        uid,
        config_dir,
    };
    let result = (|| -> anyhow::Result<()> {
        write_root(&binary_path, &std::fs::read(source)?, 0o755)?;
        write_root(
            Path::new(PLIST),
            daemon_plist(&binary_path, authorized_group, group.gid.as_raw()).as_bytes(),
            0o644,
        )?;
        write_root(
            Path::new(MANIFEST),
            &serde_json::to_vec_pretty(&state)?,
            0o600,
        )?;
        run("/usr/bin/plutil", &["-lint", PLIST])?;
        run("/bin/launchctl", &["bootstrap", "system", PLIST])
    })();
    if let Err(error) = result {
        for (path, bytes, mode) in [
            (binary_path.as_path(), previous_binary, 0o755),
            (Path::new(PLIST), previous_plist, 0o644),
            (Path::new(MANIFEST), previous_manifest, 0o600),
        ] {
            if let Some(bytes) = bytes {
                write_root(path, &bytes, mode)?;
            } else if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        if installed() {
            let _ = run("/bin/launchctl", &["bootstrap", "system", PLIST]);
        }
        return Err(error.context("installation failed; prior files restored"));
    }
    for name in resume {
        user_command(&state, &["autoconnect", "resume", &name])?;
    }
    println!("Installed {DAEMON_LABEL} at {}", binary_path.display());
    Ok(())
}
fn reload_macos() -> anyhow::Result<()> {
    let state = installation()?;
    // Suspension remains in effect if any cleanup or launchctl step fails.
    let enabled = teardown(&state)?;
    bootout()?;
    run("/bin/launchctl", &["bootstrap", "system", PLIST])?;
    for name in enabled {
        user_command(&state, &["autoconnect", "resume", &name])?;
    }
    Ok(())
}
fn uninstall_macos() -> anyhow::Result<()> {
    let state = installation()?;
    teardown(&state)?;
    bootout()?;
    remove_agent(&state)?;
    for file in [
        Path::new(PLIST),
        Path::new(MANIFEST),
        state.binary.as_path(),
    ] {
        if file.exists() {
            std::fs::remove_file(file)?;
        }
    }
    println!("Uninstalled service; profiles and recovery journals preserved");
    Ok(())
}

fn bootout() -> anyhow::Result<()> {
    if Command::new("/bin/launchctl")
        .args(["print", &format!("system/{DAEMON_LABEL}")])
        .output()?
        .status
        .success()
    {
        run(
            "/bin/launchctl",
            &["bootout", &format!("system/{DAEMON_LABEL}")],
        )?;
    }
    Ok(())
}
fn user_command(state: &Installation, args: &[&str]) -> anyhow::Result<()> {
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-H", "-u", &format!("#{}", state.uid), "--"])
        .arg("/usr/bin/env")
        .arg(format!(
            "XDG_CONFIG_HOME={}",
            state
                .config_dir
                .parent()
                .context("configuration directory missing parent")?
                .display()
        ))
        .arg(&state.binary)
        .args(args);
    anyhow::ensure!(
        command
            .stdin(std::process::Stdio::null())
            .status()?
            .success(),
        "user command failed: {}",
        args.join(" ")
    );
    Ok(())
}
fn user_config(state: &Installation) -> anyhow::Result<PathBuf> {
    Ok(state.config_dir.clone())
}
fn teardown(state: &Installation) -> anyhow::Result<Vec<String>> {
    println!("Suspending automatic connections and waiting for active operations to finish...");
    let desired = user_config(state)?.join("desired.json");
    let mut enabled = Vec::new();
    match std::fs::read(desired) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            if let Some(entries) = value["entries"].as_object() {
                for (name, e) in entries {
                    if e["suspended"] == false {
                        enabled.push(name.clone());
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    user_command(state, &["autoconnect", "disable", "--all"])?;
    user_command(state, &["disconnect", "--all"])?;
    // Any unfinished root journal blocks removal, including sessions absent from user metadata.
    if let Ok(entries) = std::fs::read_dir("/var/run/wireguard") {
        for entry in entries {
            let path = entry?.path();
            if path.to_string_lossy().ends_with(".recovery.json") {
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                anyhow::ensure!(
                    value["actions"].as_array().is_some_and(|a| a.is_empty()),
                    "unresolved recovery journal {}; service remains installed",
                    path.display()
                );
            }
        }
    }
    Ok(enabled)
}
fn secure_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.exists() {
        if let Some(parent) = path.parent() {
            secure_directory(parent)?;
        }
        std::fs::create_dir(path)?;
    }
    // /var is a macOS system symlink; canonicalize before validating ancestors.
    let canonical = std::fs::canonicalize(path)?;
    for ancestor in canonical.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "unsafe root installation directory {}",
            ancestor.display()
        );
    }
    Ok(())
}
fn write_root(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    crate::shared::persistence::write_private_atomic(path, bytes)?;
    nix::unistd::chown(
        path,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    )?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}
pub fn install_agent() -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "macos"),
        "login agent installation is available only on macOS"
    );
    anyhow::ensure!(
        !nix::unistd::Uid::effective().is_root(),
        "enable autoconnect as the login user"
    );
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())?.context("login user missing")?;
    let directory = user.dir.join("Library/LaunchAgents");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{AGENT_LABEL}.plist"));
    let binary = if installed() {
        installation_for_agent()?
    } else {
        std::env::current_exe()?
    };
    let logs = crate::config::app_config_dir().join("autoconnect.log");
    let config_dir = crate::config::app_config_dir();
    let config_home = config_dir
        .parent()
        .context("configuration directory missing parent")?;
    let text = render_plist(
        include_str!("../launchd/io.tunmux.autoconnect.plist"),
        &[
            ("BINARY", xml(&binary.to_string_lossy())),
            ("CONFIG_HOME", xml(&config_home.to_string_lossy())),
            ("LOG", xml(&logs.to_string_lossy())),
        ],
    );
    crate::shared::persistence::write_private_atomic(&path, text.as_bytes())?;
    run("/usr/bin/plutil", &["-lint", &path.to_string_lossy()])?;
    let domain = format!("gui/{}", nix::unistd::getuid());
    if !Command::new("/bin/launchctl")
        .args(["print", &format!("{domain}/{AGENT_LABEL}")])
        .output()?
        .status
        .success()
    {
        run(
            "/bin/launchctl",
            &["bootstrap", &domain, &path.to_string_lossy()],
        )?;
    }
    Ok(())
}
fn installation_for_agent() -> anyhow::Result<PathBuf> {
    // The root manifest is private. The root-owned plist contains the public executable path.
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", "ProgramArguments.0", "raw", "-o", "-", PLIST])
        .output()?;
    anyhow::ensure!(output.status.success(), "cannot read installed binary path");
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
fn remove_agent(state: &Installation) -> anyhow::Result<()> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(state.uid))?
        .context("login user missing")?;
    let service = format!("gui/{}/{AGENT_LABEL}", state.uid);
    if Command::new("/bin/launchctl")
        .args(["print", &service])
        .output()?
        .status
        .success()
    {
        run("/bin/launchctl", &["bootout", &service])?;
    }
    let path = user
        .dir
        .join(format!("Library/LaunchAgents/{AGENT_LABEL}.plist"));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
fn diagnose() -> anyhow::Result<()> {
    println!(
        "daemon plist: {PLIST} (exists: {})",
        Path::new(PLIST).exists()
    );
    println!(
        "control socket: {}",
        crate::config::privileged_socket_path().display()
    );
    let output = Command::new("/bin/launchctl")
        .args(["print", &format!("system/{DAEMON_LABEL}")])
        .output()?;
    println!(
        "{}",
        String::from_utf8_lossy(if output.status.success() {
            &output.stdout
        } else {
            &output.stderr
        })
    );
    for state in crate::wireguard::connection::ConnectionState::load_all()? {
        let h = crate::wireguard::health::inspect(&state);
        println!("{}: {} ({})", state.instance_name, h.kind, h.reason);
    }
    match std::fs::read_dir("/var/run/wireguard") {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path.to_string_lossy().ends_with(".recovery.json") {
                    println!("recovery journal: {}", path.display());
                }
            }
        }
        Err(e) => println!("recovery inspection unavailable: {e}"),
    }
    Ok(())
}

pub fn dispatch(command: ServiceCommand) -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        dispatch_linux(command)
    } else {
        dispatch_macos(command)
    }
}

const LINUX_SERVICE: &str = "tunmux-privileged.service";
const LINUX_SOCKET: &str = "tunmux-privileged.socket";

struct LinuxPaths {
    units: PathBuf,
    manifest: PathBuf,
    systemctl: PathBuf,
    socket_dir: PathBuf,
}
impl LinuxPaths {
    fn system() -> Self {
        Self {
            units: "/etc/systemd/system".into(),
            manifest: "/var/lib/tunmux/install.json".into(),
            systemctl: "/usr/bin/systemctl".into(),
            socket_dir: "/run/tunmux".into(),
        }
    }
    fn ctl(&self, args: &[&str]) -> anyhow::Result<()> {
        run(
            self.systemctl.to_str().context("invalid systemctl path")?,
            args,
        )
    }
    fn query(&self, verb: &str) -> anyhow::Result<bool> {
        let output = Command::new(&self.systemctl)
            .args([verb, "--quiet", LINUX_SOCKET])
            .output()
            .with_context(|| format!("cannot query systemd {verb}"))?;
        Ok(output.status.success())
    }
}

#[derive(Serialize, Deserialize)]
struct LinuxInstallation {
    version: u32,
    binary: PathBuf,
    digests: Vec<Vec<u8>>,
}
fn digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}
fn protected_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {}", path.display()))?;
    anyhow::ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "unsafe installed file {}",
        path.display()
    );
    Ok(())
}
fn linux_state(paths: &LinuxPaths) -> anyhow::Result<Option<LinuxInstallation>> {
    match std::fs::symlink_metadata(&paths.manifest) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    protected_file(&paths.manifest)?;
    let state: LinuxInstallation = serde_json::from_slice(&std::fs::read(&paths.manifest)?)?;
    anyhow::ensure!(
        state.version == 1 && state.binary.is_absolute() && state.digests.len() == 3,
        "invalid Linux installation manifest"
    );
    Ok(Some(state))
}
fn linux_artifacts(paths: &LinuxPaths, binary: &Path) -> Vec<PathBuf> {
    vec![
        binary.to_owned(),
        paths.units.join(LINUX_SERVICE),
        paths.units.join(LINUX_SOCKET),
    ]
}
fn check_linux_artifacts(
    paths: &LinuxPaths,
    binary: &Path,
    previous: Option<&LinuxInstallation>,
) -> anyhow::Result<()> {
    if let Some(state) = previous {
        anyhow::ensure!(
            state.binary == binary,
            "use the existing binary path when upgrading"
        );
    }
    for (index, path) in linux_artifacts(paths, binary).iter().enumerate() {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                protected_file(path)?;
                let bytes = std::fs::read(path).with_context(|| {
                    format!("cannot read installed artifact {}", path.display())
                })?;
                anyhow::ensure!(
                    previous.is_some_and(|s| s.digests[index] == digest(&bytes)),
                    "refusing to overwrite or remove unrelated artifact {}",
                    path.display()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn systemd_argument(value: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!value.contains('\0'), "systemd argument contains NUL");
    let mut escaped = String::from("\"");
    for ch in value.chars() {
        match ch {
            '%' => escaped.push_str("%%"),
            '$' => escaped.push_str("$$"),
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            c if c.is_control() => {
                use std::fmt::Write;
                let mut bytes = [0; 4];
                for byte in c.encode_utf8(&mut bytes).as_bytes() {
                    write!(escaped, "\\x{byte:02x}")?;
                }
            }
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    Ok(escaped)
}
fn linux_units(binary: &Path, group: &str, gid: u32) -> anyhow::Result<(String, String)> {
    let binary = binary.to_str().context("binary path must be UTF-8")?;
    let service = include_str!("../systemd/tunmux-privileged.service").replace(
        "ExecStart=/usr/bin/tunmux privileged --serve --authorized-group tunmux",
        &format!(
            "ExecStart=/usr/bin/env -- {} privileged --serve --authorized-group {}",
            systemd_argument(binary)?,
            systemd_argument(group)?
        ),
    );
    let socket = include_str!("../systemd/tunmux-privileged.socket")
        .replace("SocketGroup=tunmux", &format!("SocketGroup={gid}"));
    Ok((service, socket))
}
fn linux_group(name: &str) -> anyhow::Result<nix::unistd::Group> {
    nix::unistd::Group::from_name(name)?.with_context(|| {
        format!("authorized group {name:?} does not exist; create it or select --authorized-group")
    })
}
fn dispatch_linux(command: ServiceCommand) -> anyhow::Result<()> {
    let paths = LinuxPaths::system();
    match command {
        ServiceCommand::Install { binary_path, authorized_group, user, config_dir } => {
            anyhow::ensure!(user.is_none() && config_dir.is_none(), "--user and --config-dir are macOS-only installation options");
            require_root()?;
            linux_group(&authorized_group)?;
            install_linux(&paths, &binary_path, &authorized_group, &std::env::current_exe()?)
        }
        ServiceCommand::Uninstall => { require_root()?; uninstall_linux(&paths) }
        ServiceCommand::Reload => anyhow::bail!("Linux reload is unsupported; use sudo systemctl restart tunmux-privileged.service"),
        ServiceCommand::Diagnose => anyhow::bail!("Linux diagnose is unsupported; use systemctl status tunmux-privileged.socket tunmux-privileged.service and journalctl -u tunmux-privileged.service"),
    }
}
fn require_root() -> anyhow::Result<()> {
    anyhow::ensure!(
        nix::unistd::Uid::effective().is_root(),
        "service changes require root; run sudo tunmux service <command>"
    );
    Ok(())
}
fn install_linux(
    paths: &LinuxPaths,
    binary: &Path,
    group: &str,
    source: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        binary.is_absolute() && binary.file_name().is_some(),
        "binary path must be an absolute file path"
    );
    secure_directory(binary.parent().context("binary has no parent")?)?;
    let parent = std::fs::canonicalize(binary.parent().context("binary has no parent")?)?;
    anyhow::ensure!(!["/root", "/home", "/run/user"].iter().any(|hidden| parent.starts_with(hidden)),
        "binary path is hidden by systemd ProtectHome; choose a path outside /root, /home and /run/user");
    secure_directory(&paths.units)?;
    secure_directory(paths.manifest.parent().context("manifest has no parent")?)?;
    anyhow::ensure!(
        binary != paths.manifest
            && ![LINUX_SERVICE, LINUX_SOCKET]
                .iter()
                .any(|name| binary == paths.units.join(name)),
        "binary path conflicts with installation metadata or units"
    );
    secure_directory(&paths.socket_dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.socket_dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let previous = linux_state(paths)?;
    check_linux_artifacts(paths, binary, previous.as_ref())?;
    let gid = linux_group(group)?.gid.as_raw();
    let (service, socket) = linux_units(binary, group, gid)?;
    let contents = [
        std::fs::read(source).context("cannot read running executable")?,
        service.into_bytes(),
        socket.into_bytes(),
    ];
    let state = LinuxInstallation {
        version: 1,
        binary: binary.to_owned(),
        digests: contents.iter().map(|b| digest(b)).collect(),
    };
    let mut artifacts = linux_artifacts(paths, binary);
    artifacts.push(paths.manifest.clone());
    let backups = artifacts
        .iter()
        .map(|p| match std::fs::read(p) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let enabled = paths.query("is-enabled")?;
    let active = paths.query("is-active")?;
    let modes = [0o755, 0o644, 0o644, 0o600];
    let result = (|| -> anyhow::Result<()> {
        if previous.is_some() {
            paths.ctl(&["stop", LINUX_SOCKET, LINUX_SERVICE])?;
        }
        for ((path, bytes), mode) in artifacts
            .iter()
            .zip(
                contents
                    .iter()
                    .chain(std::iter::once(&serde_json::to_vec_pretty(&state)?)),
            )
            .zip(modes)
        {
            write_root(path, bytes, mode)?;
        }
        paths.ctl(&["daemon-reload"])?;
        paths.ctl(&["enable", "--now", LINUX_SOCKET])
    })();
    if let Err(error) = result {
        let rollback = (|| -> anyhow::Result<()> {
            let stopped = paths.ctl(&["stop", LINUX_SOCKET, LINUX_SERVICE]);
            for ((path, bytes), mode) in artifacts.iter().zip(backups).zip(modes) {
                if let Some(bytes) = bytes {
                    write_root(path, &bytes, mode)?;
                } else if path.try_exists()? {
                    std::fs::remove_file(path)?;
                }
            }
            paths.ctl(&["daemon-reload"])?;
            paths.ctl(&[if enabled { "enable" } else { "disable" }, LINUX_SOCKET])?;
            if active {
                paths.ctl(&["start", LINUX_SOCKET])?;
            }
            if previous.is_some() {
                stopped?;
            }
            Ok(())
        })();
        return match rollback {
            Ok(()) => Err(anyhow::anyhow!(
                "installation failed; prior artifacts and socket state restored: {error:#}"
            )),
            Err(e) => Err(anyhow::anyhow!(
                "installation failed: {error:#}; rollback also failed: {e:#}"
            )),
        };
    }
    println!(
        "Installed systemd socket activation at {}",
        binary.display()
    );
    Ok(())
}
fn uninstall_linux(paths: &LinuxPaths) -> anyhow::Result<()> {
    secure_directory(&paths.units)?;
    secure_directory(paths.manifest.parent().context("manifest has no parent")?)?;
    let state = linux_state(paths)?.context("no installer-owned Linux service found")?;
    secure_directory(state.binary.parent().context("binary has no parent")?)?;
    check_linux_artifacts(paths, &state.binary, Some(&state))?;
    paths.ctl(&["disable", "--now", LINUX_SOCKET, LINUX_SERVICE])?;
    for path in linux_artifacts(paths, &state.binary)
        .iter()
        .chain(std::iter::once(&paths.manifest))
    {
        if path.try_exists()? {
            std::fs::remove_file(path)
                .with_context(|| format!("cannot remove {}", path.display()))?;
        }
    }
    paths.ctl(&["daemon-reload"])?;
    println!("Uninstalled service; profiles, runtime state and recovery journals preserved");
    Ok(())
}

#[cfg(test)]
mod linux_tests {
    use super::*;

    #[test]
    fn test_render_systemd_arguments() {
        let (service, socket) =
            linux_units(Path::new("/opt/a b/%i/$bin/\"tunmux"), "vpn", 1234).unwrap();
        assert!(service.contains(
            r#"ExecStart=/usr/bin/env -- "/opt/a b/%%i/$$bin/\"tunmux" privileged --serve --authorized-group "vpn""#
        ));
        assert!(socket.contains("SocketGroup=1234"));
        assert!(socket.contains("DirectoryMode=0755"));
        assert!(!socket.contains("PartOf="));
        assert!(!service.contains("WantedBy="));
        assert!(service.contains("CAP_CHOWN"));
        assert!(systemd_argument("bad\0value").is_err());
        assert_eq!(systemd_argument("a\nb\\c").unwrap(), "\"a\\x0ab\\\\c\"");
    }

    #[test]
    fn test_service_cli_defaults_and_removed_export() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["tunmux", "service", "install"]).unwrap();
        let crate::cli::TopCommand::Service {
            command:
                ServiceCommand::Install {
                    binary_path,
                    authorized_group,
                    ..
                },
        } = cli.command
        else {
            panic!("expected service install");
        };
        assert_eq!(binary_path, Path::new("/usr/local/libexec/tunmux"));
        assert_eq!(
            authorized_group,
            if cfg!(target_os = "macos") {
                "admin"
            } else {
                "tunmux"
            }
        );
        assert!(crate::cli::Cli::try_parse_from([
            "tunmux",
            "service",
            "export-systemd",
            "/tmp/units"
        ])
        .is_err());
    }

    #[test]
    fn test_missing_linux_group_has_actionable_error() {
        let error = linux_group("tunmux-missing-group-8f19f301").unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn test_linux_dispatch_rejects_macos_options_before_root_check() {
        for (user, config_dir) in [(Some(1000), None), (None, Some("/tmp/tunmux".into()))] {
            let error = dispatch_linux(ServiceCommand::Install {
                binary_path: "/usr/local/libexec/tunmux".into(),
                authorized_group: "tunmux".into(),
                user,
                config_dir,
            })
            .unwrap_err();
            assert!(error.to_string().contains("macOS-only"));
        }
        assert!(dispatch_linux(ServiceCommand::Reload)
            .unwrap_err()
            .to_string()
            .contains("systemctl"));
        assert!(dispatch_linux(ServiceCommand::Diagnose)
            .unwrap_err()
            .to_string()
            .contains("journalctl"));
    }

    // Run in a disposable root environment: sudo cargo test test_linux_install_transaction -- --ignored
    #[test]
    #[ignore = "requires root and protected temporary directory ancestors"]
    fn test_linux_install_transaction() {
        use std::os::unix::fs::PermissionsExt;
        assert!(nix::unistd::Uid::effective().is_root());
        let root = PathBuf::from(format!(
            "/usr/local/libexec/tunmux-install-test-{:x}",
            rand::random::<u64>()
        ));
        secure_directory(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        let paths = LinuxPaths {
            units: root.join("units"),
            manifest: root.join("state/install.json"),
            systemctl: root.join("systemctl"),
            socket_dir: root.join("runtime"),
        };
        let fail = root.join("fail");
        let log = root.join("calls");
        std::fs::write(
            &paths.systemctl,
            format!(
                r#"#!/bin/sh
cd '{}'
echo "$*" >> calls
case "$1" in
is-enabled) test -f enabled; exit $?;;
is-active) test -f active; exit $?;;
stop) /bin/rm -f active;;
disable) /bin/rm -f enabled active;;
start) touch active;;
enable)
    if test -f fail; then /bin/rm fail; exit 1; fi
    touch enabled
    if test "$2" = --now; then touch active; fi;;
esac
"#,
                root.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&paths.systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = root.join("source");
        let binary = root.join("bin/tunmux");
        std::fs::write(&source, "first executable").unwrap();
        std::fs::write(&fail, "fail once").unwrap();
        assert!(install_linux(&paths, &binary, "root", &source).is_err());
        assert!(!binary.exists());
        assert!(!paths.manifest.exists());
        std::fs::write(&binary, "unrelated executable").unwrap();
        assert!(install_linux(&paths, &binary, "root", &source).is_err());
        assert_eq!(std::fs::read(&binary).unwrap(), b"unrelated executable");
        std::fs::remove_file(&binary).unwrap();
        install_linux(&paths, &binary, "root", &source).unwrap();
        install_linux(&paths, &binary, "root", &source).unwrap();
        let manifest = std::fs::read(&paths.manifest).unwrap();
        std::fs::write(&source, "upgraded executable").unwrap();
        std::fs::write(&fail, "fail once").unwrap();
        assert!(install_linux(&paths, &binary, "root", &source).is_err());
        assert_eq!(std::fs::read(&binary).unwrap(), b"first executable");
        assert_eq!(std::fs::read(&paths.manifest).unwrap(), manifest);
        assert!(paths.query("is-enabled").unwrap());
        assert!(paths.query("is-active").unwrap());
        std::fs::write(paths.units.join(LINUX_SERVICE), "unrelated").unwrap();
        assert!(uninstall_linux(&paths).is_err());
        let (service, _) = linux_units(&binary, "root", 0).unwrap();
        std::fs::write(paths.units.join(LINUX_SERVICE), service).unwrap();
        uninstall_linux(&paths).unwrap();
        assert!(!binary.exists());
        assert!(!paths.manifest.exists());
        let calls = std::fs::read_to_string(log).unwrap();
        assert!(calls.contains("enable --now tunmux-privileged.socket"));
        assert!(!calls.contains("enable --now tunmux-privileged.service"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plist_escapes_arguments_and_uses_named_socket() {
        let text = daemon_plist(Path::new("/Library/a&b/tunmux"), "admin", 80);
        assert!(text.contains("a&amp;b"));
        assert!(text.contains("<key>PrivilegedListener</key>"));
        assert!(text.contains("<integer>432</integer>"));
        assert!(text.contains("<key>SockPathGroup</key>\n            <integer>80</integer>"));
        assert!(!text.contains("--detach"));
    }
}
