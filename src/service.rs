//! Explicit macOS service installation. No installation is performed during ordinary connects.
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::ServiceCommand;
use anyhow::Context;
use serde::{Deserialize, Serialize};

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
fn plist(args: &[String], extra: &str) -> String {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>ProgramArguments</key><array>{}</array>{extra}</dict></plist>\n", args.iter().map(|a|format!("<string>{}</string>",xml(a))).collect::<String>())
}
fn daemon_plist(binary: &Path, group: &str, gid: u32) -> String {
    plist(&[binary.to_string_lossy().into_owned(),"privileged".into(),"--serve".into(),"--authorized-group".into(),group.into()],
        &format!("<key>Label</key><string>{DAEMON_LABEL}</string><key>UserName</key><string>root</string><key>GroupName</key><string>{}</string><key>EnvironmentVariables</key><dict><key>TUNMUX_LAUNCHD_SOCKET</key><string>1</string><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict><key>Sockets</key><dict><key>PrivilegedListener</key><dict><key>SockFamily</key><string>Unix</string><key>SockType</key><string>stream</string><key>SockPathName</key><string>{}</string><key>SockPathOwner</key><integer>0</integer><key>SockPathGroup</key><integer>{gid}</integer><key>SockPathMode</key><integer>432</integer></dict></dict><key>StandardOutPath</key><string>/var/log/tunmux/privileged.log</string><key>StandardErrorPath</key><string>/var/log/tunmux/privileged.log</string>",xml(group),xml(&crate::config::privileged_socket_path().to_string_lossy())))
}
fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
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
pub fn dispatch(command: ServiceCommand) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "macos"),
        "service installation is available only on macOS"
    );
    if matches!(command, ServiceCommand::Diagnose) {
        return diagnose();
    }
    anyhow::ensure!(
        nix::unistd::Uid::effective().is_root(),
        "service changes require root; run sudo tunmux service <command>"
    );
    match command {
        ServiceCommand::Install {
            binary_path,
            authorized_group,
            user,
            config_dir,
        } => {
            anyhow::ensure!(binary_path.is_absolute(), "binary path must be absolute");
            let group = nix::unistd::Group::from_name(&authorized_group)?
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
                authorized_group: authorized_group.clone(),
                uid,
                config_dir,
            };
            let result = (|| -> anyhow::Result<()> {
                write_root(&binary_path, &std::fs::read(source)?, 0o755)?;
                write_root(
                    Path::new(PLIST),
                    daemon_plist(&binary_path, &authorized_group, group.gid.as_raw()).as_bytes(),
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
        }
        ServiceCommand::Reload => {
            let state = installation()?;
            // Suspension remains in effect if any cleanup or launchctl step fails.
            let enabled = teardown(&state)?;
            bootout()?;
            run("/bin/launchctl", &["bootstrap", "system", PLIST])?;
            for name in enabled {
                user_command(&state, &["autoconnect", "resume", &name])?;
            }
        }
        ServiceCommand::Uninstall => {
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
        }
        ServiceCommand::Diagnose => unreachable!(),
    }
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
    let text=plist(&[binary.to_string_lossy().into_owned(),"autoconnect".into(),"run".into()],&format!("<key>Label</key><string>{AGENT_LABEL}</string><key>EnvironmentVariables</key><dict><key>XDG_CONFIG_HOME</key><string>{}</string><key>TUNMUX_NONINTERACTIVE</key><string>1</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer><key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>",xml(&crate::config::app_config_dir().parent().context("configuration directory missing parent")?.to_string_lossy()),xml(&logs.to_string_lossy()),xml(&logs.to_string_lossy())));
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plist_escapes_arguments_and_uses_named_socket() {
        let text = daemon_plist(Path::new("/Library/a&b/tunmux"), "admin", 80);
        assert!(text.contains("a&amp;b"));
        assert!(text.contains("<key>PrivilegedListener</key>"));
        assert!(text.contains("<integer>432</integer>"));
        assert!(text.contains("<key>SockPathGroup</key><integer>80</integer>"));
        assert!(!text.contains("--detach"));
    }
}
