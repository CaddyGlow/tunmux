//! Elevation programs used to start the privileged daemon as root.

use std::io::IsTerminal;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use nix::unistd::Uid;

use crate::config::PrivilegedElevation;
use crate::error::{AppError, Result};

use super::util::shell_quote;

#[cfg(target_os = "macos")]
const AUTO_CANDIDATES: &[&str] = &["sudo", "osascript"];
#[cfg(not(target_os = "macos"))]
const AUTO_CANDIDATES: &[&str] = &["doas", "sudo", "run0", "pkexec"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElevatorKind {
    Sudo,
    Doas,
    Run0,
    Pkexec,
    Osascript,
    Other,
}

impl ElevatorKind {
    fn from_program(program: &Path) -> Self {
        match program.file_name().and_then(|name| name.to_str()) {
            Some("sudo") => Self::Sudo,
            Some("doas") => Self::Doas,
            Some("run0") => Self::Run0,
            Some("pkexec") => Self::Pkexec,
            Some("osascript") => Self::Osascript,
            _ => Self::Other,
        }
    }

    /// Whether the program can prompt through a graphical or polkit agent
    /// when no terminal is attached.
    fn prompts_without_tty(self) -> bool {
        matches!(self, Self::Run0 | Self::Pkexec | Self::Osascript)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prompt {
    Allowed,
    Never,
}

/// A resolved way to run the privileged daemon as root.
#[derive(Debug, Clone)]
pub(crate) enum Elevation {
    /// Run the daemon directly (already root, or elevation disabled).
    Direct,
    Program {
        program: PathBuf,
        kind: ElevatorKind,
        prompt: Prompt,
    },
}

impl Elevation {
    pub(crate) fn resolve(setting: &PrivilegedElevation) -> Result<Self> {
        let prompt = match setting {
            PrivilegedElevation::None => return Ok(Self::Direct),
            PrivilegedElevation::Program(program) => {
                return Ok(Self::Program {
                    kind: ElevatorKind::from_program(program),
                    program: program.clone(),
                    prompt: Prompt::Allowed,
                });
            }
            PrivilegedElevation::Auto => Prompt::Allowed,
            PrivilegedElevation::Passwordless => Prompt::Never,
        };

        if Uid::effective().is_root() {
            return Ok(Self::Direct);
        }

        let available: Vec<(ElevatorKind, PathBuf)> = AUTO_CANDIDATES
            .iter()
            .filter_map(|name| find_in_path(name))
            .map(|program| (ElevatorKind::from_program(&program), program))
            // osascript has no non-interactive mode.
            .filter(|(kind, _)| prompt == Prompt::Allowed || *kind != ElevatorKind::Osascript)
            .collect();
        // Without a terminal (a desktop front-end), sudo and doas cannot ask
        // for a password, so prefer a program that prompts through an agent.
        let headless = prompt == Prompt::Allowed && !std::io::stdin().is_terminal();
        let preferred = available
            .iter()
            .position(|(kind, _)| headless && kind.prompts_without_tty())
            .unwrap_or(0);
        available
            .into_iter()
            .nth(preferred)
            .map(|(kind, program)| Self::Program {
                program,
                kind,
                prompt,
            })
            .ok_or_else(|| {
                AppError::Other(format!(
                    "no elevation program found in PATH (tried {}); set general.privileged_elevation",
                    AUTO_CANDIDATES.join(", ")
                ))
            })
    }

    /// Whether a password prompt can be shown right now.
    pub(crate) fn can_prompt(&self) -> bool {
        match self {
            Self::Direct => false,
            Self::Program { kind, prompt, .. } => {
                *prompt == Prompt::Allowed
                    && (kind.prompts_without_tty() || std::io::stdin().is_terminal())
            }
        }
    }

    /// Whether the elevated process can be driven over stdin/stdout pipes.
    pub(crate) fn supports_pipes(&self) -> bool {
        !matches!(
            self,
            Self::Program {
                kind: ElevatorKind::Osascript,
                ..
            }
        )
    }

    /// Build a command that runs `exe args` as root.
    ///
    /// With `interactive` false the command never prompts; returns `None` when
    /// the program has no way to run without prompting.
    #[must_use]
    pub(crate) fn command(
        &self,
        exe: &Path,
        args: &[String],
        interactive: bool,
    ) -> Option<Command> {
        let (program, kind) = match self {
            Self::Direct => {
                let mut command = Command::new(exe);
                command.args(args);
                return Some(command);
            }
            Self::Program { program, kind, .. } => (program, *kind),
        };

        let mut command = Command::new(program);
        match kind {
            ElevatorKind::Sudo | ElevatorKind::Doas => {
                if !interactive {
                    command.arg("-n");
                }
            }
            ElevatorKind::Run0 => {
                if !interactive {
                    command.arg("--no-ask-password");
                }
                // run0 runs the command in a transient unit; keep a daemon that
                // detached from the main process alive when the unit stops.
                command.arg("--property=KillMode=process");
            }
            ElevatorKind::Pkexec | ElevatorKind::Osascript => {
                if !interactive {
                    return None;
                }
            }
            ElevatorKind::Other => {}
        }

        if kind == ElevatorKind::Osascript {
            let shell_command = std::iter::once(exe.to_string_lossy().into_owned())
                .chain(args.iter().cloned())
                .map(|arg| shell_quote(&arg))
                .collect::<Vec<_>>()
                .join(" ");
            command.arg("-e").arg(format!(
                "do shell script \"{}\" with administrator privileges",
                applescript_escape(&shell_command)
            ));
        } else {
            command.arg(exe).args(args);
        }
        Some(command)
    }

    /// Program name to show in messages, or `None` when running directly.
    #[must_use]
    pub(crate) fn display_name(&self) -> Option<String> {
        match self {
            Self::Direct => None,
            Self::Program { program, .. } => Some(program.display().to_string()),
        }
    }

    /// Prefix for the manual start command shown in error messages.
    #[must_use]
    pub(crate) fn manual_prefix(&self) -> String {
        match self {
            Self::Direct => String::new(),
            // A terminal user on macOS elevates with sudo, not osascript.
            Self::Program {
                kind: ElevatorKind::Osascript,
                ..
            } => "sudo ".to_string(),
            Self::Program { program, .. } => format!("{} ", program.display()),
        }
    }

    pub(crate) fn map_spawn_error(&self, err: std::io::Error, manual_command: String) -> AppError {
        let name = self
            .display_name()
            .unwrap_or_else(|| "privileged daemon".to_string());
        if err.kind() == std::io::ErrorKind::NotFound {
            AppError::Other(format!(
                "{} not found; set general.privileged_elevation or run: {}",
                name, manual_command
            ))
        } else {
            AppError::Other(format!("failed to execute {}: {}", name, err))
        }
    }
}

/// Run `command` to completion, killing it after `timeout`.
pub(crate) fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> std::io::Result<ExitStatus> {
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("elevation prompt timed out after {}s", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| {
            candidate
                .metadata()
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

fn applescript_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(command: &Command) -> Vec<String> {
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_elevation_commands_per_program() {
        let exe = Path::new("/opt/tunmux");
        let args = vec!["privileged".to_string(), "--serve".to_string()];
        let program = |path: &str| {
            Elevation::resolve(&PrivilegedElevation::Program(PathBuf::from(path)))
                .expect("explicit program resolves")
        };

        let sudo = program("/usr/bin/sudo");
        assert_eq!(
            args_of(&sudo.command(exe, &args, false).expect("sudo -n")),
            [
                "/usr/bin/sudo",
                "-n",
                "/opt/tunmux",
                "privileged",
                "--serve"
            ]
        );
        assert_eq!(
            args_of(&sudo.command(exe, &args, true).expect("sudo")),
            ["/usr/bin/sudo", "/opt/tunmux", "privileged", "--serve"]
        );

        let run0 = program("run0");
        assert_eq!(
            args_of(&run0.command(exe, &args, false).expect("run0")),
            [
                "run0",
                "--no-ask-password",
                "--property=KillMode=process",
                "/opt/tunmux",
                "privileged",
                "--serve"
            ]
        );

        let pkexec = program("/usr/bin/pkexec");
        assert!(pkexec.command(exe, &args, false).is_none());

        let osascript = program("/usr/bin/osascript");
        assert!(!osascript.supports_pipes());
        assert_eq!(osascript.manual_prefix(), "sudo ");
        let spaced = Path::new("/Applications/Tun Mux/tunmux");
        assert_eq!(
            args_of(&osascript.command(spaced, &args, true).expect("osascript")),
            [
                "/usr/bin/osascript",
                "-e",
                "do shell script \"'/Applications/Tun Mux/tunmux' privileged --serve\" with administrator privileges"
            ]
        );

        let direct = Elevation::resolve(&PrivilegedElevation::None).expect("none resolves");
        assert!(!direct.can_prompt());
        assert_eq!(
            args_of(&direct.command(exe, &args, false).expect("direct")),
            ["/opt/tunmux", "privileged", "--serve"]
        );
    }

    #[test]
    fn test_privileged_elevation_parses_config_values() {
        let parse = |value: &str| PrivilegedElevation::from(value.to_string());
        assert_eq!(parse("auto"), PrivilegedElevation::Auto);
        assert_eq!(parse(""), PrivilegedElevation::Auto);
        assert_eq!(parse("none"), PrivilegedElevation::None);
        assert_eq!(parse("passwordless"), PrivilegedElevation::Passwordless);
        assert_eq!(
            parse("/usr/bin/doas"),
            PrivilegedElevation::Program(PathBuf::from("/usr/bin/doas"))
        );
    }
}
