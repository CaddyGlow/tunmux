//! Double-fork daemonization for the hidden daemon subcommands.

/// What a daemonized process keeps from its launcher's stdout/stderr.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OutputPolicy {
    /// Redirect both to /dev/null.
    Discard,
    /// Keep terminals and log files; redirect pipes and sockets, which would
    /// otherwise keep the launcher waiting for EOF.
    KeepTerminalAndFiles,
}

/// Double-fork daemonize.
pub fn daemonize(output: OutputPolicy) -> anyhow::Result<()> {
    use nix::unistd::{fork, setsid, ForkResult};
    use std::os::fd::AsFd;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("first fork failed: {}", e),
    }

    setsid().map_err(|e| anyhow::anyhow!("setsid failed: {}", e))?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(ForkResult::Child) => {}
        Err(e) => anyhow::bail!("second fork failed: {}", e),
    }

    let devnull = std::fs::File::open("/dev/null")?;
    nix::unistd::dup2_stdin(&devnull)?;
    let keep = |fd: std::os::fd::BorrowedFd<'_>| {
        output == OutputPolicy::KeepTerminalAndFiles && keeps_output(fd)
    };
    if !keep(std::io::stdout().as_fd()) {
        nix::unistd::dup2_stdout(&devnull)?;
    }
    if !keep(std::io::stderr().as_fd()) {
        nix::unistd::dup2_stderr(&devnull)?;
    }

    Ok(())
}

fn keeps_output(fd: std::os::fd::BorrowedFd<'_>) -> bool {
    use std::io::IsTerminal;
    if fd.is_terminal() {
        return true;
    }
    fd.try_clone_to_owned()
        .map(std::fs::File::from)
        .and_then(|file| file.metadata())
        .is_ok_and(|meta| meta.is_file())
}
