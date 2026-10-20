use std::fs::File;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::Context;
use daemonize2::Daemonize;

pub(crate) fn open_helper_log(path: &std::path::Path) -> anyhow::Result<File> {
    File::options()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open helper log {}", path.display()))
        .and_then(|file| {
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "helper log must be a regular file"
            );
            Ok(file)
        })
}

pub(crate) fn helper_daemon(log: File) -> anyhow::Result<Daemonize<()>> {
    // The daemon must not keep a launcher's captured output pipes open.
    let stderr = log
        .try_clone()
        .context("failed to clone helper log descriptor")?;
    Ok(Daemonize::new()
        .working_directory("/tmp")
        .stdout(log)
        .stderr(stderr))
}
