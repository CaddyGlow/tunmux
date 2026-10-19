use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::oneshot;

use super::network::{
    cleanup_network, configure_network, reconcile_network, CleanupState, SessionLock,
};
use super::ParsedUserspaceConfig;

/// A dedicated worker owns network effects so OS commands never starve the
/// single-thread WireGuard runtime. Dropping the sender also requests cleanup.
pub(super) struct NetworkWorker {
    shutdown: mpsc::Sender<()>,
    completed: oneshot::Receiver<anyhow::Result<()>>,
}

impl NetworkWorker {
    pub(super) async fn start(
        interface: String,
        config: Option<ParsedUserspaceConfig>,
        owner: String,
        session_lock: SessionLock,
        cancel: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<Self> {
        let (shutdown, requests) = mpsc::channel();
        let (ready, startup) = oneshot::channel();
        let (finished, mut completed) = oneshot::channel();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        std::thread::Builder::new()
            .name("tunmux-network".into())
            .spawn(move || {
                let _session_lock = session_lock;
                let state = match config {
                    Some(config) => configure_network(&interface, &config, &owner, &worker_cancelled),
                    None => Ok(CleanupState::None),
                };
                let mut state = match state {
                    Ok(state) => state,
                    Err(error) => {
                        let _ = ready.send(Err(format!("{error:#}")));
                        drop(_session_lock);
                        let _ = finished.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_ok() {
                    loop {
                        // Stop/disconnect takes priority over the next reconciliation.
                        match requests.recv_timeout(Duration::from_secs(10)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if let Err(error) = reconcile_network(&mut state) {
                                    tracing::warn!(interface, error = %error, "network_reconciliation_failed");
                                }
                            }
                        }
                    }
                }
                let result = cleanup_network(&state);
                if let Err(error) = &result {
                    tracing::error!(interface, error = %error, "network_restoration_failed");
                }
                drop(_session_lock);
                let _ = finished.send(result);
            })
            .context("failed to start network worker")?;
        let startup = tokio::select! {
            biased;
            _ = cancel => Err(anyhow::anyhow!("helper startup cancelled by shutdown")),
            _ = tokio::time::sleep(Duration::from_secs(45)) => Err(anyhow::anyhow!("network startup deadline exceeded")),
            result = startup => result.context("network worker exited during setup")
                .and_then(|result| result.map_err(anyhow::Error::msg)),
        };
        match startup {
            Ok(()) => Ok(Self {
                shutdown,
                completed,
            }),
            Err(error) => {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
                let _ = shutdown.send(());
                match tokio::time::timeout(Duration::from_secs(60), &mut completed).await {
                    Ok(Ok(Ok(()))) => Err(error),
                    Ok(Ok(Err(cleanup))) => {
                        Err(error.context(format!("startup restoration: {cleanup:#}")))
                    }
                    _ => {
                        Err(error
                            .context("startup restoration incomplete; recovery journal retained"))
                    }
                }
            }
        }
    }

    pub(super) async fn stop(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        // Reconciliation and rollback each have their own bounded command
        // deadlines. On expiry the worker retains its session lock and journal
        // until it exits; the async runtime does not wait on a blocking task.
        tokio::time::timeout(Duration::from_secs(60), self.completed)
            .await
            .context("network worker cleanup exceeded 60 seconds; recovery journal retained")?
            .context("network worker exited without cleanup acknowledgment")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{Flock, FlockArg};
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_worker_stop_preserves_lifecycle_session_ownership() {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "tunmux-worker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let lock = std::sync::Arc::new(Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap());
        let lifecycle_ownership = lock.clone();
        let worker = NetworkWorker::start(
            "unused".into(),
            None,
            "test".into(),
            lock,
            std::future::pending(),
        )
        .await
        .unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
        worker.stop().await.unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
        drop(lifecycle_ownership);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let acquired = Flock::lock(contender, FlockArg::LockExclusiveNonblock).unwrap();
        drop(acquired);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn test_shutdown_during_startup_waits_for_worker_release() {
        let path =
            std::env::temp_dir().join(format!("tunmux-start-cancel-{}", rand::random::<u64>()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let lock = std::sync::Arc::new(Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap());
        let result =
            NetworkWorker::start("unused".into(), None, "test".into(), lock, async {}).await;
        assert!(result.is_err());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
        drop(lock);
        std::fs::remove_file(path).unwrap();
    }
}
