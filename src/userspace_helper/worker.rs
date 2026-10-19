use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use anyhow::Context;
use tokio::sync::oneshot;

use super::network::{
    cleanup_network, configure_network, reconcile_network_cancellable, recover_network_cancellable,
    CleanupState, SessionLock,
};
use super::ParsedUserspaceConfig;

/// A dedicated worker owns network effects so OS commands never starve the
/// single-thread WireGuard runtime. Dropping the sender also requests cleanup.
pub(super) struct NetworkWorker {
    shutdown: mpsc::Sender<()>,
    completed: oneshot::Receiver<anyhow::Result<()>>,
    cancelled: Arc<AtomicBool>,
}

// A dedicated thread keeps privileged commands away from the current-thread
// runtime. Cancellation waits for its bounded recovery to relinquish ownership.
async fn recover_on_worker(
    recover: impl FnOnce(&AtomicBool) -> anyhow::Result<SessionLock> + Send + 'static,
    cancel: impl std::future::Future<Output = ()>,
) -> anyhow::Result<SessionLock> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = cancelled.clone();
    let (finished, mut completed) = oneshot::channel();
    let span = tracing::Span::current();
    std::thread::Builder::new()
        .name("tunmux-recovery".into())
        .spawn(move || {
            let _span = span.enter();
            let _ = finished.send(recover(&worker_cancelled));
        })
        .context("failed to start recovery worker")?;
    tokio::select! {
        biased;
        _ = cancel => {},
        _ = tokio::time::sleep(Duration::from_secs(30)) => {},
        result = &mut completed => return result.context("recovery worker exited")?,
    }
    cancelled.store(true, Ordering::Release);
    // Discard a returned lock before reporting cancellation. A timed-out thread
    // keeps its own lock until its command completes; no replacement is allowed.
    let result = tokio::time::timeout(Duration::from_secs(30), completed).await;
    drop(result);
    anyhow::bail!(
        "network recovery cancelled or exceeded its deadline; retry recovery before connecting"
    )
}

impl Drop for NetworkWorker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.shutdown.send(());
    }
}

impl NetworkWorker {
    pub(super) async fn recover(
        owner: String,
        cancel: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<SessionLock> {
        recover_on_worker(
            move |cancelled| recover_network_cancellable(&owner, cancelled),
            cancel,
        )
        .await
    }

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
        let span = tracing::Span::current();
        std::thread::Builder::new()
            .name("tunmux-network".into())
            .spawn(move || {
                let _span = span.enter();
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
                let changes = crate::network_changes::NetworkChanges::start();
                let mut debounce = crate::network_changes::Debounce::new(std::time::Instant::now());
                if ready.send(Ok(())).is_ok() {
                    loop {
                        // Stop/disconnect takes priority over the next reconciliation.
                        match requests.recv_timeout(Duration::from_millis(100)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                if !debounce.due(changes.generation(), std::time::Instant::now()) { continue; }
                                if let Err(error) = reconcile_network_cancellable(&mut state, &worker_cancelled) {
                                    tracing::warn!(interface, error = %error, "network_reconciliation_failed");
                                }
                                if super::network::has_pending_gateway(&state) { debounce.confirm_soon(std::time::Instant::now()); }
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
                cancelled,
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

    pub(super) async fn stop(mut self) -> anyhow::Result<()> {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.shutdown.send(());
        // Reconciliation and rollback each have their own bounded command
        // deadlines. On expiry the worker retains its session lock and journal
        // until it exits; the async runtime does not wait on a blocking task.
        tokio::time::timeout(Duration::from_secs(60), &mut self.completed)
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

    #[tokio::test(flavor = "current_thread")]
    async fn test_recovery_does_not_starve_shutdown_and_releases_ownership() {
        let (started, running) = oneshot::channel();
        let (finished, released) = oneshot::channel();
        let (cancel, cancelled) = oneshot::channel();
        let recovery = recover_on_worker(
            move |cancelled| {
                started.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                finished.send(()).unwrap();
                anyhow::bail!("cancelled")
            },
            async {
                let _ = cancelled.await;
            },
        );
        let signal = async {
            running.await.unwrap();
            // This future must run on the same runtime while recovery is busy.
            cancel.send(()).unwrap();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(recovery, signal)
        })
        .await
        .unwrap();
        assert!(result.is_err());
        released.await.unwrap();
    }

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
