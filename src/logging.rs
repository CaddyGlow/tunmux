use std::fs::OpenOptions;
use std::sync::OnceLock;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use time::macros::format_description;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

const LOG_TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// Resolved startup filter. Explicit directives take precedence over CLI verbosity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub filter: String,
}

static CONFIG: OnceLock<LoggingConfig> = OnceLock::new();

impl LoggingConfig {
    pub fn resolve(verbose: bool, directives: Option<&str>) -> anyhow::Result<Self> {
        let filter = directives
            .map(str::to_owned)
            .unwrap_or_else(|| format!("warn,tunmux={}", if verbose { "debug" } else { "info" }));
        EnvFilter::try_new(&filter).context("invalid logging filter")?;
        Ok(Self { filter })
    }
}

pub fn configure(verbose: bool, explicit: Option<&str>) -> anyhow::Result<()> {
    let env = std::env::var("RUST_LOG").ok();
    let config = LoggingConfig::resolve(verbose, explicit.or(env.as_deref()))?;
    CONFIG
        .set(config)
        .map_err(|_| anyhow::anyhow!("logging configuration already installed"))
}

pub fn current_config() -> LoggingConfig {
    CONFIG.get().cloned().unwrap_or_else(|| LoggingConfig {
        filter: std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,tunmux=info".into()),
    })
}

/// Carry the resolved filter as an argument so sudo environment filtering cannot lose it.
pub fn apply_to_command(command: &mut std::process::Command) {
    command.args(forwarded_args());
}

/// CLI arguments that carry the current logging configuration to a child process.
#[must_use]
pub fn forwarded_args() -> [String; 2] {
    ["--log-filter".to_string(), current_config().filter]
}

/// Keep this in the process's main scope so queued file events flush on return.
#[must_use]
pub struct LoggingGuard {
    _worker: Option<WorkerGuard>,
}

fn filter(verbose: bool) -> anyhow::Result<EnvFilter> {
    let config = if let Some(config) = CONFIG.get() {
        config.clone()
    } else {
        LoggingConfig::resolve(verbose, std::env::var("RUST_LOG").ok().as_deref())?
    };
    EnvFilter::try_new(config.filter).context("invalid logging filter")
}

pub fn init_terminal(verbose: bool) -> anyhow::Result<LoggingGuard> {
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(std::io::stderr());
    tracing_subscriber::registry()
        .with(filter(verbose)?)
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
                .with_writer(writer),
        )
        .try_init()
        .context("failed to initialize terminal logging")?;
    Ok(LoggingGuard {
        _worker: Some(guard),
    })
}

pub fn init_file(path: &str, verbose: bool) -> anyhow::Result<LoggingGuard> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log file {path}"))?;
    // Lossy bounded queues ensure slow output never blocks VPN teardown.
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(file);
    tracing_subscriber::registry()
        .with(filter(verbose)?)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
                .with_writer(writer),
        )
        .try_init()
        .context("failed to initialize file logging")?;
    Ok(LoggingGuard {
        _worker: Some(guard),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_filter_overrides_verbose_default() {
        let config = LoggingConfig::resolve(true, Some("tunmux=debug,gotatun=warn")).unwrap();
        assert_eq!(config.filter, "tunmux=debug,gotatun=warn");
    }

    #[test]
    fn test_default_keeps_dependencies_quiet() {
        assert_eq!(
            LoggingConfig::resolve(true, None).unwrap().filter,
            "warn,tunmux=debug"
        );
        assert_eq!(
            LoggingConfig::resolve(false, None).unwrap().filter,
            "warn,tunmux=info"
        );
    }

    #[test]
    fn test_spawn_filter_is_explicit_and_target_aware() {
        let mut command = std::process::Command::new("tunmux");
        apply_to_command(&mut command);
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(arguments[0], "--log-filter");
        assert_eq!(arguments[1], current_config().filter.as_str());
    }

    #[test]
    fn test_owned_guard_flushes_queued_events() {
        #[derive(Clone)]
        struct Output(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Output(Default::default());
        let (writer, worker) = tracing_appender::non_blocking(output.clone());
        let guard = LoggingGuard {
            _worker: Some(worker),
        };
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(writer)
            .finish();
        tracing::subscriber::with_default(subscriber, || tracing::info!("flush_marker"));
        drop(guard);
        let bytes = output.0.lock().unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("flush_marker"));
    }

    #[test]
    fn test_invalid_filter_is_reported() {
        assert!(LoggingConfig::resolve(false, Some("tunmux=not_a_level")).is_err());
    }
}
