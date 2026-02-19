use std::fs::OpenOptions;
use std::sync::{Once, OnceLock};

use slog::Drain;

fn level_from_env_or_default(default: log::LevelFilter) -> log::LevelFilter {
    let Ok(value) = std::env::var("RUST_LOG") else {
        return default;
    };
    let lower = value.to_ascii_lowercase();
    if lower.contains("trace") {
        log::LevelFilter::Trace
    } else if lower.contains("debug") {
        log::LevelFilter::Debug
    } else if lower.contains("warn") {
        log::LevelFilter::Warn
    } else if lower.contains("error") {
        log::LevelFilter::Error
    } else if lower.contains("off") {
        log::LevelFilter::Off
    } else {
        log::LevelFilter::Info
    }
}

fn install_logger(logger: slog::Logger, level: log::LevelFilter) {
    static LOGGER_GUARD: OnceLock<slog_scope::GlobalLoggerGuard> = OnceLock::new();
    static STDLOG_INIT: Once = Once::new();

    if LOGGER_GUARD.get().is_none() {
        let guard = slog_scope::set_global_logger(logger);
        let _ = LOGGER_GUARD.set(guard);
    }

    STDLOG_INIT.call_once(|| {
        let _ = slog_stdlog::init();
    });
    log::set_max_level(level);
}

pub fn init_terminal(verbose: bool) {
    let default = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let level = level_from_env_or_default(default);
    let decorator = slog_term::TermDecorator::new().stderr().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!());
    install_logger(logger, level);
}

pub fn init_file(path: &str, verbose: bool) -> anyhow::Result<()> {
    let default = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let level = level_from_env_or_default(default);
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let decorator = slog_term::PlainDecorator::new(file);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!());
    install_logger(logger, level);
    Ok(())
}
