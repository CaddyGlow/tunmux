use std::fs::OpenOptions;
use std::sync::{Once, OnceLock};

use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::UtcTime;

const LOG_TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

fn level_from_env_or_default(default: LevelFilter) -> LevelFilter {
    let Ok(value) = std::env::var("RUST_LOG") else {
        return default;
    };
    let lower = value.to_ascii_lowercase();
    if lower.contains("trace") {
        LevelFilter::TRACE
    } else if lower.contains("debug") {
        LevelFilter::DEBUG
    } else if lower.contains("warn") {
        LevelFilter::WARN
    } else if lower.contains("error") {
        LevelFilter::ERROR
    } else if lower.contains("off") {
        LevelFilter::OFF
    } else {
        LevelFilter::INFO
    }
}

fn to_log_level_filter(level: LevelFilter) -> log::LevelFilter {
    match level {
        LevelFilter::OFF => log::LevelFilter::Off,
        LevelFilter::ERROR => log::LevelFilter::Error,
        LevelFilter::WARN => log::LevelFilter::Warn,
        LevelFilter::INFO => log::LevelFilter::Info,
        LevelFilter::DEBUG => log::LevelFilter::Debug,
        LevelFilter::TRACE => log::LevelFilter::Trace,
    }
}

fn install_subscriber<S>(subscriber: S, level: LevelFilter)
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    static SUBSCRIBER_INIT: Once = Once::new();
    static LOG_TRACER_INIT: Once = Once::new();

    SUBSCRIBER_INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(subscriber);
    });

    LOG_TRACER_INIT.call_once(|| {
        let _ = tracing_log::LogTracer::init();
    });

    log::set_max_level(to_log_level_filter(level));
}

pub fn init_terminal(verbose: bool) {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    install_subscriber(subscriber, level);
}

pub fn init_file(path: &str, verbose: bool) -> anyhow::Result<()> {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let (writer, guard) = tracing_appender::non_blocking(file);
    static FILE_GUARD: OnceLock<WorkerGuard> = OnceLock::new();
    let _ = FILE_GUARD.set(guard);

    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
        .with_max_level(level)
        .with_writer(writer)
        .finish();
    install_subscriber(subscriber, level);
    Ok(())
}
