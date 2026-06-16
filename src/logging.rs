use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Once, OnceLock};

use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::time::UtcTime;

const LOG_TIMESTAMP_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
const DEBUG_ENV: &str = "TUNMUX_DEBUG";

fn level_from_env_or_default(default: LevelFilter) -> LevelFilter {
    if debug_enabled() {
        return LevelFilter::DEBUG;
    }
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

pub fn enable_debug() {
    std::env::set_var(DEBUG_ENV, "1");
}

pub fn debug_enabled() -> bool {
    std::env::var_os(DEBUG_ENV).is_some()
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

// --- Per-request log capture (privileged service) ------------------------------------------
//
// The privileged service installs a subscriber whose writer tees every formatted log line to
// stderr *and*, while a capture is active on the current thread, into a buffer. Request handling
// is synchronous and single-threaded per connection, so a thread-local buffer cleanly scopes the
// captured lines to one request. The captured lines are then streamed back to the calling CLI.

/// Hard cap on bytes captured per request. A verbose/debug session (or unexpected helper output)
/// would otherwise grow this buffer without bound in the privileged daemon. Past the cap, capture
/// stops and a truncation marker is appended when the buffer is drained.
const MAX_CAPTURE_BYTES: usize = 256 * 1024;

struct CaptureBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}

thread_local! {
    static LOG_CAPTURE: RefCell<Option<CaptureBuffer>> = const { RefCell::new(None) };
}

/// Start capturing this thread's formatted log output into a buffer.
pub fn begin_log_capture() {
    LOG_CAPTURE.with(|cell| {
        *cell.borrow_mut() = Some(CaptureBuffer {
            bytes: Vec::new(),
            truncated: false,
        })
    });
}

/// Stop capturing and return the captured output split into lines (without trailing newlines).
pub fn take_log_capture() -> Vec<String> {
    LOG_CAPTURE
        .with(|cell| cell.borrow_mut().take())
        .map(|capture| {
            let mut lines: Vec<String> = String::from_utf8_lossy(&capture.bytes)
                .lines()
                .map(str::to_string)
                .collect();
            if capture.truncated {
                lines.push("(log capture truncated)".to_string());
            }
            lines
        })
        .unwrap_or_default()
}

/// Writer that always writes to stderr and, when a capture is active on this thread, also appends
/// to the thread-local capture buffer.
struct ServiceWriter;

impl Write for ServiceWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stderr().write_all(buf);
        LOG_CAPTURE.with(|cell| {
            if let Some(capture) = cell.borrow_mut().as_mut() {
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(capture.bytes.len());
                if buf.len() <= remaining {
                    capture.bytes.extend_from_slice(buf);
                } else {
                    capture.bytes.extend_from_slice(&buf[..remaining]);
                    capture.truncated = true;
                }
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

/// Logging for the privileged service: like `init_terminal`, but its writer also captures output
/// per request so it can be streamed back to the calling CLI. ANSI is disabled so captured lines
/// are plain text.
pub fn init_service(verbose: bool) {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_ansi(false)
        .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
        .with_max_level(level)
        .with_writer(|| ServiceWriter)
        .finish();
    install_subscriber(subscriber, level);
}

/// Writer over a shared append-mode file handle. Each write is an O_APPEND syscall with no
/// userspace buffering, so log lines are durable and readable by another process immediately
/// (unlike the async `tracing_appender::non_blocking` writer used by `init_file`).
struct SharedFileWriter(Arc<File>);

impl Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Synchronous, line-durable file logging. Used by the gotatun helper so the privileged service
/// can tail its log file and stream it back to the caller without a flush race.
pub fn init_file_sync(path: &str, verbose: bool) -> anyhow::Result<()> {
    let default = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = level_from_env_or_default(default);
    let file = Arc::new(OpenOptions::new().create(true).append(true).open(path)?);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_timer(UtcTime::new(LOG_TIMESTAMP_FORMAT))
        .with_max_level(level)
        .with_writer(move || SharedFileWriter(file.clone()))
        .finish();
    install_subscriber(subscriber, level);
    Ok(())
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
