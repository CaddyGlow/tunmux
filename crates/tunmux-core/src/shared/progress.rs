//! Progress lines from core operations such as connect and disconnect.
//!
//! Front-ends install a reporter once at startup; without one the lines are
//! dropped, so library callers stay silent unless they opt in.

use std::sync::OnceLock;

static REPORTER: OnceLock<fn(&str)> = OnceLock::new();

/// Install the process-wide reporter. Later calls are ignored.
pub fn set_reporter(reporter: fn(&str)) {
    let _ = REPORTER.set(reporter);
}

/// Send one line to the installed reporter, if any.
pub fn report(message: &str) {
    if let Some(reporter) = REPORTER.get() {
        reporter(message);
    }
}

/// Format and report one progress line.
#[macro_export]
macro_rules! progress {
    ($($arg:tt)*) => {
        $crate::shared::progress::report(&format!($($arg)*))
    };
}
