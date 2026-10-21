//! Version strings for `--version` and the dist archive names.
//!
//! The version is the workspace package version; git only adds the commit. Without git or `.git`
//! (source tarballs, Docker contexts) there is no commit.

/// The package version, e.g. `0.1.0`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What `--version` prints after the name: `0.1.0 (88a8b70)`, `0.1.0 (88a8b70-dirty)`, or `0.1.0`
/// without git.
pub const LONG_VERSION: &str = env!("TUNMUX_LONG_VERSION");

/// The version part of archive names: `0.1.0` for a clean checkout of tag `v0.1.0` (or without
/// git), `0.1.0-88a8b70` or `0.1.0-88a8b70-dirty` otherwise.
pub const DIST_LABEL: &str = env!("TUNMUX_DIST_LABEL");
