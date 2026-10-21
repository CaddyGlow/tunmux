//! Provider subcommands: argument conversion, prompts and printed output
//! around the provider logic in the library modules.

#[cfg(feature = "airvpn")]
pub mod airvpn;
#[cfg(feature = "ivpn")]
pub mod ivpn;
#[cfg(feature = "mullvad")]
pub mod mullvad;
#[cfg(feature = "proton")]
pub mod proton;
#[cfg(feature = "wgconf")]
pub mod wgconf;
