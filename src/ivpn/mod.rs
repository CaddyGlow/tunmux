pub mod api;

#[cfg(not(target_os = "android"))]
pub mod handlers;
