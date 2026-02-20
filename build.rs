fn main() {
    println!("cargo:rerun-if-env-changed=TUNMUX_GIT_TAG");

    let build_version = std::env::var("TUNMUX_GIT_TAG")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=TUNMUX_BUILD_VERSION={build_version}");
}
