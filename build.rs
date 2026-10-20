use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TUNMUX_GIT_TAG");

    let build_version = std::env::var("TUNMUX_GIT_TAG")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=TUNMUX_BUILD_VERSION={build_version}");
}

/// `git describe` for builds from a checkout; source tarballs and Docker
/// contexts have no `.git` and fall back to the package version.
fn git_describe() -> Option<String> {
    let version = git(&["describe", "--tags", "--always", "--dirty"])?;
    // Rerun when the commit, tags or staged files change.
    let mut watched = vec![
        "HEAD".to_string(),
        "index".to_string(),
        "refs/tags".to_string(),
    ];
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(branch);
    }
    for path in watched {
        if let Some(path) = git(&["rev-parse", "--git-path", &path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    Some(version)
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}
