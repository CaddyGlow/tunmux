use std::process::Command;

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let commit = git_commit();
    let (long, dist) = match &commit {
        Some(c) if c.release => (format!("{version} ({})", c.label), version.to_string()),
        Some(c) => (
            format!("{version} ({})", c.label),
            format!("{version}-{}", c.label),
        ),
        None => (version.to_string(), version.to_string()),
    };
    println!("cargo:rustc-env=TUNMUX_LONG_VERSION={long}");
    println!("cargo:rustc-env=TUNMUX_DIST_LABEL={dist}");
}

struct Commit {
    /// Short hash, with `-dirty` when tracked files differ from HEAD.
    label: String,
    /// HEAD is tagged `v<package version>` and the tree is clean.
    release: bool,
}

/// `None` without git or `.git` (source tarballs, Docker contexts).
fn git_commit() -> Option<Commit> {
    let hash = git(&["rev-parse", "--short", "HEAD"])?;
    // Rerun when the commit, tags or staged files change.
    let mut watched = vec![
        "HEAD".to_string(),
        "index".to_string(),
        "refs/tags".to_string(),
        "packed-refs".to_string(),
    ];
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(branch);
    }
    for path in watched {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", &path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let tagged = git(&["tag", "--points-at", "HEAD"]).is_some_and(|t| t.lines().any(|l| l == tag));
    Some(Commit {
        label: if dirty { format!("{hash}-dirty") } else { hash },
        release: tagged && !dirty,
    })
}

/// Trimmed stdout of a successful, non-empty git command.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}
