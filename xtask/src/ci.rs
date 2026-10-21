//! Repository checks shared by GitHub Actions, git hooks and local runs.

use std::process::Command;

use super::{capture, run, workspace_root, Result};

const CARGO_AUDIT_VERSION: &str = "0.22.2";
const RUMDL_VERSION: &str = "0.2.77";
const MARKDOWN_FILES: &[&str] = &["README.md", "AGENTS.md"];

/// `--no-default-features` selections; `none` builds with no features at all.
const FEATURE_SETS: &[&str] = &[
    "none",
    "proton",
    "airvpn,crypto-rustcrypto",
    "airvpn,crypto-aws-lc",
    "mullvad",
    "ivpn",
    "wgconf",
    "proxy",
    "proxy,wgconf",
];

/// Steps run when none are named; `docker` needs a daemon and is opt-in.
const DEFAULT_STEPS: &[&str] = &["fmt", "clippy", "test", "features", "markdown", "audit"];
const ALL_STEPS: &[&str] = &[
    "fmt", "clippy", "test", "features", "markdown", "audit", "docker",
];

const DOCKER_IMAGES: &[(&str, &str)] = &[
    ("Dockerfile", "tunmux:ci"),
    ("Dockerfile.distroless", "tunmux:ci-distroless"),
];

struct CiOptions {
    steps: Vec<String>,
    quick: bool,
    install_tools: bool,
    feature_sets: Vec<String>,
}

pub fn help() -> &'static str {
    "\
Usage: cargo xtask ci [STEP...] [OPTIONS]
       cargo xtask ci feature-sets

Steps (default: fmt clippy test features markdown audit):
  fmt        rustfmt check
  clippy     Clippy on all targets and features, warnings denied
  test       tests with default and all features
  features   Clippy and CLI tests per --no-default-features selection
  markdown   rumdl on README.md and AGENTS.md
  audit      cargo audit
  docker     build and smoke-test both container images
  all        every step, including docker

Options:
  --quick               fmt plus Clippy on default features (pre-commit)
  --feature-set <name>  limit `features` to one selection (repeatable)
  --install-tools       cargo install the pinned cargo-audit and rumdl (CI only)

`feature-sets` prints the selections as JSON for a GitHub Actions matrix."
}

pub fn main(args: &[String]) -> Result<()> {
    if args.first().map(String::as_str) == Some("feature-sets") {
        let quoted: Vec<String> = FEATURE_SETS.iter().map(|s| format!("\"{s}\"")).collect();
        println!("[{}]", quoted.join(","));
        return Ok(());
    }
    let opts = parse(args)?;
    std::env::set_current_dir(workspace_root()?).map_err(|e| format!("cannot enter root: {e}"))?;

    if opts.quick {
        step("fmt");
        fmt()?;
        step("clippy (default features)");
        return run(&mut cargo(&[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]));
    }
    for name in &opts.steps {
        step(name);
        match name.as_str() {
            "fmt" => fmt()?,
            "clippy" => clippy()?,
            "test" => test()?,
            "features" => features(&opts.feature_sets)?,
            "markdown" => markdown(opts.install_tools)?,
            "audit" => audit(opts.install_tools)?,
            "docker" => docker()?,
            other => return Err(format!("unknown ci step `{other}`")),
        }
    }
    eprintln!("[ci] all checks passed");
    Ok(())
}

fn parse(args: &[String]) -> Result<CiOptions> {
    let mut opts = CiOptions {
        steps: Vec::new(),
        quick: false,
        install_tools: false,
        feature_sets: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--quick" => opts.quick = true,
            "--install-tools" => opts.install_tools = true,
            "--feature-set" => {
                let set = iter.next().ok_or("--feature-set needs a value")?;
                if !FEATURE_SETS.contains(&set.as_str()) {
                    return Err(format!("unknown feature set `{set}`"));
                }
                opts.feature_sets.push(set.clone());
            }
            "all" => opts.steps.extend(ALL_STEPS.iter().map(|s| s.to_string())),
            flag if flag.starts_with('-') => return Err(format!("unknown option `{flag}`")),
            name if ALL_STEPS.contains(&name) => opts.steps.push(name.to_string()),
            name => return Err(format!("unknown ci step `{name}`")),
        }
    }
    if opts.steps.is_empty() {
        opts.steps = DEFAULT_STEPS.iter().map(|s| s.to_string()).collect();
    }
    Ok(opts)
}

fn step(name: &str) {
    eprintln!("[ci] {name}");
}

fn cargo(args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(args);
    cmd
}

fn fmt() -> Result<()> {
    run(&mut cargo(&["fmt", "--all", "--check"]))
}

fn clippy() -> Result<()> {
    run(&mut cargo(&[
        "clippy",
        "--locked",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ]))
}

fn test() -> Result<()> {
    run(&mut cargo(&["test", "--locked"]))?;
    run(&mut cargo(&[
        "test",
        "--locked",
        "--workspace",
        "--all-features",
    ]))
}

fn features(only: &[String]) -> Result<()> {
    for set in FEATURE_SETS {
        if !only.is_empty() && !only.iter().any(|o| o == set) {
            continue;
        }
        step(&format!("features: {set}"));
        let features = if *set == "none" { "" } else { set };
        let base = ["--locked", "--no-default-features", "--features", features];
        run(cargo(&["clippy", "--all-targets"])
            .args(base)
            .args(["--", "-D", "warnings"]))?;
        run(cargo(&["test"]).args(base).arg("cli::tests"))?;
        if set.starts_with("airvpn,") {
            run(cargo(&["test"]).args(base).arg("airvpn::crypto::tests"))?;
        }
    }
    Ok(())
}

fn markdown(install: bool) -> Result<()> {
    ensure_tool("rumdl", "rumdl", RUMDL_VERSION, install)?;
    run(Command::new("rumdl").arg("check").args(MARKDOWN_FILES))
}

fn audit(install: bool) -> Result<()> {
    ensure_tool("cargo-audit", "cargo-audit", CARGO_AUDIT_VERSION, install)?;
    run(&mut cargo(&["audit"]))
}

fn docker() -> Result<()> {
    for (dockerfile, tag) in DOCKER_IMAGES {
        step(&format!("docker: {dockerfile}"));
        run(Command::new("docker").args(["build", "--file", dockerfile, "--tag", tag, "."]))?;
        for args in [&["--version"][..], &["--help"], &["status"]] {
            run(Command::new("docker").args(["run", "--rm", tag]).args(args))?;
        }
    }
    Ok(())
}

/// Installs the pinned version when asked; otherwise only warns on drift so
/// local runs use whatever the dev shell provides.
fn ensure_tool(crate_name: &str, binary: &str, version: &str, install: bool) -> Result<()> {
    if install {
        return run(&mut cargo(&[
            "install",
            crate_name,
            "--version",
            version,
            "--locked",
        ]));
    }
    let reported = capture(Command::new(binary).arg("--version"))
        .map_err(|e| format!("{e}\n  ({crate_name} {version} is required)"))?;
    if !reported.split_whitespace().any(|word| word == version) {
        eprintln!("[ci] warning: {binary} reports `{reported}`, CI pins {version}");
    }
    Ok(())
}
