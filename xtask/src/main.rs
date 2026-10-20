//! Release builds and repository checks: `cargo xtask help`.

#[cfg(target_os = "linux")]
mod bench_wg;
mod ci;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const APP_NAME: &str = "tunmux";
const FLATPAK_APP_ID: &str = "io.tunmux.Tunmux";
const FLATHUB_REPO: &str = "https://dl.flathub.org/repo/flathub.flatpakrepo";
/// Oldest glibc the cross-built gnu binaries link against (Debian 10, RHEL 8).
const GLIBC_FLOOR: &str = "2.28";

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Builder {
    /// cargo-zigbuild, with zig as C compiler and linker.
    Zig,
    /// cargo-zigbuild for C, clang + lld against an Apple SDK for linking.
    Darwin,
    /// cargo-xwin with the MSVC CRT and Windows SDK.
    Xwin,
}

struct Target {
    triple: &'static str,
    builder: Builder,
    /// Built by the `all` selector; unsupported targets need explicit selection.
    in_all: bool,
    groups: &'static [&'static str],
}

const TARGETS: &[Target] = &[
    linux("x86_64-unknown-linux-gnu", GNU),
    linux("aarch64-unknown-linux-gnu", GNU),
    linux("x86_64-unknown-linux-musl", MUSL),
    linux("aarch64-unknown-linux-musl", MUSL),
    Target {
        triple: "x86_64-apple-darwin",
        builder: Builder::Darwin,
        in_all: true,
        groups: &["macos"],
    },
    Target {
        triple: "aarch64-apple-darwin",
        builder: Builder::Darwin,
        in_all: true,
        groups: &["macos"],
    },
    // The crate is Unix-only today (nix, std::os::unix, fd passing), so this
    // target stays opt-in until a Windows port lands.
    Target {
        triple: "x86_64-pc-windows-msvc",
        builder: Builder::Xwin,
        in_all: false,
        groups: &["windows"],
    },
];

const fn linux(triple: &'static str, groups: &'static [&'static str]) -> Target {
    Target {
        triple,
        builder: Builder::Zig,
        in_all: true,
        groups,
    }
}

const GNU: &[&str] = &["linux", "gnu"];
const MUSL: &[&str] = &["linux", "musl"];
const FLATPAK_ARCHES: &[&str] = &["x86_64", "aarch64"];

struct Options {
    selectors: Vec<String>,
    version: Option<String>,
    out_dir: PathBuf,
    cargo_args: Vec<String>,
    keep_going: bool,
    install_flatpak_deps: bool,
}

enum Job<'a> {
    Binary(&'a Target),
    Flatpak(&'static str),
}

impl Job<'_> {
    fn name(&self) -> String {
        match self {
            Job::Binary(t) => t.triple.to_string(),
            Job::Flatpak(arch) => format!("flatpak-{arch}"),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        #[cfg(target_os = "linux")]
        Some("bench-wg") => bench_wg::main(&args[1..]).map_err(|err| format!("{err:#}")),
        #[cfg(not(target_os = "linux"))]
        Some("bench-wg") => Err("bench-wg requires Linux".into()),
        Some("dist") => parse_options(&args[1..]).and_then(|opts| dist(&opts)),
        Some("ci") if args[1..].iter().any(|a| a == "-h" || a == "--help") => {
            println!("{}", ci::help());
            Ok(())
        }
        Some("ci") => ci::main(&args[1..]),
        Some("targets") => {
            print_targets();
            Ok(())
        }
        None | Some("help" | "-h" | "--help") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`; see `cargo xtask help`")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "\
Usage: cargo xtask <command>

Commands:
  bench-wg [OPTIONS]            Compare kernel WireGuard and GotaTun (Linux)
  dist [SELECTOR...] [OPTIONS]   Build and package release artifacts into dist/
  ci [STEP...] [OPTIONS]         Run repository checks (`cargo xtask ci --help`)
  targets                        List known targets and selector groups
  help                           Show this message

Selectors (default: all):
  all                 every supported target plus flatpak bundles
  linux, gnu, musl    Linux target groups
  macos, windows      platform groups (windows is not supported yet)
  flatpak             flatpak bundle for the host architecture
  flatpak-<arch>      flatpak bundle for x86_64 or aarch64
  <triple>            a single Rust target triple

Options:
  --version <label>        version label (default: git describe, else dev)
  --out <dir>              output directory (default: dist)
  --features <list>        forwarded to cargo
  --no-default-features    forwarded to cargo
  --keep-going             continue after a failed target
  --install-flatpak-deps   let flatpak-builder install the Flathub runtime
                           for the current user

Toolchain: run inside the project's Nix dev shell. Linux targets use
cargo-zigbuild; macOS targets also need clang, lld and SDKROOT pointing at a
MacOSX SDK (native cargo is used on a macOS host); Windows uses cargo-xwin.
Targets whose Rust standard library is missing are skipped under `all`."
    );
}

fn print_targets() {
    let sysroot = rust_sysroot().ok();
    for target in TARGETS {
        let std = match &sysroot {
            Some(root) if has_std(root, target.triple) => "std installed",
            Some(_) => "std missing",
            None => "std unknown",
        };
        let note = if target.in_all { "" } else { ", explicit only" };
        println!(
            "{:<32} [{}] {std}{note}",
            target.triple,
            target.groups.join(", ")
        );
    }
    for arch in FLATPAK_ARCHES {
        println!(
            "{:<32} [flatpak] bundles {arch}-unknown-linux-musl",
            format!("flatpak-{arch}")
        );
    }
}

fn parse_options(args: &[String]) -> Result<Options> {
    let mut opts = Options {
        selectors: Vec::new(),
        version: None,
        out_dir: PathBuf::from("dist"),
        cargo_args: Vec::new(),
        keep_going: false,
        install_flatpak_deps: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = |flag: &str| {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--version" => opts.version = Some(value("--version")?),
            "--out" => opts.out_dir = PathBuf::from(value("--out")?),
            "--features" => {
                let features = value("--features")?;
                opts.cargo_args.extend(["--features".into(), features]);
            }
            "--no-default-features" => opts.cargo_args.push(arg.clone()),
            "--keep-going" => opts.keep_going = true,
            "--install-flatpak-deps" => opts.install_flatpak_deps = true,
            flag if flag.starts_with('-') => return Err(format!("unknown option `{flag}`")),
            selector => opts.selectors.push(selector.to_string()),
        }
    }
    if opts.selectors.is_empty() {
        opts.selectors.push("all".into());
    }
    Ok(opts)
}

fn resolve_jobs(selectors: &[String]) -> Result<Vec<(Job<'static>, bool)>> {
    // The flag records whether a job was named explicitly, which turns a
    // missing standard library from a skip into an error.
    let mut jobs: Vec<(Job<'static>, bool)> = Vec::new();
    let mut push = |job: Job<'static>, explicit: bool| {
        if !jobs.iter().any(|(j, _)| j.name() == job.name()) {
            jobs.push((job, explicit));
        }
    };
    for selector in selectors {
        let selector = selector.as_str();
        match selector {
            "all" => {
                for target in TARGETS.iter().filter(|t| t.in_all) {
                    push(Job::Binary(target), false);
                }
                push(Job::Flatpak(host_flatpak_arch()?), false);
            }
            "flatpak" => push(Job::Flatpak(host_flatpak_arch()?), true),
            _ => {
                if let Some(arch) = selector.strip_prefix("flatpak-") {
                    let arch = FLATPAK_ARCHES
                        .iter()
                        .find(|a| **a == arch)
                        .ok_or_else(|| format!("unsupported flatpak architecture `{arch}`"))?;
                    push(Job::Flatpak(arch), true);
                    continue;
                }
                let matched: Vec<&Target> = TARGETS
                    .iter()
                    .filter(|t| t.triple == selector || t.groups.contains(&selector))
                    .collect();
                if matched.is_empty() {
                    return Err(format!(
                        "unknown selector `{selector}`; see `cargo run -p xtask -- targets`"
                    ));
                }
                let explicit = matched.len() == 1;
                for target in matched {
                    push(Job::Binary(target), explicit);
                }
            }
        }
    }
    Ok(jobs)
}

fn dist(opts: &Options) -> Result<()> {
    let root = workspace_root()?;
    env::set_current_dir(&root).map_err(|e| format!("cannot enter {}: {e}", root.display()))?;
    let version = match &opts.version {
        Some(v) => v.clone(),
        None => default_version(),
    };
    validate_version(&version)?;
    let jobs = resolve_jobs(&opts.selectors)?;
    let sysroot = rust_sysroot()?;
    let target_dir = cargo_target_dir()?;
    fs::create_dir_all(&opts.out_dir)
        .map_err(|e| format!("cannot create {}: {e}", opts.out_dir.display()))?;

    let ctx = Context {
        opts,
        version: &version,
        target_dir: &target_dir,
    };
    let mut built = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for (job, explicit) in &jobs {
        let name = job.name();
        let triple = match job {
            Job::Binary(t) => t.triple.to_string(),
            Job::Flatpak(arch) => format!("{arch}-unknown-linux-musl"),
        };
        if !has_std(&sysroot, &triple) {
            let reason = format!("Rust standard library for {triple} is not installed");
            if *explicit {
                failed.push(format!("{name}: {reason}"));
            } else {
                eprintln!("xtask: skipping {name}: {reason}");
                skipped.push(name);
            }
            continue;
        }
        eprintln!("xtask: building {name} ({version})");
        let result = match job {
            Job::Binary(target) => ctx.package_binary(target),
            Job::Flatpak(arch) => ctx.flatpak(arch),
        };
        match result {
            Ok(path) => built.push(path),
            Err(err) => {
                eprintln!("xtask: {name} failed: {err}");
                failed.push(format!("{name}: {err}"));
                if !opts.keep_going {
                    break;
                }
            }
        }
    }

    eprintln!();
    for path in &built {
        eprintln!("built    {}", path.display());
    }
    for name in &skipped {
        eprintln!("skipped  {name}");
    }
    for failure in &failed {
        eprintln!("failed   {failure}");
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{} job(s) failed", failed.len()))
    }
}

struct Context<'a> {
    opts: &'a Options,
    version: &'a str,
    target_dir: &'a Path,
}

impl Context<'_> {
    fn binary_name(&self, target: &Target) -> &'static str {
        if target.builder == Builder::Xwin {
            "tunmux.exe"
        } else {
            APP_NAME
        }
    }

    fn build(&self, target: &Target) -> Result<PathBuf> {
        let mut cmd = Command::new("cargo");
        match target.builder {
            Builder::Zig => {
                // zigbuild reads a glibc version suffix on gnu triples.
                let spec = if target.triple.contains("-gnu") {
                    format!("{}.{GLIBC_FLOOR}", target.triple)
                } else {
                    target.triple.to_string()
                };
                cmd.args(["zigbuild", "--target", &spec]);
            }
            Builder::Darwin if cfg!(target_os = "macos") => {
                cmd.args(["build", "--target", target.triple]);
            }
            Builder::Darwin => {
                let linker = self.darwin_linker(target.triple)?;
                let var = format!(
                    "CARGO_TARGET_{}_LINKER",
                    target.triple.to_uppercase().replace('-', "_")
                );
                cmd.env(var, linker);
                cmd.args(["zigbuild", "--target", target.triple]);
            }
            Builder::Xwin if cfg!(windows) => {
                cmd.args(["build", "--target", target.triple]);
            }
            Builder::Xwin => {
                cmd.args(["xwin", "build", "--target", target.triple]);
            }
        }
        cmd.args([
            "--release",
            "--locked",
            "--package",
            APP_NAME,
            "--bin",
            APP_NAME,
        ])
        .args(&self.opts.cargo_args)
        .env("TUNMUX_GIT_TAG", self.version);
        run(&mut cmd)?;
        let binary = self
            .target_dir
            .join(target.triple)
            .join("release")
            .join(self.binary_name(target));
        if !binary.is_file() {
            return Err(format!("expected binary at {}", binary.display()));
        }
        Ok(binary)
    }

    /// Writes a linker wrapper: Nix's clang wrapper injects Linux link flags,
    /// so the unwrapped compiler is used when available.
    fn darwin_linker(&self, triple: &str) -> Result<PathBuf> {
        let sdk = env::var("SDKROOT").map_err(|_| {
            "SDKROOT must point at a MacOSX SDK to cross-link macOS targets".to_string()
        })?;
        if !Path::new(&sdk).is_dir() {
            return Err(format!("SDKROOT {sdk} is not a directory"));
        }
        let clang_target = match triple {
            "aarch64-apple-darwin" => "arm64-apple-macos11",
            "x86_64-apple-darwin" => "x86_64-apple-macos10.12",
            other => return Err(format!("no clang target for {other}")),
        };
        let clang = env::var("TUNMUX_DARWIN_CLANG").unwrap_or_else(|_| unwrapped_clang());
        let dir = self.target_dir.join("xtask");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = dir.join(format!("{triple}-cc"));
        let script = format!(
            "#!/bin/sh\nexec '{clang}' --target={clang_target} -isysroot '{sdk}' -fuse-ld=lld \"$@\"\n"
        );
        fs::write(&path, script).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        make_executable(&path)?;
        Ok(path)
    }

    fn package_binary(&self, target: &Target) -> Result<PathBuf> {
        let binary = self.build(target)?;
        let name = format!("{APP_NAME}-{}-{}", self.version, target.triple);
        let stage = self.opts.out_dir.join(&name);
        if stage.exists() {
            fs::remove_dir_all(&stage)
                .map_err(|e| format!("cannot clean {}: {e}", stage.display()))?;
        }
        fs::create_dir_all(&stage)
            .map_err(|e| format!("cannot create {}: {e}", stage.display()))?;
        copy(&binary, &stage.join(self.binary_name(target)))?;
        copy(Path::new("LICENSE"), &stage.join("LICENSE"))?;
        copy(Path::new("README.md"), &stage.join("README.md"))?;
        check_linkage(target.triple, &stage.join(self.binary_name(target)))?;
        smoke_test(target, &stage.join(self.binary_name(target)), self.version)?;

        let archive = if target.builder == Builder::Xwin {
            let archive = format!("{name}.zip");
            run(Command::new("zip")
                .args(["-qr", &archive, &name])
                .current_dir(&self.opts.out_dir))?;
            archive
        } else {
            let archive = format!("{name}.tar.gz");
            run(Command::new("tar")
                .args(["-czf", &archive, &name])
                .current_dir(&self.opts.out_dir))?;
            archive
        };
        fs::remove_dir_all(&stage).map_err(|e| format!("cannot clean {}: {e}", stage.display()))?;
        write_checksum(&self.opts.out_dir, &archive)?;
        Ok(self.opts.out_dir.join(archive))
    }

    /// Wraps the static musl binary in a Flatpak bundle. The sandbox only
    /// suits rootless local-proxy mode; kernel and namespace modes need root.
    fn flatpak(&self, arch: &'static str) -> Result<PathBuf> {
        let triple = format!("{arch}-unknown-linux-musl");
        let target = TARGETS
            .iter()
            .find(|t| t.triple == triple)
            .ok_or_else(|| format!("no target definition for {triple}"))?;
        let binary = self.build(target)?;

        let work = self.target_dir.join("xtask").join("flatpak").join(arch);
        if work.exists() {
            fs::remove_dir_all(&work)
                .map_err(|e| format!("cannot clean {}: {e}", work.display()))?;
        }
        let src = work.join("src");
        fs::create_dir_all(&src).map_err(|e| format!("cannot create {}: {e}", src.display()))?;
        let manifest = src.join(format!("{FLATPAK_APP_ID}.yml"));
        copy(
            Path::new("packaging/flatpak")
                .join(format!("{FLATPAK_APP_ID}.yml"))
                .as_path(),
            &manifest,
        )?;
        copy(&binary, &src.join(APP_NAME))?;
        check_linkage(&triple, &src.join(APP_NAME))?;
        copy(Path::new("LICENSE"), &src.join("LICENSE"))?;

        let repo = work.join("repo");
        let mut builder = Command::new("flatpak-builder");
        builder
            .arg(format!("--arch={arch}"))
            .args(["--force-clean", "--disable-rofiles-fuse"])
            .arg(format!("--state-dir={}", work.join("state").display()))
            .arg(format!("--repo={}", repo.display()));
        if self.opts.install_flatpak_deps {
            run(Command::new("flatpak").args([
                "remote-add",
                "--user",
                "--if-not-exists",
                "flathub",
                FLATHUB_REPO,
            ]))?;
            builder.args(["--user", "--install-deps-from=flathub"]);
        }
        builder.arg(work.join("build")).arg(&manifest);
        run(&mut builder).map_err(|e| {
            format!(
                "{e}\n  (the org.freedesktop runtime must be installed; \
                 pass --install-flatpak-deps to install it for this user)"
            )
        })?;

        let bundle = format!("{APP_NAME}-{}-{arch}.flatpak", self.version);
        let bundle_path = self.opts.out_dir.join(&bundle);
        run(Command::new("flatpak")
            .arg("build-bundle")
            .arg(format!("--arch={arch}"))
            .arg(&repo)
            .arg(&bundle_path)
            .arg(FLATPAK_APP_ID))?;
        write_checksum(&self.opts.out_dir, &bundle)?;
        Ok(bundle_path)
    }
}

/// Linux binaries must run on stock distributions: gnu builds use the
/// distribution loader, no rpath and at most `GLIBC_FLOOR`; musl builds are
/// fully static. A binary linked by the Nix toolchain gets the loader put back.
fn check_linkage(triple: &str, exe: &Path) -> Result<()> {
    if !triple.contains("-linux-") {
        return Ok(());
    }
    let program_headers = readelf(&["-lW"], exe)?;
    let interp = program_headers.lines().find_map(|line| {
        let rest = line.split("program interpreter: ").nth(1)?;
        Some(rest.trim_end_matches(']').to_string())
    });
    if triple.contains("-musl") {
        return match interp {
            None => {
                eprintln!("xtask: {triple}: static, no loader");
                Ok(())
            }
            Some(interp) => Err(format!("{triple} is not static: loader {interp}")),
        };
    }

    let loader = distro_loader(triple)?;
    if interp.as_deref() != Some(loader) || !dynamic_entries(exe, "RPATH|RUNPATH")?.is_empty() {
        run(Command::new("patchelf")
            .args(["--set-interpreter", loader, "--remove-rpath"])
            .arg(exe))?;
    }
    let interp = readelf(&["-lW"], exe)?;
    let rpath = dynamic_entries(exe, "RPATH|RUNPATH")?;
    let needed = dynamic_entries(exe, "NEEDED")?;
    if !interp.contains(loader) || !rpath.is_empty() || needed.iter().any(|n| n.contains("/nix/")) {
        return Err(format!(
            "{triple} is still Nix-linked: rpath {rpath:?}, needed {needed:?}"
        ));
    }

    let symbols = readelf(&["-W", "--dyn-syms"], exe)?;
    let newest = symbols
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter_map(|word| word.strip_prefix("GLIBC_"))
        .filter_map(parse_version)
        .max()
        .unwrap_or_default();
    let floor = parse_version(GLIBC_FLOOR).unwrap_or_default();
    let shown = newest
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    if newest > floor {
        return Err(format!(
            "{triple} needs glibc {shown}, newer than the {GLIBC_FLOOR} floor"
        ));
    }
    eprintln!("xtask: {triple}: loader {loader}, no rpath, needs glibc >= {shown}");
    Ok(())
}

fn distro_loader(triple: &str) -> Result<&'static str> {
    match triple.split('-').next() {
        Some("x86_64") => Ok("/lib64/ld-linux-x86-64.so.2"),
        Some("aarch64") => Ok("/lib/ld-linux-aarch64.so.1"),
        _ => Err(format!("no distribution loader known for {triple}")),
    }
}

/// Values of `readelf -d` entries whose tag matches one of `tags` (`A|B`).
fn dynamic_entries(exe: &Path, tags: &str) -> Result<Vec<String>> {
    let tags: Vec<String> = tags.split('|').map(|t| format!("({t})")).collect();
    Ok(readelf(&["-dW"], exe)?
        .lines()
        .filter(|line| tags.iter().any(|t| line.contains(t.as_str())))
        .filter_map(|line| {
            let start = line.find('[')? + 1;
            let end = line.rfind(']')?;
            Some(line[start..end].to_string())
        })
        .collect())
}

fn readelf(args: &[&str], exe: &Path) -> Result<String> {
    capture(Command::new("readelf").args(args).arg(exe))
}

fn parse_version(text: &str) -> Option<Vec<u32>> {
    let parts: Vec<u32> = text
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    (!parts.is_empty()).then_some(parts)
}

fn smoke_test(target: &Target, binary: &Path, version: &str) -> Result<()> {
    let host_os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return Ok(());
    };
    let runnable = target.triple.starts_with(env::consts::ARCH) && target.triple.contains(host_os);
    if !runnable {
        return Ok(());
    }
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run {}: {e}", binary.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("{APP_NAME} {version}");
    if !output.status.success() || stdout.trim() != expected {
        return Err(format!(
            "smoke test failed: expected `{expected}`, got `{}`",
            stdout.trim()
        ));
    }
    Ok(())
}

fn write_checksum(dir: &Path, file: &str) -> Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut cmd = Command::new("shasum");
        cmd.args(["-a", "256"]);
        cmd
    } else {
        Command::new("sha256sum")
    };
    let output = cmd
        .arg(file)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("cannot run checksum tool: {e}"))?;
    if !output.status.success() {
        return Err(format!("checksum of {file} failed"));
    }
    let path = dir.join(format!("{file}.sha256"));
    fs::write(&path, &output.stdout).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| format!("cannot start {:?}: {e}", cmd.get_program()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{:?} exited with {status}", cmd.get_program()))
    }
}

fn capture(cmd: &mut Command) -> Result<String> {
    let output = cmd
        .output()
        .map_err(|e| format!("cannot start {:?}: {e}", cmd.get_program()))?;
    if !output.status.success() {
        return Err(format!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask has no parent directory".to_string())
}

fn cargo_target_dir() -> Result<PathBuf> {
    // Honour any configured target directory instead of assuming ./target.
    let metadata =
        capture(Command::new("cargo").args(["metadata", "--format-version", "1", "--no-deps"]))?;
    let key = "\"target_directory\":\"";
    let start = metadata
        .find(key)
        .map(|i| i + key.len())
        .ok_or("cargo metadata has no target_directory")?;
    let end = metadata[start..]
        .find('"')
        .ok_or("malformed cargo metadata")?;
    Ok(PathBuf::from(
        metadata[start..start + end].replace("\\\\", "\\"),
    ))
}

fn rust_sysroot() -> Result<PathBuf> {
    capture(Command::new("rustc").args(["--print", "sysroot"])).map(PathBuf::from)
}

fn has_std(sysroot: &Path, triple: &str) -> bool {
    sysroot
        .join("lib/rustlib")
        .join(triple)
        .join("lib")
        .is_dir()
}

fn host_flatpak_arch() -> Result<&'static str> {
    FLATPAK_ARCHES
        .iter()
        .copied()
        .find(|a| *a == env::consts::ARCH)
        .ok_or_else(|| {
            format!(
                "no flatpak bundle for host architecture {}",
                env::consts::ARCH
            )
        })
}

fn unwrapped_clang() -> String {
    // Nix's cc-wrapper records the real compiler in nix-support/orig-cc.
    let wrapped = capture(Command::new("sh").args(["-c", "command -v clang"])).ok();
    let orig = wrapped.as_deref().and_then(|clang| {
        let prefix = Path::new(clang).parent()?.parent()?;
        fs::read_to_string(prefix.join("nix-support/orig-cc")).ok()
    });
    match orig {
        Some(dir) => format!("{}/bin/clang", dir.trim()),
        None => "clang".to_string(),
    }
}

fn default_version() -> String {
    if let Ok(tag) = env::var("TUNMUX_GIT_TAG") {
        if !tag.trim().is_empty() {
            return tag.trim().to_string();
        }
    }
    capture(Command::new("git").args(["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|_| "dev".to_string())
}

fn validate_version(version: &str) -> Result<()> {
    let mut chars = version.chars();
    let valid_start = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let valid_rest = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid_start && valid_rest {
        Ok(())
    } else {
        Err(format!("invalid version label `{version}`"))
    }
}
