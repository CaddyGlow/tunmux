use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Compile the production setup into a standalone executable: the standard test
// harness creates threads, which makes calling fork-based daemonization unsafe.
#[path = "../src/userspace_helper/daemon.rs"]
mod daemon;

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        // Removing the directory also releases the detached test daemon.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn child(directory: &Path) {
    let daemon =
        daemon::helper_daemon(daemon::open_helper_log(&directory.join("helper.log")).unwrap())
            .unwrap();
    // SAFETY: this branch runs immediately after exec, before creating a runtime
    // or any threads. Unlike a #[test] function, main has no test harness.
    match unsafe { daemon.execute() } {
        daemonize2::Outcome::Parent(result) => {
            result.unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !directory.join("ready").exists() {
                assert!(Instant::now() < deadline, "daemon did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        daemonize2::Outcome::Child(result) => {
            result.unwrap();
            println!("daemon stdout marker");
            eprintln!("daemon stderr marker");
            std::fs::write(directory.join("ready"), std::process::id().to_string()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while directory.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

async fn test_captured_pipes() {
    let directory = TestDirectory(std::env::temp_dir().join(format!(
        "tunmux-daemon-stdio-{:032x}",
        rand::random::<u128>()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--daemon-child")
            .arg(&directory.0)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("launcher must close both captured pipes before the daemon stops")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let pid = std::fs::read_to_string(directory.0.join("ready"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).unwrap();
    let log_path = directory.0.join("helper.log");
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("daemon stdout marker"));
    assert!(log.contains("daemon stderr marker"));
    assert_eq!(
        std::fs::metadata(log_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == "--daemon-child") {
        child(Path::new(args.get(2).expect("missing test directory")));
        return;
    }
    // Honor Cargo's common filtering flags without skipping --nocapture runs.
    const TEST_NAME: &str = "test_captured_pipes";
    if args.iter().any(|arg| arg == "--list") {
        println!("{TEST_NAME}: test");
        return;
    }
    if args.iter().any(|arg| arg == "--ignored")
        || args
            .iter()
            .skip(1)
            .filter_map(|arg| arg.to_str())
            .any(|arg| !arg.starts_with('-') && !TEST_NAME.contains(arg))
    {
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test_captured_pipes());
}
