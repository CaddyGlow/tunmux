#![cfg(all(feature = "wgconf", not(target_os = "android")))]
use std::path::PathBuf;
use std::process::Command;
use tunmux_cli::cli::autoconnect::connection_spec;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = PathBuf::from(format!("/tmp/tma-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(p.join("tunmux/connections")).unwrap();
        Self(p)
    }
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_tunmux"));
        c.env("XDG_CONFIG_HOME", &self.0);
        c.env_remove("TUNMUX_DESIRED_ENTRY");
        c.env_remove("RUST_LOG");
        c
    }
    fn desired(&self) -> PathBuf {
        self.0.join("tunmux/desired.json")
    }
    fn profile(&self) -> PathBuf {
        let path = self.0.join("fixture.conf");
        std::fs::write(
            &path,
            "invalid profile; these tests must never start a device",
        )
        .unwrap();
        path
    }
    fn seed(&self) {
        let path = self.profile();
        let spec = connection_spec(&[
            "connect".into(),
            "wgconf".into(),
            "--file".into(),
            path.to_str().unwrap().into(),
            "--backend".into(),
            "userspace".into(),
        ])
        .unwrap();
        let desired = serde_json::json!({"version":1,"entries":{"work":{"spec":spec,"suspended":false,"generation":4,"instance":"_direct","failure":"retry exhausted","failures":7,"blocked":true}}});
        std::fs::write(self.desired(), serde_json::to_vec(&desired).unwrap()).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn disconnect_suspends_absent_desired_session_and_explicit_resume_resets_failures() {
    let f = Fixture::new();
    f.seed();
    let output = f
        .command()
        .args(["disconnect", "_direct"])
        .output()
        .unwrap();
    assert!(!output.status.success()); // absent observed state, but suspension must persist first
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.desired()).unwrap()).unwrap();
    assert_eq!(state["entries"]["work"]["suspended"], true);
    assert_eq!(state["entries"]["work"]["generation"], 5);
    assert!(f
        .command()
        .args(["autoconnect", "resume", "work"])
        .status()
        .unwrap()
        .success());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.desired()).unwrap()).unwrap();
    assert_eq!(state["entries"]["work"]["suspended"], false);
    assert_eq!(state["entries"]["work"]["blocked"], false);
    assert_eq!(state["entries"]["work"]["failures"], 0);
}
#[test]
fn controller_child_rechecks_suspension_before_any_startup() {
    let f = Fixture::new();
    f.seed();
    assert!(f
        .command()
        .args(["autoconnect", "disable", "--all"])
        .status()
        .unwrap()
        .success());
    let output = f
        .command()
        .env("TUNMUX_DESIRED_ENTRY", r#"["work",4]"#)
        .args([
            "connect",
            "wgconf",
            "--file",
            f.profile().to_str().unwrap(),
            "--if-missing",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("suspended or changed"));
    assert_eq!(
        std::fs::read_dir(f.0.join("tunmux/connections"))
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn changed_profile_has_a_different_source_identity() {
    let f = Fixture::new();
    let profile = f.profile();
    let args = vec![
        "connect".into(),
        "wgconf".into(),
        "--file".into(),
        profile.to_str().unwrap().into(),
    ];
    let a = connection_spec(&args).unwrap();
    std::fs::write(&profile, "a changed profile").unwrap();
    let b = connection_spec(&args).unwrap();
    assert!(!a.matches(&b));
}

#[test]
fn unscoped_disconnect_suspends_a_single_pending_connection() {
    let f = Fixture::new();
    f.seed();
    assert!(f.command().arg("disconnect").status().unwrap().success());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.desired()).unwrap()).unwrap();
    assert_eq!(state["entries"]["work"]["suspended"], true);
}
