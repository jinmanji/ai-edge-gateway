//! Assert on the resolved build graph, not on optional packages recorded in Cargo.lock.
use std::process::Command;

#[test]
fn normal_build_uses_aws_lc_without_activating_ring_or_quinn_futures_io() {
    let tree = |args: &[&str]| {
        let output = Command::new(env!("CARGO"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "tree",
                "--locked",
                "--offline",
                "--prefix",
                "none",
                "--color",
                "never",
            ])
            .args(args)
            .output()
            .expect("cargo tree available in the test environment");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let build = tree(&["-e", "normal,build,dev"]);
    assert!(!build.lines().any(|line| line.starts_with("ring v")));
    let quinn = tree(&["-e", "features", "-i", "quinn"]);
    assert!(quinn.contains("quinn feature \"rustls-aws-lc-rs\""));
    assert!(!quinn.contains("quinn feature \"rustls-ring\""));
    assert!(!quinn.contains("quinn feature \"futures-io\""));
}
