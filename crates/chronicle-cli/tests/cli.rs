use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn chronicle() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chronicle"))
}

#[test]
fn negotiate_reports_mocked_capabilities() {
    let root = repo_root();
    let output = chronicle()
        .arg("negotiate")
        .arg(root.join("examples/plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/plugin-mock.toml"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("clock.now@1 Mocked"));
    assert!(stdout.contains("random.u64@1 Mocked"));
}

#[test]
fn trace_inspect_and_replay_work() {
    let root = repo_root();
    let trace =
        std::env::temp_dir().join(format!("chronicle-cli-test-{}.ctrace", std::process::id()));
    let trace_output = chronicle()
        .arg("trace")
        .arg(root.join("examples/plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/plugin-mock.toml"))
        .arg("--out")
        .arg(&trace)
        .output()
        .unwrap();
    assert!(trace_output.status.success());

    let inspect = chronicle().arg("inspect").arg(&trace).output().unwrap();
    assert!(inspect.status.success());
    let inspect_stdout = String::from_utf8(inspect.stdout).unwrap();
    assert!(inspect_stdout.contains("capability audit"));
    assert!(inspect_stdout.contains("checksum:"));

    let replay = chronicle().arg("replay").arg(&trace).output().unwrap();
    assert!(replay.status.success());
    let replay_stdout = String::from_utf8(replay.stdout).unwrap();
    assert!(replay_stdout.contains("replayed 8 events"));

    let debug = chronicle()
        .arg("debug")
        .arg(&trace)
        .arg("--commands")
        .arg("source;next;regs;caps;jump 7;event;quit")
        .output()
        .unwrap();
    assert!(debug.status.success());
    let debug_stdout = String::from_utf8(debug.stdout).unwrap();
    assert!(debug_stdout.contains("debugging module safe_plugin"));
    assert!(debug_stdout.contains("[1/7]"));
    assert!(debug_stdout.contains("registers:"));
    assert!(debug_stdout.contains("log.print@1"));
    assert!(debug_stdout.contains("pc=7"));
    let _ = std::fs::remove_file(trace);
}

#[test]
fn denied_policy_fails_negotiation() {
    let root = repo_root();
    let output = chronicle()
        .arg("negotiate")
        .arg(root.join("examples/plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/plugin-deny.toml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("random.u64@1 Denied"));
}

#[test]
fn audit_demo_and_resource_limit_work() {
    let root = repo_root();
    let trace = std::env::temp_dir().join(format!(
        "chronicle-audit-test-{}.ctrace",
        std::process::id()
    ));
    let output = chronicle()
        .arg("trace")
        .arg(root.join("examples/audit-plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/audit-policy.toml"))
        .arg("--out")
        .arg(&trace)
        .arg("--max-instructions")
        .arg("10000")
        .output()
        .unwrap();
    assert!(output.status.success());

    let replay = chronicle().arg("replay").arg(&trace).output().unwrap();
    assert!(replay.status.success());
    let replay_stdout = String::from_utf8(replay.stdout).unwrap();
    assert!(replay_stdout.contains("replayed"));

    let limited = chronicle()
        .arg("run")
        .arg(root.join("examples/audit-plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/audit-policy.toml"))
        .arg("--max-instructions")
        .arg("1")
        .output()
        .unwrap();
    assert!(!limited.status.success());
    let stderr = String::from_utf8(limited.stderr).unwrap();
    assert!(stderr.contains("instruction budget"));
    let _ = std::fs::remove_file(trace);
}
