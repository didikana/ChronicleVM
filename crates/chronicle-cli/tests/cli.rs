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
    let trace_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&trace).unwrap()).unwrap();
    assert_eq!(
        trace_json["metadata"]["limits"]["max_instructions"],
        serde_json::json!(100000)
    );
    assert!(trace_json["metadata"]["module_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(trace_json["metadata"]["policy_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let inspect = chronicle().arg("inspect").arg(&trace).output().unwrap();
    assert!(inspect.status.success());
    let inspect_stdout = String::from_utf8(inspect.stdout).unwrap();
    assert!(inspect_stdout.contains("capability audit"));
    assert!(inspect_stdout.contains("checksum:"));

    let replay = chronicle().arg("replay").arg(&trace).output().unwrap();
    assert!(replay.status.success());
    let replay_stdout = String::from_utf8(replay.stdout).unwrap();
    assert!(replay_stdout.contains("replayed 8 events"));

    let audit = chronicle().arg("audit").arg(&trace).output().unwrap();
    assert!(audit.status.success());
    let audit_stdout = String::from_utf8(audit.stdout).unwrap();
    assert!(audit_stdout.contains("audit: valid"));
    assert!(audit_stdout.contains("module digest: sha256:"));

    let audit_json = chronicle()
        .arg("audit")
        .arg(&trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(audit_json.status.success());
    let audit_report: serde_json::Value = serde_json::from_slice(&audit_json.stdout).unwrap();
    assert_eq!(audit_report["valid"], serde_json::json!(true));
    assert_eq!(
        audit_report["limits"]["max_instructions"],
        serde_json::json!(100000)
    );
    assert!(
        audit_report["capabilities"]["clock.now@1"]["calls"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let debug = chronicle()
        .arg("debug")
        .arg(&trace)
        .arg("--commands")
        .arg(
            "source;next;regs;caps;jump 7;state;back 2;forward 1;diff 1 7;slice 1 3;why;event;quit",
        )
        .output()
        .unwrap();
    assert!(debug.status.success());
    let debug_stdout = String::from_utf8(debug.stdout).unwrap();
    assert!(debug_stdout.contains("debugging module safe_plugin"));
    assert!(debug_stdout.contains("[1/7]"));
    assert!(debug_stdout.contains("registers:"));
    assert!(debug_stdout.contains("log.print@1"));
    assert!(debug_stdout.contains("pc=7"));
    assert!(debug_stdout.contains("state #"));
    assert!(debug_stdout.contains("diff 1 -> 7"));
    assert!(debug_stdout.contains("slice 1..=3"));
    assert!(debug_stdout.contains("why #"));
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

    let slice = std::env::temp_dir().join(format!(
        "chronicle-audit-slice-{}.ctrace",
        std::process::id()
    ));
    let slice_output = chronicle()
        .arg("trace-slice")
        .arg(&trace)
        .arg("--from")
        .arg("15")
        .arg("--to")
        .arg("35")
        .arg("--out")
        .arg(&slice)
        .output()
        .unwrap();
    assert!(slice_output.status.success());
    let inspect_slice = chronicle().arg("inspect").arg(&slice).output().unwrap();
    assert!(inspect_slice.status.success());
    let inspect_stdout = String::from_utf8(inspect_slice.stdout).unwrap();
    assert!(inspect_stdout.contains("events: 21"));
    let slice_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&slice).unwrap()).unwrap();
    assert_eq!(
        slice_json["metadata"]["slice"]["from"],
        serde_json::json!(15)
    );
    assert_eq!(slice_json["metadata"]["slice"]["to"], serde_json::json!(35));

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

    let limited_trace = std::env::temp_dir().join(format!(
        "chronicle-limited-trace-{}.ctrace",
        std::process::id()
    ));
    let limited_trace_output = chronicle()
        .arg("trace")
        .arg(root.join("examples/audit-plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/audit-policy.toml"))
        .arg("--out")
        .arg(&limited_trace)
        .arg("--max-instructions")
        .arg("1")
        .output()
        .unwrap();
    assert!(!limited_trace_output.status.success());
    let limited_audit = chronicle()
        .arg("audit")
        .arg(&limited_trace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(limited_audit.status.success());
    let limited_report: serde_json::Value = serde_json::from_slice(&limited_audit.stdout).unwrap();
    assert_eq!(limited_report["valid"], serde_json::json!(true));
    assert!(limited_report["error"]
        .as_str()
        .unwrap()
        .contains("instruction budget"));
    let _ = std::fs::remove_file(trace);
    let _ = std::fs::remove_file(slice);
    let _ = std::fs::remove_file(limited_trace);
}

#[test]
fn malicious_demo_is_stopped_by_resource_limit() {
    let root = repo_root();
    let default_output = chronicle()
        .arg("run")
        .arg(root.join("examples/malicious-plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/policy.toml"))
        .output()
        .unwrap();
    assert!(!default_output.status.success());
    let default_stderr = String::from_utf8(default_output.stderr).unwrap();
    assert!(default_stderr.contains("instruction budget exceeded max 100000"));

    let output = chronicle()
        .arg("run")
        .arg(root.join("examples/malicious-plugin.chr"))
        .arg("--policy")
        .arg(root.join("examples/policy.toml"))
        .arg("--max-instructions")
        .arg("25")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("instruction budget"));
}
