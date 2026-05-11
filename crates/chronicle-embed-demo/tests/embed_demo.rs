use chronicle_core::{Trace, Vm};
use std::process::Command;

#[test]
fn embedding_demo_writes_replayable_trace() {
    let output = Command::new(env!("CARGO_BIN_EXE_chronicle-embed-demo"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("kv.get@1 -> Granted"));
    assert!(stdout.contains("audit.emit@1 -> Granted"));
    assert!(stdout.contains("wrote /tmp/embedded-plugin.ctrace"));

    let trace_bytes = std::fs::read("/tmp/embedded-plugin.ctrace").unwrap();
    let trace: Trace = serde_json::from_slice(&trace_bytes).unwrap();
    assert_eq!(trace.module.name, "embedded_plugin");
    assert_eq!(Vm::replay(trace).unwrap().events_checked, 17);
}
