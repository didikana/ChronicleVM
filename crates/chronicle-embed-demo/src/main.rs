use anyhow::{bail, Result};
use chronicle_core::{
    CapabilityDecision, CapabilityDecl, HostPolicy, HostRegistry, Value, ValueType, Vm,
};
use chronicle_lang::Compiler;
use std::collections::BTreeMap;
use std::fs;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn main() -> Result<()> {
    let source = include_str!("../../../examples/embedded-plugin.chr");
    let compiled = Compiler::compile(source)?;
    let host = embedding_host()?;
    let policy = embedding_policy();

    let report = policy.negotiate_with_host(&compiled.module, &host);
    println!("negotiation:");
    for entry in &report.entries {
        println!("  {} -> {:?}", entry.capability, entry.status);
    }
    if !report.is_success() {
        bail!("embedding policy did not satisfy plugin manifest");
    }

    let mut vm = Vm::new_with_host(compiled.module, policy, host)?;
    let trace = vm.run_with_trace("main")?;
    if let Some(error) = &trace.error {
        bail!("plugin failed: {error}");
    }

    let replay = Vm::replay(trace.clone())?;
    let trace_path = "/tmp/embedded-plugin.ctrace";
    fs::write(trace_path, serde_json::to_vec_pretty(&trace)?)?;
    println!(
        "replayed {} events checksum {}",
        replay.events_checked, replay.trace_checksum
    );

    let capability_calls = trace
        .events
        .iter()
        .filter(|event| event.capability.is_some())
        .count();
    println!(
        "trace captured {} events and {} capability calls",
        trace.events.len(),
        capability_calls
    );
    println!("wrote {trace_path}");
    println!(
        "result {}",
        trace
            .result
            .as_ref()
            .map(render_value)
            .unwrap_or_else(|| "nil".into())
    );
    Ok(())
}

fn embedding_policy() -> HostPolicy {
    HostPolicy {
        decisions: BTreeMap::from([
            ("log.print@1".into(), CapabilityDecision::Grant),
            (
                "clock.now@1".into(),
                CapabilityDecision::Mock(Value::I64(1_900_000_000)),
            ),
            (
                "random.u64@1".into(),
                CapabilityDecision::Mock(Value::I64(77_001)),
            ),
            ("kv.get@1".into(), CapabilityDecision::Grant),
            ("kv.set@1".into(), CapabilityDecision::Grant),
            ("audit.emit@1".into(), CapabilityDecision::Grant),
        ]),
    }
}

fn embedding_host() -> Result<HostRegistry> {
    let mut host = HostRegistry::with_builtins();
    let store = Arc::new(Mutex::new(BTreeMap::<String, Value>::new()));
    let audit_count = Arc::new(AtomicUsize::new(0));

    let get_store = Arc::clone(&store);
    host.insert(
        CapabilityDecl {
            id: "kv.get@1".into(),
            params: vec![ValueType::String],
            return_type: ValueType::Any,
            reason: Some("read plugin state from the embedding app".into()),
        },
        move |args| {
            let Value::String(key) = &args[0] else {
                unreachable!("host registry validates kv.get@1 arguments")
            };
            Ok(get_store
                .lock()
                .expect("kv store lock")
                .get(key)
                .cloned()
                .unwrap_or(Value::Nil))
        },
    )?;

    let set_store = Arc::clone(&store);
    host.insert(
        CapabilityDecl {
            id: "kv.set@1".into(),
            params: vec![ValueType::String, ValueType::Any],
            return_type: ValueType::Nil,
            reason: Some("write plugin state through the embedding app".into()),
        },
        move |args| {
            let Value::String(key) = &args[0] else {
                unreachable!("host registry validates kv.set@1 arguments")
            };
            set_store
                .lock()
                .expect("kv store lock")
                .insert(key.clone(), args[1].clone());
            Ok(Value::Nil)
        },
    )?;

    host.insert(
        CapabilityDecl {
            id: "audit.emit@1".into(),
            params: vec![ValueType::AnyVariadic],
            return_type: ValueType::Nil,
            reason: Some("emit an application audit event".into()),
        },
        move |args| {
            let number = audit_count.fetch_add(1, Ordering::SeqCst) + 1;
            println!(
                "audit#{number}: {}",
                args.iter().map(render_value).collect::<Vec<_>>().join(" ")
            );
            Ok(Value::Nil)
        },
    )?;

    Ok(host)
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Bool(value) => value.to_string(),
        Value::I64(value) => value.to_string(),
        Value::F64(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(render_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Function(value) | Value::Capability(value) => value.clone(),
    }
}
