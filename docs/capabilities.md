# Capability Model

ChronicleVM modules do not access host powers directly. They declare versioned,
typed capabilities, and the host policy negotiates a concrete decision before
execution.

## Embedding Host API

Rust embedders use `HostRegistry` to expose app-owned capabilities. A registry
entry includes the same versioned ID and typed signature that appears in the
plugin manifest, plus a handler closure:

```rust
host.insert(
    CapabilityDecl {
        id: "kv.get@1".into(),
        params: vec![ValueType::String],
        return_type: ValueType::Any,
        reason: Some("read app-owned plugin state".into()),
    },
    |args| Ok(Value::Nil),
)?;
```

`HostRegistry::with_builtins()` registers `log.print@1`, `clock.now@1`, and
`random.u64@1`. Apps can add their own namespaces, such as `kv.*` or
`audit.*`, and then construct the VM with `Vm::new_with_host(module, policy,
host)`.

Negotiation is host-aware: a granted capability succeeds only when the host
registry contains the exact declared ID, parameter types, and return type.
Mocks are validated against the declared return type. Denied, missing, unknown,
or type-invalid capabilities fail before plugin execution.

During tracing, granted host handlers are called and their returned values are
recorded in the trace. During replay, ChronicleVM consumes the recorded
capability events and never calls the host registry.

## Manifest

Assembly:

```asm
.cap log.print@1(any...) -> nil reason="emit audit line"
.cap clock.now@1() -> i64 reason="timestamp plugin execution"
```

High-level source:

```text
cap log.print@1(any...) -> nil "emit audit line"
cap clock.now@1() -> i64 "timestamp plugin execution"
```

Supported value types are `nil`, `bool`, `i64`, `f64`, `string`, `array`,
`function`, `capability`, `any`, and final-position `any...`.

## Policy

```toml
[capabilities."clock.now@1"]
decision = "mock"
mock = 1800000000
```

Decisions are `grant`, `deny`, and `mock`. Mock values must match the declared
return type.

## Negotiation

`chronicle negotiate module.chr --policy policy.toml` reports every declared
capability as granted, mocked, denied, unknown, or type-invalid. `run` and
`trace` fail before execution unless all declared capabilities are granted or
mocked.

## Audit Trail

Trace events record capability ID, decision, arguments, and returned value.
`chronicle inspect` includes a capability summary with total calls and
granted/mocked counts.
