# Capability Model

ChronicleVM modules do not access host powers directly. They declare versioned,
typed capabilities, and the host policy negotiates a concrete decision before
execution.

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
