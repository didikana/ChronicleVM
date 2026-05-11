# Security Model

ChronicleVM is a replayable sandbox runtime for safe plugins. Its security
model is based on rejecting malformed modules before execution, negotiating
host powers explicitly, bounding deterministic execution, and recording enough
trace data to audit what happened.

## Untrusted Inputs

ChronicleVM treats these inputs as untrusted:

- High-level `.chr` source.
- Assembly `.casm` source.
- Binary `.cmod` modules.
- TOML host policies.
- JSON trace files used for inspection or replay.

All executable modules must pass decoding and verification before the VM runs.
Policy negotiation also happens before execution, so denied, missing, unknown,
or type-invalid capabilities stop the run before plugin code can call them.

## Security Boundaries

- **Decoder:** rejects unsupported bytecode versions, malformed binary payloads,
  invalid tags, truncated data, and trailing bytes.
- **Verifier:** enforces register bounds, constant bounds, function references,
  arity, jump targets, source-map shape, capability declarations, and typed
  capability calls.
- **Capability negotiation:** compares the module manifest with the host policy
  and, for embedded hosts, the registered host signatures.
- **Resource limits:** bound deterministic execution with max instruction count,
  call depth, register count, and array size.
- **Trace/replay contract:** records capability invocations and returned values;
  replay consumes the trace and never calls live host capabilities.

## Non-Goals

ChronicleVM does not provide OS isolation, process sandboxing, native-code
sandboxing, cryptographic trace attestation, side-channel protection, or
defense against malicious host capability handlers. Hosts should still run
ChronicleVM inside the isolation boundary appropriate for their deployment.

## Expected Failure Behavior

Invalid input should fail by returning a structured decode, verify, policy,
runtime, resource-limit, or replay error. Malformed modules should not panic.
Programs that exceed resource limits may produce traces containing the failed
event, so the failure can still be inspected and replayed as evidence.

## Local Hardening Checks

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo bench -p chronicle-cli --no-run
```

The test suite includes deterministic malformed-module smoke tests that feed
truncated, mutated, old-version, bad-tag, and random-looking binary data into
`Module::from_bytes` and assert that decoding does not panic.
