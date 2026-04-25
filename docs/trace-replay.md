# Trace and Replay Model

ChronicleVM traces are the deterministic replay contract. A live run records
enough information to re-execute the same module later without calling host
capabilities.

## Recorded Per Event

- Function name.
- Program counter.
- Source line when available.
- Opcode name.
- Register changes.
- Capability invocation ID, decision, arguments, and returned value.
- Runtime error text, if any.
- Stable event checksum.

The trace also stores the module, entry export, final result or error, and a
final checksum over the replay-relevant event stream.

## Replay Guarantees

- Replay never calls live host capabilities.
- Replay consumes recorded capability return values in order.
- Replay must produce the same instruction events, register changes, capability
  calls, result, and final checksum.
- On divergence, the first mismatching event is reported with expected and
  actual function, program counter, source line, opcode, and checksum.

## Determinism

- Mocked capabilities are deterministic by policy.
- Live capabilities such as `clock.now@1` and `random.u64@1` are nondeterministic
  while tracing, but deterministic after capture because their values are stored
  in the trace.
- Source line mappings are diagnostic metadata and must remain stable for exact
  replay equality.
