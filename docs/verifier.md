# Verifier Spec

The verifier rejects malformed modules before execution. It is intentionally
conservative: a rejected module may be fixable, but an accepted module must not
reference impossible VM state.

## Enforced Invariants

- Module exports point to existing function indexes.
- Function names and capability IDs are unique.
- Functions have at least one register and arity never exceeds register count.
- Source maps are either empty or exactly match bytecode length.
- Register operands are in bounds for every instruction.
- Constant references are in bounds.
- Jump targets land on valid instruction indexes.
- Function calls reference existing functions and match callee arity.
- Capability calls reference declared capability IDs.
- Capability declarations are versioned, for example `clock.now@1`.
- Capability signatures have at most one variadic marker and it must be final.
- Capability calls match declared arity and known static argument types.

## Failure Classes

`VerifyErrorKind` is the structured public failure taxonomy:

- `malformed_module`
- `unsupported_bytecode_version`
- `duplicate_symbol`
- `register_out_of_bounds`
- `constant_out_of_bounds`
- `invalid_jump_target`
- `missing_export`
- `missing_callee`
- `arity_mismatch`
- `undeclared_capability`
- `capability_signature_mismatch`
- `source_map_mismatch`
- `type_mismatch`

CLI commands print concise messages, while library callers can inspect the
structured kind, function, and program counter.
