# Benchmarks

ChronicleVM uses Criterion benchmarks to measure overhead rather than guess.

Run:

```sh
cargo bench -p chronicle-cli
```

Build-only smoke check:

```sh
cargo bench -p chronicle-cli --no-run
```

## Categories

- Verifier overhead on a binary `.cmod`.
- `.chr` compile plus verify.
- `.casm` assemble plus verify.
- Binary `.cmod` load plus verify.
- Baseline execution without trace.
- Traced execution.
- Replay execution.
- Capability mediation with mock policy.
- Capability mediation with granted live built-ins.

The goal is not raw speed yet. The goal is to keep the tradeoffs visible:
verification cost, trace overhead, replay cost, and policy mediation cost.
