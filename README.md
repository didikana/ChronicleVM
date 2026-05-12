# ChronicleVM

ChronicleVM is a Rust safe-plugin runtime built around one idea: plugin
execution should be bounded, inspectable, and replayable.

It includes a bytecode VM, high-level `.chr` language, typed capability
negotiation, deterministic trace/replay, time-travel debugging, a browser trace
viewer, an embeddable Rust host SDK, and security hardening for malformed input
and runaway plugins.

[![CI](https://github.com/didikana/ChronicleVM/actions/workflows/ci.yml/badge.svg)](https://github.com/didikana/ChronicleVM/actions/workflows/ci.yml)

## 90-Second Quickstart

```sh
git clone https://github.com/didikana/ChronicleVM && cd ChronicleVM
cargo run -p chronicle-cli -- trace examples/audit-plugin.chr \
  --policy examples/audit-policy.toml --out /tmp/audit.ctrace
cargo run -p chronicle-cli -- audit /tmp/audit.ctrace
```

`audit: valid` confirms the trace is checksummed and replayable. Step through
every instruction event in the browser:

```sh
python3 -m http.server 4173 --directory docs
# Open http://localhost:4173/trace-viewer/ and load /tmp/audit.ctrace
```

## Why It Exists

Most plugin systems answer "did it run?" ChronicleVM answers more useful
questions:

- What host powers did the plugin request?
- Which powers were granted, mocked, or denied?
- What exactly happened at each instruction?
- Can the run be replayed without calling live host capabilities?
- Can a failure trace be preserved as evidence?

That makes ChronicleVM a systems/security project, not just a toy VM.

## Highlights

- **Typed capabilities:** plugins declare versioned host powers such as
  `clock.now@1`, `random.u64@1`, or app-owned capabilities like `kv.get@1`.
- **Policy negotiation:** hosts grant, deny, or mock capabilities before any
  plugin bytecode runs.
- **Deterministic trace/replay:** traces record instruction events, register
  changes, source lines, capability calls, results, errors, and checksums.
- **Trace audit:** `chronicle audit` validates full traces by replaying them and
  reports module/policy digests, limits, capability counts, result, or error.
- **Time-travel debugging:** step forward/backward, jump to events, inspect
  reconstructed state, diff event ranges, and slice traces.
- **Security hardening:** CLI sandbox limits are enabled by default, malformed
  binary modules return structured errors, and property tests exercise random
  and mutated binary inputs.
- **Embeddable host SDK:** Rust apps can register custom capability handlers and
  run plugins with `Vm::new_with_host`.
- **Static trace viewer:** a GitHub Pages-ready viewer loads `.ctrace` files
  locally in the browser.

## Demo

Run the flagship audit plugin:

```sh
cargo run -p chronicle-cli -- trace examples/audit-plugin.chr \
  --policy examples/audit-policy.toml \
  --out /tmp/audit.ctrace

cargo run -p chronicle-cli -- audit /tmp/audit.ctrace
cargo run -p chronicle-cli -- replay /tmp/audit.ctrace
cargo run -p chronicle-cli -- debug /tmp/audit.ctrace \
  --commands "source;next;regs;caps;jump 20;why;quit"
```

Open the trace viewer:

```sh
python3 -m http.server 4173 --directory docs
```

Then visit `http://localhost:4173/trace-viewer/` and open
`/tmp/audit.ctrace`.

## What The Demo Shows

The audit plugin uses mocked time/randomness, prints audit events, computes a
risk score, and returns a deterministic decision. The trace captures:

- source-correlated instruction events,
- capability calls and returned values,
- register changes,
- final result or resource-limit error,
- replay checksum,
- provenance metadata with `sha256:` module and policy digests.

Replay validates the trace without invoking live host capabilities.

## CLI

```sh
cargo run -p chronicle-cli -- verify examples/plugin.chr
cargo run -p chronicle-cli -- negotiate examples/plugin.chr --policy examples/plugin-mock.toml
cargo run -p chronicle-cli -- compile examples/plugin.chr --out /tmp/plugin.cmod
cargo run -p chronicle-cli -- run examples/plugin.chr --policy examples/plugin-mock.toml
cargo run -p chronicle-cli -- trace examples/plugin.chr --policy examples/plugin-mock.toml --out /tmp/plugin.ctrace
cargo run -p chronicle-cli -- inspect /tmp/plugin.ctrace
cargo run -p chronicle-cli -- audit /tmp/plugin.ctrace --json
cargo run -p chronicle-cli -- replay /tmp/plugin.ctrace
cargo run -p chronicle-cli -- trace-slice /tmp/plugin.ctrace --from 1 --to 3 --out /tmp/slice.ctrace
```

Install locally:

```sh
cargo install --path crates/chronicle-cli
```

## Safe Defaults

`run` and `trace` use deterministic sandbox limits by default:

- `--max-instructions 100000`
- `--max-call-depth 64`
- `--max-registers 1024`
- `--max-array-items 4096`

Override limits individually:

```sh
chronicle run examples/audit-plugin.chr --policy examples/audit-policy.toml \
  --max-instructions 10000 \
  --max-call-depth 32
```

Use `--unbounded` only when intentionally reproducing older unlimited CLI
behavior. It cannot be combined with explicit `--max-*` flags.

## Security Demo

`examples/malicious-plugin.chr` intentionally loops forever. ChronicleVM stops
it with the default instruction budget:

```sh
cargo run -p chronicle-cli -- run examples/malicious-plugin.chr \
  --policy examples/policy.toml
```

Expected result:

```text
resource limit exceeded: instruction budget exceeded max 100000
```

You can also capture a bounded failure trace and audit it:

```sh
cargo run -p chronicle-cli -- trace examples/audit-plugin.chr \
  --policy examples/audit-policy.toml \
  --max-instructions 1 \
  --out /tmp/limited.ctrace

cargo run -p chronicle-cli -- audit /tmp/limited.ctrace
```

## Embedding ChronicleVM

Rust hosts register app-owned capabilities with typed signatures and construct
the VM with `Vm::new_with_host`.

```rust
use chronicle_core::{
    CapabilityDecl, CapabilityDecision, HostPolicy, HostRegistry, Value, ValueType, Vm,
};
use std::collections::BTreeMap;

let mut host = HostRegistry::with_builtins();
host.insert(
    CapabilityDecl {
        id: "audit.emit@1".into(),
        params: vec![ValueType::AnyVariadic],
        return_type: ValueType::Nil,
        reason: Some("emit an app audit event".into()),
    },
    |args| {
        println!("audit event: {args:?}");
        Ok(Value::Nil)
    },
)?;

let policy = HostPolicy {
    decisions: BTreeMap::from([("audit.emit@1".into(), CapabilityDecision::Grant)]),
};
let mut vm = Vm::new_with_host(module, policy, host)?;
let trace = vm.run_with_trace("main")?;
```

Run the embedding demo:

```sh
cargo run -p chronicle-embed-demo
cargo run -p chronicle-cli -- audit /tmp/embedded-plugin.ctrace
cargo run -p chronicle-cli -- replay /tmp/embedded-plugin.ctrace
```

## Language Sketch

```text
module safe_plugin
cap log.print@1(any...) -> nil "emit audit line"
cap clock.now@1() -> i64 "timestamp plugin execution"

fn main
  let timestamp = cap clock.now@1()
  print("plugin started", timestamp)
  return ["ok", timestamp]
end
```

The high-level language supports functions, parameters, calls, `if`/`else`,
`while`, arrays, arithmetic, comparisons, boolean operators, capability calls,
and `print(...)` sugar for `log.print@1`.

## Why Not WASM?

WebAssembly gives you portable sandboxing. ChronicleVM gives you *inspectable*
sandboxing.

- **Per-instruction event recording** with register snapshots — WASM does not
  expose this
- **Typed capability negotiation** before execution begins, not at import time
- **Replay from a trace** without re-calling live host functions
- **CLI debugger** that steps backward through recorded events
- **Pure Rust library** — no JS runtime or browser dependency required

## Why Deterministic Replay?

"The plugin ran fine in CI" is not evidence when CI used live clocks and real
randomness.

- A production failure can be re-examined without reproducing original conditions
- `chronicle audit` checksums the trace and re-runs it, verifying the same result
- Capability values come from the recorded trace — not new calls to live hosts
- The exact inputs, decisions, and outputs are preserved as auditable evidence

## Architecture

**Execution flow:** `.chr` source → `chronicle-lang` compiler → bytecode
(`.cmod`) → verifier → VM with capability gate (bounded by sandbox limits) →
`.ctrace` trace file → `audit` / `replay` / `debug` / browser viewer.

| Crate | Purpose |
| --- | --- |
| `chronicle-core` | bytecode model, verifier, VM runtime, capabilities, trace/replay, host SDK |
| `chronicle-asm` | `.casm` assembly parser |
| `chronicle-lang` | high-level `.chr` compiler |
| `chronicle-cli` | command-line runner, debugger, audit tooling |
| `chronicle-embed-demo` | Rust embedding example with custom host capabilities |

## Documentation

- [Security model](docs/security.md)
- [Trace and replay](docs/trace-replay.md)
- [Capabilities](docs/capabilities.md)
- [Verifier](docs/verifier.md)
- [Benchmarks](docs/benchmarks.md)

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo bench -p chronicle-cli --no-run
```

The test suite covers verifier errors, resource limits, trace replay, host SDK
behavior, CLI flows, malformed binary smoke cases, and property-based malformed
input checks.
