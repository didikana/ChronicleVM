# Chronicle VM

Chronicle VM is a small Rust VM for safe plugins. Its v1 identity is a
replayable sandbox: modules declare capabilities, a host policy negotiates what
they receive, and execution can be traced and replayed deterministically.
Traces preserve source line metadata from `.casm` modules, so inspection can
connect VM events back to source instructions.

Formal specs:

- [Verifier](docs/verifier.md)
- [Trace and replay](docs/trace-replay.md)
- [Capabilities](docs/capabilities.md)
- [Benchmarks](docs/benchmarks.md)

## Workspace

- `chronicle-core`: bytecode model, verifier, runtime, capabilities, trace replay.
- `chronicle-asm`: text assembly parser for `.casm` modules.
- `chronicle-lang`: high-level `.chr` language compiler.
- `chronicle-cli`: `chronicle` command line runner.

## Try It

```sh
cargo run -p chronicle-cli -- run examples/hello.casm --policy examples/policy.toml
cargo run -p chronicle-cli -- trace examples/clock.casm --policy examples/policy.toml --out /tmp/run.ctrace
cargo run -p chronicle-cli -- inspect /tmp/run.ctrace
cargo run -p chronicle-cli -- replay /tmp/run.ctrace
cargo run -p chronicle-cli -- debug /tmp/run.ctrace
cargo run -p chronicle-cli -- verify examples/plugin.casm
cargo run -p chronicle-cli -- negotiate examples/plugin.chr --policy examples/plugin-mock.toml
cargo run -p chronicle-cli -- assemble examples/plugin.casm --out /tmp/plugin.cmod
cargo run -p chronicle-cli -- compile examples/plugin.chr --emit casm --out /tmp/plugin.casm
cargo run -p chronicle-cli -- compile examples/plugin.chr --out /tmp/plugin.cmod
cargo run -p chronicle-cli -- run examples/plugin.casm --policy examples/plugin-mock.toml
cargo run -p chronicle-cli -- run examples/plugin.chr --policy examples/plugin-mock.toml
```

## 5-Minute Demo

The flagship demo is a deterministic audit plugin. It uses the high-level
language, typed capability negotiation, mocked time/randomness, tracing, replay,
CLI debugging, and the browser trace viewer.

```sh
cargo run -p chronicle-cli -- compile examples/audit-plugin.chr --out /tmp/audit.cmod
cargo run -p chronicle-cli -- negotiate /tmp/audit.cmod --policy examples/audit-policy.toml
cargo run -p chronicle-cli -- trace /tmp/audit.cmod --policy examples/audit-policy.toml --out /tmp/audit.ctrace --max-instructions 10000
cargo run -p chronicle-cli -- inspect /tmp/audit.ctrace
cargo run -p chronicle-cli -- replay /tmp/audit.ctrace
cargo run -p chronicle-cli -- debug /tmp/audit.ctrace --commands "source;next;regs;caps;jump 20;event;quit"
python3 -m http.server 4173 --directory tools/trace-viewer
```

Then visit `http://localhost:4173` and open `/tmp/audit.ctrace`.

## Assembly Sketch

```asm
.module "hello"
.cap log.print@1(any...) -> nil reason="debug output"

.fn main r3
  const r0, "Hello from Chronicle"
  cap_call r1, log.print@1, r0
  ret r1
.end
```

Function headers use `.fn name rN`, where `N` is the register count and valid
registers are `r0` through `rN-1`. For callable functions, add `arity=N`.

## Policy Sketch

```toml
[capabilities."log.print@1"]
decision = "grant"

[capabilities."clock.now@1"]
decision = "grant"

[capabilities."random.u64@1"]
decision = "mock"
mock = 42
```

Any undeclared or unlisted capability is denied by default.

## Binary Modules

`chronicle assemble` writes Chronicle binary modules with a `CHVMOD2` header.
The CLI can run or verify `.casm` source modules, binary modules such as
`.cmod`, high-level `.chr` source modules, and legacy JSON module files.

## Chronicle Language Sketch

`.chr` files are a compact high-level source format that compiles to `.casm` or
binary bytecode:

```text
module safe_plugin
cap log.print@1(any...) -> nil "emit audit line"

fn main
  let started = "plugin started"
  cap log.print@1(started)
  let result = [1, 2]
  return result
end
```

The language supports multiple functions, parameter passing, user function
calls, `if`/`else`, `while`, reassignment through `let`, literals, variables,
arrays, parenthesized expressions, boolean operators (`and`, `or`, `not`),
comparisons (`==`, `!=`, `<`, `>`, `<=`, `>=`), arithmetic with spaced operators
such as `a + b`, capability calls like `cap clock.now@1()`, and `print(...)`
sugar for `cap log.print@1(...)`.

```text
fn bump(value)
  return value + 1
end

fn main
  let i = 0
  let total = 0
  while i < 4
    let total = total + bump(i)
    let i = i + 1
  end

  if total == 10
    return "ok"
  else
    return "bad"
  end
end
```

## Benchmarks

```sh
cargo bench -p chronicle-cli
```

## Install Locally

```sh
cargo install --path crates/chronicle-cli
```

After installation, the CLI is available as `chronicle`.

## Resource Limits

`run` and `trace` accept deterministic sandbox limits:

```sh
chronicle run examples/audit-plugin.chr --policy examples/audit-policy.toml \
  --max-instructions 10000 \
  --max-call-depth 32 \
  --max-registers 256 \
  --max-array-items 1024
```

If a limit is hit during tracing, the trace records the failed event and the
resource-limit error.

## Trace Debugger

```sh
chronicle debug /tmp/plugin.ctrace
```

The interactive debugger supports `next`, `prev`, `jump N`, `regs`, `caps`,
`event`, `source`, `help`, and `quit`. For scripted use and tests:

```sh
chronicle debug /tmp/plugin.ctrace --commands "source;next;regs;caps;quit"
```

## Web Trace Viewer

Open `tools/trace-viewer/index.html` in a browser, or serve it locally:

```sh
python3 -m http.server 4173 --directory tools/trace-viewer
```

Then visit `http://localhost:4173` and drop a `.ctrace` file into the viewer.
The page also includes a built-in sample trace for quick demos.

## Safe Plugin Demo

`examples/plugin.chr` and `examples/plugin.casm` declare three capabilities. Run them with
`plugin-mock.toml` for deterministic host values, `plugin-grant.toml` for live
host values, or `plugin-deny.toml` to see capability negotiation fail before
execution.
