# Chronicle VM

Chronicle VM is a small Rust VM for safe plugins. Its v1 identity is a
replayable sandbox: modules declare capabilities, a host policy negotiates what
they receive, and execution can be traced and replayed deterministically.
Traces preserve source line metadata from `.casm` modules, so inspection can
connect VM events back to source instructions.

## Workspace

- `chronicle-core`: bytecode model, verifier, runtime, capabilities, trace replay.
- `chronicle-asm`: text assembly parser for `.casm` modules.
- `chronicle-cli`: `chronicle` command line runner.

## Try It

```sh
cargo run -p chronicle-cli -- run examples/hello.casm --policy examples/policy.toml
cargo run -p chronicle-cli -- trace examples/clock.casm --policy examples/policy.toml --out /tmp/run.ctrace
cargo run -p chronicle-cli -- inspect /tmp/run.ctrace
cargo run -p chronicle-cli -- replay /tmp/run.ctrace
cargo run -p chronicle-cli -- verify examples/plugin.casm
cargo run -p chronicle-cli -- assemble examples/plugin.casm --out /tmp/plugin.cmod
cargo run -p chronicle-cli -- run examples/plugin.casm --policy examples/plugin-mock.toml
```

## Assembly Sketch

```asm
.module "hello"
.cap log.print reason="debug output"

.fn main r3
  const r0, "Hello from Chronicle"
  cap_call r1, log.print, r0
  ret r1
.end
```

Function headers use `.fn name rN`, where `N` is the register count and valid
registers are `r0` through `rN-1`. For callable functions, add `arity=N`.

## Policy Sketch

```toml
[capabilities]
"log.print" = "grant"
"clock.now" = "grant"
"random.u64" = { mock = 42 }
```

Any undeclared or unlisted capability is denied by default.

## Binary Modules

`chronicle assemble` writes Chronicle binary modules with a `CHVMOD1` header.
The CLI can run or verify `.casm` source modules, binary modules such as
`.cmod`, and legacy JSON module files.

## Safe Plugin Demo

`examples/plugin.casm` declares three capabilities. Run it with
`plugin-mock.toml` for deterministic host values, `plugin-grant.toml` for live
host values, or `plugin-deny.toml` to see capability negotiation fail before
execution.
