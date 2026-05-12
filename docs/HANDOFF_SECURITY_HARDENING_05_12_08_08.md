# Handoff: ChronicleVM Security Hardening and Host SDK

**Created:** 2026-05-12 08:08:44 EDT  
**Branch:** main  
**Session Duration:** Multi-session work across May 10-12, 2026

---

## Summary

ChronicleVM has been advanced from a trace/replay VM prototype into a more complete safe-plugin runtime: typed capabilities, time-travel trace debugging, a web viewer, Rust embedding support, and security hardening are now implemented. The latest CI issue was fixed by bounding untrusted binary module lengths so malformed `.cmod` inputs return structured decode errors instead of attempting huge allocations.

---

## Work Completed

### Changes Made

- [x] Added embeddable Rust host SDK with `CapabilityHost`, `HostRegistry`, and `Vm::new_with_host`.
- [x] Added `chronicle-embed-demo` crate and `examples/embedded-plugin.chr`.
- [x] Added security threat model documentation in `docs/security.md`.
- [x] Added malicious plugin demo stopped by instruction-budget resource limits.
- [x] Expanded verifier, resource-limit, host SDK, and malformed binary tests.
- [x] Fixed CI memory abort by bounding binary list/string lengths in the decoder.

### Key Decisions

| Decision | Rationale | Alternatives Considered |
| --- | --- | --- |
| Keep CLI behavior on built-in host while adding `Vm::new_with_host` | Avoid breaking demos while enabling real embedding | Replace all VM construction with explicit host plumbing |
| Use deterministic malformed-input smoke tests | CI-friendly and catches panic/abort regressions | Full fuzzing infrastructure, deferred |
| Bound binary lengths in the reader | Untrusted length fields must not drive huge allocations | Rely on truncation checks after allocation, which caused CI abort |
| Document non-goals clearly | Keeps sandbox claims defensible | Overclaiming OS/native isolation |

---

## Files Affected

### Created

- `crates/chronicle-embed-demo/Cargo.toml` - workspace crate for embedding demo.
- `crates/chronicle-embed-demo/src/main.rs` - example Rust app registering custom host capabilities.
- `crates/chronicle-embed-demo/tests/embed_demo.rs` - verifies demo writes replayable trace.
- `examples/embedded-plugin.chr` - plugin using `kv.*` and `audit.emit@1` custom capabilities.
- `examples/embedded-policy.toml` - policy for embedded plugin.
- `docs/security.md` - threat model, security boundaries, non-goals, failure behavior.
- `examples/malicious-plugin.chr` - runaway plugin stopped by resource limits.
- `docs/HANDOFF_SECURITY_HARDENING_05_12_08_08.md` - this handoff.

### Modified

- `crates/chronicle-core/src/lib.rs` - host SDK, host-aware negotiation, custom capability routing, replay safety tests, malformed binary tests, resource-limit tests, decoder length bounds.
  - Important symbols: `CapabilityHost`, `HostRegistry`, `Vm::new_with_host`, `HostPolicy::negotiate_with_host`, `MAX_BINARY_LIST_ITEMS`, `MAX_BINARY_STRING_BYTES`, `BinaryModuleReader::read_many`, `BinaryModuleReader::read_string`.
- `crates/chronicle-cli/tests/cli.rs` - added malicious plugin resource-limit integration test.
- `README.md` - added embedding docs, security demo, and security model link.
- `docs/capabilities.md` - added embedding host API notes.
- `Cargo.toml` / `Cargo.lock` - added `chronicle-embed-demo` workspace crate.

### Read (Reference)

- `.github/workflows/ci.yml` - verified CI runs fmt, clippy, tests, and benchmark build.
- `docs/verifier.md`, `docs/trace-replay.md`, `docs/benchmarks.md` - referenced for current project docs shape.
- `examples/audit-plugin.chr`, `examples/audit-policy.toml` - reference flagship demo style.

### Deleted

- None.

---

## Technical Context

### Architecture/Design Notes

ChronicleVM now has two VM construction paths: `Vm::new(module, policy)` uses `HostRegistry::with_builtins()` for existing CLI flows, while `Vm::new_with_host(module, policy, host)` lets Rust apps register custom typed capabilities. Replay still uses recorded `CapabilityTrace` values and never calls live host handlers.

Malformed binary decoding is intentionally conservative. `BinaryModuleReader::read_many` rejects list lengths over `1_000_000`, and `read_string` rejects strings over `16 MiB`. This prevents mutated length fields from causing massive allocations before an error can be returned.

### Dependencies

- No new external dependencies beyond existing workspace dependencies.
- Added internal workspace crate: `chronicle-embed-demo`.

### Configuration Changes

- `.gitignore` already ignores `/target/` and `*.ctrace`.
- CI config unchanged; new tests run under normal `cargo test`.

---

## Things to Know

### Gotchas & Pitfalls

- The CI failure was not a Rust panic; it was process abort from allocator failure after `Vec::with_capacity(len)` trusted a mutated length.
- `.cmod` decoding currently falls back to JSON for non-CHVMOD magic. Bad random bytes return `ChronicleError::Decode` through JSON parsing.
- `run_with_trace` records runtime/resource errors in the trace, but some pre-execution failures produce no events.
- Host SDK tests intentionally prove replay does not call custom handlers.

### Assumptions Made

- Rust embedding comes before JS/Python/FFI bindings.
- Deterministic smoke fuzzing is sufficient for this milestone.
- Security docs should be explicit that ChronicleVM is not OS isolation or native-code sandboxing.

### Known Issues

- No full cargo-fuzz/libFuzzer setup yet.
- No release packaging or binary distribution workflow yet.
- Commit author identity is auto-configured from machine hostname; Git has warned about setting global name/email.

---

## Current State

### What's Working

- Host SDK and embed demo work.
- Time-travel trace/debug/viewer flow works.
- Security hardening tests pass locally.
- CI memory-abort cause is fixed in committed change `715e05c Bound binary module lengths`.

### What's Not Working

- No known failing local checks at handoff time.
- No running dev server or watcher is required.

### Tests

- [x] Unit tests: `cargo test` passing.
- [x] Integration tests: CLI and embed demo tests passing.
- [x] Manual testing: malicious plugin returns `resource limit exceeded: instruction budget exceeded max 25`.
- [x] Static checks: `cargo fmt --check` and clippy passing.
- [x] Benchmark build: `cargo bench -p chronicle-cli --no-run` passing.

---

## Next Steps

### Immediate (Start Here)

1. Run `git status --short --branch` and confirm only this handoff file is uncommitted, if anything.
2. Push `main` if not already pushed: `git push origin main`.
3. Check GitHub Actions for the latest run and confirm `cargo test` no longer aborts on malformed binary tests.

### Subsequent

- Add optional `cargo fuzz` or `proptest`-style longer fuzzing as a separate non-CI developer command.
- Add release polish: GitHub release binaries, screenshots/GIFs, and install docs.
- Add developer tooling: `.chr` syntax highlighting or basic VS Code extension.

### Blocked On

- Nothing currently blocks continuation.

---

## Related Resources

### Documentation

- `README.md`
- `docs/security.md`
- `docs/capabilities.md`
- `docs/trace-replay.md`
- `.github/workflows/ci.yml`

### Commands to Run

```bash
git status --short --branch
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo bench -p chronicle-cli --no-run
cargo run -p chronicle-cli -- run examples/malicious-plugin.chr --policy examples/policy.toml --max-instructions 25
git push origin main
```

### Search Queries

- `rg -n "MAX_BINARY|read_many|read_string|with_capacity" crates/chronicle-core/src/lib.rs` - finds decoder length hardening.
- `rg -n "HostRegistry|CapabilityHost|new_with_host" crates` - finds embedding API.
- `rg -n "malicious|security|instruction budget" README.md docs examples crates` - finds security demo and tests.

### Open Questions

- [ ] Should full fuzzing use `cargo-fuzz`, `proptest`, or remain deterministic smoke tests for now?
- [ ] Should binary length caps become public/configurable constants?
- [ ] Should Git author identity be explicitly configured before future commits?

### Session Notes

The latest important bug was discovered by GitHub Actions after security hardening landed: a mutated binary module length caused a 35GB allocation attempt. The fix is small and targeted: reject oversized lengths before allocation and avoid `Vec::with_capacity` for untrusted lengths.

This handoff was generated at context window capacity. Start a new session and use this document as your initial context.
