use anyhow::{anyhow, Context, Result};
use chronicle_asm::Assembler;
use chronicle_core::{
    digest_bytes, CapabilityDecision, CapabilityTraceDecision, ChronicleError, HostPolicy, Module,
    ReplayError, StateDiff, Trace, TraceCapabilityDecision, TraceMetadata, TraceNavigator,
    TraceSliceMetadata, TraceState, Value, Verifier, Vm, VmLimits,
};
use chronicle_lang::Compiler;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "chronicle")]
#[command(about = "Replayable sandbox VM for safe plugins")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Assemble {
        module: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Compile {
        source: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = CompileEmit::Binary)]
        emit: CompileEmit,
    },
    Verify {
        module: PathBuf,
    },
    Negotiate {
        module: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    Run {
        module: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value = "main")]
        entry: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Trace {
        module: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "main")]
        entry: String,
        #[command(flatten)]
        limits: LimitArgs,
    },
    Audit {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Replay {
        trace: PathBuf,
        #[arg(long)]
        verbose: bool,
    },
    Inspect {
        trace: PathBuf,
    },
    TraceSlice {
        trace: PathBuf,
        #[arg(long)]
        from: usize,
        #[arg(long)]
        to: usize,
        #[arg(long)]
        out: PathBuf,
    },
    Debug {
        trace: PathBuf,
        #[arg(long, help = "Run semicolon-separated debugger commands and exit")]
        commands: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompileEmit {
    Binary,
    Casm,
}

#[derive(Clone, Debug, Default, Args)]
struct LimitArgs {
    #[arg(long)]
    unbounded: bool,
    #[arg(long)]
    max_instructions: Option<usize>,
    #[arg(long)]
    max_call_depth: Option<usize>,
    #[arg(long)]
    max_registers: Option<usize>,
    #[arg(long)]
    max_array_items: Option<usize>,
}

impl LimitArgs {
    fn effective_limits(&self) -> Result<VmLimits> {
        if self.unbounded && self.has_explicit_limits() {
            anyhow::bail!("--unbounded cannot be combined with explicit --max-* limits");
        }
        let mut limits = if self.unbounded {
            VmLimits::default()
        } else {
            VmLimits::sandbox_defaults()
        };
        if let Some(value) = self.max_instructions {
            limits.max_instructions = Some(value);
        }
        if let Some(value) = self.max_call_depth {
            limits.max_call_depth = Some(value);
        }
        if let Some(value) = self.max_registers {
            limits.max_registers = Some(value);
        }
        if let Some(value) = self.max_array_items {
            limits.max_array_items = Some(value);
        }
        Ok(limits)
    }

    fn has_explicit_limits(&self) -> bool {
        self.max_instructions.is_some()
            || self.max_call_depth.is_some()
            || self.max_registers.is_some()
            || self.max_array_items.is_some()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Assemble { module, out } => {
            let module = load_module(&module)?;
            fs::write(&out, module.to_bytes()?)?;
            println!("wrote {}", out.display());
        }
        Command::Compile { source, out, emit } => {
            let source_text = fs::read_to_string(&source)
                .with_context(|| format!("failed to read source {}", source.display()))?;
            let compiled = Compiler::compile(&source_text)?;
            match emit {
                CompileEmit::Binary => fs::write(&out, compiled.module.to_bytes()?)?,
                CompileEmit::Casm => fs::write(&out, compiled.casm)?,
            }
            println!("wrote {}", out.display());
        }
        Command::Verify { module } => {
            let module = load_module(&module)?;
            println!(
                "verified module {}: {} functions, {} capabilities",
                module.name,
                module.functions.len(),
                module.capabilities.len()
            );
        }
        Command::Negotiate { module, policy } => {
            let module = load_module(&module)?;
            let policy = load_policy(&policy)?;
            let report = policy.negotiate(&module);
            for entry in &report.entries {
                println!(
                    "{} {:?} {:?}{}",
                    entry.capability,
                    entry.status,
                    entry.decision,
                    entry
                        .reason
                        .as_ref()
                        .map(|reason| format!(" reason={reason}"))
                        .unwrap_or_default()
                );
            }
            if !report.is_success() {
                anyhow::bail!("capability negotiation failed");
            }
        }
        Command::Run {
            module,
            policy,
            entry,
            limits,
        } => {
            let module = load_module(&module)?;
            let policy = load_policy(&policy)?;
            let mut vm = Vm::new(module, policy)?.with_limits(limits.effective_limits()?);
            let result = vm.run_entry(&entry)?;
            println!("{}", render_value(&result));
        }
        Command::Trace {
            module,
            policy,
            out,
            entry,
            limits,
        } => {
            let module = load_module(&module)?;
            let policy = load_policy_with_digest(&policy)?;
            let effective_limits = limits.effective_limits()?;
            let mut vm = Vm::new(module.clone(), policy.policy.clone())?
                .with_limits(effective_limits.clone());
            let mut trace = vm.run_with_trace(&entry)?;
            trace.metadata = Some(build_trace_metadata(
                &module,
                &policy.policy,
                Some(policy.digest),
                effective_limits,
                None,
            )?);
            fs::write(&out, serde_json::to_vec_pretty(&trace)?)?;
            if let Some(error) = trace.error {
                return Err(anyhow!("trace captured error: {error}"));
            }
            println!("wrote {}", out.display());
        }
        Command::Audit { trace, json } => {
            let trace = load_trace(&trace)?;
            let report = audit_trace(trace);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_audit_report(&report);
            }
            if !report.valid {
                anyhow::bail!(
                    "trace audit failed: {}",
                    report
                        .replay_error
                        .as_deref()
                        .unwrap_or("replay validation failed")
                );
            }
        }
        Command::Replay { trace, verbose } => {
            let trace = load_trace(&trace)?;
            match Vm::replay(trace) {
                Ok(report) => {
                    if let Some(error) = &report.error {
                        println!(
                            "replayed {} events, checksum {}, error {}",
                            report.events_checked, report.trace_checksum, error
                        );
                    } else {
                        println!(
                            "replayed {} events, checksum {}, result {}",
                            report.events_checked,
                            report.trace_checksum,
                            report
                                .result
                                .as_ref()
                                .map(render_value)
                                .unwrap_or_else(|| "nil".into())
                        );
                    }
                }
                Err(ChronicleError::Replay(error)) => {
                    print_replay_error(&error, verbose);
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Command::Inspect { trace } => {
            let trace = load_trace(&trace)?;
            println!("module: {}", trace.module.name);
            println!("entry: {}", trace.entry);
            println!("events: {}", trace.events.len());
            if let Some(result) = &trace.result {
                println!("result: {}", render_value(result));
            }
            if let Some(error) = &trace.error {
                println!("error: {error}");
            }
            println!("checksum: {}", trace.checksum);
            print_capability_audit(&trace);
            for event in &trace.events {
                let source = event
                    .source_line
                    .map(|line| format!(" line={line}"))
                    .unwrap_or_default();
                println!(
                    "{} pc={}{} op={} changes={}",
                    event.function,
                    event.pc,
                    source,
                    event.opcode,
                    event.register_changes.len()
                );
                if let Some(capability) = &event.capability {
                    println!(
                        "  cap {} {:?} -> {}",
                        capability.id,
                        capability.decision,
                        render_value(&capability.result)
                    );
                }
                for change in &event.register_changes {
                    println!("  r{} = {}", change.register, render_value(&change.value));
                }
                if let Some(error) = &event.error {
                    println!("  error {error}");
                }
            }
        }
        Command::TraceSlice {
            trace,
            from,
            to,
            out,
        } => {
            let trace = load_trace(&trace)?;
            let sliced = trace.slice(from, to)?;
            fs::write(&out, serde_json::to_vec_pretty(&sliced)?)?;
            println!(
                "wrote {} events {}..={} to {} checksum {}",
                sliced.events.len(),
                from,
                to,
                out.display(),
                sliced.checksum
            );
        }
        Command::Debug { trace, commands } => {
            let trace = load_trace(&trace)?;
            run_debugger(&trace, commands.as_deref())?;
        }
    }
    Ok(())
}

fn load_module(path: &PathBuf) -> Result<Module> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read module {}", path.display()))?;
    let module = if path.extension().and_then(|value| value.to_str()) == Some("chr") {
        let source = std::str::from_utf8(&bytes).context("language source is not valid UTF-8")?;
        Compiler::compile(source)?.module
    } else if path.extension().and_then(|value| value.to_str()) == Some("casm") {
        let source = std::str::from_utf8(&bytes).context("assembly module is not valid UTF-8")?;
        Assembler::parse(source)?
    } else {
        Module::from_bytes(&bytes)?
    };
    Verifier::verify(&module)?;
    Ok(module)
}

fn load_trace(path: &PathBuf) -> Result<Trace> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read trace {}", path.display()))?;
    serde_json::from_slice(&bytes).context("failed to decode trace")
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    #[serde(default)]
    capabilities: BTreeMap<String, RawPolicyEntry>,
}

#[derive(Debug, Deserialize)]
struct RawPolicyEntry {
    decision: String,
    mock: Option<toml::Value>,
}

#[derive(Clone, Debug)]
struct LoadedPolicy {
    policy: HostPolicy,
    digest: String,
}

fn load_policy(path: &PathBuf) -> Result<HostPolicy> {
    Ok(load_policy_with_digest(path)?.policy)
}

fn load_policy_with_digest(path: &PathBuf) -> Result<LoadedPolicy> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy {}", path.display()))?;
    let raw: RawPolicy = toml::from_str(&source).context("failed to parse policy TOML")?;
    let mut decisions = BTreeMap::new();
    for (capability, entry) in raw.capabilities {
        decisions.insert(capability, convert_decision(entry)?);
    }
    Ok(LoadedPolicy {
        policy: HostPolicy { decisions },
        digest: digest_bytes(source.as_bytes()),
    })
}

fn convert_decision(entry: RawPolicyEntry) -> Result<CapabilityDecision> {
    match entry.decision.as_str() {
        "grant" => Ok(CapabilityDecision::Grant),
        "deny" => Ok(CapabilityDecision::Deny),
        "mock" => Ok(CapabilityDecision::Mock(toml_value_to_vm_value(
            entry
                .mock
                .ok_or_else(|| anyhow!("mock decision needs mock value"))?,
        )?)),
        value => Err(anyhow!("unknown policy decision {value}")),
    }
}

fn toml_value_to_vm_value(value: toml::Value) -> Result<Value> {
    match value {
        toml::Value::String(value) => Ok(Value::String(value)),
        toml::Value::Integer(value) => Ok(Value::I64(value)),
        toml::Value::Float(value) => Ok(Value::F64(value)),
        toml::Value::Boolean(value) => Ok(Value::Bool(value)),
        toml::Value::Array(values) => values
            .into_iter()
            .map(toml_value_to_vm_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        other => Err(anyhow!("unsupported mock value {other:?}")),
    }
}

fn build_trace_metadata(
    module: &Module,
    policy: &HostPolicy,
    policy_digest: Option<String>,
    limits: VmLimits,
    slice: Option<TraceSliceMetadata>,
) -> Result<TraceMetadata> {
    let capabilities = policy
        .negotiate(module)
        .entries
        .into_iter()
        .filter_map(|entry| {
            let decision = match entry.status {
                chronicle_core::NegotiationStatus::Granted => TraceCapabilityDecision::Grant,
                chronicle_core::NegotiationStatus::Mocked => TraceCapabilityDecision::Mock,
                _ => return None,
            };
            Some((entry.capability, decision))
        })
        .collect();
    Ok(TraceMetadata {
        format_version: 1,
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        module_digest: digest_bytes(&module.to_bytes()?),
        policy_digest,
        limits,
        capabilities,
        slice,
    })
}

#[derive(Debug, Serialize)]
struct AuditReport {
    valid: bool,
    replay_error: Option<String>,
    module: String,
    entry: String,
    events: usize,
    checksum: u64,
    runtime_version: Option<String>,
    module_digest: Option<String>,
    policy_digest: Option<String>,
    limits: Option<VmLimits>,
    result: Option<Value>,
    error: Option<String>,
    slice: Option<TraceSliceMetadata>,
    capabilities: BTreeMap<String, AuditCapabilityCounts>,
}

#[derive(Debug, Default, Serialize)]
struct AuditCapabilityCounts {
    calls: usize,
    granted: usize,
    mocked: usize,
    replayed: usize,
    negotiated: Option<TraceCapabilityDecision>,
}

fn audit_trace(trace: Trace) -> AuditReport {
    let replay = Vm::replay(trace.clone());
    let (valid, replay_error) = match replay {
        Ok(_) => (true, None),
        Err(error) => (false, Some(error.to_string())),
    };
    let mut capabilities: BTreeMap<String, AuditCapabilityCounts> = BTreeMap::new();
    if let Some(metadata) = &trace.metadata {
        for (capability, decision) in &metadata.capabilities {
            capabilities
                .entry(capability.clone())
                .or_default()
                .negotiated = Some(decision.clone());
        }
    }
    for event in &trace.events {
        let Some(capability) = &event.capability else {
            continue;
        };
        let counts = capabilities.entry(capability.id.clone()).or_default();
        counts.calls += 1;
        match capability.decision {
            CapabilityTraceDecision::Granted => counts.granted += 1,
            CapabilityTraceDecision::Mocked => counts.mocked += 1,
            CapabilityTraceDecision::Replayed => counts.replayed += 1,
        }
    }
    AuditReport {
        valid,
        replay_error,
        module: trace.module.name.clone(),
        entry: trace.entry.clone(),
        events: trace.events.len(),
        checksum: trace.checksum,
        runtime_version: trace
            .metadata
            .as_ref()
            .map(|metadata| metadata.runtime_version.clone()),
        module_digest: trace
            .metadata
            .as_ref()
            .map(|metadata| metadata.module_digest.clone()),
        policy_digest: trace
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.policy_digest.clone()),
        limits: trace
            .metadata
            .as_ref()
            .map(|metadata| metadata.limits.clone()),
        result: trace.result.clone(),
        error: trace.error.clone(),
        slice: trace
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.slice.clone()),
        capabilities,
    }
}

fn print_audit_report(report: &AuditReport) {
    println!("audit: {}", if report.valid { "valid" } else { "invalid" });
    if let Some(error) = &report.replay_error {
        println!("replay error: {error}");
    }
    println!("module: {}", report.module);
    println!("entry: {}", report.entry);
    println!("events: {}", report.events);
    println!("checksum: {}", report.checksum);
    if let Some(version) = &report.runtime_version {
        println!("runtime: {version}");
    }
    if let Some(digest) = &report.module_digest {
        println!("module digest: {digest}");
    }
    if let Some(digest) = &report.policy_digest {
        println!("policy digest: {digest}");
    }
    if let Some(limits) = &report.limits {
        println!("limits: {}", render_limits(limits));
    }
    if let Some(slice) = &report.slice {
        println!(
            "slice: {}..={} of {} events from checksum {}",
            slice.from, slice.to, slice.source_event_count, slice.source_checksum
        );
    }
    if let Some(result) = &report.result {
        println!("result: {}", render_value(result));
    }
    if let Some(error) = &report.error {
        println!("error: {error}");
    }
    if !report.capabilities.is_empty() {
        println!("capabilities:");
        for (id, counts) in &report.capabilities {
            let negotiated = counts
                .negotiated
                .as_ref()
                .map(|decision| format!(" negotiated={decision:?}"))
                .unwrap_or_default();
            println!(
                "  {id}: calls={} granted={} mocked={} replayed={}{}",
                counts.calls, counts.granted, counts.mocked, counts.replayed, negotiated
            );
        }
    }
}

fn render_limits(limits: &VmLimits) -> String {
    format!(
        "max_instructions={} max_call_depth={} max_registers={} max_array_items={}",
        render_optional_usize(limits.max_instructions),
        render_optional_usize(limits.max_call_depth),
        render_optional_usize(limits.max_registers),
        render_optional_usize(limits.max_array_items)
    )
}

fn render_optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unbounded".into())
}

fn print_capability_audit(trace: &Trace) {
    let mut counts: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for event in &trace.events {
        if let Some(capability) = &event.capability {
            let entry = counts.entry(capability.id.clone()).or_default();
            entry.0 += 1;
            match capability.decision {
                chronicle_core::CapabilityTraceDecision::Granted => entry.1 += 1,
                chronicle_core::CapabilityTraceDecision::Mocked => entry.2 += 1,
                chronicle_core::CapabilityTraceDecision::Replayed => {}
            }
        }
    }
    if counts.is_empty() {
        return;
    }
    println!("capability audit:");
    for (id, (total, granted, mocked)) in counts {
        println!("  {id}: calls={total} granted={granted} mocked={mocked}");
    }
}

fn print_replay_error(error: &ReplayError, verbose: bool) {
    eprintln!("replay failed: {}", error.message);
    if let Some(diff) = &error.diff {
        eprintln!("first divergence at event {}", diff.index);
        if let Some(expected) = &diff.expected {
            eprintln!(
                "expected: {} pc={} line={:?} op={} checksum={}",
                expected.function,
                expected.pc,
                expected.source_line,
                expected.opcode,
                expected.checksum
            );
            if verbose {
                eprintln!("expected detail: {expected:#?}");
            }
        }
        if let Some(actual) = &diff.actual {
            eprintln!(
                "actual:   {} pc={} line={:?} op={} checksum={}",
                actual.function, actual.pc, actual.source_line, actual.opcode, actual.checksum
            );
            if verbose {
                eprintln!("actual detail: {actual:#?}");
            }
        }
        if let Some(expected_state) = &diff.expected_state_before {
            eprintln!(
                "expected state before: #{} {} pc={} line={:?} registers={}",
                expected_state.event_index,
                expected_state.function,
                expected_state.pc,
                expected_state.source_line,
                expected_state.registers.len()
            );
            if verbose {
                print_state_stderr("expected", expected_state);
            }
        }
        if let Some(actual_state) = &diff.actual_state_before {
            eprintln!(
                "actual state before:   #{} {} pc={} line={:?} registers={}",
                actual_state.event_index,
                actual_state.function,
                actual_state.pc,
                actual_state.source_line,
                actual_state.registers.len()
            );
            if verbose {
                print_state_stderr("actual", actual_state);
            }
        }
    }
}

fn print_state_stderr(label: &str, state: &TraceState) {
    eprintln!("{label} registers:");
    for (register, value) in &state.registers {
        eprintln!("  r{} = {}", register, render_value(value));
    }
    if let Some(capability) = &state.last_capability {
        eprintln!(
            "{label} last capability: {} {:?} -> {}",
            capability.id,
            capability.decision,
            render_value(&capability.result)
        );
    }
    if let Some(error) = &state.error {
        eprintln!("{label} error: {error}");
    }
}

fn run_debugger(trace: &Trace, commands: Option<&str>) -> Result<()> {
    if trace.events.is_empty() {
        println!("trace has no events");
        return Ok(());
    }

    let mut state = DebugState::new(trace);
    print_debug_header(trace);
    state.print_current(trace);

    if let Some(commands) = commands {
        for command in commands.split(';') {
            if !state.handle(trace, command.trim())? {
                break;
            }
        }
        return Ok(());
    }

    let stdin = io::stdin();
    loop {
        print!("chronicle-debug> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        if !state.handle(trace, line.trim())? {
            break;
        }
    }
    Ok(())
}

fn print_debug_header(trace: &Trace) {
    println!(
        "debugging module {} entry {}: {} events checksum {}",
        trace.module.name,
        trace.entry,
        trace.events.len(),
        trace.checksum
    );
    println!(
        "commands: next, prev, back N, forward N, jump N, state, regs, caps, diff A B, slice A B, export-slice A B --out file, why, event, source, help, quit"
    );
}

struct DebugState {
    index: usize,
    navigator: TraceNavigator,
}

impl DebugState {
    fn new(trace: &Trace) -> Self {
        Self {
            index: 0,
            navigator: TraceNavigator::new(trace.clone()),
        }
    }

    fn handle(&mut self, trace: &Trace, command: &str) -> Result<bool> {
        if command.is_empty() {
            return Ok(true);
        }
        let mut parts = command.split_whitespace();
        match parts.next().unwrap_or_default() {
            "n" | "next" => {
                if self.index + 1 < trace.events.len() {
                    self.index += 1;
                }
                self.print_current(trace);
            }
            "p" | "prev" => {
                self.index = self.index.saturating_sub(1);
                self.print_current(trace);
            }
            "back" => {
                let amount = parse_optional_amount(parts.next())?;
                self.index = self.index.saturating_sub(amount);
                self.print_current(trace);
            }
            "forward" => {
                let amount = parse_optional_amount(parts.next())?;
                self.index = (self.index + amount).min(trace.events.len() - 1);
                self.print_current(trace);
            }
            "j" | "jump" => {
                let Some(index) = parts.next() else {
                    anyhow::bail!("jump expects an event index");
                };
                let index = index.parse::<usize>().context("invalid event index")?;
                if index >= trace.events.len() {
                    anyhow::bail!("event index {index} out of bounds");
                }
                self.index = index;
                self.print_current(trace);
            }
            "state" => self.print_state()?,
            "r" | "regs" => self.print_registers(),
            "c" | "caps" => self.print_caps(trace),
            "diff" => {
                let from = parse_required_index(parts.next(), "diff expects from index")?;
                let to = parse_required_index(parts.next(), "diff expects to index")?;
                self.print_diff(from, to)?;
            }
            "slice" => {
                let from = parse_required_index(parts.next(), "slice expects from index")?;
                let to = parse_required_index(parts.next(), "slice expects to index")?;
                self.print_slice(from, to)?;
            }
            "export-slice" => {
                let from = parse_required_index(parts.next(), "export-slice expects from index")?;
                let to = parse_required_index(parts.next(), "export-slice expects to index")?;
                let flag = parts.next().unwrap_or_default();
                if flag != "--out" {
                    anyhow::bail!("export-slice expects --out path");
                }
                let Some(path) = parts.next() else {
                    anyhow::bail!("export-slice expects output path");
                };
                let sliced = trace.slice(from, to)?;
                fs::write(path, serde_json::to_vec_pretty(&sliced)?)?;
                println!(
                    "exported {} events {}..={} to {} checksum {}",
                    sliced.events.len(),
                    from,
                    to,
                    path,
                    sliced.checksum
                );
            }
            "why" => self.print_why(trace)?,
            "e" | "event" => println!("{:#?}", trace.events[self.index]),
            "s" | "source" => self.print_source(trace),
            "h" | "help" => print_debug_header(trace),
            "q" | "quit" | "exit" => return Ok(false),
            other => println!("unknown command {other}; try help"),
        }
        Ok(true)
    }

    fn print_current(&self, trace: &Trace) {
        let event = &trace.events[self.index];
        println!(
            "[{}/{}] {} pc={} line={:?} op={} checksum={}",
            self.index,
            trace.events.len() - 1,
            event.function,
            event.pc,
            event.source_line,
            event.opcode,
            event.checksum
        );
        if let Some(capability) = &event.capability {
            println!(
                "cap {} {:?} -> {}",
                capability.id,
                capability.decision,
                render_value(&capability.result)
            );
        }
        for change in &event.register_changes {
            println!("r{} = {}", change.register, render_value(&change.value));
        }
        if let Some(error) = &event.error {
            println!("error: {error}");
        }
    }

    fn print_registers(&self) {
        let Ok(state) = self.navigator.state_at(self.index) else {
            return;
        };
        let registers = state.registers;
        if registers.is_empty() {
            println!("registers: <empty>");
            return;
        }
        println!("registers:");
        for (register, value) in registers {
            println!("  r{} = {}", register, render_value(&value));
        }
    }

    fn print_caps(&self, trace: &Trace) {
        let mut seen = 0;
        for (index, event) in trace.events.iter().enumerate().take(self.index + 1) {
            if let Some(capability) = &event.capability {
                seen += 1;
                println!(
                    "#{index} {} {:?} args=[{}] -> {}",
                    capability.id,
                    capability.decision,
                    capability
                        .args
                        .iter()
                        .map(render_value)
                        .collect::<Vec<_>>()
                        .join(", "),
                    render_value(&capability.result)
                );
            }
        }
        if seen == 0 {
            println!("capabilities: <none yet>");
        }
    }

    fn print_source(&self, trace: &Trace) {
        let event = &trace.events[self.index];
        println!(
            "{} pc={} line={:?} op={}",
            event.function, event.pc, event.source_line, event.opcode
        );
        for source in self
            .navigator
            .source_window(self.index, 2)
            .unwrap_or_default()
        {
            let marker = if source.event_index == self.index {
                ">"
            } else {
                " "
            };
            println!(
                "{marker} #{} {} pc={} line={:?} op={}",
                source.event_index, source.function, source.pc, source.source_line, source.opcode
            );
        }
    }

    fn print_state(&self) -> Result<()> {
        let state = self.navigator.state_at(self.index)?;
        println!(
            "state #{} {} pc={} line={:?}",
            state.event_index, state.function, state.pc, state.source_line
        );
        print_state_registers(&state);
        if let Some(capability) = &state.last_capability {
            println!(
                "last capability: {} {:?} -> {}",
                capability.id,
                capability.decision,
                render_value(&capability.result)
            );
        }
        if let Some(error) = &state.error {
            println!("error: {error}");
        }
        Ok(())
    }

    fn print_diff(&self, from: usize, to: usize) -> Result<()> {
        let diff = self.navigator.diff_between(from, to)?;
        print_state_diff(&diff);
        Ok(())
    }

    fn print_slice(&self, from: usize, to: usize) -> Result<()> {
        let sliced = self.navigator.trace().slice(from, to)?;
        println!(
            "slice {}..={} events={} checksum={}",
            from,
            to,
            sliced.events.len(),
            sliced.checksum
        );
        for (offset, event) in sliced.events.iter().enumerate() {
            println!(
                "  #{} {} pc={} line={:?} op={} changes={}{}",
                from + offset,
                event.function,
                event.pc,
                event.source_line,
                event.opcode,
                event.register_changes.len(),
                event
                    .capability
                    .as_ref()
                    .map(|capability| format!(" cap={}", capability.id))
                    .unwrap_or_default()
            );
        }
        Ok(())
    }

    fn print_why(&self, trace: &Trace) -> Result<()> {
        let event = &trace.events[self.index];
        println!(
            "why #{}: {} pc={} line={:?} op={} checksum={}",
            self.index, event.function, event.pc, event.source_line, event.opcode, event.checksum
        );
        if self.index > 0 {
            let previous = &trace.events[self.index - 1];
            println!(
                "previous: #{} {} pc={} line={:?} op={}",
                self.index - 1,
                previous.function,
                previous.pc,
                previous.source_line,
                previous.opcode
            );
        }
        if event.register_changes.is_empty() {
            println!("changed registers: <none>");
        } else {
            println!("changed registers:");
            for change in &event.register_changes {
                println!("  r{} = {}", change.register, render_value(&change.value));
            }
        }
        if let Some(capability) = &event.capability {
            println!(
                "capability: {} {:?} args=[{}] -> {}",
                capability.id,
                capability.decision,
                capability
                    .args
                    .iter()
                    .map(render_value)
                    .collect::<Vec<_>>()
                    .join(", "),
                render_value(&capability.result)
            );
        }
        if let Some(error) = &event.error {
            println!("error: {error}");
        }
        Ok(())
    }
}

fn parse_optional_amount(value: Option<&str>) -> Result<usize> {
    value
        .unwrap_or("1")
        .parse::<usize>()
        .context("invalid amount")
}

fn parse_required_index(value: Option<&str>, message: &str) -> Result<usize> {
    value
        .ok_or_else(|| anyhow!(message.to_string()))?
        .parse::<usize>()
        .context("invalid event index")
}

fn print_state_registers(state: &TraceState) {
    if state.registers.is_empty() {
        println!("registers: <empty>");
        return;
    }
    println!("registers:");
    for (register, value) in &state.registers {
        println!("  r{} = {}", register, render_value(value));
    }
}

fn print_state_diff(diff: &StateDiff) {
    println!(
        "diff {} -> {} function {} -> {} checksums={}",
        diff.from,
        diff.to,
        diff.from_function,
        diff.to_function,
        diff.checksum_range.len()
    );
    if let Some(entered) = &diff.entered_function {
        println!("entered function: {entered}");
    }
    if let Some(exited) = &diff.exited_function {
        println!("exited function: {exited}");
    }
    if diff.changed_registers.is_empty() {
        println!("changed registers: <none>");
    } else {
        println!("changed registers:");
        for change in &diff.changed_registers {
            println!("  r{} = {}", change.register, render_value(&change.value));
        }
    }
    if diff.capability_calls.is_empty() {
        println!("capability calls: <none>");
    } else {
        println!("capability calls:");
        for capability in &diff.capability_calls {
            println!(
                "  {} {:?} -> {}",
                capability.id,
                capability.decision,
                render_value(&capability.result)
            );
        }
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Bool(value) => value.to_string(),
        Value::I64(value) => value.to_string(),
        Value::F64(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!("{values:?}"),
        Value::Function(value) | Value::Capability(value) => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_args_use_sandbox_defaults() {
        assert_eq!(
            LimitArgs::default().effective_limits().unwrap(),
            VmLimits::sandbox_defaults()
        );
    }

    #[test]
    fn limit_args_override_individual_defaults() {
        let limits = LimitArgs {
            max_instructions: Some(7),
            ..LimitArgs::default()
        }
        .effective_limits()
        .unwrap();
        assert_eq!(limits.max_instructions, Some(7));
        assert_eq!(
            limits.max_call_depth,
            VmLimits::sandbox_defaults().max_call_depth
        );
    }

    #[test]
    fn unbounded_rejects_explicit_limits() {
        let err = LimitArgs {
            unbounded: true,
            max_instructions: Some(7),
            ..LimitArgs::default()
        }
        .effective_limits()
        .unwrap_err();
        assert!(err.to_string().contains("--unbounded cannot be combined"));
    }
}
