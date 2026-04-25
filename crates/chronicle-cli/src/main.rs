use anyhow::{anyhow, Context, Result};
use chronicle_asm::Assembler;
use chronicle_core::{CapabilityDecision, HostPolicy, Module, Trace, Value, Verifier, Vm};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
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
    Verify {
        module: PathBuf,
    },
    Run {
        module: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value = "main")]
        entry: String,
    },
    Trace {
        module: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "main")]
        entry: String,
    },
    Replay {
        trace: PathBuf,
    },
    Inspect {
        trace: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Assemble { module, out } => {
            let module = load_module(&module)?;
            fs::write(&out, module.to_bytes()?)?;
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
        Command::Run {
            module,
            policy,
            entry,
        } => {
            let module = load_module(&module)?;
            let policy = load_policy(&policy)?;
            let mut vm = Vm::new(module, policy)?;
            let result = vm.run_entry(&entry)?;
            println!("{}", render_value(&result));
        }
        Command::Trace {
            module,
            policy,
            out,
            entry,
        } => {
            let module = load_module(&module)?;
            let policy = load_policy(&policy)?;
            let mut vm = Vm::new(module, policy)?;
            let trace = vm.run_with_trace(&entry)?;
            fs::write(&out, serde_json::to_vec_pretty(&trace)?)?;
            if let Some(error) = trace.error {
                return Err(anyhow!("trace captured error: {error}"));
            }
            println!("wrote {}", out.display());
        }
        Command::Replay { trace } => {
            let trace = load_trace(&trace)?;
            let report = Vm::replay(trace)?;
            println!(
                "replayed {} events, result {}",
                report.events_checked,
                report
                    .result
                    .as_ref()
                    .map(render_value)
                    .unwrap_or_else(|| "nil".into())
            );
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
                        "  cap {} -> {}",
                        capability.name,
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
    }
    Ok(())
}

fn load_module(path: &PathBuf) -> Result<Module> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read module {}", path.display()))?;
    let module = if path.extension().and_then(|value| value.to_str()) == Some("casm") {
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
    capabilities: BTreeMap<String, RawDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawDecision {
    Text(String),
    Table {
        decision: Option<String>,
        mock: Option<toml::Value>,
    },
}

fn load_policy(path: &PathBuf) -> Result<HostPolicy> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read policy {}", path.display()))?;
    let raw: RawPolicy = toml::from_str(&source).context("failed to parse policy TOML")?;
    let mut decisions = BTreeMap::new();
    for (capability, decision) in raw.capabilities {
        decisions.insert(capability, convert_decision(decision)?);
    }
    Ok(HostPolicy { decisions })
}

fn convert_decision(decision: RawDecision) -> Result<CapabilityDecision> {
    match decision {
        RawDecision::Text(value) if value == "grant" => Ok(CapabilityDecision::Grant),
        RawDecision::Text(value) if value == "deny" => Ok(CapabilityDecision::Deny),
        RawDecision::Text(value) => Err(anyhow!("unknown policy decision {value}")),
        RawDecision::Table { decision, mock } => {
            if let Some(mock) = mock {
                return Ok(CapabilityDecision::Mock(toml_value_to_vm_value(mock)?));
            }
            match decision.as_deref() {
                Some("grant") => Ok(CapabilityDecision::Grant),
                Some("deny") => Ok(CapabilityDecision::Deny),
                Some(value) => Err(anyhow!("unknown policy decision {value}")),
                None => Err(anyhow!("policy table needs decision or mock")),
            }
        }
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
