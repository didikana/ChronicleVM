use chronicle_core::{CapabilityDecl, Function, Instruction, Module, Value};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AsmError {
    #[error("line {line}: {message}")]
    Line { line: usize, message: String },
    #[error("module is missing .module declaration")]
    MissingModule,
}

pub type Result<T> = std::result::Result<T, AsmError>;

pub struct Assembler;

impl Assembler {
    pub fn parse(source: &str) -> Result<Module> {
        Parser::new(source).parse()
    }
}

struct Parser<'a> {
    source: &'a str,
    module_name: Option<String>,
    constants: Vec<Value>,
    capabilities: Vec<CapabilityDecl>,
    functions: Vec<Function>,
    exports: BTreeMap<String, usize>,
}

#[derive(Default)]
struct FunctionBuilder {
    name: String,
    registers: usize,
    arity: usize,
    pending: Vec<(usize, PendingInstruction)>,
    labels: BTreeMap<String, usize>,
}

enum PendingInstruction {
    Ready(Instruction),
    Jump(String),
    JumpIf { cond: usize, label: String },
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            module_name: None,
            constants: Vec::new(),
            capabilities: Vec::new(),
            functions: Vec::new(),
            exports: BTreeMap::new(),
        }
    }

    fn parse(mut self) -> Result<Module> {
        let mut current: Option<FunctionBuilder> = None;
        for (line_index, raw_line) in self.source.lines().enumerate() {
            let line_no = line_index + 1;
            let cleaned = strip_comment(raw_line);
            let line = cleaned.trim();
            if line.is_empty() {
                continue;
            }

            if line == ".end" {
                let builder = current.take().ok_or_else(|| err(line_no, ".end without .fn"))?;
                self.finish_function(line_no, builder)?;
                continue;
            }

            if current.is_some() {
                if let Some(label) = line.strip_suffix(':') {
                    let builder = current.as_mut().expect("checked above");
                    builder.labels.insert(label.trim().to_string(), builder.pending.len());
                } else {
                    let instruction = self.parse_instruction(line_no, line)?;
                    let builder = current.as_mut().expect("checked above");
                    builder.pending.push((line_no, instruction));
                }
                continue;
            }

            if line.starts_with(".module ") {
                self.module_name = Some(parse_quoted(line_no, line.trim_start_matches(".module ").trim())?);
            } else if line.starts_with(".cap ") {
                self.capabilities.push(parse_capability(line_no, line)?);
            } else if line.starts_with(".fn ") {
                current = Some(parse_function_header(line_no, line)?);
            } else if line.starts_with(".export ") {
                let name = line.trim_start_matches(".export ").trim().to_string();
                self.exports.insert(name, usize::MAX);
            } else {
                return Err(err(line_no, "expected .module, .cap, .fn, or .export"));
            }
        }

        if current.is_some() {
            return Err(err(self.source.lines().count(), "function missing .end"));
        }

        let name = self.module_name.ok_or(AsmError::MissingModule)?;
        for (index, function) in self.functions.iter().enumerate() {
            if self.exports.contains_key(&function.name) || self.exports.is_empty() || function.name == "main" {
                self.exports.insert(function.name.clone(), index);
            }
        }
        for (export, index) in self.exports.iter_mut() {
            if *index == usize::MAX {
                let Some(found) = self.functions.iter().position(|function| function.name == *export) else {
                    return Err(err(0, format!("export {export} does not name a function")));
                };
                *index = found;
            }
        }

        Ok(Module {
            name,
            constants: self.constants,
            capabilities: self.capabilities,
            functions: self.functions,
            exports: self.exports,
        })
    }

    fn finish_function(&mut self, line_no: usize, builder: FunctionBuilder) -> Result<()> {
        let mut code = Vec::new();
        let mut source_lines = Vec::new();
        let labels = builder.labels;
        for (source_line, pending) in builder.pending {
            let instruction = match pending {
                PendingInstruction::Ready(instruction) => instruction,
                PendingInstruction::Jump(label) => {
                    let target = resolve_label(source_line, &labels, &label)?;
                    Instruction::Jump { target }
                }
                PendingInstruction::JumpIf { cond, label } => {
                    let target = resolve_label(source_line, &labels, &label)?;
                    Instruction::JumpIf { cond, target }
                }
            };
            code.push(instruction);
            source_lines.push(Some(source_line));
        }
        if code.is_empty() {
            return Err(err(line_no, "function has no instructions"));
        }
        self.functions.push(Function {
            name: builder.name,
            registers: builder.registers,
            arity: builder.arity,
            code,
            source_lines,
        });
        Ok(())
    }

    fn parse_instruction(&mut self, line_no: usize, line: &str) -> Result<PendingInstruction> {
        let mut parts = line.splitn(2, char::is_whitespace);
        let opcode = parts.next().unwrap_or_default();
        let operands = parts.next().unwrap_or_default().trim();
        let args = split_operands(line_no, operands)?;

        let ready = |instruction| Ok(PendingInstruction::Ready(instruction));
        match opcode {
            "const" => {
                expect(line_no, opcode, &args, 2)?;
                let dst = parse_register(line_no, &args[0])?;
                let value = parse_value(line_no, &args[1])?;
                let constant = self.intern_constant(value);
                ready(Instruction::Const { dst, constant })
            }
            "move" => {
                expect(line_no, opcode, &args, 2)?;
                ready(Instruction::Move {
                    dst: parse_register(line_no, &args[0])?,
                    src: parse_register(line_no, &args[1])?,
                })
            }
            "add" | "sub" | "mul" | "div" | "eq" | "lt" => {
                expect(line_no, opcode, &args, 3)?;
                let dst = parse_register(line_no, &args[0])?;
                let lhs = parse_register(line_no, &args[1])?;
                let rhs = parse_register(line_no, &args[2])?;
                let instruction = match opcode {
                    "add" => Instruction::Add { dst, lhs, rhs },
                    "sub" => Instruction::Sub { dst, lhs, rhs },
                    "mul" => Instruction::Mul { dst, lhs, rhs },
                    "div" => Instruction::Div { dst, lhs, rhs },
                    "eq" => Instruction::Eq { dst, lhs, rhs },
                    "lt" => Instruction::Lt { dst, lhs, rhs },
                    _ => unreachable!(),
                };
                ready(instruction)
            }
            "jump" => {
                expect(line_no, opcode, &args, 1)?;
                if let Ok(target) = args[0].parse::<usize>() {
                    ready(Instruction::Jump { target })
                } else {
                    Ok(PendingInstruction::Jump(args[0].clone()))
                }
            }
            "jump_if" => {
                expect(line_no, opcode, &args, 2)?;
                let cond = parse_register(line_no, &args[0])?;
                if let Ok(target) = args[1].parse::<usize>() {
                    ready(Instruction::JumpIf { cond, target })
                } else {
                    Ok(PendingInstruction::JumpIf {
                        cond,
                        label: args[1].clone(),
                    })
                }
            }
            "call" => {
                if args.len() < 2 {
                    return Err(err(line_no, "call expects dst, function, and optional args"));
                }
                ready(Instruction::Call {
                    dst: parse_register(line_no, &args[0])?,
                    function: args[1].clone(),
                    args: parse_registers(line_no, &args[2..])?,
                })
            }
            "ret" => {
                expect(line_no, opcode, &args, 1)?;
                ready(Instruction::Ret {
                    src: parse_register(line_no, &args[0])?,
                })
            }
            "cap_call" => {
                if args.len() < 2 {
                    return Err(err(line_no, "cap_call expects dst, capability, and optional args"));
                }
                ready(Instruction::CapCall {
                    dst: parse_register(line_no, &args[0])?,
                    capability: args[1].clone(),
                    args: parse_registers(line_no, &args[2..])?,
                })
            }
            "array_new" => {
                if args.is_empty() {
                    return Err(err(line_no, "array_new expects dst and optional item registers"));
                }
                ready(Instruction::ArrayNew {
                    dst: parse_register(line_no, &args[0])?,
                    items: parse_registers(line_no, &args[1..])?,
                })
            }
            "array_get" => {
                expect(line_no, opcode, &args, 3)?;
                ready(Instruction::ArrayGet {
                    dst: parse_register(line_no, &args[0])?,
                    array: parse_register(line_no, &args[1])?,
                    index: parse_register(line_no, &args[2])?,
                })
            }
            "array_set" => {
                expect(line_no, opcode, &args, 3)?;
                ready(Instruction::ArraySet {
                    array: parse_register(line_no, &args[0])?,
                    index: parse_register(line_no, &args[1])?,
                    value: parse_register(line_no, &args[2])?,
                })
            }
            _ => Err(err(line_no, format!("unknown opcode {opcode}"))),
        }
    }

    fn intern_constant(&mut self, value: Value) -> usize {
        if let Some(index) = self.constants.iter().position(|existing| existing == &value) {
            index
        } else {
            self.constants.push(value);
            self.constants.len() - 1
        }
    }
}

fn parse_function_header(line_no: usize, line: &str) -> Result<FunctionBuilder> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return Err(err(line_no, ".fn expects name and register count"));
    }
    let registers = parse_register_count(line_no, parts[2])?;
    let mut arity = 0;
    for part in &parts[3..] {
        if let Some(value) = part.strip_prefix("arity=") {
            arity = value
                .parse::<usize>()
                .map_err(|_| err(line_no, "invalid arity"))?;
        }
    }
    Ok(FunctionBuilder {
        name: parts[1].to_string(),
        registers,
        arity,
        pending: Vec::new(),
        labels: BTreeMap::new(),
    })
}

fn parse_capability(line_no: usize, line: &str) -> Result<CapabilityDecl> {
    let rest = line.trim_start_matches(".cap ").trim();
    let mut parts = rest.split_whitespace();
    let name = parts
        .next()
        .ok_or_else(|| err(line_no, ".cap expects a capability name"))?
        .to_string();
    let reason = rest
        .split_once("reason=")
        .map(|(_, value)| parse_quoted(line_no, value.trim()))
        .transpose()?;
    Ok(CapabilityDecl { name, reason })
}

fn parse_value(line_no: usize, token: &str) -> Result<Value> {
    if token == "nil" {
        Ok(Value::Nil)
    } else if token == "true" {
        Ok(Value::Bool(true))
    } else if token == "false" {
        Ok(Value::Bool(false))
    } else if token.starts_with('"') {
        Ok(Value::String(parse_quoted(line_no, token)?))
    } else if token.contains('.') {
        token
            .parse::<f64>()
            .map(Value::F64)
            .map_err(|_| err(line_no, format!("invalid float literal {token}")))
    } else {
        token
            .parse::<i64>()
            .map(Value::I64)
            .map_err(|_| err(line_no, format!("invalid literal {token}")))
    }
}

fn parse_quoted(line_no: usize, token: &str) -> Result<String> {
    if !token.starts_with('"') || !token.ends_with('"') || token.len() < 2 {
        return Err(err(line_no, "expected quoted string"));
    }
    Ok(token[1..token.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\n", "\n"))
}

fn parse_register(line_no: usize, token: &str) -> Result<usize> {
    let number = token
        .strip_prefix('r')
        .ok_or_else(|| err(line_no, format!("expected register, got {token}")))?;
    number
        .parse::<usize>()
        .map_err(|_| err(line_no, format!("invalid register {token}")))
}

fn parse_register_count(line_no: usize, token: &str) -> Result<usize> {
    let count = parse_register(line_no, token)?;
    if count == 0 {
        Err(err(line_no, "register count must be greater than zero"))
    } else {
        Ok(count)
    }
}

fn parse_registers(line_no: usize, tokens: &[String]) -> Result<Vec<usize>> {
    tokens.iter().map(|token| parse_register(line_no, token)).collect()
}

fn split_operands(line_no: usize, input: &str) -> Result<Vec<String>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                in_string = !in_string;
                current.push(ch);
            }
            ',' if !in_string => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_string {
        return Err(err(line_no, "unterminated string"));
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }
    Ok(args)
}

fn strip_comment(line: &str) -> String {
    let mut result = String::new();
    let mut in_string = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_string = !in_string;
                result.push(ch);
            }
            '#' if !in_string => break,
            _ => result.push(ch),
        }
    }
    result
}

fn resolve_label(line_no: usize, labels: &BTreeMap<String, usize>, label: &str) -> Result<usize> {
    labels
        .get(label)
        .copied()
        .ok_or_else(|| err(line_no, format!("unknown label {label}")))
}

fn expect(line_no: usize, opcode: &str, args: &[String], expected: usize) -> Result<()> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(err(
            line_no,
            format!("{opcode} expects {expected} operands, got {}", args.len()),
        ))
    }
}

fn err(line: usize, message: impl Into<String>) -> AsmError {
    AsmError::Line {
        line,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronicle_core::Verifier;

    #[test]
    fn parses_module_with_capability_and_label() {
        let source = r#"
          .module "demo"
          .cap log.print reason="debug output"
          .fn main r3
            const r0, "hello"
            cap_call r1, log.print, r0
          done:
            ret r1
          .end
        "#;
        let module = Assembler::parse(source).unwrap();
        Verifier::verify(&module).unwrap();
        assert_eq!(module.name, "demo");
        assert_eq!(module.capabilities[0].name, "log.print");
        assert!(module.exports.contains_key("main"));
    }

    #[test]
    fn assembled_branch_array_program_executes() {
        let source = r#"
          .module "branch-array"
          .fn main r6
            const r0, 1
            const r1, 2
            lt r2, r0, r1
            jump_if r2, yes
            const r3, 99
            ret r3
          yes:
            array_new r4, r0, r1
            array_get r5, r4, r0
            ret r5
          .end
        "#;
        let module = Assembler::parse(source).unwrap();
        Verifier::verify(&module).unwrap();
        let mut vm = chronicle_core::Vm::new(module, chronicle_core::HostPolicy::default()).unwrap();
        assert_eq!(vm.run_entry("main").unwrap(), Value::I64(2));
    }

    #[test]
    fn verifies_undeclared_capability() {
        let source = r#"
          .module "bad-cap"
          .fn main r2
            cap_call r0, log.print
            ret r0
          .end
        "#;
        let module = Assembler::parse(source).unwrap();
        assert!(Verifier::verify(&module).is_err());
    }
}
