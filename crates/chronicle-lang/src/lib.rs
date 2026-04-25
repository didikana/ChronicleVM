use chronicle_core::{CapabilityDecl, Function, Instruction, Module, Value, Verifier};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LangError {
    #[error("line {line}: {message}")]
    Line { line: usize, message: String },
    #[error("module is missing a module declaration")]
    MissingModule,
    #[error("program is missing a function")]
    MissingFunction,
    #[error(transparent)]
    Verify(#[from] chronicle_core::ChronicleError),
}

pub type Result<T> = std::result::Result<T, LangError>;

pub struct Compiler;

impl Compiler {
    pub fn compile(source: &str) -> Result<CompiledProgram> {
        Parser::new(source).parse()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledProgram {
    pub module: Module,
    pub casm: String,
}

struct Parser<'a> {
    source: &'a str,
    module_name: Option<String>,
    capabilities: Vec<CapabilityDecl>,
    body: Vec<SourceStatement>,
}

#[derive(Clone, Debug, PartialEq)]
struct SourceStatement {
    line: usize,
    kind: Statement,
}

#[derive(Clone, Debug, PartialEq)]
enum Statement {
    Let { name: String, expr: Expr },
    Expr(Expr),
    Return(Expr),
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Literal(Value),
    Var(String),
    Binary {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Array(Vec<Expr>),
    CapCall {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Lt,
}

struct FunctionCompiler {
    constants: Vec<Value>,
    variables: BTreeMap<String, usize>,
    next_register: usize,
    code: Vec<Instruction>,
    source_lines: Vec<Option<usize>>,
    declared_caps: BTreeSet<String>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            module_name: None,
            capabilities: Vec::new(),
            body: Vec::new(),
        }
    }

    fn parse(mut self) -> Result<CompiledProgram> {
        let mut in_function = false;
        for (index, raw_line) in self.source.lines().enumerate() {
            let line_no = index + 1;
            let cleaned = strip_comment(raw_line);
            let line = cleaned.trim();
            if line.is_empty() {
                continue;
            }

            if in_function {
                if line == "end" {
                    in_function = false;
                    continue;
                }
                self.body.push(SourceStatement {
                    line: line_no,
                    kind: parse_statement(line_no, line)?,
                });
                continue;
            }

            if let Some(rest) = line.strip_prefix("module ") {
                self.module_name = Some(parse_name_or_string(line_no, rest.trim())?);
            } else if let Some(rest) = line.strip_prefix("cap ") {
                self.capabilities
                    .push(parse_capability(line_no, rest.trim())?);
            } else if line == "fn main" {
                in_function = true;
            } else {
                return Err(err(line_no, "expected module, cap, or fn main"));
            }
        }

        if in_function {
            return Err(err(self.source.lines().count(), "function missing end"));
        }

        let module_name = self.module_name.ok_or(LangError::MissingModule)?;
        if self.body.is_empty() {
            return Err(LangError::MissingFunction);
        }

        let mut compiler = FunctionCompiler::new(&self.capabilities);
        for statement in &self.body {
            compiler.compile_statement(statement)?;
        }
        let (constants, function) = compiler.finish();
        let module = Module {
            name: module_name,
            constants,
            capabilities: self.capabilities,
            functions: vec![function],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        Verifier::verify(&module)?;
        let casm = render_casm(&module);
        Ok(CompiledProgram { module, casm })
    }
}

impl FunctionCompiler {
    fn new(capabilities: &[CapabilityDecl]) -> Self {
        Self {
            constants: Vec::new(),
            variables: BTreeMap::new(),
            next_register: 0,
            code: Vec::new(),
            source_lines: Vec::new(),
            declared_caps: capabilities.iter().map(|cap| cap.name.clone()).collect(),
        }
    }

    fn compile_statement(&mut self, statement: &SourceStatement) -> Result<()> {
        match &statement.kind {
            Statement::Let { name, expr } => {
                let register = self.compile_expr(expr, statement.line)?;
                self.variables.insert(name.clone(), register);
            }
            Statement::Expr(expr) => {
                self.compile_expr(expr, statement.line)?;
            }
            Statement::Return(expr) => {
                let register = self.compile_expr(expr, statement.line)?;
                self.push(statement.line, Instruction::Ret { src: register });
            }
        }
        Ok(())
    }

    fn compile_expr(&mut self, expr: &Expr, line: usize) -> Result<usize> {
        match expr {
            Expr::Literal(value) => {
                let dst = self.alloc();
                let constant = self.intern_constant(value.clone());
                self.push(line, Instruction::Const { dst, constant });
                Ok(dst)
            }
            Expr::Var(name) => self
                .variables
                .get(name)
                .copied()
                .ok_or_else(|| err(line, format!("unknown variable {name}"))),
            Expr::Binary { op, lhs, rhs } => {
                let lhs = self.compile_expr(lhs, line)?;
                let rhs = self.compile_expr(rhs, line)?;
                let dst = self.alloc();
                let instruction = match op {
                    BinaryOp::Add => Instruction::Add { dst, lhs, rhs },
                    BinaryOp::Sub => Instruction::Sub { dst, lhs, rhs },
                    BinaryOp::Mul => Instruction::Mul { dst, lhs, rhs },
                    BinaryOp::Div => Instruction::Div { dst, lhs, rhs },
                    BinaryOp::Eq => Instruction::Eq { dst, lhs, rhs },
                    BinaryOp::Lt => Instruction::Lt { dst, lhs, rhs },
                };
                self.push(line, instruction);
                Ok(dst)
            }
            Expr::Array(items) => {
                let mut registers = Vec::new();
                for item in items {
                    registers.push(self.compile_expr(item, line)?);
                }
                let dst = self.alloc();
                self.push(
                    line,
                    Instruction::ArrayNew {
                        dst,
                        items: registers,
                    },
                );
                Ok(dst)
            }
            Expr::CapCall { name, args } => {
                if !self.declared_caps.contains(name) {
                    return Err(err(line, format!("capability {name} was not declared")));
                }
                let mut registers = Vec::new();
                for arg in args {
                    registers.push(self.compile_expr(arg, line)?);
                }
                let dst = self.alloc();
                self.push(
                    line,
                    Instruction::CapCall {
                        dst,
                        capability: name.clone(),
                        args: registers,
                    },
                );
                Ok(dst)
            }
        }
    }

    fn finish(mut self) -> (Vec<Value>, Function) {
        if !matches!(self.code.last(), Some(Instruction::Ret { .. })) {
            let dst = self.alloc();
            let constant = self.intern_constant(Value::Nil);
            self.push(0, Instruction::Const { dst, constant });
            self.push(0, Instruction::Ret { src: dst });
        }
        (
            self.constants,
            Function {
                name: "main".into(),
                registers: self.next_register.max(1),
                arity: 0,
                code: self.code,
                source_lines: self.source_lines,
            },
        )
    }

    fn push(&mut self, line: usize, instruction: Instruction) {
        self.code.push(instruction);
        self.source_lines
            .push(if line == 0 { None } else { Some(line) });
    }

    fn alloc(&mut self) -> usize {
        let register = self.next_register;
        self.next_register += 1;
        register
    }

    fn intern_constant(&mut self, value: Value) -> usize {
        if let Some(index) = self
            .constants
            .iter()
            .position(|existing| existing == &value)
        {
            index
        } else {
            self.constants.push(value);
            self.constants.len() - 1
        }
    }
}

fn parse_statement(line_no: usize, line: &str) -> Result<Statement> {
    if let Some(rest) = line.strip_prefix("let ") {
        let (name, expr) = rest
            .split_once('=')
            .ok_or_else(|| err(line_no, "let expects name = expression"))?;
        let name = name.trim();
        validate_ident(line_no, name)?;
        Ok(Statement::Let {
            name: name.to_string(),
            expr: parse_expr(line_no, expr.trim())?,
        })
    } else if let Some(rest) = line.strip_prefix("return ") {
        Ok(Statement::Return(parse_expr(line_no, rest.trim())?))
    } else {
        Ok(Statement::Expr(parse_expr(line_no, line)?))
    }
}

fn parse_expr(line_no: usize, input: &str) -> Result<Expr> {
    let input = input.trim();
    for (needle, op) in [
        (" == ", BinaryOp::Eq),
        (" < ", BinaryOp::Lt),
        (" + ", BinaryOp::Add),
        (" - ", BinaryOp::Sub),
        (" * ", BinaryOp::Mul),
        (" / ", BinaryOp::Div),
    ] {
        if let Some((lhs, rhs)) = split_top_level(input, needle) {
            return Ok(Expr::Binary {
                op,
                lhs: Box::new(parse_expr(line_no, lhs)?),
                rhs: Box::new(parse_expr(line_no, rhs)?),
            });
        }
    }

    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1];
        return Ok(Expr::Array(
            split_args(line_no, inner)?
                .into_iter()
                .map(|arg| parse_expr(line_no, &arg))
                .collect::<Result<Vec<_>>>()?,
        ));
    }

    if let Some(rest) = input.strip_prefix("cap ") {
        return parse_cap_call(line_no, rest.trim());
    }

    if input == "nil" {
        Ok(Expr::Literal(Value::Nil))
    } else if input == "true" {
        Ok(Expr::Literal(Value::Bool(true)))
    } else if input == "false" {
        Ok(Expr::Literal(Value::Bool(false)))
    } else if input.starts_with('"') {
        Ok(Expr::Literal(Value::String(parse_quoted(line_no, input)?)))
    } else if input.contains('.') && input.parse::<f64>().is_ok() {
        Ok(Expr::Literal(Value::F64(input.parse::<f64>().unwrap())))
    } else if input.parse::<i64>().is_ok() {
        Ok(Expr::Literal(Value::I64(input.parse::<i64>().unwrap())))
    } else {
        validate_ident(line_no, input)?;
        Ok(Expr::Var(input.to_string()))
    }
}

fn parse_cap_call(line_no: usize, input: &str) -> Result<Expr> {
    let open = input
        .find('(')
        .ok_or_else(|| err(line_no, "capability call expects name(args)"))?;
    if !input.ends_with(')') {
        return Err(err(line_no, "capability call missing closing ')'"));
    }
    let name = input[..open].trim();
    validate_cap_name(line_no, name)?;
    let inner = &input[open + 1..input.len() - 1];
    Ok(Expr::CapCall {
        name: name.to_string(),
        args: split_args(line_no, inner)?
            .into_iter()
            .map(|arg| parse_expr(line_no, &arg))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn parse_capability(line_no: usize, input: &str) -> Result<CapabilityDecl> {
    let mut parts = input.splitn(2, char::is_whitespace);
    let name = parts
        .next()
        .ok_or_else(|| err(line_no, "cap expects a capability name"))?;
    validate_cap_name(line_no, name)?;
    let reason = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse_quoted(line_no, value))
        .transpose()?;
    Ok(CapabilityDecl {
        name: name.to_string(),
        reason,
    })
}

fn render_casm(module: &Module) -> String {
    let mut out = String::new();
    out.push_str(&format!(".module \"{}\"\n", escape_string(&module.name)));
    for capability in &module.capabilities {
        out.push_str(&format!(".cap {}", capability.name));
        if let Some(reason) = &capability.reason {
            out.push_str(&format!(" reason=\"{}\"", escape_string(reason)));
        }
        out.push('\n');
    }
    out.push('\n');

    let function = &module.functions[0];
    out.push_str(&format!(".fn main r{}\n", function.registers));
    for instruction in &function.code {
        out.push_str("  ");
        out.push_str(&render_instruction(instruction, &module.constants));
        out.push('\n');
    }
    out.push_str(".end\n");
    out
}

fn render_instruction(instruction: &Instruction, constants: &[Value]) -> String {
    match instruction {
        Instruction::Const { dst, constant } => {
            format!("const r{dst}, {}", render_literal(&constants[*constant]))
        }
        Instruction::Add { dst, lhs, rhs } => format!("add r{dst}, r{lhs}, r{rhs}"),
        Instruction::Sub { dst, lhs, rhs } => format!("sub r{dst}, r{lhs}, r{rhs}"),
        Instruction::Mul { dst, lhs, rhs } => format!("mul r{dst}, r{lhs}, r{rhs}"),
        Instruction::Div { dst, lhs, rhs } => format!("div r{dst}, r{lhs}, r{rhs}"),
        Instruction::Eq { dst, lhs, rhs } => format!("eq r{dst}, r{lhs}, r{rhs}"),
        Instruction::Lt { dst, lhs, rhs } => format!("lt r{dst}, r{lhs}, r{rhs}"),
        Instruction::CapCall {
            dst,
            capability,
            args,
        } => format!(
            "cap_call r{dst}, {capability}{}",
            render_register_suffix(args)
        ),
        Instruction::ArrayNew { dst, items } => {
            format!("array_new r{dst}{}", render_register_suffix(items))
        }
        Instruction::Ret { src } => format!("ret r{src}"),
        Instruction::Move { dst, src } => format!("move r{dst}, r{src}"),
        Instruction::Jump { target } => format!("jump {target}"),
        Instruction::JumpIf { cond, target } => format!("jump_if r{cond}, {target}"),
        Instruction::Call {
            dst,
            function,
            args,
        } => format!("call r{dst}, {function}{}", render_register_suffix(args)),
        Instruction::ArrayGet { dst, array, index } => {
            format!("array_get r{dst}, r{array}, r{index}")
        }
        Instruction::ArraySet {
            array,
            index,
            value,
        } => format!("array_set r{array}, r{index}, r{value}"),
    }
}

fn render_register_suffix(registers: &[usize]) -> String {
    if registers.is_empty() {
        String::new()
    } else {
        format!(
            ", {}",
            registers
                .iter()
                .map(|register| format!("r{register}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn render_literal(value: &Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Bool(value) => value.to_string(),
        Value::I64(value) => value.to_string(),
        Value::F64(value) => value.to_string(),
        Value::String(value) => format!("\"{}\"", escape_string(value)),
        other => format!("\"{:?}\"", other),
    }
}

fn split_top_level<'a>(input: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
    let mut in_string = false;
    let mut depth = 0usize;
    let bytes = input.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut index = 0;
    while index + needle_bytes.len() <= bytes.len() {
        match bytes[index] as char {
            '"' => in_string = !in_string,
            '[' | '(' if !in_string => depth += 1,
            ']' | ')' if !in_string => depth = depth.saturating_sub(1),
            _ => {}
        }
        if !in_string && depth == 0 && bytes[index..].starts_with(needle_bytes) {
            return Some((&input[..index], &input[index + needle.len()..]));
        }
        index += 1;
    }
    None
}

fn split_args(line_no: usize, input: &str) -> Result<Vec<String>> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut depth = 0usize;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_string = !in_string;
                current.push(ch);
            }
            '[' | '(' if !in_string => {
                depth += 1;
                current.push(ch);
            }
            ']' | ')' if !in_string => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if !in_string && depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_string || depth != 0 {
        return Err(err(line_no, "unterminated expression list"));
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }
    Ok(args)
}

fn parse_name_or_string(line_no: usize, input: &str) -> Result<String> {
    if input.starts_with('"') {
        parse_quoted(line_no, input)
    } else {
        validate_ident(line_no, input)?;
        Ok(input.to_string())
    }
}

fn parse_quoted(line_no: usize, input: &str) -> Result<String> {
    if !input.starts_with('"') || !input.ends_with('"') || input.len() < 2 {
        return Err(err(line_no, "expected quoted string"));
    }
    Ok(input[1..input.len() - 1]
        .replace("\\\"", "\"")
        .replace("\\n", "\n"))
}

fn validate_ident(line_no: usize, input: &str) -> Result<()> {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return Err(err(line_no, "empty identifier"));
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(err(line_no, format!("invalid identifier {input}")));
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err(err(line_no, format!("invalid identifier {input}")));
    }
    Ok(())
}

fn validate_cap_name(line_no: usize, input: &str) -> Result<()> {
    if input.is_empty()
        || !input
            .chars()
            .all(|ch| ch == '.' || ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
    {
        return Err(err(line_no, format!("invalid capability name {input}")));
    }
    Ok(())
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

fn escape_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn err(line: usize, message: impl Into<String>) -> LangError {
    LangError::Line {
        line,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_plugin_language_to_module_and_casm() {
        let source = r#"
          module safe_plugin
          cap log.print "audit"
          cap clock.now "time"
          cap random.u64 "request id"

          fn main
            let started = "plugin started"
            cap log.print(started)
            let now = cap clock.now()
            let request = cap random.u64()
            let result = [now, request]
            return result
          end
        "#;
        let compiled = Compiler::compile(source).unwrap();
        assert_eq!(compiled.module.name, "safe_plugin");
        assert!(compiled.casm.contains(".cap log.print"));
        assert_eq!(
            compiled.module.functions[0].source_lines.len(),
            compiled.module.functions[0].code.len()
        );
    }

    #[test]
    fn rejects_undeclared_capability() {
        let source = r#"
          module bad
          fn main
            cap log.print("hello")
          end
        "#;
        assert!(Compiler::compile(source).is_err());
    }
}
