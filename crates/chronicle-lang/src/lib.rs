use chronicle_core::{CapabilityDecl, Function, Instruction, Module, Value, ValueType, Verifier};
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
    functions: Vec<SourceFunction>,
}

#[derive(Clone, Debug, PartialEq)]
struct LogicalLine {
    line: usize,
    text: String,
}

#[derive(Clone, Debug, PartialEq)]
struct SourceFunction {
    line: usize,
    name: String,
    params: Vec<String>,
    body: Vec<SourceStatement>,
}

#[derive(Clone, Debug, PartialEq)]
struct SourceStatement {
    line: usize,
    kind: Statement,
}

#[derive(Clone, Debug, PartialEq)]
enum Statement {
    Let {
        name: String,
        expr: Expr,
    },
    Expr(Expr),
    Return(Expr),
    If {
        condition: Expr,
        then_body: Vec<SourceStatement>,
        else_body: Vec<SourceStatement>,
    },
    While {
        condition: Expr,
        body: Vec<SourceStatement>,
    },
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Literal(Value),
    Var(String),
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
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
    Call {
        name: String,
        args: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum UnaryOp {
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    And,
    Or,
}

struct FunctionCompiler {
    constants: Vec<Value>,
    variables: BTreeMap<String, usize>,
    next_register: usize,
    code: Vec<Instruction>,
    source_lines: Vec<Option<usize>>,
    declared_caps: BTreeSet<String>,
    function_names: BTreeSet<String>,
    function_name: String,
    arity: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            module_name: None,
            capabilities: Vec::new(),
            functions: Vec::new(),
        }
    }

    fn parse(mut self) -> Result<CompiledProgram> {
        let lines = logical_lines(self.source);
        let mut index = 0;
        while index < lines.len() {
            let line = &lines[index];
            if let Some(rest) = line.text.strip_prefix("module ") {
                self.module_name = Some(parse_name_or_string(line.line, rest.trim())?);
                index += 1;
            } else if let Some(rest) = line.text.strip_prefix("cap ") {
                self.capabilities
                    .push(parse_capability(line.line, rest.trim())?);
                index += 1;
            } else if let Some(rest) = line.text.strip_prefix("fn ") {
                let (name, params) = parse_function_header(line.line, rest.trim())?;
                let body_lines = collect_function_body(&lines, &mut index)?;
                let mut body_index = 0;
                let body = parse_block(&body_lines, &mut body_index, false)?;
                if body_index != body_lines.len() {
                    return Err(err(
                        body_lines[body_index].line,
                        "unexpected block terminator",
                    ));
                }
                self.functions.push(SourceFunction {
                    line: line.line,
                    name,
                    params,
                    body,
                });
            } else {
                return Err(err(line.line, "expected module, cap, or fn"));
            }
        }

        let module_name = self.module_name.ok_or(LangError::MissingModule)?;
        if self.functions.is_empty() {
            return Err(LangError::MissingFunction);
        }

        let mut seen_functions = BTreeSet::new();
        for function in &self.functions {
            if !seen_functions.insert(function.name.clone()) {
                return Err(err(
                    function.line,
                    format!("duplicate function {}", function.name),
                ));
            }
        }
        if !seen_functions.contains("main") {
            return Err(err(0, "program must define main"));
        }

        let mut constants = Vec::new();
        let mut functions = Vec::new();
        for function in &self.functions {
            let mut compiler = FunctionCompiler::new(
                &self.capabilities,
                seen_functions.clone(),
                function.name.clone(),
                &function.params,
            )?;
            for statement in &function.body {
                compiler.compile_statement(statement)?;
            }
            functions.push(compiler.finish(&mut constants));
        }
        let exports = functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.name.clone(), index))
            .collect();
        let module = Module {
            name: module_name,
            constants,
            capabilities: self.capabilities,
            functions,
            exports,
        };
        Verifier::verify(&module)?;
        let casm = render_casm(&module);
        Ok(CompiledProgram { module, casm })
    }
}

impl FunctionCompiler {
    fn new(
        capabilities: &[CapabilityDecl],
        function_names: BTreeSet<String>,
        function_name: String,
        params: &[String],
    ) -> Result<Self> {
        let mut variables = BTreeMap::new();
        for (index, param) in params.iter().enumerate() {
            validate_ident(0, param)?;
            if variables.insert(param.clone(), index).is_some() {
                return Err(err(0, format!("duplicate parameter {param}")));
            }
        }
        Ok(Self {
            constants: Vec::new(),
            variables,
            next_register: params.len(),
            code: Vec::new(),
            source_lines: Vec::new(),
            declared_caps: capabilities.iter().map(|cap| cap.id.clone()).collect(),
            function_names,
            function_name,
            arity: params.len(),
        })
    }

    fn compile_statement(&mut self, statement: &SourceStatement) -> Result<()> {
        match &statement.kind {
            Statement::Let { name, expr } => {
                let value_register = self.compile_expr(expr, statement.line)?;
                if let Some(existing) = self.variables.get(name).copied() {
                    self.push(
                        statement.line,
                        Instruction::Move {
                            dst: existing,
                            src: value_register,
                        },
                    );
                } else {
                    self.variables.insert(name.clone(), value_register);
                }
            }
            Statement::Expr(expr) => {
                self.compile_expr(expr, statement.line)?;
            }
            Statement::Return(expr) => {
                let register = self.compile_expr(expr, statement.line)?;
                self.push(statement.line, Instruction::Ret { src: register });
            }
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
                let variables_before_block = self.variables.clone();
                let cond = self.compile_expr(condition, statement.line)?;
                let jump_to_then =
                    self.push_placeholder(statement.line, Instruction::JumpIf { cond, target: 0 });
                for nested in else_body {
                    self.compile_statement(nested)?;
                }
                self.variables = variables_before_block.clone();
                let jump_to_end = if block_returns(else_body) {
                    None
                } else {
                    Some(self.push_placeholder(statement.line, Instruction::Jump { target: 0 }))
                };
                let then_start = self.code.len();
                self.patch_target(jump_to_then, then_start);
                for nested in then_body {
                    self.compile_statement(nested)?;
                }
                self.variables = variables_before_block;
                let end = self.code.len();
                if let Some(jump_to_end) = jump_to_end {
                    self.patch_target(jump_to_end, end);
                }
            }
            Statement::While { condition, body } => {
                let variables_before_block = self.variables.clone();
                let loop_start = self.code.len();
                let cond = self.compile_expr(condition, statement.line)?;
                let jump_to_body =
                    self.push_placeholder(statement.line, Instruction::JumpIf { cond, target: 0 });
                let jump_to_end =
                    self.push_placeholder(statement.line, Instruction::Jump { target: 0 });
                let body_start = self.code.len();
                self.patch_target(jump_to_body, body_start);
                for nested in body {
                    self.compile_statement(nested)?;
                }
                self.variables = variables_before_block;
                self.push(statement.line, Instruction::Jump { target: loop_start });
                let end = self.code.len();
                self.patch_target(jump_to_end, end);
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
            Expr::Unary { op, expr } => {
                let register = self.compile_expr(expr, line)?;
                match op {
                    UnaryOp::Not => self.compile_not(register, line),
                }
            }
            Expr::Binary { op, lhs, rhs } => self.compile_binary(op, lhs, rhs, line),
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
            Expr::Call { name, args } => {
                if !self.function_names.contains(name) {
                    return Err(err(line, format!("unknown function {name}")));
                }
                let mut registers = Vec::new();
                for arg in args {
                    registers.push(self.compile_expr(arg, line)?);
                }
                let dst = self.alloc();
                self.push(
                    line,
                    Instruction::Call {
                        dst,
                        function: name.clone(),
                        args: registers,
                    },
                );
                Ok(dst)
            }
        }
    }

    fn finish(mut self, module_constants: &mut Vec<Value>) -> Function {
        if !matches!(self.code.last(), Some(Instruction::Ret { .. })) {
            let dst = self.alloc();
            let constant = self.intern_constant(Value::Nil);
            self.push(0, Instruction::Const { dst, constant });
            self.push(0, Instruction::Ret { src: dst });
        }
        for instruction in &mut self.code {
            if let Instruction::Const { constant, .. } = instruction {
                let value = self.constants[*constant].clone();
                *constant = intern_module_constant(module_constants, value);
            }
        }
        Function {
            name: self.function_name,
            registers: self.next_register.max(1),
            arity: self.arity,
            code: self.code,
            source_lines: self.source_lines,
        }
    }

    fn push(&mut self, line: usize, instruction: Instruction) {
        self.code.push(instruction);
        self.source_lines
            .push(if line == 0 { None } else { Some(line) });
    }

    fn push_placeholder(&mut self, line: usize, instruction: Instruction) -> usize {
        let index = self.code.len();
        self.push(line, instruction);
        index
    }

    fn patch_target(&mut self, index: usize, target: usize) {
        match &mut self.code[index] {
            Instruction::Jump { target: existing }
            | Instruction::JumpIf {
                target: existing, ..
            } => *existing = target,
            _ => unreachable!("only jump instructions can be patched"),
        }
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

    fn compile_binary(
        &mut self,
        op: &BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        line: usize,
    ) -> Result<usize> {
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
            BinaryOp::Gt => Instruction::Lt {
                dst,
                lhs: rhs,
                rhs: lhs,
            },
            BinaryOp::Neq => {
                self.push(line, Instruction::Eq { dst, lhs, rhs });
                return self.compile_not(dst, line);
            }
            BinaryOp::Lte => {
                self.push(
                    line,
                    Instruction::Lt {
                        dst,
                        lhs: rhs,
                        rhs: lhs,
                    },
                );
                return self.compile_not(dst, line);
            }
            BinaryOp::Gte => {
                self.push(line, Instruction::Lt { dst, lhs, rhs });
                return self.compile_not(dst, line);
            }
            BinaryOp::And => return self.compile_and(lhs, rhs, line),
            BinaryOp::Or => return self.compile_or(lhs, rhs, line),
        };
        self.push(line, instruction);
        Ok(dst)
    }

    fn compile_not(&mut self, src: usize, line: usize) -> Result<usize> {
        let false_reg = self.alloc_bool(false, line);
        let dst = self.alloc();
        self.push(
            line,
            Instruction::Eq {
                dst,
                lhs: src,
                rhs: false_reg,
            },
        );
        Ok(dst)
    }

    fn compile_and(&mut self, lhs: usize, rhs: usize, line: usize) -> Result<usize> {
        let dst = self.alloc_bool(false, line);
        let jump_to_rhs = self.push_placeholder(
            line,
            Instruction::JumpIf {
                cond: lhs,
                target: 0,
            },
        );
        let jump_to_end = self.push_placeholder(line, Instruction::Jump { target: 0 });
        let rhs_start = self.code.len();
        self.patch_target(jump_to_rhs, rhs_start);
        self.push(line, Instruction::Move { dst, src: rhs });
        let end = self.code.len();
        self.patch_target(jump_to_end, end);
        Ok(dst)
    }

    fn compile_or(&mut self, lhs: usize, rhs: usize, line: usize) -> Result<usize> {
        let dst = self.alloc_bool(true, line);
        let jump_to_end_if_lhs = self.push_placeholder(
            line,
            Instruction::JumpIf {
                cond: lhs,
                target: 0,
            },
        );
        self.push(line, Instruction::Move { dst, src: rhs });
        let end = self.code.len();
        self.patch_target(jump_to_end_if_lhs, end);
        Ok(dst)
    }

    fn alloc_bool(&mut self, value: bool, line: usize) -> usize {
        let dst = self.alloc();
        let constant = self.intern_constant(Value::Bool(value));
        self.push(line, Instruction::Const { dst, constant });
        dst
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

fn logical_lines(source: &str) -> Vec<LogicalLine> {
    source
        .lines()
        .enumerate()
        .filter_map(|(index, raw_line)| {
            let text = strip_comment(raw_line).trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(LogicalLine {
                    line: index + 1,
                    text,
                })
            }
        })
        .collect()
}

fn collect_function_body(lines: &[LogicalLine], index: &mut usize) -> Result<Vec<LogicalLine>> {
    let fn_line = lines[*index].line;
    *index += 1;
    let mut depth = 0usize;
    let mut body = Vec::new();
    while *index < lines.len() {
        let line = &lines[*index];
        if starts_block(&line.text) {
            depth += 1;
            body.push(line.clone());
            *index += 1;
        } else if line.text == "end" {
            if depth == 0 {
                *index += 1;
                return Ok(body);
            }
            depth -= 1;
            body.push(line.clone());
            *index += 1;
        } else {
            body.push(line.clone());
            *index += 1;
        }
    }
    Err(err(fn_line, "function missing end"))
}

fn parse_block(
    lines: &[LogicalLine],
    index: &mut usize,
    stop_on_else: bool,
) -> Result<Vec<SourceStatement>> {
    let mut statements = Vec::new();
    while *index < lines.len() {
        let line = &lines[*index];
        if line.text == "end" || (stop_on_else && line.text == "else") {
            break;
        }
        if line.text == "else" {
            return Err(err(line.line, "else without matching if"));
        }
        if let Some(rest) = line.text.strip_prefix("if ") {
            let condition = parse_expr(line.line, rest.trim())?;
            *index += 1;
            let then_body = parse_block(lines, index, true)?;
            let else_body = if *index < lines.len() && lines[*index].text == "else" {
                *index += 1;
                parse_block(lines, index, false)?
            } else {
                Vec::new()
            };
            if *index >= lines.len() || lines[*index].text != "end" {
                return Err(err(line.line, "if missing end"));
            }
            *index += 1;
            statements.push(SourceStatement {
                line: line.line,
                kind: Statement::If {
                    condition,
                    then_body,
                    else_body,
                },
            });
        } else if let Some(rest) = line.text.strip_prefix("while ") {
            let condition = parse_expr(line.line, rest.trim())?;
            *index += 1;
            let body = parse_block(lines, index, false)?;
            if *index >= lines.len() || lines[*index].text != "end" {
                return Err(err(line.line, "while missing end"));
            }
            *index += 1;
            statements.push(SourceStatement {
                line: line.line,
                kind: Statement::While { condition, body },
            });
        } else {
            statements.push(SourceStatement {
                line: line.line,
                kind: parse_statement(line.line, &line.text)?,
            });
            *index += 1;
        }
    }
    Ok(statements)
}

fn starts_block(line: &str) -> bool {
    line.starts_with("if ") || line.starts_with("while ")
}

fn block_returns(statements: &[SourceStatement]) -> bool {
    statements
        .last()
        .is_some_and(|statement| statement_returns(&statement.kind))
}

fn statement_returns(statement: &Statement) -> bool {
    match statement {
        Statement::Return(_) => true,
        Statement::If {
            then_body,
            else_body,
            ..
        } => !else_body.is_empty() && block_returns(then_body) && block_returns(else_body),
        _ => false,
    }
}

fn parse_expr(line_no: usize, input: &str) -> Result<Expr> {
    let input = strip_outer_parens(input.trim());
    for (needle, op) in [
        (" or ", BinaryOp::Or),
        (" and ", BinaryOp::And),
        (" == ", BinaryOp::Eq),
        (" != ", BinaryOp::Neq),
        (" <= ", BinaryOp::Lte),
        (" >= ", BinaryOp::Gte),
        (" < ", BinaryOp::Lt),
        (" > ", BinaryOp::Gt),
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

    if let Some(rest) = input.strip_prefix("not ") {
        return Ok(Expr::Unary {
            op: UnaryOp::Not,
            expr: Box::new(parse_expr(line_no, rest)?),
        });
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

    if let Some((name, args)) = parse_call_shape(line_no, input)? {
        if name == "print" {
            return Ok(Expr::CapCall {
                name: "log.print@1".into(),
                args,
            });
        }
        return Ok(Expr::Call { name, args });
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

fn strip_outer_parens(mut input: &str) -> &str {
    loop {
        let trimmed = input.trim();
        if !(trimmed.starts_with('(') && trimmed.ends_with(')')) {
            return trimmed;
        }
        let mut in_string = false;
        let mut depth = 0usize;
        let mut wraps = true;
        for (index, ch) in trimmed.char_indices() {
            match ch {
                '"' => in_string = !in_string,
                '(' if !in_string => depth += 1,
                ')' if !in_string => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 && index != trimmed.len() - 1 {
                        wraps = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if wraps {
            input = &trimmed[1..trimmed.len() - 1];
        } else {
            return trimmed;
        }
    }
}

fn parse_function_header(line_no: usize, input: &str) -> Result<(String, Vec<String>)> {
    if let Some(open) = input.find('(') {
        if !input.ends_with(')') {
            return Err(err(line_no, "function header missing ')'"));
        }
        let name = input[..open].trim();
        validate_ident(line_no, name)?;
        let params = split_args(line_no, &input[open + 1..input.len() - 1])?;
        for param in &params {
            validate_ident(line_no, param)?;
        }
        Ok((name.to_string(), params))
    } else {
        validate_ident(line_no, input)?;
        Ok((input.to_string(), Vec::new()))
    }
}

fn parse_call_shape(line_no: usize, input: &str) -> Result<Option<(String, Vec<Expr>)>> {
    let Some(open) = input.find('(') else {
        return Ok(None);
    };
    if !input.ends_with(')') {
        return Ok(None);
    }
    let name = input[..open].trim();
    if !is_valid_ident(name) {
        return Ok(None);
    }
    let inner = &input[open + 1..input.len() - 1];
    Ok(Some((
        name.to_string(),
        split_args(line_no, inner)?
            .into_iter()
            .map(|arg| parse_expr(line_no, &arg))
            .collect::<Result<Vec<_>>>()?,
    )))
}

fn intern_module_constant(constants: &mut Vec<Value>, value: Value) -> usize {
    if let Some(index) = constants.iter().position(|existing| existing == &value) {
        index
    } else {
        constants.push(value);
        constants.len() - 1
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
    let (signature, tail) = input
        .split_once("->")
        .ok_or_else(|| err(line_no, "cap expects id(params) -> return_type"))?;
    let open = signature
        .find('(')
        .ok_or_else(|| err(line_no, "cap signature expects id(params)"))?;
    let close = signature
        .rfind(')')
        .ok_or_else(|| err(line_no, "cap signature missing ')'"))?;
    let id = signature[..open].trim();
    validate_cap_name(line_no, id)?;
    let params = split_args(line_no, &signature[open + 1..close])?
        .into_iter()
        .map(|value| parse_value_type(line_no, &value))
        .collect::<Result<Vec<_>>>()?;
    let mut tail_parts = tail.trim().splitn(2, char::is_whitespace);
    let return_type = parse_value_type(
        line_no,
        tail_parts
            .next()
            .ok_or_else(|| err(line_no, "cap expects return type"))?,
    )?;
    let reason = tail_parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse_quoted(line_no, value))
        .transpose()?;
    Ok(CapabilityDecl {
        id: id.to_string(),
        params,
        return_type,
        reason,
    })
}

fn parse_value_type(line_no: usize, input: &str) -> Result<ValueType> {
    match input.trim() {
        "nil" => Ok(ValueType::Nil),
        "bool" => Ok(ValueType::Bool),
        "i64" => Ok(ValueType::I64),
        "f64" => Ok(ValueType::F64),
        "string" => Ok(ValueType::String),
        "array" => Ok(ValueType::Array),
        "function" => Ok(ValueType::Function),
        "capability" => Ok(ValueType::Capability),
        "any" => Ok(ValueType::Any),
        "any..." => Ok(ValueType::AnyVariadic),
        other => Err(err(line_no, format!("unknown value type {other}"))),
    }
}

fn render_casm(module: &Module) -> String {
    let mut out = String::new();
    out.push_str(&format!(".module \"{}\"\n", escape_string(&module.name)));
    for capability in &module.capabilities {
        out.push_str(&format!(".cap {}(", capability.id));
        out.push_str(
            &capability
                .params
                .iter()
                .map(render_value_type)
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str(&format!(
            ") -> {}",
            render_value_type(&capability.return_type)
        ));
        if let Some(reason) = &capability.reason {
            out.push_str(&format!(" reason=\"{}\"", escape_string(reason)));
        }
        out.push('\n');
    }
    out.push('\n');

    for function in &module.functions {
        out.push_str(&format!(".fn {} r{}", function.name, function.registers));
        if function.arity > 0 {
            out.push_str(&format!(" arity={}", function.arity));
        }
        out.push('\n');
        for instruction in &function.code {
            out.push_str("  ");
            out.push_str(&render_instruction(instruction, &module.constants));
            out.push('\n');
        }
        out.push_str(".end\n\n");
    }
    out
}

fn render_value_type(value_type: &ValueType) -> String {
    match value_type {
        ValueType::Nil => "nil",
        ValueType::Bool => "bool",
        ValueType::I64 => "i64",
        ValueType::F64 => "f64",
        ValueType::String => "string",
        ValueType::Array => "array",
        ValueType::Function => "function",
        ValueType::Capability => "capability",
        ValueType::Any => "any",
        ValueType::AnyVariadic => "any...",
    }
    .into()
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
    if is_valid_ident(input) {
        Ok(())
    } else {
        Err(err(line_no, format!("invalid identifier {input}")))
    }
}

fn is_valid_ident(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn validate_cap_name(line_no: usize, input: &str) -> Result<()> {
    if input.is_empty()
        || !input.chars().all(|ch| {
            ch == '.' || ch == '@' || ch == '_' || ch == '-' || ch.is_ascii_alphanumeric()
        })
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
          cap log.print@1(any...) -> nil "audit"
          cap clock.now@1() -> i64 "time"
          cap random.u64@1() -> i64 "request id"

          fn main
            let started = "plugin started"
            cap log.print@1(started)
            let now = cap clock.now@1()
            let request = cap random.u64@1()
            let result = [now, request]
            return result
          end
        "#;
        let compiled = Compiler::compile(source).unwrap();
        assert_eq!(compiled.module.name, "safe_plugin");
        assert!(compiled.casm.contains(".cap log.print@1"));
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
            cap log.print@1("hello")
          end
        "#;
        assert!(Compiler::compile(source).is_err());
    }

    #[test]
    fn compiles_functions_branches_and_loops() {
        let source = r#"
          module language_demo

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
        "#;
        let compiled = Compiler::compile(source).unwrap();
        assert_eq!(compiled.module.functions.len(), 2);
        assert!(compiled.casm.contains(".fn bump r"));
        assert!(compiled.casm.contains("arity=1"));
        assert!(compiled.casm.contains("jump_if"));
        assert!(compiled.casm.contains("call r"));
    }

    #[test]
    fn block_local_variables_do_not_leak() {
        let source = r#"
          module scoped
          fn main
            if true
              let hidden = 1
            end
            return hidden
          end
        "#;
        assert!(Compiler::compile(source).is_err());
    }

    #[test]
    fn compiles_parentheses_boolean_ops_and_print_sugar() {
        let source = r#"
          module ergonomic
          cap log.print@1(any...) -> nil "audit"

          fn main
            let score = 7
            if (score >= 5) and not (score != 7)
              print("accepted", score)
              return score > 6
            else
              print("rejected", score)
              return score <= 6
            end
          end
        "#;
        let compiled = Compiler::compile(source).unwrap();
        assert!(compiled.casm.contains("cap_call"));
        assert!(compiled.casm.contains("log.print@1"));
        assert!(compiled.casm.contains("lt r"));
        assert!(compiled.casm.contains("eq r"));
    }
}
