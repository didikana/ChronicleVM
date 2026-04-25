use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MODULE_MAGIC: &[u8; 8] = b"CHVMOD1\0";

#[derive(Debug, Error)]
pub enum ChronicleError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("verify error: {0}")]
    Verify(String),
    #[error("capability error: {0}")]
    Capability(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("replay divergence: {0}")]
    Replay(String),
}

pub type Result<T> = std::result::Result<T, ChronicleError>;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Nil,
    Bool(bool),
    I64(i64),
    F64(f64),
    String(String),
    Array(Vec<Value>),
    Function(String),
    Capability(String),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Nil => false,
            Value::Bool(v) => *v,
            Value::I64(v) => *v != 0,
            Value::F64(v) => *v != 0.0,
            Value::String(v) => !v.is_empty(),
            Value::Array(v) => !v.is_empty(),
            Value::Function(_) | Value::Capability(_) => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDecl {
    pub name: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub constants: Vec<Value>,
    pub capabilities: Vec<CapabilityDecl>,
    pub functions: Vec<Function>,
    pub exports: BTreeMap<String, usize>,
}

impl Module {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(MODULE_MAGIC) {
            BinaryModuleReader::new(bytes).read_module()
        } else {
            serde_json::from_slice(bytes).map_err(|err| ChronicleError::Decode(err.to_string()))
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = BinaryModuleWriter::default();
        writer.write_module(self)?;
        Ok(writer.bytes)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|err| ChronicleError::Decode(err.to_string()))
    }

    pub fn function_index(&self, name: &str) -> Option<usize> {
        self.functions
            .iter()
            .position(|function| function.name == name)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub registers: usize,
    pub arity: usize,
    pub code: Vec<Instruction>,
    #[serde(default)]
    pub source_lines: Vec<Option<usize>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    Const {
        dst: usize,
        constant: usize,
    },
    Move {
        dst: usize,
        src: usize,
    },
    Add {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Sub {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Mul {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Div {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Eq {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Lt {
        dst: usize,
        lhs: usize,
        rhs: usize,
    },
    Jump {
        target: usize,
    },
    JumpIf {
        cond: usize,
        target: usize,
    },
    Call {
        dst: usize,
        function: String,
        args: Vec<usize>,
    },
    Ret {
        src: usize,
    },
    CapCall {
        dst: usize,
        capability: String,
        args: Vec<usize>,
    },
    ArrayNew {
        dst: usize,
        items: Vec<usize>,
    },
    ArrayGet {
        dst: usize,
        array: usize,
        index: usize,
    },
    ArraySet {
        array: usize,
        index: usize,
        value: usize,
    },
}

impl Instruction {
    pub fn opcode(&self) -> &'static str {
        match self {
            Instruction::Const { .. } => "const",
            Instruction::Move { .. } => "move",
            Instruction::Add { .. } => "add",
            Instruction::Sub { .. } => "sub",
            Instruction::Mul { .. } => "mul",
            Instruction::Div { .. } => "div",
            Instruction::Eq { .. } => "eq",
            Instruction::Lt { .. } => "lt",
            Instruction::Jump { .. } => "jump",
            Instruction::JumpIf { .. } => "jump_if",
            Instruction::Call { .. } => "call",
            Instruction::Ret { .. } => "ret",
            Instruction::CapCall { .. } => "cap_call",
            Instruction::ArrayNew { .. } => "array_new",
            Instruction::ArrayGet { .. } => "array_get",
            Instruction::ArraySet { .. } => "array_set",
        }
    }
}

#[derive(Default)]
struct BinaryModuleWriter {
    bytes: Vec<u8>,
}

impl BinaryModuleWriter {
    fn write_module(&mut self, module: &Module) -> Result<()> {
        self.bytes.extend_from_slice(MODULE_MAGIC);
        self.write_string(&module.name)?;
        self.write_len(module.constants.len())?;
        for value in &module.constants {
            self.write_value(value)?;
        }
        self.write_len(module.capabilities.len())?;
        for capability in &module.capabilities {
            self.write_string(&capability.name)?;
            self.write_optional_string(capability.reason.as_deref())?;
        }
        self.write_len(module.functions.len())?;
        for function in &module.functions {
            self.write_string(&function.name)?;
            self.write_usize(function.registers)?;
            self.write_usize(function.arity)?;
            self.write_len(function.code.len())?;
            for instruction in &function.code {
                self.write_instruction(instruction)?;
            }
            self.write_len(function.source_lines.len())?;
            for line in &function.source_lines {
                match line {
                    Some(line) => {
                        self.write_u8(1);
                        self.write_usize(*line)?;
                    }
                    None => self.write_u8(0),
                }
            }
        }
        self.write_len(module.exports.len())?;
        for (name, index) in &module.exports {
            self.write_string(name)?;
            self.write_usize(*index)?;
        }
        Ok(())
    }

    fn write_instruction(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction {
            Instruction::Const { dst, constant } => {
                self.write_u8(0);
                self.write_usize(*dst)?;
                self.write_usize(*constant)?;
            }
            Instruction::Move { dst, src } => {
                self.write_u8(1);
                self.write_usize(*dst)?;
                self.write_usize(*src)?;
            }
            Instruction::Add { dst, lhs, rhs } => self.write_three_reg(2, *dst, *lhs, *rhs)?,
            Instruction::Sub { dst, lhs, rhs } => self.write_three_reg(3, *dst, *lhs, *rhs)?,
            Instruction::Mul { dst, lhs, rhs } => self.write_three_reg(4, *dst, *lhs, *rhs)?,
            Instruction::Div { dst, lhs, rhs } => self.write_three_reg(5, *dst, *lhs, *rhs)?,
            Instruction::Eq { dst, lhs, rhs } => self.write_three_reg(6, *dst, *lhs, *rhs)?,
            Instruction::Lt { dst, lhs, rhs } => self.write_three_reg(7, *dst, *lhs, *rhs)?,
            Instruction::Jump { target } => {
                self.write_u8(8);
                self.write_usize(*target)?;
            }
            Instruction::JumpIf { cond, target } => {
                self.write_u8(9);
                self.write_usize(*cond)?;
                self.write_usize(*target)?;
            }
            Instruction::Call {
                dst,
                function,
                args,
            } => {
                self.write_u8(10);
                self.write_usize(*dst)?;
                self.write_string(function)?;
                self.write_usize_vec(args)?;
            }
            Instruction::Ret { src } => {
                self.write_u8(11);
                self.write_usize(*src)?;
            }
            Instruction::CapCall {
                dst,
                capability,
                args,
            } => {
                self.write_u8(12);
                self.write_usize(*dst)?;
                self.write_string(capability)?;
                self.write_usize_vec(args)?;
            }
            Instruction::ArrayNew { dst, items } => {
                self.write_u8(13);
                self.write_usize(*dst)?;
                self.write_usize_vec(items)?;
            }
            Instruction::ArrayGet { dst, array, index } => {
                self.write_u8(14);
                self.write_usize(*dst)?;
                self.write_usize(*array)?;
                self.write_usize(*index)?;
            }
            Instruction::ArraySet {
                array,
                index,
                value,
            } => {
                self.write_u8(15);
                self.write_usize(*array)?;
                self.write_usize(*index)?;
                self.write_usize(*value)?;
            }
        }
        Ok(())
    }

    fn write_three_reg(&mut self, tag: u8, dst: usize, lhs: usize, rhs: usize) -> Result<()> {
        self.write_u8(tag);
        self.write_usize(dst)?;
        self.write_usize(lhs)?;
        self.write_usize(rhs)?;
        Ok(())
    }

    fn write_value(&mut self, value: &Value) -> Result<()> {
        match value {
            Value::Nil => self.write_u8(0),
            Value::Bool(value) => {
                self.write_u8(1);
                self.write_u8(u8::from(*value));
            }
            Value::I64(value) => {
                self.write_u8(2);
                self.bytes.extend_from_slice(&value.to_le_bytes());
            }
            Value::F64(value) => {
                self.write_u8(3);
                self.bytes.extend_from_slice(&value.to_le_bytes());
            }
            Value::String(value) => {
                self.write_u8(4);
                self.write_string(value)?;
            }
            Value::Array(values) => {
                self.write_u8(5);
                self.write_len(values.len())?;
                for value in values {
                    self.write_value(value)?;
                }
            }
            Value::Function(value) => {
                self.write_u8(6);
                self.write_string(value)?;
            }
            Value::Capability(value) => {
                self.write_u8(7);
                self.write_string(value)?;
            }
        }
        Ok(())
    }

    fn write_optional_string(&mut self, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => {
                self.write_u8(1);
                self.write_string(value)?;
            }
            None => self.write_u8(0),
        }
        Ok(())
    }

    fn write_usize_vec(&mut self, values: &[usize]) -> Result<()> {
        self.write_len(values.len())?;
        for value in values {
            self.write_usize(*value)?;
        }
        Ok(())
    }

    fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_len(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn write_len(&mut self, value: usize) -> Result<()> {
        self.write_usize(value)
    }

    fn write_usize(&mut self, value: usize) -> Result<()> {
        let value = u32::try_from(value)
            .map_err(|_| ChronicleError::Decode("value exceeds binary module u32 limit".into()))?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
}

struct BinaryModuleReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryModuleReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_module(&mut self) -> Result<Module> {
        self.expect_magic()?;
        let name = self.read_string()?;
        let constants = self.read_many(Self::read_value)?;
        let capabilities = self.read_many(|reader| {
            Ok(CapabilityDecl {
                name: reader.read_string()?,
                reason: reader.read_optional_string()?,
            })
        })?;
        let functions = self.read_many(|reader| {
            let name = reader.read_string()?;
            let registers = reader.read_usize()?;
            let arity = reader.read_usize()?;
            let code = reader.read_many(Self::read_instruction)?;
            let source_lines = reader.read_many(|reader| {
                Ok(match reader.read_u8()? {
                    0 => None,
                    1 => Some(reader.read_usize()?),
                    tag => {
                        return Err(ChronicleError::Decode(format!(
                            "invalid source line tag {tag}"
                        )))
                    }
                })
            })?;
            Ok(Function {
                name,
                registers,
                arity,
                code,
                source_lines,
            })
        })?;
        let exports = self.read_many(|reader| Ok((reader.read_string()?, reader.read_usize()?)))?;
        if self.offset != self.bytes.len() {
            return Err(ChronicleError::Decode(
                "trailing bytes in binary module".into(),
            ));
        }
        Ok(Module {
            name,
            constants,
            capabilities,
            functions,
            exports: exports.into_iter().collect(),
        })
    }

    fn read_instruction(&mut self) -> Result<Instruction> {
        Ok(match self.read_u8()? {
            0 => Instruction::Const {
                dst: self.read_usize()?,
                constant: self.read_usize()?,
            },
            1 => Instruction::Move {
                dst: self.read_usize()?,
                src: self.read_usize()?,
            },
            2 => self.read_three_reg(|dst, lhs, rhs| Instruction::Add { dst, lhs, rhs })?,
            3 => self.read_three_reg(|dst, lhs, rhs| Instruction::Sub { dst, lhs, rhs })?,
            4 => self.read_three_reg(|dst, lhs, rhs| Instruction::Mul { dst, lhs, rhs })?,
            5 => self.read_three_reg(|dst, lhs, rhs| Instruction::Div { dst, lhs, rhs })?,
            6 => self.read_three_reg(|dst, lhs, rhs| Instruction::Eq { dst, lhs, rhs })?,
            7 => self.read_three_reg(|dst, lhs, rhs| Instruction::Lt { dst, lhs, rhs })?,
            8 => Instruction::Jump {
                target: self.read_usize()?,
            },
            9 => Instruction::JumpIf {
                cond: self.read_usize()?,
                target: self.read_usize()?,
            },
            10 => Instruction::Call {
                dst: self.read_usize()?,
                function: self.read_string()?,
                args: self.read_usize_vec()?,
            },
            11 => Instruction::Ret {
                src: self.read_usize()?,
            },
            12 => Instruction::CapCall {
                dst: self.read_usize()?,
                capability: self.read_string()?,
                args: self.read_usize_vec()?,
            },
            13 => Instruction::ArrayNew {
                dst: self.read_usize()?,
                items: self.read_usize_vec()?,
            },
            14 => Instruction::ArrayGet {
                dst: self.read_usize()?,
                array: self.read_usize()?,
                index: self.read_usize()?,
            },
            15 => Instruction::ArraySet {
                array: self.read_usize()?,
                index: self.read_usize()?,
                value: self.read_usize()?,
            },
            tag => {
                return Err(ChronicleError::Decode(format!(
                    "unknown instruction tag {tag}"
                )))
            }
        })
    }

    fn read_three_reg(
        &mut self,
        make: impl FnOnce(usize, usize, usize) -> Instruction,
    ) -> Result<Instruction> {
        let dst = self.read_usize()?;
        let lhs = self.read_usize()?;
        let rhs = self.read_usize()?;
        Ok(make(dst, lhs, rhs))
    }

    fn read_value(&mut self) -> Result<Value> {
        Ok(match self.read_u8()? {
            0 => Value::Nil,
            1 => Value::Bool(match self.read_u8()? {
                0 => false,
                1 => true,
                tag => return Err(ChronicleError::Decode(format!("invalid bool tag {tag}"))),
            }),
            2 => Value::I64(i64::from_le_bytes(self.read_array()?)),
            3 => Value::F64(f64::from_le_bytes(self.read_array()?)),
            4 => Value::String(self.read_string()?),
            5 => Value::Array(self.read_many(Self::read_value)?),
            6 => Value::Function(self.read_string()?),
            7 => Value::Capability(self.read_string()?),
            tag => return Err(ChronicleError::Decode(format!("unknown value tag {tag}"))),
        })
    }

    fn read_optional_string(&mut self) -> Result<Option<String>> {
        Ok(match self.read_u8()? {
            0 => None,
            1 => Some(self.read_string()?),
            tag => return Err(ChronicleError::Decode(format!("invalid option tag {tag}"))),
        })
    }

    fn read_usize_vec(&mut self) -> Result<Vec<usize>> {
        self.read_many(Self::read_usize)
    }

    fn read_many<T>(&mut self, mut read: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let len = self.read_usize()?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(read(self)?);
        }
        Ok(values)
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_usize()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|err| ChronicleError::Decode(err.to_string()))
    }

    fn read_usize(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.read_array()?) as usize)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChronicleError::Decode("failed to read fixed-width bytes".into()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| ChronicleError::Decode("binary module offset overflow".into()))?;
        if end > self.bytes.len() {
            return Err(ChronicleError::Decode(
                "unexpected end of binary module".into(),
            ));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn expect_magic(&mut self) -> Result<()> {
        let magic = self.take(MODULE_MAGIC.len())?;
        if magic == MODULE_MAGIC {
            Ok(())
        } else {
            Err(ChronicleError::Decode("invalid binary module magic".into()))
        }
    }
}

pub struct Verifier;

impl Verifier {
    pub fn verify(module: &Module) -> Result<()> {
        for (export, index) in &module.exports {
            if *index >= module.functions.len() {
                return Err(ChronicleError::Verify(format!(
                    "export {export} points to missing function {index}"
                )));
            }
        }

        for function in &module.functions {
            if function.registers == 0 {
                return Err(ChronicleError::Verify(format!(
                    "function {} must have at least one register",
                    function.name
                )));
            }
            if function.arity > function.registers {
                return Err(ChronicleError::Verify(format!(
                    "function {} arity exceeds register count",
                    function.name
                )));
            }
            if !function.source_lines.is_empty()
                && function.source_lines.len() != function.code.len()
            {
                return Err(ChronicleError::Verify(format!(
                    "function {} source line map length does not match code length",
                    function.name
                )));
            }
            for (pc, instruction) in function.code.iter().enumerate() {
                verify_instruction(module, function, pc, instruction)?;
            }
        }

        Ok(())
    }
}

fn verify_instruction(
    module: &Module,
    function: &Function,
    pc: usize,
    instruction: &Instruction,
) -> Result<()> {
    let reg = |register: usize| -> Result<()> {
        if register >= function.registers {
            Err(ChronicleError::Verify(format!(
                "{} pc {pc}: register r{register} out of bounds",
                function.name
            )))
        } else {
            Ok(())
        }
    };
    let target = |target: usize| -> Result<()> {
        if target >= function.code.len() {
            Err(ChronicleError::Verify(format!(
                "{} pc {pc}: jump target {target} out of bounds",
                function.name
            )))
        } else {
            Ok(())
        }
    };

    match instruction {
        Instruction::Const { dst, constant } => {
            reg(*dst)?;
            if *constant >= module.constants.len() {
                return Err(ChronicleError::Verify(format!(
                    "{} pc {pc}: constant {constant} out of bounds",
                    function.name
                )));
            }
        }
        Instruction::Move { dst, src } => {
            reg(*dst)?;
            reg(*src)?;
        }
        Instruction::Add { dst, lhs, rhs }
        | Instruction::Sub { dst, lhs, rhs }
        | Instruction::Mul { dst, lhs, rhs }
        | Instruction::Div { dst, lhs, rhs }
        | Instruction::Eq { dst, lhs, rhs }
        | Instruction::Lt { dst, lhs, rhs } => {
            reg(*dst)?;
            reg(*lhs)?;
            reg(*rhs)?;
        }
        Instruction::Jump {
            target: jump_target,
        } => target(*jump_target)?,
        Instruction::JumpIf {
            cond,
            target: jump_target,
        } => {
            reg(*cond)?;
            target(*jump_target)?;
        }
        Instruction::Call {
            dst,
            function: callee,
            args,
        } => {
            reg(*dst)?;
            for arg in args {
                reg(*arg)?;
            }
            let Some(callee_index) = module.function_index(callee) else {
                return Err(ChronicleError::Verify(format!(
                    "{} pc {pc}: missing callee {callee}",
                    function.name
                )));
            };
            if module.functions[callee_index].arity != args.len() {
                return Err(ChronicleError::Verify(format!(
                    "{} pc {pc}: callee {callee} expects {} args, got {}",
                    function.name,
                    module.functions[callee_index].arity,
                    args.len()
                )));
            }
        }
        Instruction::Ret { src } => reg(*src)?,
        Instruction::CapCall {
            dst,
            capability,
            args,
        } => {
            reg(*dst)?;
            for arg in args {
                reg(*arg)?;
            }
            if !module
                .capabilities
                .iter()
                .any(|decl| decl.name == *capability)
            {
                return Err(ChronicleError::Verify(format!(
                    "{} pc {pc}: capability {capability} was not declared",
                    function.name
                )));
            }
        }
        Instruction::ArrayNew { dst, items } => {
            reg(*dst)?;
            for item in items {
                reg(*item)?;
            }
        }
        Instruction::ArrayGet { dst, array, index } => {
            reg(*dst)?;
            reg(*array)?;
            reg(*index)?;
        }
        Instruction::ArraySet {
            array,
            index,
            value,
        } => {
            reg(*array)?;
            reg(*index)?;
            reg(*value)?;
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDecision {
    Grant,
    Deny,
    Mock(Value),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HostPolicy {
    pub decisions: BTreeMap<String, CapabilityDecision>,
}

impl HostPolicy {
    pub fn decision_for(&self, capability: &str) -> CapabilityDecision {
        self.decisions
            .get(capability)
            .cloned()
            .unwrap_or(CapabilityDecision::Deny)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub module: Module,
    pub entry: String,
    pub events: Vec<TraceEvent>,
    pub result: Option<Value>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub function: String,
    pub pc: usize,
    pub source_line: Option<usize>,
    pub opcode: String,
    pub register_changes: Vec<RegisterChange>,
    pub capability: Option<CapabilityTrace>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegisterChange {
    pub register: usize,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityTrace {
    pub name: String,
    pub args: Vec<Value>,
    pub result: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub events_checked: usize,
    pub result: Option<Value>,
}

#[derive(Clone)]
pub struct Vm {
    module: Module,
    capabilities: BTreeMap<String, CapabilityDecision>,
    replay_capabilities: Vec<CapabilityTrace>,
    replay_capability_index: usize,
}

impl Vm {
    pub fn new(module: Module, host_policy: HostPolicy) -> Result<Self> {
        Verifier::verify(&module)?;
        let mut capabilities = BTreeMap::new();
        for decl in &module.capabilities {
            let decision = host_policy.decision_for(&decl.name);
            if matches!(decision, CapabilityDecision::Deny) {
                return Err(ChronicleError::Capability(format!(
                    "capability {} denied",
                    decl.name
                )));
            }
            capabilities.insert(decl.name.clone(), decision);
        }
        Ok(Self {
            module,
            capabilities,
            replay_capabilities: Vec::new(),
            replay_capability_index: 0,
        })
    }

    pub fn run_entry(&mut self, entry: &str) -> Result<Value> {
        let (result, _) = self.execute_collect(entry, true);
        result
    }

    pub fn run_with_trace(&mut self, entry: &str) -> Result<Trace> {
        let (result, events) = self.execute_collect(entry, true);
        match result {
            Ok(result) => Ok(Trace {
                module: self.module.clone(),
                entry: entry.to_string(),
                events,
                result: Some(result),
                error: None,
            }),
            Err(err) => Ok(Trace {
                module: self.module.clone(),
                entry: entry.to_string(),
                events,
                result: None,
                error: Some(err.to_string()),
            }),
        }
    }

    pub fn replay(trace: Trace) -> Result<ReplayReport> {
        Verifier::verify(&trace.module)?;
        let capability_results = trace
            .events
            .iter()
            .filter_map(|event| event.capability.clone())
            .collect::<Vec<_>>();
        let mut capabilities = BTreeMap::new();
        for decl in &trace.module.capabilities {
            capabilities.insert(decl.name.clone(), CapabilityDecision::Grant);
        }
        let mut vm = Self {
            module: trace.module.clone(),
            capabilities,
            replay_capabilities: capability_results,
            replay_capability_index: 0,
        };
        let (result, events) = vm.execute_collect(&trace.entry, false);
        let result = result?;
        if events != trace.events {
            return Err(ChronicleError::Replay(
                "trace events did not match replay".into(),
            ));
        }
        if Some(result.clone()) != trace.result {
            return Err(ChronicleError::Replay(
                "trace result did not match replay".into(),
            ));
        }
        Ok(ReplayReport {
            events_checked: events.len(),
            result: Some(result),
        })
    }

    fn execute_collect(
        &mut self,
        entry: &str,
        live_capabilities: bool,
    ) -> (Result<Value>, Vec<TraceEvent>) {
        let mut events = Vec::new();
        let Some(index) = self.module.exports.get(entry).copied() else {
            return (
                Err(ChronicleError::Runtime(format!(
                    "missing entry export {entry}"
                ))),
                events,
            );
        };
        let result = self.execute_function(index, Vec::new(), &mut events, live_capabilities);
        (result, events)
    }

    fn execute_function(
        &mut self,
        function_index: usize,
        args: Vec<Value>,
        events: &mut Vec<TraceEvent>,
        live_capabilities: bool,
    ) -> Result<Value> {
        let function = self.module.functions[function_index].clone();
        let mut registers = vec![Value::Nil; function.registers];
        for (index, arg) in args.into_iter().enumerate() {
            registers[index] = arg;
        }
        let mut pc = 0;
        while pc < function.code.len() {
            let instruction = function.code[pc].clone();
            let mut event = TraceEvent {
                function: function.name.clone(),
                pc,
                source_line: function.source_lines.get(pc).copied().flatten(),
                opcode: instruction.opcode().to_string(),
                register_changes: Vec::new(),
                capability: None,
                error: None,
            };
            let mut next_pc = pc + 1;
            let step = self.apply_instruction(
                &function,
                &mut registers,
                &instruction,
                &mut next_pc,
                &mut event,
                events,
                live_capabilities,
            );
            match step {
                Ok(Some(value)) => {
                    events.push(event);
                    return Ok(value);
                }
                Ok(None) => {
                    events.push(event);
                    pc = next_pc;
                }
                Err(err) => {
                    event.error = Some(err.to_string());
                    events.push(event);
                    return Err(err);
                }
            }
        }
        Err(ChronicleError::Runtime(format!(
            "function {} ended without ret",
            function.name
        )))
    }

    fn apply_instruction(
        &mut self,
        function: &Function,
        registers: &mut [Value],
        instruction: &Instruction,
        next_pc: &mut usize,
        event: &mut TraceEvent,
        events: &mut Vec<TraceEvent>,
        live_capabilities: bool,
    ) -> Result<Option<Value>> {
        match instruction {
            Instruction::Const { dst, constant } => {
                set_reg(
                    registers,
                    event,
                    *dst,
                    self.module.constants[*constant].clone(),
                );
            }
            Instruction::Move { dst, src } => {
                set_reg(registers, event, *dst, registers[*src].clone());
            }
            Instruction::Add { dst, lhs, rhs } => {
                let value = numeric(
                    registers[*lhs].clone(),
                    registers[*rhs].clone(),
                    |a, b| a + b,
                    |a, b| a + b,
                )?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::Sub { dst, lhs, rhs } => {
                let value = numeric(
                    registers[*lhs].clone(),
                    registers[*rhs].clone(),
                    |a, b| a - b,
                    |a, b| a - b,
                )?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::Mul { dst, lhs, rhs } => {
                let value = numeric(
                    registers[*lhs].clone(),
                    registers[*rhs].clone(),
                    |a, b| a * b,
                    |a, b| a * b,
                )?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::Div { dst, lhs, rhs } => {
                if matches!(&registers[*rhs], Value::I64(0) | Value::F64(0.0)) {
                    return Err(ChronicleError::Runtime("division by zero".into()));
                }
                let value = numeric(
                    registers[*lhs].clone(),
                    registers[*rhs].clone(),
                    |a, b| a / b,
                    |a, b| a / b,
                )?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::Eq { dst, lhs, rhs } => {
                set_reg(
                    registers,
                    event,
                    *dst,
                    Value::Bool(registers[*lhs] == registers[*rhs]),
                );
            }
            Instruction::Lt { dst, lhs, rhs } => {
                let value = compare_lt(&registers[*lhs], &registers[*rhs])?;
                set_reg(registers, event, *dst, Value::Bool(value));
            }
            Instruction::Jump { target } => *next_pc = *target,
            Instruction::JumpIf { cond, target } => {
                if registers[*cond].truthy() {
                    *next_pc = *target;
                }
            }
            Instruction::Call {
                dst,
                function: callee,
                args,
            } => {
                let callee_index = self
                    .module
                    .function_index(callee)
                    .ok_or_else(|| ChronicleError::Runtime(format!("missing callee {callee}")))?;
                let call_args = args.iter().map(|arg| registers[*arg].clone()).collect();
                let value =
                    self.execute_function(callee_index, call_args, events, live_capabilities)?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::Ret { src } => return Ok(Some(registers[*src].clone())),
            Instruction::CapCall {
                dst,
                capability,
                args,
            } => {
                let call_args = args
                    .iter()
                    .map(|arg| registers[*arg].clone())
                    .collect::<Vec<_>>();
                let value =
                    self.call_capability(capability, call_args.clone(), live_capabilities)?;
                event.capability = Some(CapabilityTrace {
                    name: capability.clone(),
                    args: call_args,
                    result: value.clone(),
                });
                set_reg(registers, event, *dst, value);
            }
            Instruction::ArrayNew { dst, items } => {
                let value =
                    Value::Array(items.iter().map(|item| registers[*item].clone()).collect());
                set_reg(registers, event, *dst, value);
            }
            Instruction::ArrayGet { dst, array, index } => {
                let Value::Array(items) = &registers[*array] else {
                    return Err(ChronicleError::Runtime(
                        "array_get target is not an array".into(),
                    ));
                };
                let item_index = value_to_index(&registers[*index])?;
                let value = items.get(item_index).cloned().ok_or_else(|| {
                    ChronicleError::Runtime(format!("array index {item_index} out of bounds"))
                })?;
                set_reg(registers, event, *dst, value);
            }
            Instruction::ArraySet {
                array,
                index,
                value,
            } => {
                let item_index = value_to_index(&registers[*index])?;
                let new_value = registers[*value].clone();
                let Value::Array(items) = &mut registers[*array] else {
                    return Err(ChronicleError::Runtime(
                        "array_set target is not an array".into(),
                    ));
                };
                let Some(slot) = items.get_mut(item_index) else {
                    return Err(ChronicleError::Runtime(format!(
                        "array index {item_index} out of bounds"
                    )));
                };
                *slot = new_value;
                event.register_changes.push(RegisterChange {
                    register: *array,
                    value: registers[*array].clone(),
                });
            }
        }
        let _ = function;
        Ok(None)
    }

    fn call_capability(&mut self, name: &str, args: Vec<Value>, live: bool) -> Result<Value> {
        if !live {
            let Some(recorded) = self
                .replay_capabilities
                .get(self.replay_capability_index)
                .cloned()
            else {
                return Err(ChronicleError::Replay(format!(
                    "missing recorded capability {name}"
                )));
            };
            self.replay_capability_index += 1;
            if recorded.name != name || recorded.args != args {
                return Err(ChronicleError::Replay(format!(
                    "capability call mismatch for {name}"
                )));
            }
            return Ok(recorded.result);
        }

        match self.capabilities.get(name) {
            Some(CapabilityDecision::Grant) => builtin_capability(name, &args),
            Some(CapabilityDecision::Mock(value)) => Ok(value.clone()),
            Some(CapabilityDecision::Deny) | None => Err(ChronicleError::Capability(format!(
                "capability {name} unavailable"
            ))),
        }
    }
}

fn set_reg(registers: &mut [Value], event: &mut TraceEvent, register: usize, value: Value) {
    registers[register] = value.clone();
    event
        .register_changes
        .push(RegisterChange { register, value });
}

fn numeric(
    lhs: Value,
    rhs: Value,
    int_op: impl Fn(i64, i64) -> i64,
    float_op: impl Fn(f64, f64) -> f64,
) -> Result<Value> {
    match (lhs, rhs) {
        (Value::I64(a), Value::I64(b)) => Ok(Value::I64(int_op(a, b))),
        (Value::I64(a), Value::F64(b)) => Ok(Value::F64(float_op(a as f64, b))),
        (Value::F64(a), Value::I64(b)) => Ok(Value::F64(float_op(a, b as f64))),
        (Value::F64(a), Value::F64(b)) => Ok(Value::F64(float_op(a, b))),
        _ => Err(ChronicleError::Runtime("numeric operands required".into())),
    }
}

fn compare_lt(lhs: &Value, rhs: &Value) -> Result<bool> {
    match (lhs, rhs) {
        (Value::I64(a), Value::I64(b)) => Ok(a < b),
        (Value::I64(a), Value::F64(b)) => Ok((*a as f64) < *b),
        (Value::F64(a), Value::I64(b)) => Ok(*a < (*b as f64)),
        (Value::F64(a), Value::F64(b)) => Ok(a < b),
        _ => Err(ChronicleError::Runtime("numeric operands required".into())),
    }
}

fn value_to_index(value: &Value) -> Result<usize> {
    match value {
        Value::I64(index) if *index >= 0 => Ok(*index as usize),
        _ => Err(ChronicleError::Runtime(
            "array index must be a non-negative i64".into(),
        )),
    }
}

fn builtin_capability(name: &str, args: &[Value]) -> Result<Value> {
    match name {
        "log.print" => {
            println!(
                "{}",
                args.iter().map(display_value).collect::<Vec<_>>().join(" ")
            );
            Ok(Value::Nil)
        }
        "clock.now" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| ChronicleError::Capability(err.to_string()))?;
            Ok(Value::I64(now.as_secs() as i64))
        }
        "random.u64" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| ChronicleError::Capability(err.to_string()))?;
            Ok(Value::I64(
                (now.as_nanos() as u64 ^ 0x9E37_79B9_7F4A_7C15) as i64,
            ))
        }
        other => Err(ChronicleError::Capability(format!(
            "unknown built-in capability {other}"
        ))),
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Nil => "nil".into(),
        Value::Bool(v) => v.to_string(),
        Value::I64(v) => v.to_string(),
        Value::F64(v) => v.to_string(),
        Value::String(v) => v.clone(),
        Value::Array(v) => format!("{v:?}"),
        Value::Function(v) | Value::Capability(v) => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_grant(name: &str) -> HostPolicy {
        HostPolicy {
            decisions: BTreeMap::from([(name.into(), CapabilityDecision::Grant)]),
        }
    }

    #[test]
    fn verifies_register_bounds() {
        let module = Module {
            name: "bad".into(),
            constants: vec![Value::I64(1)],
            capabilities: vec![],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![Instruction::Const {
                    dst: 2,
                    constant: 0,
                }],
                source_lines: vec![Some(1)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        assert!(Verifier::verify(&module).is_err());
    }

    #[test]
    fn runs_and_replays_capability_result() {
        let module = Module {
            name: "clock".into(),
            constants: vec![],
            capabilities: vec![CapabilityDecl {
                name: "clock.now".into(),
                reason: None,
            }],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![
                    Instruction::CapCall {
                        dst: 0,
                        capability: "clock.now".into(),
                        args: vec![],
                    },
                    Instruction::Ret { src: 0 },
                ],
                source_lines: vec![Some(1), Some(2)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let mut vm = Vm::new(module, policy_grant("clock.now")).unwrap();
        let trace = vm.run_with_trace("main").unwrap();
        let report = Vm::replay(trace).unwrap();
        assert_eq!(report.events_checked, 2);
    }

    #[test]
    fn denies_missing_policy_capability_before_execution() {
        let module = Module {
            name: "denied".into(),
            constants: vec![],
            capabilities: vec![CapabilityDecl {
                name: "log.print".into(),
                reason: None,
            }],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![Instruction::Ret { src: 0 }],
                source_lines: vec![Some(1)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        assert!(Vm::new(module, HostPolicy::default()).is_err());
    }

    #[test]
    fn mock_capability_returns_policy_value() {
        let module = Module {
            name: "mock".into(),
            constants: vec![],
            capabilities: vec![CapabilityDecl {
                name: "random.u64".into(),
                reason: None,
            }],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![
                    Instruction::CapCall {
                        dst: 0,
                        capability: "random.u64".into(),
                        args: vec![],
                    },
                    Instruction::Ret { src: 0 },
                ],
                source_lines: vec![Some(1), Some(2)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let policy = HostPolicy {
            decisions: BTreeMap::from([(
                "random.u64".into(),
                CapabilityDecision::Mock(Value::I64(42)),
            )]),
        };
        let mut vm = Vm::new(module, policy).unwrap();
        assert_eq!(vm.run_entry("main").unwrap(), Value::I64(42));
    }

    #[test]
    fn detects_replay_divergence() {
        let module = Module {
            name: "diverge".into(),
            constants: vec![Value::I64(1)],
            capabilities: vec![],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![
                    Instruction::Const {
                        dst: 0,
                        constant: 0,
                    },
                    Instruction::Ret { src: 0 },
                ],
                source_lines: vec![Some(1), Some(2)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let mut vm = Vm::new(module, HostPolicy::default()).unwrap();
        let mut trace = vm.run_with_trace("main").unwrap();
        trace.events[0].opcode = "changed".into();
        assert!(Vm::replay(trace).is_err());
    }

    #[test]
    fn binary_module_round_trips() {
        let module = Module {
            name: "roundtrip".into(),
            constants: vec![
                Value::I64(7),
                Value::String("value".into()),
                Value::Array(vec![Value::Bool(true), Value::Nil]),
            ],
            capabilities: vec![CapabilityDecl {
                name: "log.print".into(),
                reason: Some("test".into()),
            }],
            functions: vec![Function {
                name: "main".into(),
                registers: 3,
                arity: 0,
                code: vec![
                    Instruction::Const {
                        dst: 0,
                        constant: 0,
                    },
                    Instruction::Const {
                        dst: 1,
                        constant: 1,
                    },
                    Instruction::CapCall {
                        dst: 2,
                        capability: "log.print".into(),
                        args: vec![1],
                    },
                    Instruction::Ret { src: 0 },
                ],
                source_lines: vec![Some(10), Some(11), Some(12), Some(13)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let bytes = module.to_bytes().unwrap();
        assert!(bytes.starts_with(MODULE_MAGIC));
        let decoded = Module::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, module);
        Verifier::verify(&decoded).unwrap();
    }

    #[test]
    fn json_module_decode_remains_supported() {
        let module = Module {
            name: "json".into(),
            constants: vec![],
            capabilities: vec![],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![Instruction::Ret { src: 0 }],
                source_lines: vec![Some(1)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let json = module.to_json_bytes().unwrap();
        assert_eq!(Module::from_bytes(&json).unwrap(), module);
    }
}
