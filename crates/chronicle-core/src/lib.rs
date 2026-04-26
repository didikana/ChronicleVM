use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const MODULE_MAGIC: &[u8; 8] = b"CHVMOD2\0";
const OLD_MODULE_MAGIC: &[u8; 8] = b"CHVMOD1\0";

#[derive(Debug, Error)]
pub enum ChronicleError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("verify error: {0}")]
    Verify(#[from] VerifyError),
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("replay error: {0}")]
    Replay(#[source] Box<ReplayError>),
}

pub type Result<T> = std::result::Result<T, ChronicleError>;

impl From<ReplayError> for ChronicleError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(Box::new(error))
    }
}

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
    pub fn value_type(&self) -> ValueType {
        match self {
            Value::Nil => ValueType::Nil,
            Value::Bool(_) => ValueType::Bool,
            Value::I64(_) => ValueType::I64,
            Value::F64(_) => ValueType::F64,
            Value::String(_) => ValueType::String,
            Value::Array(_) => ValueType::Array,
            Value::Function(_) => ValueType::Function,
            Value::Capability(_) => ValueType::Capability,
        }
    }

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
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Nil,
    Bool,
    I64,
    F64,
    String,
    Array,
    Function,
    Capability,
    Any,
    AnyVariadic,
}

impl ValueType {
    pub fn accepts(&self, value: &Value) -> bool {
        match self {
            ValueType::Any | ValueType::AnyVariadic => true,
            expected => *expected == value.value_type(),
        }
    }

    fn accepts_type(&self, actual: &ValueType) -> bool {
        matches!(self, ValueType::Any | ValueType::AnyVariadic) || self == actual
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDecl {
    pub id: String,
    pub params: Vec<ValueType>,
    pub return_type: ValueType,
    pub reason: Option<String>,
}

impl CapabilityDecl {
    pub fn is_variadic(&self) -> bool {
        matches!(self.params.last(), Some(ValueType::AnyVariadic))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyErrorKind {
    MalformedModule,
    UnsupportedBytecodeVersion,
    DuplicateSymbol,
    RegisterOutOfBounds,
    ConstantOutOfBounds,
    InvalidJumpTarget,
    MissingExport,
    MissingCallee,
    ArityMismatch,
    UndeclaredCapability,
    CapabilitySignatureMismatch,
    SourceMapMismatch,
    TypeMismatch,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyError {
    pub kind: VerifyErrorKind,
    pub message: String,
    pub function: Option<String>,
    pub pc: Option<usize>,
}

impl VerifyError {
    pub fn new(kind: VerifyErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            function: None,
            pc: None,
        }
    }

    fn at(mut self, function: &Function, pc: usize) -> Self {
        self.function = Some(function.name.clone());
        self.pc = Some(pc);
        self
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Some(function), Some(pc)) = (&self.function, self.pc) {
            write!(
                formatter,
                "{:?} at {function} pc={pc}: {}",
                self.kind, self.message
            )
        } else {
            write!(formatter, "{:?}: {}", self.kind, self.message)
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyErrorKind {
    MissingPolicy,
    DeniedCapability,
    MockTypeMismatch,
    UnknownDecision,
    UnsupportedCapabilityVersion,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyError {
    pub kind: PolicyErrorKind,
    pub capability: String,
    pub message: String,
}

impl PolicyError {
    pub fn new(
        kind: PolicyErrorKind,
        capability: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            capability: capability.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?} for {}: {}",
            self.kind, self.capability, self.message
        )
    }
}

impl std::error::Error for PolicyError {}

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
        } else if bytes.starts_with(OLD_MODULE_MAGIC) {
            Err(ChronicleError::Verify(VerifyError::new(
                VerifyErrorKind::UnsupportedBytecodeVersion,
                "CHVMOD1 modules are not supported by this runtime; reassemble as CHVMOD2",
            )))
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
            self.write_string(&capability.id)?;
            self.write_len(capability.params.len())?;
            for param in &capability.params {
                self.write_value_type(param);
            }
            self.write_value_type(&capability.return_type);
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

    fn write_value_type(&mut self, value_type: &ValueType) {
        self.write_u8(match value_type {
            ValueType::Nil => 0,
            ValueType::Bool => 1,
            ValueType::I64 => 2,
            ValueType::F64 => 3,
            ValueType::String => 4,
            ValueType::Array => 5,
            ValueType::Function => 6,
            ValueType::Capability => 7,
            ValueType::Any => 8,
            ValueType::AnyVariadic => 9,
        });
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
            let id = reader.read_string()?;
            let params = reader.read_many(Self::read_value_type)?;
            let return_type = reader.read_value_type()?;
            Ok(CapabilityDecl {
                id,
                params,
                return_type,
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

    fn read_value_type(&mut self) -> Result<ValueType> {
        Ok(match self.read_u8()? {
            0 => ValueType::Nil,
            1 => ValueType::Bool,
            2 => ValueType::I64,
            3 => ValueType::F64,
            4 => ValueType::String,
            5 => ValueType::Array,
            6 => ValueType::Function,
            7 => ValueType::Capability,
            8 => ValueType::Any,
            9 => ValueType::AnyVariadic,
            tag => {
                return Err(ChronicleError::Decode(format!(
                    "unknown value type tag {tag}"
                )))
            }
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
        let mut capability_ids = BTreeSet::new();
        for capability in &module.capabilities {
            if !capability_ids.insert(capability.id.clone()) {
                return Err(VerifyError::new(
                    VerifyErrorKind::DuplicateSymbol,
                    format!("duplicate capability {}", capability.id),
                )
                .into());
            }
            validate_capability_decl(capability)?;
        }
        let mut function_names = BTreeSet::new();
        for function in &module.functions {
            if !function_names.insert(function.name.clone()) {
                return Err(VerifyError::new(
                    VerifyErrorKind::DuplicateSymbol,
                    format!("duplicate function {}", function.name),
                )
                .into());
            }
        }

        for (export, index) in &module.exports {
            if *index >= module.functions.len() {
                return Err(VerifyError::new(
                    VerifyErrorKind::MissingExport,
                    format!("export {export} points to missing function {index}"),
                )
                .into());
            }
        }

        for function in &module.functions {
            if function.registers == 0 {
                return Err(VerifyError::new(
                    VerifyErrorKind::MalformedModule,
                    format!("function {} must have at least one register", function.name),
                )
                .into());
            }
            if function.arity > function.registers {
                return Err(VerifyError::new(
                    VerifyErrorKind::ArityMismatch,
                    format!("function {} arity exceeds register count", function.name),
                )
                .into());
            }
            if !function.source_lines.is_empty()
                && function.source_lines.len() != function.code.len()
            {
                return Err(VerifyError::new(
                    VerifyErrorKind::SourceMapMismatch,
                    format!(
                        "function {} source line map length does not match code length",
                        function.name
                    ),
                )
                .into());
            }
            let mut register_types = vec![None; function.registers];
            for (pc, instruction) in function.code.iter().enumerate() {
                verify_instruction(module, function, pc, instruction, &mut register_types)?;
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
    register_types: &mut [Option<ValueType>],
) -> Result<()> {
    let reg = |register: usize| -> Result<()> {
        if register >= function.registers {
            Err(VerifyError::new(
                VerifyErrorKind::RegisterOutOfBounds,
                format!("register r{register} out of bounds"),
            )
            .at(function, pc)
            .into())
        } else {
            Ok(())
        }
    };
    let target = |target: usize| -> Result<()> {
        if target >= function.code.len() {
            Err(VerifyError::new(
                VerifyErrorKind::InvalidJumpTarget,
                format!("jump target {target} out of bounds"),
            )
            .at(function, pc)
            .into())
        } else {
            Ok(())
        }
    };

    match instruction {
        Instruction::Const { dst, constant } => {
            reg(*dst)?;
            if *constant >= module.constants.len() {
                return Err(VerifyError::new(
                    VerifyErrorKind::ConstantOutOfBounds,
                    format!("constant {constant} out of bounds"),
                )
                .at(function, pc)
                .into());
            }
            register_types[*dst] = Some(module.constants[*constant].value_type());
        }
        Instruction::Move { dst, src } => {
            reg(*dst)?;
            reg(*src)?;
            register_types[*dst] = register_types[*src].clone();
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
            let result_type = match instruction {
                Instruction::Eq { .. } | Instruction::Lt { .. } => ValueType::Bool,
                _ => ValueType::I64,
            };
            register_types[*dst] = Some(result_type);
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
                return Err(VerifyError::new(
                    VerifyErrorKind::MissingCallee,
                    format!("missing callee {callee}"),
                )
                .at(function, pc)
                .into());
            };
            if module.functions[callee_index].arity != args.len() {
                return Err(VerifyError::new(
                    VerifyErrorKind::ArityMismatch,
                    format!(
                        "callee {callee} expects {} args, got {}",
                        module.functions[callee_index].arity,
                        args.len()
                    ),
                )
                .at(function, pc)
                .into());
            }
            register_types[*dst] = None;
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
            let Some(decl) = module
                .capabilities
                .iter()
                .find(|decl| decl.id == *capability)
            else {
                return Err(VerifyError::new(
                    VerifyErrorKind::UndeclaredCapability,
                    format!("capability {capability} was not declared"),
                )
                .at(function, pc)
                .into());
            };
            verify_capability_args(function, pc, decl, args, register_types)?;
            register_types[*dst] = Some(decl.return_type.clone());
        }
        Instruction::ArrayNew { dst, items } => {
            reg(*dst)?;
            for item in items {
                reg(*item)?;
            }
            register_types[*dst] = Some(ValueType::Array);
        }
        Instruction::ArrayGet { dst, array, index } => {
            reg(*dst)?;
            reg(*array)?;
            reg(*index)?;
            register_types[*dst] = None;
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

fn validate_capability_decl(decl: &CapabilityDecl) -> Result<()> {
    if decl.id.is_empty() || !decl.id.contains('@') {
        return Err(VerifyError::new(
            VerifyErrorKind::CapabilitySignatureMismatch,
            format!(
                "capability {} must include a version suffix like @1",
                decl.id
            ),
        )
        .into());
    }
    if decl
        .params
        .iter()
        .take(decl.params.len().saturating_sub(1))
        .any(|param| matches!(param, ValueType::AnyVariadic))
    {
        return Err(VerifyError::new(
            VerifyErrorKind::CapabilitySignatureMismatch,
            format!(
                "capability {} has variadic marker before final parameter",
                decl.id
            ),
        )
        .into());
    }
    if let Some(expected) = builtin_signature(&decl.id) {
        if expected.params != decl.params || expected.return_type != decl.return_type {
            return Err(VerifyError::new(
                VerifyErrorKind::CapabilitySignatureMismatch,
                format!("capability {} does not match built-in signature", decl.id),
            )
            .into());
        }
    }
    Ok(())
}

fn verify_capability_args(
    function: &Function,
    pc: usize,
    decl: &CapabilityDecl,
    args: &[usize],
    register_types: &[Option<ValueType>],
) -> Result<()> {
    let fixed = if decl.is_variadic() {
        decl.params.len() - 1
    } else {
        decl.params.len()
    };
    let arity_ok = if decl.is_variadic() {
        args.len() >= fixed
    } else {
        args.len() == fixed
    };
    if !arity_ok {
        return Err(VerifyError::new(
            VerifyErrorKind::ArityMismatch,
            format!(
                "capability {} expects {}{} args, got {}",
                decl.id,
                fixed,
                if decl.is_variadic() { "+" } else { "" },
                args.len()
            ),
        )
        .at(function, pc)
        .into());
    }
    for (index, register) in args.iter().enumerate() {
        let expected = if index < decl.params.len() {
            &decl.params[index]
        } else {
            decl.params.last().unwrap_or(&ValueType::Any)
        };
        if let Some(actual) = &register_types[*register] {
            if !expected.accepts_type(actual) {
                return Err(VerifyError::new(
                    VerifyErrorKind::TypeMismatch,
                    format!(
                        "capability {} arg {index} expects {:?}, got {:?}",
                        decl.id, expected, actual
                    ),
                )
                .at(function, pc)
                .into());
            }
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
    pub fn negotiate(&self, module: &Module) -> NegotiationReport {
        let mut entries = Vec::new();
        for decl in &module.capabilities {
            let decision = self
                .decisions
                .get(&decl.id)
                .cloned()
                .unwrap_or(CapabilityDecision::Deny);
            let status = match &decision {
                CapabilityDecision::Grant => {
                    if builtin_signature(&decl.id).is_some() || !is_builtin_namespace(&decl.id) {
                        NegotiationStatus::Granted
                    } else {
                        NegotiationStatus::Unknown
                    }
                }
                CapabilityDecision::Mock(value) => {
                    if !decl.return_type.accepts(value) {
                        NegotiationStatus::TypeInvalid
                    } else {
                        NegotiationStatus::Mocked
                    }
                }
                CapabilityDecision::Deny => NegotiationStatus::Denied,
            };
            entries.push(NegotiationEntry {
                capability: decl.id.clone(),
                decision,
                status,
                reason: decl.reason.clone(),
            });
        }
        NegotiationReport { entries }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NegotiationReport {
    pub entries: Vec<NegotiationEntry>,
}

impl NegotiationReport {
    pub fn is_success(&self) -> bool {
        self.entries.iter().all(|entry| {
            matches!(
                entry.status,
                NegotiationStatus::Granted | NegotiationStatus::Mocked
            )
        })
    }

    pub fn into_capability_table(self) -> Result<BTreeMap<String, CapabilityDecision>> {
        let mut capabilities = BTreeMap::new();
        for entry in self.entries {
            match entry.status {
                NegotiationStatus::Granted | NegotiationStatus::Mocked => {
                    capabilities.insert(entry.capability, entry.decision);
                }
                NegotiationStatus::Denied => {
                    return Err(PolicyError::new(
                        PolicyErrorKind::DeniedCapability,
                        entry.capability,
                        "capability denied by policy or missing from policy",
                    )
                    .into());
                }
                NegotiationStatus::Unknown => {
                    return Err(PolicyError::new(
                        PolicyErrorKind::UnsupportedCapabilityVersion,
                        entry.capability,
                        "unknown built-in capability/version",
                    )
                    .into());
                }
                NegotiationStatus::TypeInvalid => {
                    return Err(PolicyError::new(
                        PolicyErrorKind::MockTypeMismatch,
                        entry.capability,
                        "mock value does not match declared return type",
                    )
                    .into());
                }
            }
        }
        Ok(capabilities)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NegotiationEntry {
    pub capability: String,
    pub decision: CapabilityDecision,
    pub status: NegotiationStatus,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegotiationStatus {
    Granted,
    Mocked,
    Denied,
    Unknown,
    TypeInvalid,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub module: Module,
    pub entry: String,
    pub events: Vec<TraceEvent>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub checksum: u64,
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
    pub checksum: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegisterChange {
    pub register: usize,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityTrace {
    pub id: String,
    pub decision: CapabilityTraceDecision,
    pub args: Vec<Value>,
    pub result: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTraceDecision {
    Granted,
    Mocked,
    Replayed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub events_checked: usize,
    pub result: Option<Value>,
    pub trace_checksum: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayDiff {
    pub index: usize,
    pub expected: Option<TraceEvent>,
    pub actual: Option<TraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayError {
    pub message: String,
    pub diff: Option<ReplayDiff>,
}

impl ReplayError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            diff: None,
        }
    }

    fn with_diff(message: impl Into<String>, diff: ReplayDiff) -> Self {
        Self {
            message: message.into(),
            diff: Some(diff),
        }
    }
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for ReplayError {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmLimits {
    pub max_instructions: Option<usize>,
    pub max_call_depth: Option<usize>,
    pub max_registers: Option<usize>,
    pub max_array_items: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Vm {
    module: Module,
    capabilities: BTreeMap<String, CapabilityDecision>,
    replay_capabilities: Vec<CapabilityTrace>,
    replay_capability_index: usize,
    limits: VmLimits,
    instruction_count: usize,
    call_depth: usize,
}

impl Vm {
    pub fn new(module: Module, host_policy: HostPolicy) -> Result<Self> {
        Verifier::verify(&module)?;
        let report = host_policy.negotiate(&module);
        let capabilities = report.into_capability_table()?;
        Ok(Self {
            module,
            capabilities,
            replay_capabilities: Vec::new(),
            replay_capability_index: 0,
            limits: VmLimits::default(),
            instruction_count: 0,
            call_depth: 0,
        })
    }

    pub fn with_limits(mut self, limits: VmLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn run_entry(&mut self, entry: &str) -> Result<Value> {
        let (result, _) = self.execute_collect(entry, true);
        result
    }

    pub fn run_with_trace(&mut self, entry: &str) -> Result<Trace> {
        let (result, events) = self.execute_collect(entry, true);
        match result {
            Ok(result) => {
                let checksum = trace_checksum(&events, &Some(result.clone()), &None);
                Ok(Trace {
                    module: self.module.clone(),
                    entry: entry.to_string(),
                    events,
                    result: Some(result),
                    error: None,
                    checksum,
                })
            }
            Err(err) => {
                let error = err.to_string();
                let checksum = trace_checksum(&events, &None, &Some(error.clone()));
                Ok(Trace {
                    module: self.module.clone(),
                    entry: entry.to_string(),
                    events,
                    result: None,
                    error: Some(error),
                    checksum,
                })
            }
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
            capabilities.insert(decl.id.clone(), CapabilityDecision::Grant);
        }
        let mut vm = Self {
            module: trace.module.clone(),
            capabilities,
            replay_capabilities: capability_results,
            replay_capability_index: 0,
            limits: VmLimits::default(),
            instruction_count: 0,
            call_depth: 0,
        };
        let (result, events) = vm.execute_collect(&trace.entry, false);
        let result = result?;
        if events != trace.events {
            return Err(ReplayError::with_diff(
                "trace events did not match replay",
                first_replay_diff(&trace.events, &events),
            )
            .into());
        }
        if Some(result.clone()) != trace.result {
            return Err(ReplayError::new("trace result did not match replay").into());
        }
        let checksum = trace_checksum(&events, &Some(result.clone()), &None);
        if checksum != trace.checksum {
            return Err(ReplayError::new("trace checksum did not match replay").into());
        }
        Ok(ReplayReport {
            events_checked: events.len(),
            result: Some(result),
            trace_checksum: checksum,
        })
    }

    fn execute_collect(
        &mut self,
        entry: &str,
        live_capabilities: bool,
    ) -> (Result<Value>, Vec<TraceEvent>) {
        self.instruction_count = 0;
        self.call_depth = 0;
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
        self.enter_function(&function)?;
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
                checksum: 0,
            };
            let mut next_pc = pc + 1;
            let step = self.consume_instruction_limit().and_then(|_| {
                self.apply_instruction(
                    &mut registers,
                    &instruction,
                    &mut next_pc,
                    &mut event,
                    events,
                    live_capabilities,
                )
            });
            match step {
                Ok(Some(value)) => {
                    seal_event(&mut event);
                    events.push(event);
                    self.leave_function();
                    return Ok(value);
                }
                Ok(None) => {
                    seal_event(&mut event);
                    events.push(event);
                    pc = next_pc;
                }
                Err(err) => {
                    event.error = Some(err.to_string());
                    seal_event(&mut event);
                    events.push(event);
                    self.leave_function();
                    return Err(err);
                }
            }
        }
        self.leave_function();
        Err(ChronicleError::Runtime(format!(
            "function {} ended without ret",
            function.name
        )))
    }

    fn apply_instruction(
        &mut self,
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
                    id: capability.clone(),
                    decision: self.capability_trace_decision(capability, live_capabilities),
                    args: call_args,
                    result: value.clone(),
                });
                set_reg(registers, event, *dst, value);
            }
            Instruction::ArrayNew { dst, items } => {
                if let Some(max) = self.limits.max_array_items {
                    if items.len() > max {
                        return Err(ChronicleError::ResourceLimit(format!(
                            "array_new requested {} items, max is {max}",
                            items.len()
                        )));
                    }
                }
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
        Ok(None)
    }

    fn enter_function(&mut self, function: &Function) -> Result<()> {
        if let Some(max) = self.limits.max_call_depth {
            if self.call_depth >= max {
                return Err(ChronicleError::ResourceLimit(format!(
                    "call depth exceeded max {max}"
                )));
            }
        }
        if let Some(max) = self.limits.max_registers {
            if function.registers > max {
                return Err(ChronicleError::ResourceLimit(format!(
                    "function {} uses {} registers, max is {max}",
                    function.name, function.registers
                )));
            }
        }
        self.call_depth += 1;
        Ok(())
    }

    fn leave_function(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    fn consume_instruction_limit(&mut self) -> Result<()> {
        if let Some(max) = self.limits.max_instructions {
            if self.instruction_count >= max {
                return Err(ChronicleError::ResourceLimit(format!(
                    "instruction budget exceeded max {max}"
                )));
            }
        }
        self.instruction_count += 1;
        Ok(())
    }

    fn call_capability(&mut self, name: &str, args: Vec<Value>, live: bool) -> Result<Value> {
        if !live {
            let Some(recorded) = self
                .replay_capabilities
                .get(self.replay_capability_index)
                .cloned()
            else {
                return Err(ReplayError::new(format!("missing recorded capability {name}")).into());
            };
            self.replay_capability_index += 1;
            if recorded.id != name || recorded.args != args {
                return Err(
                    ReplayError::new(format!("capability call mismatch for {name}")).into(),
                );
            }
            return Ok(recorded.result);
        }

        match self.capabilities.get(name) {
            Some(CapabilityDecision::Grant) => builtin_capability(name, &args),
            Some(CapabilityDecision::Mock(value)) => Ok(value.clone()),
            Some(CapabilityDecision::Deny) | None => Err(PolicyError::new(
                PolicyErrorKind::DeniedCapability,
                name,
                "capability unavailable at runtime",
            )
            .into()),
        }
    }

    fn capability_trace_decision(&self, name: &str, live: bool) -> CapabilityTraceDecision {
        if !live {
            self.replay_capabilities
                .get(self.replay_capability_index.saturating_sub(1))
                .filter(|recorded| recorded.id == name)
                .map(|recorded| recorded.decision.clone())
                .unwrap_or(CapabilityTraceDecision::Replayed)
        } else if matches!(
            self.capabilities.get(name),
            Some(CapabilityDecision::Mock(_))
        ) {
            CapabilityTraceDecision::Mocked
        } else {
            CapabilityTraceDecision::Granted
        }
    }
}

fn set_reg(registers: &mut [Value], event: &mut TraceEvent, register: usize, value: Value) {
    registers[register] = value.clone();
    event
        .register_changes
        .push(RegisterChange { register, value });
}

fn seal_event(event: &mut TraceEvent) {
    event.checksum = 0;
    event.checksum = stable_checksum(event);
}

fn trace_checksum(events: &[TraceEvent], result: &Option<Value>, error: &Option<String>) -> u64 {
    stable_checksum(&(events, result, error))
}

fn stable_checksum<T: Serialize>(value: &T) -> u64 {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn first_replay_diff(expected: &[TraceEvent], actual: &[TraceEvent]) -> ReplayDiff {
    let len = expected.len().max(actual.len());
    for index in 0..len {
        let expected_event = expected.get(index).cloned();
        let actual_event = actual.get(index).cloned();
        if expected_event != actual_event {
            return ReplayDiff {
                index,
                expected: expected_event,
                actual: actual_event,
            };
        }
    }
    ReplayDiff {
        index: len,
        expected: None,
        actual: None,
    }
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
        "log.print@1" => {
            println!(
                "{}",
                args.iter().map(display_value).collect::<Vec<_>>().join(" ")
            );
            Ok(Value::Nil)
        }
        "clock.now@1" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| ChronicleError::Runtime(err.to_string()))?;
            Ok(Value::I64(now.as_secs() as i64))
        }
        "random.u64@1" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| ChronicleError::Runtime(err.to_string()))?;
            Ok(Value::I64(
                (now.as_nanos() as u64 ^ 0x9E37_79B9_7F4A_7C15) as i64,
            ))
        }
        other => Err(PolicyError::new(
            PolicyErrorKind::UnsupportedCapabilityVersion,
            other,
            "unknown built-in capability",
        )
        .into()),
    }
}

pub fn builtin_signature(id: &str) -> Option<CapabilityDecl> {
    match id {
        "log.print@1" => Some(CapabilityDecl {
            id: id.into(),
            params: vec![ValueType::AnyVariadic],
            return_type: ValueType::Nil,
            reason: None,
        }),
        "clock.now@1" => Some(CapabilityDecl {
            id: id.into(),
            params: vec![],
            return_type: ValueType::I64,
            reason: None,
        }),
        "random.u64@1" => Some(CapabilityDecl {
            id: id.into(),
            params: vec![],
            return_type: ValueType::I64,
            reason: None,
        }),
        _ => None,
    }
}

fn is_builtin_namespace(id: &str) -> bool {
    id.starts_with("log.") || id.starts_with("clock.") || id.starts_with("random.")
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

    fn cap(id: &str) -> CapabilityDecl {
        builtin_signature(id).unwrap()
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
        let err = Verifier::verify(&module).unwrap_err();
        match err {
            ChronicleError::Verify(err) => {
                assert_eq!(err.kind, VerifyErrorKind::RegisterOutOfBounds)
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn runs_and_replays_capability_result() {
        let module = Module {
            name: "clock".into(),
            constants: vec![],
            capabilities: vec![cap("clock.now@1")],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![
                    Instruction::CapCall {
                        dst: 0,
                        capability: "clock.now@1".into(),
                        args: vec![],
                    },
                    Instruction::Ret { src: 0 },
                ],
                source_lines: vec![Some(1), Some(2)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let mut vm = Vm::new(module, policy_grant("clock.now@1")).unwrap();
        let trace = vm.run_with_trace("main").unwrap();
        let report = Vm::replay(trace).unwrap();
        assert_eq!(report.events_checked, 2);
    }

    #[test]
    fn instruction_limit_is_recorded_in_trace() {
        let module = Module {
            name: "limited".into(),
            constants: vec![Value::I64(1)],
            capabilities: vec![],
            functions: vec![Function {
                name: "main".into(),
                registers: 2,
                arity: 0,
                code: vec![
                    Instruction::Const {
                        dst: 0,
                        constant: 0,
                    },
                    Instruction::Const {
                        dst: 1,
                        constant: 0,
                    },
                    Instruction::Ret { src: 1 },
                ],
                source_lines: vec![Some(1), Some(2), Some(3)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let mut vm = Vm::new(module, HostPolicy::default())
            .unwrap()
            .with_limits(VmLimits {
                max_instructions: Some(1),
                ..VmLimits::default()
            });
        let trace = vm.run_with_trace("main").unwrap();
        assert_eq!(trace.events.len(), 2);
        assert!(trace.error.unwrap().contains("instruction budget"));
        assert!(trace.events[1]
            .error
            .as_ref()
            .unwrap()
            .contains("instruction budget"));
    }

    #[test]
    fn denies_missing_policy_capability_before_execution() {
        let module = Module {
            name: "denied".into(),
            constants: vec![],
            capabilities: vec![cap("log.print@1")],
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
            capabilities: vec![cap("random.u64@1")],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![
                    Instruction::CapCall {
                        dst: 0,
                        capability: "random.u64@1".into(),
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
                "random.u64@1".into(),
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
        let err = Vm::replay(trace).unwrap_err();
        match err {
            ChronicleError::Replay(err) => assert_eq!(err.diff.unwrap().index, 0),
            other => panic!("unexpected error {other:?}"),
        }
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
                reason: Some("test".into()),
                ..cap("log.print@1")
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
                        capability: "log.print@1".into(),
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

    #[test]
    fn old_binary_version_is_rejected() {
        let mut bytes = Vec::from(OLD_MODULE_MAGIC.as_slice());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let err = Module::from_bytes(&bytes).unwrap_err();
        match err {
            ChronicleError::Verify(err) => {
                assert_eq!(err.kind, VerifyErrorKind::UnsupportedBytecodeVersion)
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn truncated_binary_is_rejected() {
        let bytes = Vec::from(MODULE_MAGIC.as_slice());
        assert!(Module::from_bytes(&bytes).is_err());
    }

    #[test]
    fn mock_type_mismatch_fails_negotiation() {
        let module = Module {
            name: "mock-type".into(),
            constants: vec![],
            capabilities: vec![cap("clock.now@1")],
            functions: vec![Function {
                name: "main".into(),
                registers: 1,
                arity: 0,
                code: vec![Instruction::Ret { src: 0 }],
                source_lines: vec![Some(1)],
            }],
            exports: BTreeMap::from([("main".into(), 0)]),
        };
        let policy = HostPolicy {
            decisions: BTreeMap::from([(
                "clock.now@1".into(),
                CapabilityDecision::Mock(Value::String("bad".into())),
            )]),
        };
        let err = Vm::new(module, policy).unwrap_err();
        match err {
            ChronicleError::Policy(err) => assert_eq!(err.kind, PolicyErrorKind::MockTypeMismatch),
            other => panic!("unexpected error {other:?}"),
        }
    }
}
