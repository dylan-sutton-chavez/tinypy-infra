// parser/types.rs

use alloc::{string::String, vec::Vec};
use hashbrown::HashMap;

pub(crate) const MAX_EXPR_DEPTH: usize = 200;
pub(crate) const MAX_INSTRUCTIONS: usize = 65_535;

/*
OpCodes
    Enumeration of all bytecode instructions supported by the virtual machine.
*/

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpCode { 
    LoadConst, LoadName, StoreName, Call, PopTop, ReturnValue, BuildString, CallPrint, CallLen, 
    FormatValue, CallAbs, Minus, CallStr, CallInt, CallRange, Phi, CallChr, CallType, MakeFunction, 
    Add, Sub, Mul, Div, Eq, CallFloat, CallBool, CallRound, CallMin, CallMax, CallSum, CallSorted, 
    CallEnumerate, CallZip, CallList, CallTuple, CallDict, CallIsInstance, CallSet, CallInput, 
    CallOrd, BuildDict, BuildList, NotEq, Lt, Gt, LtEq, GtEq, And, Or, Not, JumpIfFalse, Jump, 
    GetIter, ForIter, GetItem, Mod, Pow, FloorDiv, LoadTrue, LoadFalse, LoadNone, LoadAttr, StoreAttr, 
    BuildSlice, MakeClass, SetupExcept, PopExcept, Raise, Import, ImportFrom, BitAnd, BitOr, BitXor, 
    BitNot, Shl, Shr, In, NotIn, Is, IsNot, UnpackSequence, BuildTuple, SetupWith, ExitWith, Yield, 
    Del, Assert, Global, Nonlocal, UnpackArgs, ListComp, SetComp, DictComp, BuildSet, RaiseFrom, 
    UnpackEx, LoadEllipsis, GenExpr, Await, MakeCoroutine, YieldFrom, TypeAlias, StoreItem
}

/*
Builtin Dispatch
    O(1) lookup table mapping Python builtin names to their corresponding OpCodes.
*/

pub(super) fn builtin(name: &str) -> Option<(OpCode, bool)> {
    match name {
        "len" => Some((OpCode::CallLen, true)),
        "abs" => Some((OpCode::CallAbs, true)),
        "str" => Some((OpCode::CallStr, true)),
        "int" => Some((OpCode::CallInt, true)),
        "type" => Some((OpCode::CallType, true)),
        "float" => Some((OpCode::CallFloat, true)),
        "bool" => Some((OpCode::CallBool, true)),
        "round" => Some((OpCode::CallRound, true)),
        "min" => Some((OpCode::CallMin, true)),
        "max" => Some((OpCode::CallMax, true)),
        "sum" => Some((OpCode::CallSum, true)),
        "sorted" => Some((OpCode::CallSorted, true)),
        "enumerate" => Some((OpCode::CallEnumerate, true)),
        "zip" => Some((OpCode::CallZip, true)),
        "list" => Some((OpCode::CallList, true)),
        "tuple" => Some((OpCode::CallTuple, true)),
        "dict" => Some((OpCode::CallDict, true)),
        "set" => Some((OpCode::CallSet, true)),
        "input" => Some((OpCode::CallInput, true)),
        "isinstance" => Some((OpCode::CallIsInstance, true)),
        "chr" => Some((OpCode::CallChr, true)),
        "ord" => Some((OpCode::CallOrd, true)),
        _ => None,
    }
}

/*
Value
    Represents constant literals stored in the bytecode constants pool.
*/

#[derive(Debug)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    None,
}

/*
Instruction
    Single bytecode instruction containing an opcode and 16-bit operand.
*/

#[derive(Debug)]
pub struct Instruction {
    pub opcode:  OpCode,
    pub operand: u16,
}

/*
SSAChunk
    Container for generated instructions, constants, names, PHI sources and metadata.
*/

#[derive(Default)]
pub struct SSAChunk {
    pub instructions: Vec<Instruction>,
    pub constants: Vec<Value>,
    pub names: Vec<String>,
    pub functions: Vec<(Vec<String>, SSAChunk, u16)>,
    pub annotations: HashMap<String, String>,
    pub phi_sources: Vec<(u16, u16)>,
    pub classes: Vec<SSAChunk>,
    pub(super) name_index: HashMap<String, u16>,
}

impl SSAChunk {
    pub(super) fn emit(&mut self, op: OpCode, operand: u16) {
        if self.instructions.len() >= MAX_INSTRUCTIONS { return; } // silently drops instead of panicking
        self.instructions.push(Instruction { opcode: op, operand });
    }

    pub(super) fn push_const(&mut self, v: Value) -> u16 {
        if self.constants.len() >= u16::MAX as usize {
            return 0;
        }
        self.constants.push(v);
        (self.constants.len() - 1) as u16
    }

    pub(super) fn push_name(&mut self, n: &str) -> u16 {
        if let Some(&i) = self.name_index.get(n) { return i; } // interning: same string -> same index
        if self.names.len() >= u16::MAX as usize {
            return 0;
        }
        let i = self.names.len() as u16;
        self.names.push(n.to_string());
        self.name_index.insert(n.to_string(), i);
        i
    }
}

/*
JoinNode
    Tracks SSA versions before/after branches to insert correct PHI nodes later.
*/

pub(super) struct JoinNode {
    pub(super) backup: HashMap<String, u32>,
    pub(super) then: Option<HashMap<String, u32>>,
}

/*
Diagnostic
    Stores parsing error details including line, column range and message.
*/

pub struct Diagnostic {
    pub line: usize,
    pub col: usize,
    pub end: usize,
    pub msg: String,
}

/*
String Helpers
    Parses and unescapes Python string literals from lexer tokens.
*/

pub(super) fn parse_string(s: &str) -> String {
    let is_raw = s.contains('r') || s.contains('R');
    let s = s.trim_start_matches(|c: char| "bBrRuU".contains(c));
    let inner = if s.starts_with("\"\"\"") || s.starts_with("'''") {
        &s[3..s.len() - 3]
    } else {
        &s[1..s.len() - 1]
    };
    if is_raw { inner.to_string() } else { unescape(inner) }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' { out.push(c); continue; }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some('0') => out.push('\0'),
            Some(c) => { out.push('\\'); out.push(c); }
            None => out.push('\\'),
        }
    }
    out
}