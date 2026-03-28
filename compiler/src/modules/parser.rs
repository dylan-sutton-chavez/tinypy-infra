/*
`parser.rs`
    Single-pass SSA bytecode emitter. No AST. Variables versioned on assignment
    (new def per write), phi-joined (select reaching defs) at control flow boundaries.

    Architecture:
        - Flat `ssa_versions: HashMap<String, u32>` tracks the current version of each variable.
        - `JoinNode` captures snapshots before control flow branches (if/for/while).
        - `commit_block` compares branch endpoints and emits Phi nodes for divergent versions.
        - `compile_body` saves/restores the entire state for function definitions.
        - `name_index: HashMap<String, u16>` provides O(1) name dedup in push_name.
        - `BUILTINS: HashMap<&str, (OpCode, bool)>` provides O(1) builtin dispatch.
        - `LoadTrue`, `LoadFalse`, `LoadNone` are dedicated opcodes — singletons never
          pollute the constants pool.
*/
use crate::modules::lexer::{Token, TokenType};
use std::iter::Peekable;
use std::collections::HashMap;
use std::sync::LazyLock;

// ─── OpCodes ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum OpCode {
    LoadConst, LoadName, StoreName, Call, PopTop, ReturnValue,
    BuildString, CallPrint, CallLen, FormatValue, CallAbs, Minus,
    CallStr, CallInt, CallRange, Phi, CallChr, CallType,
    MakeFunction, Add, Sub, Mul, Div, Eq,
    CallFloat, CallBool, CallRound, CallMin, CallMax, CallSum,
    CallSorted, CallEnumerate, CallZip, CallList, CallTuple, CallDict,
    CallIsInstance, CallSet, CallInput, CallOrd, BuildDict, BuildList,
    NotEq, Lt, Gt, LtEq, GtEq, And,
    Or, Not, JumpIfFalse, Jump, GetIter, ForIter,
    GetItem, Mod, Pow, FloorDiv,
    LoadTrue, LoadFalse, LoadNone, LoadAttr, StoreAttr, BuildSlice,
    MakeClass, SetupExcept, PopExcept, Raise, Import, ImportFrom,
    BitAnd, BitOr, BitXor, BitNot, Shl, Shr,
    In, NotIn, Is, IsNot, UnpackSequence, BuildTuple,
    SetupWith, ExitWith, Yield, Del, Assert, Global, 
    Nonlocal, UnpackArgs, ListComp, SetComp, DictComp, BuildSet,
    RaiseFrom, UnpackEx, LoadEllipsis, GenExpr
}

// ─── Builtin dispatch table (O(1) lookup) ───────────────────────────────────

/// (opcode, leaves_value_on_stack)
static BUILTINS: LazyLock<HashMap<&'static str, (OpCode, bool)>> = LazyLock::new(|| {
    HashMap::from([
        ("len",        (OpCode::CallLen,       true)),
        ("abs",        (OpCode::CallAbs,       true)),
        ("str",        (OpCode::CallStr,       true)),
        ("int",        (OpCode::CallInt,       true)),
        ("type",       (OpCode::CallType,      true)),
        ("float",      (OpCode::CallFloat,     true)),
        ("bool",       (OpCode::CallBool,      true)),
        ("round",      (OpCode::CallRound,     true)),
        ("min",        (OpCode::CallMin,       true)),
        ("max",        (OpCode::CallMax,       true)),
        ("sum",        (OpCode::CallSum,       true)),
        ("sorted",     (OpCode::CallSorted,    true)),
        ("enumerate",  (OpCode::CallEnumerate, true)),
        ("zip",        (OpCode::CallZip,       true)),
        ("list",       (OpCode::CallList,      true)),
        ("tuple",      (OpCode::CallTuple,     true)),
        ("dict",       (OpCode::CallDict,      true)),
        ("set",        (OpCode::CallSet,       true)),
        ("input",      (OpCode::CallInput,     true)),
        ("isinstance", (OpCode::CallIsInstance, true)),
        ("chr",        (OpCode::CallChr,       true)),
        ("ord",        (OpCode::CallOrd,       true)),
    ])
});

// ─── Chunk ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Instruction { pub opcode: OpCode, pub operand: u16 }

#[derive(Debug)]
pub enum Value { Str(String), Int(i64), Float(f64), Bool(bool), None }

#[derive(Default)]
pub struct SSAChunk {
    pub instructions: Vec<Instruction>,
    pub constants:    Vec<Value>,
    pub names:        Vec<String>,
    pub functions:    Vec<(Vec<String>, SSAChunk, u16)>,
    pub annotations:  HashMap<String, String>,
    pub phi_sources:  Vec<(u16, u16)>,
    pub classes: Vec<SSAChunk>,
    name_index:       HashMap<String, u16>,   // O(1) dedup for push_name
}

impl SSAChunk {
    fn emit(&mut self, op: OpCode, operand: u16) {
        self.instructions.push(Instruction { opcode: op, operand });
    }

    fn snapshot(&self) -> (usize, usize, usize) {
        (self.instructions.len(), self.constants.len(), self.names.len())
    }

    fn restore(&mut self, (inst, consts, names): (usize, usize, usize)) {
        self.instructions.truncate(inst);
        self.constants.truncate(consts);
        for name in self.names.drain(names..) {
            self.name_index.remove(&name);
        }
    }

    fn push_const(&mut self, v: Value) -> u16 {
        self.constants.push(v);
        (self.constants.len() - 1) as u16
    }

    fn push_name(&mut self, n: &str) -> u16 {
        if let Some(&i) = self.name_index.get(n) {
            return i;
        }
        let i = self.names.len() as u16;
        self.names.push(n.to_string());
        self.name_index.insert(n.to_string(), i);
        i
    }
}

// ─── Join Node (snapshot for control flow merges) ───────────────────────────

struct JoinNode {
    backup: HashMap<String, u32>,
    then:   Option<HashMap<String, u32>>,
}

// ─── Parser ─────────────────────────────────────────────────────────────────

pub struct Parser<'src, I: Iterator<Item = Token>> {
    source:       &'src str,
    tokens:       Peekable<I>,
    chunk:        SSAChunk,
    ssa_versions: HashMap<String, u32>,
    join_stack:   Vec<JoinNode>,
    loop_starts:  Vec<u16>,
    loop_breaks:  Vec<Vec<usize>>,
    saw_newline: bool,
}

// ─── String helpers ─────────────────────────────────────────────────────────

fn parse_string(s: &str) -> String {
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
            Some('n')  => out.push('\n'),
            Some('t')  => out.push('\t'),
            Some('r')  => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"')  => out.push('"'),
            Some('0')  => out.push('\0'),
            Some(c)    => { out.push('\\'); out.push(c); }
            None       => out.push('\\'),
        }
    }
    out
}

// ─── SSA version management ────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn current_version(&self, name: &str) -> u32 {
        self.ssa_versions.get(name).copied().unwrap_or(0)
    }

    fn increment_version(&mut self, name: &str) -> u32 {
        let cur = self.current_version(name);
        let new = cur + 1;
        self.ssa_versions.insert(name.to_string(), new);
        new
    }

    fn emit_load_ssa(&mut self, name: String) {
        let v   = self.current_version(&name);
        let ssa = format!("{}_{}", name, v);
        let i   = self.chunk.push_name(&ssa);
        self.chunk.emit(OpCode::LoadName, i);
    }

    fn store_name(&mut self, name: String) {
        let ver = self.increment_version(&name);
        let i   = self.chunk.push_name(&format!("{}_{}", name, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }
}

// ─── Block / branch management ─────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn enter_block(&mut self) {
        self.join_stack.push(JoinNode {
            backup: self.ssa_versions.clone(),
            then:   None,
        });
    }

    fn mid_block(&mut self) {
        let Some(j) = self.join_stack.last_mut() else { return };
        j.then = Some(self.ssa_versions.clone());
        let mut restored = j.backup.clone();
        for (name, &v) in &self.ssa_versions {
            let e = restored.entry(name.clone()).or_insert(0);
            *e = (*e).max(v);
        }
        self.ssa_versions = restored;
    }

    fn commit_block(&mut self) {
        let Some(j) = self.join_stack.pop() else { return };
        let post = self.ssa_versions.clone();

        let (a, b) = match j.then {
            Some(t) => (t, post),
            None    => (post, j.backup.clone()),
        };

        let mut names: Vec<_> = a.keys().chain(b.keys()).cloned().collect();
        names.sort();
        names.dedup();

        for name in names {
            let va = *a.get(&name).unwrap_or(&0);
            let vb = *b.get(&name).unwrap_or(&0);
            if va == vb { continue; }

            let ia = self.chunk.push_name(&format!("{}_{}", name, va));
            let ib = self.chunk.push_name(&format!("{}_{}", name, vb));

            let v  = self.increment_version(&name);
            let ix = self.chunk.push_name(&format!("{}_{}", name, v));

            self.chunk.phi_sources.push((ia, ib));
            self.chunk.emit(OpCode::Phi, ix);
        }
    }
}

// ─── Token helpers ──────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn advance(&mut self) -> Token {
        self.tokens.next().unwrap()
    }

    fn at_end(&mut self) -> bool {
        self.peek().is_none()
    }

    fn lexeme(&self, t: &Token) -> &'src str {
        &self.source[t.start..t.end]
    }

    fn peek(&mut self) -> Option<TokenType> {
        loop {
            match self.tokens.peek().map(|t| t.kind.clone()) {
                Some(TokenType::Newline) => { self.saw_newline = true; self.tokens.next(); }
                Some(TokenType::Nl | TokenType::Comment) => { self.tokens.next(); }
                Some(k) => return Some(k),
                None    => return None,
            }
        }
    }

    fn patch(&mut self, pos: usize) {
        self.chunk.instructions[pos].operand = self.chunk.instructions.len() as u16;
    }

    fn eat(&mut self, kind: TokenType) {
        if matches!(self.peek(), Some(k) if k == kind) { self.advance(); }
    }

    fn eat_if(&mut self, kind: TokenType) -> bool {
        if matches!(self.peek(), Some(k) if k == kind) { self.advance(); true } else { false }
    }

}

// ─── Top-level parse ────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub fn new(source: &'src str, iter: I) -> Self {
        Self {
            source,
            tokens:       iter.peekable(),
            chunk:        SSAChunk::default(),
            ssa_versions: HashMap::new(),
            join_stack:   Vec::new(),
            loop_starts:  Vec::new(),
            loop_breaks:  Vec::new(),
            saw_newline: false,
        }
    }

    pub fn parse(mut self) -> SSAChunk {
        while !self.at_end() {
            let produced_value = self.stmt();
            if !self.at_end() && produced_value {
                self.chunk.emit(OpCode::PopTop, 0);
            }
        }
        self.chunk.emit(OpCode::ReturnValue, 0);
        self.chunk
    }
}

// ─── Statements ─────────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn stmt(&mut self) -> bool {
        match self.peek() {
            Some(TokenType::If)       => { self.if_stmt(); false }
            Some(TokenType::While)    => { self.while_stmt(); false }
            Some(TokenType::For)      => { self.for_stmt(); false }
            Some(TokenType::Def) => { self.advance(); self.func_def(0); false }
            Some(TokenType::Match) => { self.match_stmt(); false }
            Some(TokenType::At) => {
                let mut count = 0u16;
                while self.eat_if(TokenType::At) {
                    self.expr();
                    count += 1;
                }
                self.advance();
                self.func_def(count);
                false
            }            Some(TokenType::Class) => { self.advance(); self.class_def(); false }
            Some(TokenType::Pass) => { self.advance(); false }
            Some(TokenType::Try)   => { self.try_stmt(); false }
            Some(TokenType::Import) => { self.import_stmt(); false }
            Some(TokenType::From)   => { self.from_stmt(); false }
            Some(TokenType::With) => { self.with_stmt(); false }
            Some(TokenType::Global) => {
                self.advance();
                loop {
                    let t = self.advance();
                    let name = self.lexeme(&t).to_string();
                    let idx = self.chunk.push_name(&name);
                    self.chunk.emit(OpCode::Global, idx);
                    if !self.eat_if(TokenType::Comma) { break; }
                }
                false
            }
            Some(TokenType::Nonlocal) => {
                self.advance();
                loop {
                    let t = self.advance();
                    let name = self.lexeme(&t).to_string();
                    let idx = self.chunk.push_name(&name);
                    self.chunk.emit(OpCode::Nonlocal, idx);
                    if !self.eat_if(TokenType::Comma) { break; }
                }
                false
            }
            Some(TokenType::Assert) => {
                self.advance();
                self.expr();
                self.chunk.emit(OpCode::Assert, 0);
                false
            }
            Some(TokenType::Del) => {
                self.advance();
                let t = self.advance();
                let name = self.lexeme(&t).to_string();
                let idx = self.chunk.push_name(&format!("{}_{}", name, self.current_version(&name)));
                self.chunk.emit(OpCode::Del, idx);
                false
            }
            Some(TokenType::Yield) => {
                self.advance();
                if matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker)) {
                    self.chunk.emit(OpCode::LoadNone, 0);
                } else {
                    self.expr();
                }
                self.chunk.emit(OpCode::Yield, 0);
                true
            }
            Some(TokenType::Raise) => {
                self.advance();
                if !matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker)) {
                    self.expr();
                    if self.eat_if(TokenType::From) {
                        self.expr();
                        self.chunk.emit(OpCode::RaiseFrom, 0);
                    } else {
                        self.chunk.emit(OpCode::Raise, 0);
                    }
                } else {
                    self.chunk.emit(OpCode::Raise, 0);
                }
                false
            }
            Some(TokenType::Break)    => {
                self.advance();
                self.chunk.emit(OpCode::Jump, 0);
                self.loop_breaks.last_mut().unwrap().push(self.chunk.instructions.len() - 1);
                false
            }
            Some(TokenType::Continue) => {
                self.advance();
                let start = *self.loop_starts.last().unwrap();
                self.chunk.emit(OpCode::Jump, start);
                false
            }
            Some(TokenType::Star) => {
                self.advance();
                let t = self.advance();
                let mut targets = vec![format!("*{}", self.lexeme(&t))];
                while self.eat_if(TokenType::Comma) {
                    if !matches!(self.peek(), Some(TokenType::Name)) { break; }
                    let t = self.advance();
                    targets.push(self.lexeme(&t).to_string());
                }
                self.eat(TokenType::Equal);
                self.expr();
                let after = (targets.len() - 1) as u16;
                self.chunk.emit(OpCode::UnpackEx, after);
                for target in targets.into_iter().rev() {
                    self.store_name(target.trim_start_matches('*').to_string());
                }
                false
            }
            Some(TokenType::Return) => {
                self.advance();
                if matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker)) {
                    self.chunk.emit(OpCode::LoadNone, 0);
                } else {
                    self.expr();
                    let mut count = 1u16;
                    while self.eat_if(TokenType::Comma) {
                        self.expr();
                        count += 1;
                    }
                    if count > 1 { self.chunk.emit(OpCode::BuildTuple, count); }
                }
                self.chunk.emit(OpCode::ReturnValue, 0);
                false
            }
            Some(TokenType::Name) => {
                let t = self.advance();
                self.name_stmt(t)
            }
            _ => {
                self.expr();
                true
            }
        }
    }

    fn compile_block(&mut self) {
        let indented = self.eat_if(TokenType::Indent);
        while !self.at_end() {
            if matches!(self.peek(), Some(TokenType::Dedent)) {
                self.advance();
                break;
            }
            if matches!(self.peek(), Some(TokenType::Newline | TokenType::Nl)) {
                self.advance();
                continue;
            }
            let produced_value = self.stmt();
            if !self.at_end() && produced_value {
                self.chunk.emit(OpCode::PopTop, 0);
            }
            if !indented { break; }
        }
    }
}

// ─── Control flow ───────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn if_stmt(&mut self) {
        self.advance();
        self.enter_block();
        self.if_body();
        self.commit_block();
    }

    fn match_stmt(&mut self) {
        self.advance();
        self.expr();

        let ver = self.increment_version("__match__");
        let subj = self.chunk.push_name(&format!("__match__{}", ver));
        self.chunk.emit(OpCode::StoreName, subj);

        self.eat(TokenType::Colon);
        self.eat_if(TokenType::Indent);

        let mut end_jumps = Vec::new();

        while matches!(self.peek(), Some(TokenType::Case)) {
            self.advance();

            if matches!(self.peek(), Some(TokenType::Underscore)) {
                self.advance();
                self.eat(TokenType::Colon);
                self.compile_block();
            } else {
                self.chunk.emit(OpCode::LoadName, subj);
                self.expr();
                self.chunk.emit(OpCode::Eq, 0);
                self.chunk.emit(OpCode::JumpIfFalse, 0);
                let jf = self.chunk.instructions.len() - 1;

                self.eat(TokenType::Colon);
                self.compile_block();

                self.chunk.emit(OpCode::Jump, 0);
                end_jumps.push(self.chunk.instructions.len() - 1);
                self.patch(jf);
            }
        }

        self.eat_if(TokenType::Dedent);

        for pos in end_jumps {
            self.patch(pos);
        }
    }

    fn if_body(&mut self) {
        self.expr();
        self.chunk.emit(OpCode::JumpIfFalse, 0);
        let jf = self.chunk.instructions.len() - 1;

        self.eat(TokenType::Colon);
        self.compile_block();

        match self.peek() {
            Some(TokenType::Elif) => {
                self.advance();
                self.chunk.emit(OpCode::Jump, 0);
                let jmp = self.chunk.instructions.len() - 1;
                self.mid_block();
                self.patch(jf);
                self.if_body();
                self.patch(jmp);
            }
            Some(TokenType::Else) => {
                self.advance();
                self.chunk.emit(OpCode::Jump, 0);
                let jmp = self.chunk.instructions.len() - 1;
                self.mid_block();
                self.patch(jf);
                self.eat(TokenType::Colon);
                self.compile_block();
                self.patch(jmp);
            }
            _ => {
                self.patch(jf);
            }
        }
    }

    fn while_stmt(&mut self) {
        self.advance();
        self.enter_block();

        let loop_start = self.chunk.instructions.len() as u16;
        self.loop_starts.push(loop_start);
        self.loop_breaks.push(vec![]);

        self.expr();
        self.chunk.emit(OpCode::JumpIfFalse, 0);
        let jf = self.chunk.instructions.len() - 1;

        self.eat(TokenType::Colon);
        self.compile_block();

        self.chunk.emit(OpCode::Jump, loop_start);
        self.patch(jf);

        if self.eat_if(TokenType::Else) {
            self.eat(TokenType::Colon);
            self.compile_block();
        }

        self.loop_starts.pop();
        for pos in self.loop_breaks.pop().unwrap_or_default() { self.patch(pos); }

        self.commit_block();
    }

    fn import_stmt(&mut self) {
        self.advance();
        loop {
            let module = self.dotted_name();
            let mod_idx = self.chunk.push_name(&module);
            self.chunk.emit(OpCode::Import, mod_idx);
            if self.eat_if(TokenType::As) {
                let t = self.advance();
                let alias = self.lexeme(&t).to_string();
                self.store_name(alias);
            } else {
                let root = module.split('.').next().unwrap().to_string();
                self.store_name(root);
            }
            if !self.eat_if(TokenType::Comma) { break; }
        }
    }

    fn with_stmt(&mut self) {
        self.advance();
        loop {
            self.expr();
            self.chunk.emit(OpCode::SetupWith, 0);
            if self.eat_if(TokenType::As) {
                let t = self.advance();
                let name = self.lexeme(&t).to_string();
                self.store_name(name);
            }
            if !self.eat_if(TokenType::Comma) { break; }
        }
        self.eat(TokenType::Colon);
        self.compile_block();
        self.chunk.emit(OpCode::ExitWith, 0);
    }

    fn dotted_name(&mut self) -> String {
        let t = self.advance();
        let mut name = self.lexeme(&t).to_string();
        while self.eat_if(TokenType::Dot) {
            let t = self.advance();
            name.push('.');
            name.push_str(self.lexeme(&t));
        }
        name
    }

    fn from_stmt(&mut self) {
        self.advance();
        let module = self.dotted_name();
        let mod_idx = self.chunk.push_name(&module);
        self.chunk.emit(OpCode::Import, mod_idx);
        self.eat(TokenType::Import);
        if self.eat_if(TokenType::Star) {
            let star = self.chunk.push_name("*");
            self.chunk.emit(OpCode::ImportFrom, star);
        } else {
            loop {
                let t = self.advance();
                let name = self.lexeme(&t).to_string();
                let name_idx = self.chunk.push_name(&name);
                self.chunk.emit(OpCode::ImportFrom, name_idx);
                if self.eat_if(TokenType::As) {
                    let t = self.advance();
                    let alias = self.lexeme(&t).to_string();
                    self.store_name(alias);
                } else {
                    self.store_name(name);
                }
                if !self.eat_if(TokenType::Comma) { break; }
            }
        }
        self.chunk.emit(OpCode::PopTop, 0);
    }

    fn for_stmt(&mut self) {
        self.advance();

        let mut vars = Vec::new();
        loop {
            let t = self.advance();
            vars.push(self.lexeme(&t).to_string());
            if !self.eat_if(TokenType::Comma) { break; }
            if matches!(self.peek(), Some(TokenType::In)) { break; }
        }

        self.eat(TokenType::In);
        self.expr();
        self.chunk.emit(OpCode::GetIter, 0);

        self.enter_block();

        let loop_start = self.chunk.instructions.len() as u16;
        self.loop_starts.push(loop_start);
        self.loop_breaks.push(vec![]);

        self.chunk.emit(OpCode::ForIter, 0);
        let fi = self.chunk.instructions.len() - 1;

        if vars.len() == 1 {
            let ver = self.increment_version(&vars[0]);
            let idx = self.chunk.push_name(&format!("{}_{}", vars[0], ver));
            self.chunk.emit(OpCode::StoreName, idx);
        } else {
            self.chunk.emit(OpCode::UnpackSequence, vars.len() as u16);
            for var in vars.iter().rev() {
                let ver = self.increment_version(var);
                let idx = self.chunk.push_name(&format!("{}_{}", var, ver));
                self.chunk.emit(OpCode::StoreName, idx);
            }
        }

        self.eat(TokenType::Colon);
        self.compile_block();

        self.chunk.emit(OpCode::Jump, loop_start);
        self.patch(fi);

        if self.eat_if(TokenType::Else) {
            self.eat(TokenType::Colon);
            self.compile_block();
        }

        self.loop_starts.pop();
        for pos in self.loop_breaks.pop().unwrap_or_default() { self.patch(pos); }

        self.commit_block();
    }

    fn try_stmt(&mut self) {
        self.advance();
        self.eat(TokenType::Colon);

        self.chunk.emit(OpCode::SetupExcept, 0);
        let setup = self.chunk.instructions.len() - 1;

        self.enter_block();
        self.compile_block();

        self.chunk.emit(OpCode::PopExcept, 0);
        self.chunk.emit(OpCode::Jump, 0);
        let jmp = self.chunk.instructions.len() - 1;

        self.patch(setup);

        while self.eat_if(TokenType::Except) {
            if !matches!(self.peek(), Some(TokenType::Colon)) {
                self.expr();
                if self.eat_if(TokenType::As) {
                    let t = self.advance();
                    let name = self.lexeme(&t).to_string();
                    self.store_name(name);
                }
            }
            self.eat(TokenType::Colon);
            self.compile_block();
        }

        self.patch(jmp);

        if self.eat_if(TokenType::Else) {
            self.eat(TokenType::Colon);
            self.compile_block();
        }

        if self.eat_if(TokenType::Finally) {
            self.eat(TokenType::Colon);
            self.compile_block();
        }

        self.commit_block();
    }

}

// ─── Name statements & assignment ───────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn name_stmt(&mut self, t: Token) -> bool {
        let name = self.lexeme(&t).to_string();

        if self.eat_if(TokenType::Colon) {
            if matches!(self.peek(), Some(TokenType::Name)) {
                let ann = { let t = self.advance(); self.lexeme(&t).to_string() };
                self.chunk.annotations.insert(name.clone(), ann);
            }
            if !matches!(self.peek(), Some(TokenType::Equal)) { return false; }
        }

        match self.peek() {
            Some(TokenType::Equal) => {
                self.assign(name);
                false
            }
            Some(TokenType::PlusEqual) => {
                self.advance();
                self.emit_load_ssa(name.clone());
                self.expr();
                self.chunk.emit(OpCode::Add, 0);
                self.store_name(name);
                false
            }
            Some(TokenType::MinEqual) => {
                self.advance();
                self.emit_load_ssa(name.clone());
                self.expr();
                self.chunk.emit(OpCode::Sub, 0);
                self.store_name(name);
                false
            }
            Some(TokenType::StarEqual) => {
                self.advance();
                self.emit_load_ssa(name.clone());
                self.expr();
                self.chunk.emit(OpCode::Mul, 0);
                self.store_name(name);
                false
            }
            Some(TokenType::SlashEqual) => {
                self.advance();
                self.emit_load_ssa(name.clone());
                self.expr();
                self.chunk.emit(OpCode::Div, 0);
                self.store_name(name);
                false
            }
            Some(TokenType::Dot) => {
                self.emit_load_ssa(name);
                self.advance();
                let t = self.advance();
                let attr = self.lexeme(&t).to_string();
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    self.expr();
                    let idx = self.chunk.push_name(&attr);
                    self.chunk.emit(OpCode::StoreAttr, idx);
                    false
                } else {
                    let idx = self.chunk.push_name(&attr);
                    self.chunk.emit(OpCode::LoadAttr, idx);
                    self.postfix_tail();
                    self.mul_tail();
                    self.add_tail();
                    self.shift_tail();
                    self.bitand_tail();
                    self.bitxor_tail();
                    self.bitor_tail();
                    self.cmp_tail();
                    self.and_tail();
                    self.or_tail();
                    true
                }
            }
            Some(TokenType::Comma) => {
                let mut targets = vec![name];
                let mut star_pos: Option<usize> = None;
                while self.eat_if(TokenType::Comma) {
                    if self.eat_if(TokenType::Star) {
                        star_pos = Some(targets.len());
                        let t = self.advance();
                        targets.push(format!("*{}", self.lexeme(&t)));
                    } else if matches!(self.peek(), Some(TokenType::Name)) {
                        let t = self.advance();
                        targets.push(self.lexeme(&t).to_string());
                    } else { break; }
                }
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    self.expr();
                    let mut count = 1u16;
                    while self.eat_if(TokenType::Comma) {
                        if matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker) | None) { break; }
                        self.expr();
                        count += 1;
                    }
                    if count > 1 { self.chunk.emit(OpCode::BuildTuple, count); }
                    if let Some(sp) = star_pos {
                        let before = sp as u16;
                        let after = (targets.len() - sp - 1) as u16;
                        self.chunk.emit(OpCode::UnpackEx, (before << 8) | after);
                    } else {
                        self.chunk.emit(OpCode::UnpackSequence, targets.len() as u16);
                    }
                    for target in targets.into_iter().rev() {
                        self.store_name(target.trim_start_matches('*').to_string());
                    }
                    false
                } else {
                    for t in &targets { self.emit_load_ssa(t.clone()); }
                    self.chunk.emit(OpCode::BuildTuple, targets.len() as u16);
                    true
                }
            }
            Some(TokenType::Lpar) => {
                self.call(name)
            }
            _ => {
                self.emit_load_ssa(name);
                self.postfix_tail();
                self.mul_tail();
                self.add_tail();
                self.shift_tail();
                self.bitand_tail();
                self.bitxor_tail();
                self.bitor_tail();
                self.cmp_tail();
                self.and_tail();
                self.or_tail();
                true
            }

        }
    }

    fn assign(&mut self, name: String) {
        self.advance();
        self.expr();
        self.store_name(name);
    }
}

// ─── Expression parsing (precedence climbing) ───────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    
    fn expr(&mut self) {
        self.saw_newline = false;
        self.parse_or();
        if !self.saw_newline && matches!(self.peek(), Some(TokenType::If)) {
            self.advance();
            self.parse_or();
            self.chunk.emit(OpCode::JumpIfFalse, 0);
            let jf = self.chunk.instructions.len() - 1;
            self.chunk.emit(OpCode::Jump, 0);
            let jmp = self.chunk.instructions.len() - 1;
            self.patch(jf);
            self.chunk.emit(OpCode::PopTop, 0);
            self.eat(TokenType::Else);
            self.parse_or();
            self.patch(jmp);
        }
    }

    fn parse_or(&mut self)  { self.parse_and(); self.or_tail(); }
    fn parse_and(&mut self) { self.parse_not(); self.and_tail(); }
    fn parse_cmp(&mut self)    { self.parse_bitor();  self.cmp_tail(); }
    fn parse_bitor(&mut self)  { self.parse_bitxor(); self.bitor_tail(); }
    fn parse_bitxor(&mut self) { self.parse_bitand(); self.bitxor_tail(); }
    fn parse_bitand(&mut self) { self.parse_shift();  self.bitand_tail(); }
    fn parse_shift(&mut self)  { self.parse_add();    self.shift_tail(); }
    fn parse_add(&mut self)    { self.parse_mul();    self.add_tail(); }
    fn parse_mul(&mut self)    { self.parse_unary();  self.mul_tail(); }

    fn parse_unary(&mut self) {
        match self.peek() {
            Some(TokenType::Minus) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Minus, 0); }
            Some(TokenType::Not)   => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Not, 0); }
            Some(TokenType::Tilde) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::BitNot, 0); }
            _ => self.parse_atom(),
        }
    }

    fn parse_not(&mut self) {
        if matches!(self.peek(), Some(TokenType::Not)) {
            self.advance(); self.parse_not(); self.chunk.emit(OpCode::Not, 0);
        } else {
            self.parse_cmp();
        }
    }

    fn or_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Or)) {
            self.advance(); self.parse_and(); self.chunk.emit(OpCode::Or, 0);
        }
    }

    fn and_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::And)) {
            self.advance(); self.parse_not(); self.chunk.emit(OpCode::And, 0);
        }
    }

    fn cmp_tail(&mut self) {
        match self.peek() {
            Some(TokenType::EqEqual)      => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::Eq,    0); }
            Some(TokenType::NotEqual)     => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::NotEq, 0); }
            Some(TokenType::Less)         => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::Lt,    0); }
            Some(TokenType::Greater)      => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::Gt,    0); }
            Some(TokenType::LessEqual)    => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::LtEq,  0); }
            Some(TokenType::GreaterEqual) => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::GtEq,  0); }
            Some(TokenType::In)           => { self.advance(); self.parse_bitor(); self.chunk.emit(OpCode::In,    0); }
            Some(TokenType::Is) => {
                self.advance();
                if self.eat_if(TokenType::Not) {
                    self.parse_bitor(); self.chunk.emit(OpCode::IsNot, 0);
                } else {
                    self.parse_bitor(); self.chunk.emit(OpCode::Is, 0);
                }
            }
            Some(TokenType::Not) => {
                self.advance();
                self.eat(TokenType::In);
                self.parse_bitor(); self.chunk.emit(OpCode::NotIn, 0);
            }
            _ => {}
        }
    }

    fn add_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Plus | TokenType::Minus)) {
            match self.peek() {
                Some(TokenType::Plus)  => { self.advance(); self.parse_mul(); self.chunk.emit(OpCode::Add, 0); }
                Some(TokenType::Minus) => { self.advance(); self.parse_mul(); self.chunk.emit(OpCode::Sub, 0); }
                _ => break,
            }
        }
    }

    fn mul_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Star | TokenType::Slash | TokenType::Percent | TokenType::DoubleStar | TokenType::DoubleSlash)) {
            match self.peek() {
                Some(TokenType::Star)        => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Mul,      0); }
                Some(TokenType::Slash)       => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Div,      0); }
                Some(TokenType::Percent)     => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Mod,      0); }
                Some(TokenType::DoubleStar)  => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Pow,      0); }
                Some(TokenType::DoubleSlash) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::FloorDiv, 0); }
                _ => break,
            }
        }
    }

    fn shift_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::LeftShift | TokenType::RightShift)) {
            match self.peek() {
                Some(TokenType::LeftShift)  => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::Shl, 0); }
                Some(TokenType::RightShift) => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::Shr, 0); }
                _ => break,
            }
        }
    }

    fn bitand_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Amper)) {
            self.advance(); self.parse_shift(); self.chunk.emit(OpCode::BitAnd, 0);
        }
    }

    fn bitxor_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Circumflex)) {
            self.advance(); self.parse_bitand(); self.chunk.emit(OpCode::BitXor, 0);
        }
    }

    fn bitor_tail(&mut self) {
        while matches!(self.peek(), Some(TokenType::Vbar)) {
            self.advance(); self.parse_bitxor(); self.chunk.emit(OpCode::BitOr, 0);
        }
    }
    
}

// ─── Atoms ──────────────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn parse_atom(&mut self) {
        let t = self.advance();
        match t.kind {
            TokenType::Name                    => self.name(t),
            TokenType::String => {
                let mut s = parse_string(self.lexeme(&t));
                while matches!(self.peek(), Some(TokenType::String)) {
                    let t = self.advance();
                    s.push_str(&parse_string(self.lexeme(&t)));
                }
                self.emit_const(Value::Str(s));
            }
            TokenType::Complex => {
                let raw = self.lexeme(&t).replace('_', "");
                let s = raw.trim_end_matches(|c: char| c == 'j' || c == 'J');
                self.emit_const(Value::Float(s.parse().unwrap_or(0.0)));
            }
            TokenType::Int | TokenType::Float  => self.parse_number(self.lexeme(&t), t.kind),
            TokenType::True                    => self.chunk.emit(OpCode::LoadTrue, 0),
            TokenType::False                   => self.chunk.emit(OpCode::LoadFalse, 0),
            TokenType::None                    => self.chunk.emit(OpCode::LoadNone, 0),
            TokenType::Ellipsis => self.chunk.emit(OpCode::LoadEllipsis, 0),
            TokenType::FstringStart            => self.fstring(),
            TokenType::Lbrace => self.brace_literal(),
            TokenType::Lsqb                    => self.list_literal(),
            TokenType::Lpar => {
                self.expr();
                if matches!(self.peek(), Some(TokenType::For)) {
                    self.comprehension(OpCode::GenExpr);
                } else if self.eat_if(TokenType::Comma) {
                    let mut count = 1u16;
                    while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
                        self.expr();
                        count += 1;
                        if !self.eat_if(TokenType::Comma) { break; }
                    }
                    self.eat(TokenType::Rpar);
                    self.chunk.emit(OpCode::BuildTuple, count);
                } else {
                    self.eat(TokenType::Rpar);
                }
            }
            TokenType::Lambda => self.parse_lambda(),
            _ => {}
        }
        self.postfix_tail();
    }

    fn name(&mut self, t: Token) {
        let name = self.lexeme(&t).to_string();
        match self.peek() {
            Some(TokenType::Equal) => self.assign(name),
            Some(TokenType::ColonEqual) => {
                self.advance();
                self.expr();
                let ver = self.increment_version(&name);
                let ssa = format!("{}_{}", name, ver);
                let i = self.chunk.push_name(&ssa);
                self.chunk.emit(OpCode::StoreName, i);
                self.chunk.emit(OpCode::LoadName, i);
            }
            Some(TokenType::Lpar) => { let _ = self.call(name); }
            _ => self.emit_load_ssa(name),
        }
        self.postfix_tail();
    }

    fn parse_lambda(&mut self) {
        let mut params = Vec::new();
        if !matches!(self.peek(), Some(TokenType::Colon)) {
            loop {
                let p = self.advance();
                params.push(self.lexeme(&p).to_string());
                if !self.eat_if(TokenType::Comma) { break; }
            }
        }
        self.eat(TokenType::Colon);

        let saved_chunk = std::mem::take(&mut self.chunk);
        let saved_ver   = std::mem::take(&mut self.ssa_versions);
        self.ssa_versions = HashMap::new();
        for p in &params { self.ssa_versions.insert(p.clone(), 0); }

        self.expr();
        self.chunk.emit(OpCode::ReturnValue, 0);

        let body = std::mem::take(&mut self.chunk);
        self.chunk        = saved_chunk;
        self.ssa_versions = saved_ver;

        let fi = self.chunk.functions.len() as u16;
        self.chunk.functions.push((params, body, 0));
        self.chunk.emit(OpCode::MakeFunction, fi);
    }

    fn parse_number(&mut self, raw: &str, kind: TokenType) {
        let s = raw.replace('_', "");
        if kind == TokenType::Float {
            self.emit_const(Value::Float(s.parse().unwrap_or(0.0)));
        } else {
            let v = if let Some(s) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
                i64::from_str_radix(s, 16).unwrap_or(0)
            } else if let Some(s) = s.strip_prefix("0o").or(s.strip_prefix("0O")) {
                i64::from_str_radix(s, 8).unwrap_or(0)
            } else if let Some(s) = s.strip_prefix("0b").or(s.strip_prefix("0B")) {
                i64::from_str_radix(s, 2).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            };
            self.emit_const(Value::Int(v));
        }
    }

    fn emit_const(&mut self, v: Value) {
        let i = self.chunk.push_const(v);
        self.chunk.emit(OpCode::LoadConst, i);
    }

    fn postfix_tail(&mut self) {
        loop {
            match self.peek() {
                Some(TokenType::Lsqb) => {
                    self.advance();
                    let is_slice = matches!(self.peek(), Some(TokenType::Colon));
                    if is_slice {
                        self.chunk.emit(OpCode::LoadNone, 0);
                    } else {
                        self.expr();
                    }
                    if self.eat_if(TokenType::Colon) {
                        let mut parts = 2u16;
                        if matches!(self.peek(), Some(TokenType::Colon | TokenType::Rsqb)) {
                            self.chunk.emit(OpCode::LoadNone, 0);
                        } else {
                            self.expr();
                        }
                        if self.eat_if(TokenType::Colon) {
                            parts = 3;
                            if matches!(self.peek(), Some(TokenType::Rsqb)) {
                                self.chunk.emit(OpCode::LoadNone, 0);
                            } else {
                                self.expr();
                            }
                        }
                        self.eat(TokenType::Rsqb);
                        self.chunk.emit(OpCode::BuildSlice, parts);
                        self.chunk.emit(OpCode::GetItem, 0);
                    } else {
                        self.eat(TokenType::Rsqb);
                        self.chunk.emit(OpCode::GetItem, 0);
                    }
                }
                Some(TokenType::Dot) => {
                    self.advance();
                    let t = self.advance();
                    let attr = self.lexeme(&t).to_string();
                    let idx = self.chunk.push_name(&attr);
                    self.chunk.emit(OpCode::LoadAttr, idx);
                    if matches!(self.peek(), Some(TokenType::Lpar)) {
                        let argc = self.parse_args();
                        self.chunk.emit(OpCode::Call, argc);
                    }
                }
                _ => break,
            }
        }
    }
}

// ─── Literals ───────────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn brace_literal(&mut self) {
        if matches!(self.peek(), Some(TokenType::Rbrace)) {
            self.advance();
            self.chunk.emit(OpCode::BuildDict, 0);
            return;
        }
        self.expr();
        match self.peek() {
            Some(TokenType::Colon) => {
                self.advance();
                self.expr();
                if matches!(self.peek(), Some(TokenType::For)) {
                    self.comprehension(OpCode::DictComp);
                } else {
                    let mut pairs = 1u16;
                    while self.eat_if(TokenType::Comma) {
                        if matches!(self.peek(), Some(TokenType::Rbrace)) { break; }
                        self.expr();
                        self.eat(TokenType::Colon);
                        self.expr();
                        pairs += 1;
                    }
                    self.advance();
                    self.chunk.emit(OpCode::BuildDict, pairs);
                }
            }
            Some(TokenType::For) => {
                self.comprehension(OpCode::SetComp);
            }
            _ => {
                let mut count = 1u16;
                while self.eat_if(TokenType::Comma) {
                    if matches!(self.peek(), Some(TokenType::Rbrace)) { break; }
                    self.expr();
                    count += 1;
                }
                self.advance();
                self.chunk.emit(OpCode::BuildSet, count);
            }
        }
    }

    fn comprehension(&mut self, op: OpCode) {
        let mut loop_starts = Vec::new();
        let mut for_iters = Vec::new();

        while self.eat_if(TokenType::For) {
            let t = self.advance();
            let var = self.lexeme(&t).to_string();
            self.eat(TokenType::In);
            self.parse_or();
            self.chunk.emit(OpCode::GetIter, 0);

            let ls = self.chunk.instructions.len() as u16;
            self.chunk.emit(OpCode::ForIter, 0);
            let fi = self.chunk.instructions.len() - 1;

            let ver = self.increment_version(&var);
            let idx = self.chunk.push_name(&format!("{}_{}", var, ver));
            self.chunk.emit(OpCode::StoreName, idx);

            while self.eat_if(TokenType::If) {
                self.parse_or();
                self.chunk.emit(OpCode::JumpIfFalse, ls);
            }

            loop_starts.push(ls);
            for_iters.push(fi);
        }

        let n = for_iters.len();
        let mut jump_positions = Vec::new();
        for &ls in loop_starts.iter().rev() {
            self.chunk.emit(OpCode::Jump, ls);
            jump_positions.push(self.chunk.instructions.len() - 1);
        }

        for i in 1..n {
            let target = jump_positions[n - i] as u16;
            self.chunk.instructions[for_iters[i]].operand = target;
        }

        self.patch(for_iters[0]);

        self.advance();
        self.chunk.emit(op, 0);
    }

    fn list_literal(&mut self) {
        if matches!(self.peek(), Some(TokenType::Rsqb)) {
            self.advance();
            self.chunk.emit(OpCode::BuildList, 0);
            return;
        }
        self.expr();
        if matches!(self.peek(), Some(TokenType::For)) {
            self.comprehension(OpCode::ListComp);
        } else {
            let mut count = 1u16;
            while self.eat_if(TokenType::Comma) {
                if matches!(self.peek(), Some(TokenType::Rsqb)) { break; }
                self.expr();
                count += 1;
            }
            self.advance();
            self.chunk.emit(OpCode::BuildList, count);
        }
    }

    fn fstring(&mut self) {
        let mut parts = 0u16;
        loop {
            match self.peek() {
                Some(TokenType::FstringMiddle) => {
                    let t = self.advance();
                    self.emit_const(Value::Str(self.lexeme(&t).to_string()));
                    parts += 1;
                }
                Some(TokenType::Lbrace) => {
                    self.advance();
                    self.expr();
                    if matches!(self.peek(), Some(TokenType::Colon)) {
                        let colon = self.advance();
                        let spec_start = colon.end;
                        loop {
                            match self.tokens.peek().map(|t| t.kind.clone()) {
                                Some(TokenType::Rbrace) | None => break,
                                _ => { self.tokens.next(); }
                            }
                        }
                        let spec_end = self.tokens.peek().map(|t| t.start).unwrap_or(spec_start);
                        let spec = self.source[spec_start..spec_end].to_string();
                        let idx = self.chunk.push_const(Value::Str(spec));
                        self.chunk.emit(OpCode::LoadConst, idx);
                        self.chunk.emit(OpCode::FormatValue, 1);
                    } else {
                        self.chunk.emit(OpCode::FormatValue, 0);
                    }
                    parts += 1;
                    if matches!(self.peek(), Some(TokenType::Rbrace)) {
                        self.advance();
                    }
                }
                Some(TokenType::FstringEnd) => { self.advance(); break; }
                _ => break,
            }
        }
        if parts > 0 { self.chunk.emit(OpCode::BuildString, parts); }
    }
}

// ─── Function calls ────────────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {

    fn call(&mut self, name: String) -> bool {
        // print: special case (no value on stack)
        if name == "print" {
            let _ = self.parse_args();
            self.chunk.emit(OpCode::CallPrint, 0);
            return false;
        }

        // range: special case (variable argc)
        if name == "range" {
            self.call_range();
            return true;
        }

        // O(1) builtin lookup
        if let Some((op, leaves_value)) = BUILTINS.get(name.as_str()) {
            let a = self.parse_args();
            self.chunk.emit(op.clone(), a);
            return *leaves_value;
        }

        // User-defined function
        let v = self.current_version(&name);
        let i = self.chunk.push_name(&format!("{}_{}", name, v));
        self.chunk.emit(OpCode::LoadName, i);
        let a = self.parse_args();
        self.chunk.emit(OpCode::Call, a);
        true
    }

    fn call_range(&mut self) {
        self.advance();
        let mut argc = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            self.expr();
            argc += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance();
        self.chunk.emit(OpCode::CallRange, argc);
    }
}

// ─── Function definitions ──────────────────────────────────────────────────

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    fn class_def(&mut self) {
        let cname = { let n = self.advance(); self.lexeme(&n).to_string() };

        if self.eat_if(TokenType::Lpar) {
            while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
                self.expr();
                if !self.eat_if(TokenType::Comma) { break; }
            }
            self.eat(TokenType::Rpar);
        }

        self.eat(TokenType::Colon);

        let saved_chunk = std::mem::take(&mut self.chunk);
        let saved_ver   = std::mem::take(&mut self.ssa_versions);
        self.ssa_versions = HashMap::new();

        self.compile_block();

        let body = std::mem::take(&mut self.chunk);
        self.chunk        = saved_chunk;
        self.ssa_versions = saved_ver;

        let ci = self.chunk.classes.len() as u16;
        self.chunk.classes.push(body);
        self.chunk.emit(OpCode::MakeClass, ci);

        let ver = self.increment_version(&cname);
        let i   = self.chunk.push_name(&format!("{}_{}", cname, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    fn func_def(&mut self, decorators: u16) {
        let fname = { let n = self.advance(); self.lexeme(&n).to_string() };
        let (params, defaults) = self.parse_params();
        let body = self.compile_body(&params);

        let fi = self.chunk.functions.len() as u16;
        self.chunk.functions.push((params, body, defaults));
        self.chunk.emit(OpCode::MakeFunction, fi);

        for _ in 0..decorators {
            self.chunk.emit(OpCode::Call, 1);
        }

        let ver = self.increment_version(&fname);
        let i   = self.chunk.push_name(&format!("{}_{}", fname, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    fn parse_args(&mut self) -> u16 {
        self.advance();
        let mut argc = 0;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            if self.eat_if(TokenType::Star) {
                self.expr();
                self.chunk.emit(OpCode::UnpackArgs, 1);
            } else if self.eat_if(TokenType::DoubleStar) {
                self.expr();
                self.chunk.emit(OpCode::UnpackArgs, 2);
            } else if matches!(self.peek(), Some(TokenType::Name)) {
                let t = self.advance();
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    let i = self.chunk.push_const(Value::Str(self.lexeme(&t).to_string()));
                    self.chunk.emit(OpCode::LoadConst, i);
                    self.expr();
                } else {
                    self.name(t);
                }
            } else {
                self.expr();
            }
            argc += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance();
        argc
    }

    fn parse_params(&mut self) -> (Vec<String>, u16) {
        self.advance();
        let mut params = Vec::new();
        let mut defaults = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            if self.eat_if(TokenType::Star) {
                let p = self.advance();
                params.push(format!("*{}", self.lexeme(&p)));
                if self.eat_if(TokenType::Colon) {
                    while !matches!(self.peek(), Some(
                        TokenType::Equal | TokenType::Comma | TokenType::Rpar
                    ) | None) {
                        self.advance();
                    }
                }
            } else if self.eat_if(TokenType::DoubleStar) {
                let p = self.advance();
                params.push(format!("**{}", self.lexeme(&p)));
                if self.eat_if(TokenType::Colon) {
                    while !matches!(self.peek(), Some(
                        TokenType::Equal | TokenType::Comma | TokenType::Rpar
                    ) | None) {
                        self.advance();
                    }
                }
            } else {
                let p = self.advance();
                params.push(self.lexeme(&p).to_string());
                if self.eat_if(TokenType::Colon) {
                    while !matches!(self.peek(), Some(
                        TokenType::Equal | TokenType::Comma | TokenType::Rpar
                    ) | None) {
                        self.advance();
                    }
                }
                if self.eat_if(TokenType::Equal) {
                    self.expr();
                    defaults += 1;
                }
            }
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance();
        if self.eat_if(TokenType::Rarrow) {
            while !matches!(self.peek(), Some(TokenType::Colon) | None) {
                self.advance();
            }
        }
        if matches!(self.peek(), Some(TokenType::Colon)) { self.advance(); }
        (params, defaults)
    }

    fn compile_body(&mut self, params: &[String]) -> SSAChunk {
        let saved_chunk = std::mem::take(&mut self.chunk);
        let saved_ver   = std::mem::take(&mut self.ssa_versions);

        self.ssa_versions = HashMap::new();
        for p in params {
            self.ssa_versions.insert(p.clone(), 0);
        }

        self.compile_block();

        let body = std::mem::take(&mut self.chunk);

        self.chunk        = saved_chunk;
        self.ssa_versions = saved_ver;

        body
    }
}