/*
`parser.rs`
    Single-pass SSA bytecode emitter. No AST. Variables versioned on assignment (new def per write), phi-joined (select reaching defs) at control flow boundaries.

    Usage:
        ```rust
        mod modules {
            pub mod lexer;
            pub mod parser;
        }

        let source = "value: int = abs(-42)";

        let chunk = modules::parser::Parser::new(source, modules::lexer::lexer(source)).parse();

        // Instructions.
        for (i, ins) in chunk.instructions.iter().enumerate() {
            info!("{:03} {:?} {}", i, ins.opcode, ins.operand);
        }

        let tokens: Vec<String> = modules::lexer::lexer(source)
            .map(|t| format!("{:?} [{}-{}]", t.kind, t.start, t.end))
            .collect();

        info!("{:?}", tokens);

        info!("constants: {:?}", chunk.constants);
        info!("names: {:?}", chunk.names);
        ```

    Output:
        ```bash
        2026-03-18T05:42:07.381Z INFO  [compiler] 000 LoadConst 0
        2026-03-18T05:42:07.381Z INFO  [compiler] 001 Minus 0
        2026-03-18T05:42:07.381Z INFO  [compiler] 002 CallAbs 1
        2026-03-18T05:42:07.381Z INFO  [compiler] 003 StoreName 0
        2026-03-18T05:42:07.381Z INFO  [compiler] 004 PopTop 0
        2026-03-18T05:42:07.381Z INFO  [compiler] 005 ReturnValue 0
        2026-03-18T05:42:07.381Z INFO  [compiler] ["Name [0-5]", "Colon [5-6]", "Name [7-10]", "Equal [11-12]", "Name [13-16]", "Lpar [16-17]", "Minus [17-18]", "Int [18-20]", "Rpar [20-21]", "Endmarker [20-21]"]
        2026-03-18T05:42:07.381Z INFO  [compiler] constants: [Int(42)]
        2026-03-18T05:42:07.381Z INFO  [compiler] names: ["value"]
        ```
*/
use crate::modules::lexer::{Token, TokenType};
use std::iter::Peekable;
use std::collections::HashMap;

#[derive(Debug)]
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
    GetItem, Mod, Pow, FloorDiv
}

#[derive(Debug)] pub struct Instruction { pub opcode: OpCode, pub operand: u16 }
#[derive(Debug)] pub enum Value { Str(String), Int(i64), Float(f64), Bool(bool), None }

#[derive(Default)]
pub struct SSAChunk {
    pub instructions: Vec<Instruction>,
    pub constants: Vec<Value>,
    pub names: Vec<String>,
    pub functions: Vec<(Vec<String>, SSAChunk)>,
    pub annotations: HashMap<String, String>,
}

impl SSAChunk {
    fn emit(&mut self, op: OpCode, operand: u16) { self.instructions.push(Instruction { opcode: op, operand }); }
    fn push_const(&mut self, v: Value) -> u16 { self.constants.push(v); (self.constants.len()-1) as u16 }
    fn push_name(&mut self, n: &str) -> u16 {
        if let Some(i) = self.names.iter().position(|x| x == n) { return i as u16; }
        self.names.push(n.to_string()); (self.names.len()-1) as u16
    }
}

struct JoinNode {
    backup: HashMap<String, u32>
}

pub struct Parser<'src, I: Iterator<Item = Token>> {
    source: &'src str,
    tokens: Peekable<I>,
    chunk: SSAChunk,
    ssa_versions: HashMap<String, u32>,
    join_stack: Vec<JoinNode>,
    loop_starts: Vec<u16>,        // continue salta aquí
    loop_breaks: Vec<Vec<usize>> // break: posiciones a patchear
}

fn parse_string(s: &str) -> String { 
    let is_raw = s.contains('r') || s.contains('R');
    let s = s.trim_start_matches(|c: char| "bBrRuU".contains(c));
    let inner = if s.starts_with("\"\"\"") || s.starts_with("'''") { &s[3..s.len()-3] } else { &s[1..s.len()-1] };
    if is_raw { inner.to_string() } else { unescape(inner) }
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' { out.push(c); continue; }
        match chars.next() {
            Some('n') => out.push('\n'), Some('t') => out.push('\t'),
            Some('r') => out.push('\r'), Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''), Some('"') => out.push('"'),
            Some('0') => out.push('\0'), Some(c) => { out.push('\\'); out.push(c); }
            None => out.push('\\'),
        }
    }
    out
}

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub fn new(source: &'src str, iter: I) -> Self {
        Self { source, tokens: iter.peekable(), chunk: SSAChunk::default(), ssa_versions: HashMap::new(), join_stack: Vec::new(), loop_starts: Vec::new(), loop_breaks: Vec::new() }
    }

    pub fn parse(mut self) -> SSAChunk {
        while !self.at_end() {
        let is_compound = matches!(self.peek(), 
            Some(TokenType::For | TokenType::If | TokenType::While | TokenType::Def));
            self.stmt();
            if !self.at_end() && !is_compound { self.chunk.emit(OpCode::PopTop, 0); }
        }
        self.chunk.emit(OpCode::ReturnValue, 0);
        self.chunk
    }

    fn current_version(&self, name: &str) -> u32 { self.ssa_versions.get(name).copied().unwrap_or(0) }
    
    fn increment_version(&mut self, name: &str) -> u32 {
        let v = self.current_version(name) + 1;
        self.ssa_versions.insert(name.to_string(), v);
        v
    }

    fn emit_load_ssa(&mut self, name: String) {
        let v = self.current_version(&name);
        let ssa = format!("{}_{}", name, v);
        let i = self.chunk.push_name(&ssa);
        self.chunk.emit(OpCode::LoadName, i);
    }

    fn enter_block(&mut self) { 
        self.join_stack.push(JoinNode { backup: self.ssa_versions.clone() }); 
    }
    
    fn commit_block(&mut self) {
        if let Some(j) = self.join_stack.pop() {
            let post = self.ssa_versions.clone();
            self.ssa_versions = j.backup;
            for (name, post_ver) in &post {
                let pre_ver = self.ssa_versions.get(name).copied().unwrap_or(0);
                if *post_ver != pre_ver {
                    // parte desde post_ver, no desde backup, evita colisión
                    self.ssa_versions.insert(name.to_string(), *post_ver);
                    let new_ver = self.increment_version(name);
                    let ssa = format!("{}_{}", name, new_ver);
                    let i = self.chunk.push_name(&ssa);
                    self.chunk.emit(OpCode::Phi, i);
                }
            }
        }
    }

    fn peek(&mut self) -> Option<TokenType> {
        loop {
            match self.tokens.peek().map(|t| t.kind.clone()) {
                Some(TokenType::Newline | TokenType::Nl | TokenType::Comment) => { self.tokens.next(); }
                Some(k) => return Some(k),
                None => return None,
            }
        }
    }

    fn advance(&mut self) -> Token { self.tokens.next().unwrap() }
    fn at_end(&mut self) -> bool { self.peek().is_none() }
    fn lexeme(&self, t: &Token) -> &'src str { &self.source[t.start..t.end] }

    fn store_name(&mut self, name: String) {
        let ver = self.increment_version(&name);
        let i = self.chunk.push_name(&format!("{}_{}", name, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    fn stmt(&mut self) {
        match self.peek() {
            Some(TokenType::If)    => self.if_stmt(),
            Some(TokenType::While) => self.while_stmt(),
            Some(TokenType::For)   => self.for_stmt(),
            Some(TokenType::Name)  => { let t = self.advance(); self.name_stmt(t); }
            Some(TokenType::Def)   => { self.advance(); self.func_def(); }
            Some(TokenType::Break) => {
                self.advance();
                self.chunk.emit(OpCode::Jump, 0);
                self.loop_breaks.last_mut().unwrap().push(self.chunk.instructions.len() - 1);
            }
            Some(TokenType::Continue) => {
                self.advance();
                let start = *self.loop_starts.last().unwrap();
                self.chunk.emit(OpCode::Jump, start);
            }
            Some(TokenType::Return) => {
                self.advance();
                if matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker)) {
                    self.emit_const(Value::None);
                } else {
                    self.expr();
                }
                self.chunk.emit(OpCode::ReturnValue, 0);
            }
            _ => self.expr()
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
        self.stmt();
        self.chunk.emit(OpCode::Jump, loop_start);
        self.patch(jf);
        self.loop_starts.pop();
        for pos in self.loop_breaks.pop().unwrap_or_default() { self.patch(pos); }
        self.commit_block();
    }

    fn if_stmt(&mut self) {
        self.advance();          // consume 'if'
        self.enter_block();      // un solo bloque para toda la cadena
        self.if_body();          // parsea if / elif* / else?
        self.commit_block();     // un solo join point al final
    }

    fn if_body(&mut self) {
        self.expr();
        self.chunk.emit(OpCode::JumpIfFalse, 0);
        let jf = self.chunk.instructions.len() - 1;
        self.eat(TokenType::Colon);
        self.stmt();
        self.chunk.emit(OpCode::PopTop, 0);

        match self.peek() {
            Some(TokenType::Elif) => {
                self.advance();              // consume 'elif'
                self.chunk.emit(OpCode::Jump, 0);
                let jmp = self.chunk.instructions.len() - 1;
                self.patch(jf);
                self.if_body();              // recursivo SIN enter/commit
                self.patch(jmp);
            }
            Some(TokenType::Else) => {
                self.advance();
                self.chunk.emit(OpCode::Jump, 0);
                let jmp = self.chunk.instructions.len() - 1;
                self.patch(jf);
                self.eat(TokenType::Colon);
                self.stmt();
                self.chunk.emit(OpCode::PopTop, 0);
                self.patch(jmp);
            }
            _ => { self.patch(jf); }
        }
    }

    fn for_stmt(&mut self) {
        self.advance();
        let var = { let t = self.advance(); self.lexeme(&t).to_string() };
        self.eat(TokenType::In);
        self.expr();
        self.chunk.emit(OpCode::GetIter, 0);

        let loop_start = self.chunk.instructions.len() as u16;
        self.loop_starts.push(loop_start);
        self.loop_breaks.push(vec![]);
        self.chunk.emit(OpCode::ForIter, 0);
        let fi = self.chunk.instructions.len() - 1;

        let ver = self.increment_version(&var);
        let idx = self.chunk.push_name(&format!("{}_{}", var, ver));
        self.chunk.emit(OpCode::StoreName, idx);

        self.eat(TokenType::Colon);
        self.stmt();
        self.chunk.emit(OpCode::PopTop, 0);
        self.chunk.emit(OpCode::Jump, loop_start);
        self.patch(fi);
        self.loop_starts.pop();
        for pos in self.loop_breaks.pop().unwrap_or_default() { self.patch(pos); }
    }

    // helpers
    fn patch(&mut self, pos: usize) {
        self.chunk.instructions[pos].operand = self.chunk.instructions.len() as u16;
    }
    fn eat(&mut self, kind: TokenType) {
        if matches!(self.peek(), Some(k) if k == kind) { self.advance(); }
    }
    fn eat_if(&mut self, kind: TokenType) -> bool {
        if matches!(self.peek(), Some(k) if k == kind) { self.advance(); true } else { false }
    }

    fn dict_literal(&mut self) {
        let mut pairs = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rbrace) | None) {
            self.expr(); // clave
            if matches!(self.peek(), Some(TokenType::Colon)) { self.advance(); }
            self.expr(); // valor
            pairs += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance(); // consume '}'
        self.chunk.emit(OpCode::BuildDict, pairs);
    }

    fn list_literal(&mut self) {
        let mut count = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rsqb) | None) {
            self.expr();
            count += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance(); // consume ']'
        self.chunk.emit(OpCode::BuildList, count);
    }

    fn parse_number(&mut self, raw: &str, kind: TokenType) {
        let s = raw.replace('_', "");
        if kind == TokenType::Float {
            self.emit_const(Value::Float(s.parse().unwrap_or(0.0)));
        } else {
            let v = if let Some(s) = s.strip_prefix("0x").or(s.strip_prefix("0X")) { i64::from_str_radix(s, 16).unwrap_or(0) }
            else if let Some(s) = s.strip_prefix("0o").or(s.strip_prefix("0O")) { i64::from_str_radix(s, 8).unwrap_or(0) }
            else if let Some(s) = s.strip_prefix("0b").or(s.strip_prefix("0B")) { i64::from_str_radix(s, 2).unwrap_or(0) }
            else { s.parse().unwrap_or(0) };
            self.emit_const(Value::Int(v));
        }
    }

    fn emit_const(&mut self, v: Value) {
        let i = self.chunk.push_const(v);
        self.chunk.emit(OpCode::LoadConst, i);
    }

    fn name_stmt(&mut self, t: Token) {
        let name = self.lexeme(&t).to_string();

        // anotación de tipo
        if self.eat_if(TokenType::Colon) {
            if matches!(self.peek(), Some(TokenType::Name)) {
                let ann = { let t = self.advance(); self.lexeme(&t).to_string() };
                self.chunk.annotations.insert(name.clone(), ann);
            }
            if !matches!(self.peek(), Some(TokenType::Equal)) { return; }
        }

        // assign y call no necesitan la cadena de precedencia
        match self.peek() {
            Some(TokenType::Equal)      => { self.assign(name); return; }
            Some(TokenType::PlusEqual)  => { self.advance(); self.emit_load_ssa(name.clone()); self.expr(); self.chunk.emit(OpCode::Add, 0); self.store_name(name); return; }
            Some(TokenType::MinEqual) => { self.advance(); self.emit_load_ssa(name.clone()); self.expr(); self.chunk.emit(OpCode::Sub, 0); self.store_name(name); return; }
            Some(TokenType::StarEqual)  => { self.advance(); self.emit_load_ssa(name.clone()); self.expr(); self.chunk.emit(OpCode::Mul, 0); self.store_name(name); return; }
            Some(TokenType::SlashEqual) => { self.advance(); self.emit_load_ssa(name.clone()); self.expr(); self.chunk.emit(OpCode::Div, 0); self.store_name(name); return; }
            Some(TokenType::Lpar)       => { self.call(name); return; }
            _ => {}
        }

        self.emit_load_ssa(name);
        self.mul_tail();
        self.add_tail();
        self.cmp_tail();
        self.and_tail();
        self.or_tail();
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
            Some(TokenType::EqEqual)      => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::Eq,    0); }
            Some(TokenType::NotEqual)     => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::NotEq, 0); }
            Some(TokenType::Less)         => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::Lt,    0); }
            Some(TokenType::Greater)      => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::Gt,    0); }
            Some(TokenType::LessEqual)    => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::LtEq,  0); }
            Some(TokenType::GreaterEqual) => { self.advance(); self.parse_add(); self.chunk.emit(OpCode::GtEq,  0); }
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
        while matches!(self.peek(), Some(TokenType::Star | TokenType::Slash)) {
            match self.peek() {
                Some(TokenType::Star)  => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Mul, 0); }
                Some(TokenType::Slash) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Div, 0); }
                Some(TokenType::Percent)     => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Mod,      0); }
                Some(TokenType::DoubleStar)  => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Pow,      0); }
                Some(TokenType::DoubleSlash) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::FloorDiv, 0); }
                _ => break,
            }
        }
    }

    fn expr(&mut self) { self.parse_or(); }

    fn parse_or(&mut self)  { self.parse_and();   self.or_tail();  }
    fn parse_and(&mut self) { self.parse_not();   self.and_tail(); }
    fn parse_add(&mut self) { self.parse_mul();   self.add_tail(); }
    fn parse_mul(&mut self) { self.parse_unary(); self.mul_tail(); }
    fn parse_cmp(&mut self) { self.parse_add();   self.cmp_tail(); }

    fn parse_unary(&mut self) {
        match self.peek() {
            Some(TokenType::Minus) => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Minus, 0); }
            Some(TokenType::Not)   => { self.advance(); self.parse_unary(); self.chunk.emit(OpCode::Not,   0); }
            _                      => self.parse_atom(),
        }
    }

    fn parse_not(&mut self) {
        if matches!(self.peek(), Some(TokenType::Not)) {
            self.advance(); self.parse_not(); self.chunk.emit(OpCode::Not, 0);
        } else {
            self.parse_cmp();
        }
    }

    fn parse_atom(&mut self) {
        let t = self.advance();
        match t.kind {
            TokenType::Name         => self.name(t),
            TokenType::String       => self.emit_const(Value::Str(parse_string(self.lexeme(&t)))),
            TokenType::Int | TokenType::Float => self.parse_number(self.lexeme(&t), t.kind),
            TokenType::True         => self.emit_const(Value::Bool(true)),
            TokenType::False        => self.emit_const(Value::Bool(false)),
            TokenType::None         => self.emit_const(Value::None),
            TokenType::FstringStart => self.fstring(),
            TokenType::Lbrace       => self.dict_literal(),
            TokenType::Lsqb        => self.list_literal(),
            TokenType::Lpar         => { self.expr(); self.eat(TokenType::Rpar); }
            _ => {}
        }
        while matches!(self.peek(), Some(TokenType::Lsqb)) {
            self.advance();
            self.expr();
            self.eat(TokenType::Rsqb);
            self.chunk.emit(OpCode::GetItem, 0);
        }
    }

    fn name(&mut self, t: Token) {           // solo desde expr()
        let name = self.lexeme(&t).to_string();
        match self.peek() {
            Some(TokenType::Equal) => self.assign(name),
            Some(TokenType::Lpar)  => self.call(name),
            _                      => self.emit_load_ssa(name),
        }
    }

    fn assign(&mut self, name: String) {
        self.advance();
        self.expr();
        self.store_name(name);
    }

    fn parse_args(&mut self) -> u16 {
        self.advance();
        let mut argc = 0;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            // kwarg: name=value → emite ("name", value)
            if matches!(self.peek(), Some(TokenType::Name)) {
                let t = self.advance();
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    let i = self.chunk.push_const(Value::Str(self.lexeme(&t).to_string()));
                    self.chunk.emit(OpCode::LoadConst, i);
                    self.expr();
                } else {
                    self.name(t); // expresión normal
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

    fn call(&mut self, name: String) {
        match name.as_str() {
            "print" => { let _ = self.parse_args(); self.chunk.emit(OpCode::CallPrint, 0); }
            "len" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallLen, a); }
            "abs" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallAbs, a); }
            "str" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallStr, a); }
            "int" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallInt, a); }
            "type" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallType, a); }
            "float" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallFloat, a); }
            "bool"  => { let a = self.parse_args(); self.chunk.emit(OpCode::CallBool, a); }
            "round" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallRound, a); }
            "min" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallMin, a); }
            "max" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallMax, a); }
            "sum" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallSum, a); }
            "sorted" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallSorted, a); }
            "enumerate" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallEnumerate, a); }
            "zip" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallZip, a); }
            "list" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallList, a); }
            "tuple" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallTuple, a); }
            "dict" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallDict, a); }
            "set" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallSet, a); }
            "input" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallInput, a); }
            "isinstance" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallIsInstance, a); }
            "chr" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallChr, a); }
            "ord" => { let a = self.parse_args(); self.chunk.emit(OpCode::CallOrd, a); }
            "range" => self.call_range(),
            _ => {
                let v = self.current_version(&name);
                let i = self.chunk.push_name(&format!("{}_{}", name, v));
                self.chunk.emit(OpCode::LoadName, i);
                let a = self.parse_args();
                self.chunk.emit(OpCode::Call, a);
            }
        }
    }

    fn func_def(&mut self) {
        let fname  = { let n = self.advance(); self.lexeme(&n).to_string() };
        let params = self.parse_params();
        let body   = self.compile_body(&params);

        let fi = self.chunk.functions.len() as u16;
        self.chunk.functions.push((params, body));
        self.chunk.emit(OpCode::MakeFunction, fi);

        let ver = self.increment_version(&fname);
        let i   = self.chunk.push_name(&format!("{}_{}", fname, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    fn parse_params(&mut self) -> Vec<String> {
        self.advance(); // (
        let mut params = Vec::new();
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            let p = self.advance();
            params.push(self.lexeme(&p).to_string());
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance(); // )
        if matches!(self.peek(), Some(TokenType::Colon)) { self.advance(); }
        params
    }
        
    fn compile_body(&mut self, params: &[String]) -> SSAChunk {
        let (saved_chunk, saved_ver) = (std::mem::take(&mut self.chunk), std::mem::take(&mut self.ssa_versions));
        for p in params { self.ssa_versions.insert(p.clone(), 0); }
        
        loop {
            let is_return = matches!(self.peek(), Some(TokenType::Return));
            self.stmt();
            if is_return || self.at_end() { break; }
        }
        
        let body = std::mem::take(&mut self.chunk);
        (self.chunk, self.ssa_versions) = (saved_chunk, saved_ver);
        body
    }

    fn call_range(&mut self) {
        self.advance();                                                  // consume '('
        let mut argc = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            self.expr();                                                 // ← cualquier expr
            argc += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) { self.advance(); }
        }
        self.advance();                                                  // consume ')'
        self.chunk.emit(OpCode::CallRange, argc);                       // VM recibe argc en stack
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
                    self.advance(); // consume '{'
                    self.expr();    // ← parser normal, soporta TODO
                    self.chunk.emit(OpCode::FormatValue, 0);
                    parts += 1;
                    if matches!(self.peek(), Some(TokenType::Rbrace)) {
                        self.advance(); // consume '}'
                    }
                }
                Some(TokenType::FstringEnd) => { self.advance(); break; }
                _ => break,
            }
        }
        if parts > 0 { self.chunk.emit(OpCode::BuildString, parts); }
    }
}