// parser/mod.rs

pub(super) mod types;

mod stmt;
mod control;
mod expr;
mod literals;

pub use types::*;

use crate::modules::lexer::{Token, TokenType};
use alloc::{string::{String, ToString}, vec::Vec, format};
use hashbrown::HashMap;
use core::iter::Peekable;

/*
Parser Struct
    Main parser state holding source, tokens, SSA chunk, versions and control stacks.
*/

pub struct Parser<'src, I: Iterator<Item = Token>> {
    pub(super) source: &'src str,
    pub(super) tokens: Peekable<I>,
    pub(super) chunk: SSAChunk,
    pub(super) ssa_versions: HashMap<String, u32>,
    pub(super) join_stack: Vec<JoinNode>,
    pub(super) loop_starts: Vec<u16>,
    pub(super) loop_breaks: Vec<Vec<usize>>,
    pub(super) expr_depth: usize,
    pub(super) saw_newline: bool,
    pub errors: Vec<Diagnostic>,
}

/*
SSA Version Management
    Tracks and updates SSA versions for variables to enable static single assignment.
*/

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub(super) fn current_version(&self, name: &str) -> u32 {
        self.ssa_versions.get(name).copied().unwrap_or(0)
    }

    pub(super) fn ssa_name<'a>(name: &str, ver: u32, buf: &'a mut [u8; 128]) -> &'a str {
        struct W<'a> { b: &'a mut [u8; 128], n: usize }
        impl core::fmt::Write for W<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.n + s.len();
                if end <= self.b.len() {
                    self.b[self.n..end].copy_from_slice(s.as_bytes());
                    self.n = end;
                }
                Ok(())
            }
        }
        let mut w = W { b: buf, n: 0 };
        use core::fmt::Write;
        let _ = write!(w, "{}_{}", name, ver);
        core::str::from_utf8(&w.b[..w.n]).unwrap() // lifetime tied to buf, zero heap allocation
    }

    pub(super) fn increment_version(&mut self, name: &str) -> u32 {
        let cur = self.current_version(name);
        let new = cur + 1;
        self.ssa_versions.insert(name.to_string(), new);
        new
    }

    pub(super) fn emit_load_ssa(&mut self, name: String) {
        let v = self.current_version(&name);
        let mut buf = [0u8; 128];
        let i = self.chunk.push_name(Self::ssa_name(&name, v, &mut buf));
        self.chunk.emit(OpCode::LoadName, i);
    }

    pub(super) fn emit_const(&mut self, v: Value) {
        let i = self.chunk.push_const(v);
        self.chunk.emit(OpCode::LoadConst, i);
    }

    pub(super) fn store_name(&mut self, name: String) {
        let ver = self.increment_version(&name);
        let mut buf = [0u8; 128];
        let i = self.chunk.push_name(Self::ssa_name(&name, ver, &mut buf));
        self.chunk.emit(OpCode::StoreName, i);
    }
}

/*
Block and Branch Management
    Handles SSA merging for if/else blocks and creates PHI nodes at control-flow joins.
*/

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub(super) fn enter_block(&mut self) {
        self.join_stack.push(JoinNode {
            backup: self.ssa_versions.clone(),
            then: None,
        });
    }

    pub(super) fn mid_block(&mut self) {
        let Some(j) = self.join_stack.last_mut() else { return };
        j.then = Some(self.ssa_versions.clone()); // snapshot then-branch before overwriting with else baseline
        let mut restored = j.backup.clone();
        for (name, &v) in &self.ssa_versions {
            let e = restored.entry(name.clone()).or_insert(0);
            *e = (*e).max(v);
        }
        self.ssa_versions = restored;
    }

    pub(super) fn commit_block(&mut self) {
        let Some(j) = self.join_stack.pop() else { return };
        let post = self.ssa_versions.clone();

        let (a, b) = match j.then {
            Some(t) => (t, post),
            None    => (post, j.backup.clone()),
        };

        let mut divergent: Vec<&String> = a
            .keys()
            .chain(b.keys())
            .filter(|name| a.get(*name).unwrap_or(&0) != b.get(*name).unwrap_or(&0))
            .collect();
        divergent.sort(); // deterministic Phi order regardless of HashMap iteration
        divergent.dedup(); // chain() can produce duplicates when both branches define the same var

        for name in divergent {
            let va = *a.get(name).unwrap_or(&0);
            let vb = *b.get(name).unwrap_or(&0);
            let mut ba = [0u8; 128];
            let mut bb = [0u8; 128];
            let mut bx = [0u8; 128];
            let ia = self.chunk.push_name(Self::ssa_name(name, va, &mut ba));
            let ib = self.chunk.push_name(Self::ssa_name(name, vb, &mut bb));
            let v  = self.increment_version(name);
            let ix = self.chunk.push_name(Self::ssa_name(name, v, &mut bx));
            self.chunk.phi_sources.push((ia, ib));
            self.chunk.emit(OpCode::Phi, ix);
        }
    }
}

/*
Token Helpers
    Utility methods to advance, peek, eat tokens and report parser errors cleanly.
*/

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub(super) fn advance(&mut self) -> Token {
        self.tokens.next().unwrap_or(Token {
            kind: TokenType::Endmarker,
            line: 0,
            start: 0,
            end: 0,
        })
    }

    pub(super) fn error(&mut self, msg: &str) {
        let (line, col, end) = self
            .tokens
            .peek()
            .map(|t| (t.line, t.start, t.end))
            .unwrap_or((0, 0, 0));
        self.errors.push(Diagnostic { line, col, end, msg: msg.to_string() });
    }

    pub(super) fn at_end(&mut self) -> bool {
        self.peek().is_none()
    }

    pub(super) fn lexeme(&self, t: &Token) -> &'src str {
        &self.source[t.start..t.end]
    }

    pub(super) fn peek(&mut self) -> Option<TokenType> {
        loop {
            match self.tokens.peek().map(|t| t.kind) {
                Some(TokenType::Newline) => {
                    self.saw_newline = true;
                    self.tokens.next();
                }
                Some(TokenType::Nl | TokenType::Comment) => { self.tokens.next(); }
                Some(k)  => return Some(k),
                None     => return None,
            }
        }
    }

    pub(super) fn patch(&mut self, pos: usize) {
        self.chunk.instructions[pos].operand = self.chunk.instructions.len() as u16;
    }

    pub(super) fn eat(&mut self, kind: TokenType) {
        if matches!(self.peek(), Some(k) if k == kind) {
            self.advance();
        } else {
            self.error(&format!("expected {:?}", kind));
        }
    }

    pub(super) fn eat_if(&mut self, kind: TokenType) -> bool {
        if matches!(self.peek(), Some(k) if k == kind) {
            self.advance();
            true
        } else {
            false
        }
    }
}

/*
Top-Level Entry Points
    Parser constructor and main parse method that drives full compilation to SSA.
*/

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {
    pub fn new(source: &'src str, iter: I) -> Self {
        Self {
            source,
            tokens: iter.peekable(),
            chunk: SSAChunk::default(),
            ssa_versions: HashMap::new(),
            join_stack: Vec::new(),
            loop_starts: Vec::new(),
            loop_breaks: Vec::new(),
            saw_newline: false,
            expr_depth: 0,
            errors: Vec::new(),
        }
    }

    pub fn parse(mut self) -> (SSAChunk, Vec<Diagnostic>) {
        while !self.at_end() {
            let produced_value = self.stmt();
            if !self.at_end() && produced_value {
                self.chunk.emit(OpCode::PopTop, 0);
            }
        }
        if !self.errors.is_empty() {
            self.chunk.instructions.clear();
            self.chunk.constants.clear();
            self.chunk.names.clear();
        }
        self.chunk.emit(OpCode::ReturnValue, 0);
        (self.chunk, self.errors)
    }
}