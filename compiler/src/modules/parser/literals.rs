// parser/literals.rs

use super::Parser;
use super::types::{OpCode, Value, SSAChunk};
use super::types::builtin;
use crate::modules::lexer::{Token, TokenType};
use alloc::{string::{String, ToString}, vec::Vec, format};
use hashbrown::HashMap;

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {

    /*
    Brace Literal Handler
        Parses {} for dict/set literals and dict/set comprehensions.
    */

    pub(super) fn brace_literal(&mut self) {
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
                        if matches!(self.peek(), Some(TokenType::Rbrace)) {
                            break;
                        }
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
                    if matches!(self.peek(), Some(TokenType::Rbrace)) {
                        break;
                    }
                    self.expr();
                    count += 1;
                }
                self.advance();
                self.chunk.emit(OpCode::BuildSet, count);
            }
        }
    }

    /*
    List Literal Handler
        Parses [] for list literals and list comprehensions.
    */

    pub(super) fn list_literal(&mut self) {
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
                if matches!(self.peek(), Some(TokenType::Rsqb)) {
                    break;
                }
                self.expr();
                count += 1;
            }
            self.advance();
            self.chunk.emit(OpCode::BuildList, count);
        }
    }

    /*
    Comprehension Handler
        Generates SSA bytecode for list/set/dict/generator comprehensions.
    */

    pub(super) fn comprehension(&mut self, op: OpCode) {
        let mut loop_starts = Vec::new();
        let mut for_iters = Vec::new();

        while self.eat_if(TokenType::For) {
            let mut vars = Vec::new();
            loop {
                let t = self.advance();
                vars.push(self.lexeme(&t).to_string());
                if !self.eat_if(TokenType::Comma) {
                    break;
                }
                if matches!(self.peek(), Some(TokenType::In)) {
                    break;
                }
            }

            self.eat(TokenType::In);
            self.expr_bp(1);
            self.chunk.emit(OpCode::GetIter, 0);

            let ls = self.chunk.instructions.len() as u16;
            self.chunk.emit(OpCode::ForIter, 0);
            let fi = self.chunk.instructions.len() - 1;

            if vars.len() == 1 {
                let ver = self.increment_version(&vars[0]);
                let idx = self.chunk.push_name(&Self::ssa_name(&vars[0], ver));
                self.chunk.emit(OpCode::StoreName, idx);
            } else {
                self.chunk.emit(OpCode::UnpackSequence, vars.len() as u16);
                for var in vars.iter().rev() {
                    self.store_name(var.clone());
                }
            }

            while self.eat_if(TokenType::If) {
                self.expr_bp(1);
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
            self.chunk.instructions[for_iters[i]].operand = target; // back-patch inner ForIter now that all loop headers are known
        }

        self.patch(for_iters[0]);

        self.advance();
        self.chunk.emit(op, 0);
    }

    /*
    F-String Parser
        Parses f-strings with embedded expressions and format specs.
    */

    pub(super) fn fstring(&mut self) {
        let mut parts = 0u16;
        if matches!(self.peek(), Some(TokenType::FstringEnd)) {
            self.advance();
            self.emit_const(Value::Str(String::new()));
            return;
        }
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
                Some(TokenType::FstringEnd) => {
                    self.advance();
                    break;
                }
                _ => break,
            }
        }
        if parts > 0 {
            self.chunk.emit(OpCode::BuildString, parts);
        }
    }

    /*
    Function Call Handler
        Dispatches print/range/builtins or general function calls with args.
    */

    pub(super) fn call(&mut self, name: String) -> bool {
        if name == "print" {
            let _ = self.parse_args();
            self.chunk.emit(OpCode::CallPrint, 0);
            return false;
        }

        if name == "range" {
            self.call_range();
            return true;
        }

        if let Some((op, leaves_value)) = builtin(name.as_str()) {
            let a = self.parse_args();
            self.chunk.emit(op, a);
            return leaves_value;
        }

        let v = self.current_version(&name);
        let i = self.chunk.push_name(&Self::ssa_name(&name, v));
        self.chunk.emit(OpCode::LoadName, i);
        let a = self.parse_args();
        self.chunk.emit(OpCode::Call, a);
        true
    }

    pub(super) fn call_range(&mut self) {
        self.advance();
        let mut argc = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            self.expr();
            argc += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) {
                self.advance();
            }
        }
        self.advance();
        self.chunk.emit(OpCode::CallRange, argc);
    }

    pub(super) fn parse_args(&mut self) -> u16 {
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
                    self.infix_bp(0);
                }
            } else {
                self.expr();
            }
            argc += 1;
            if matches!(self.peek(), Some(TokenType::Comma)) {
                self.advance();
            }
        }
        self.eat(TokenType::Rpar);
        argc
    }

    /*
    Class Definition
        Parses class header, compiles body separately and emits MakeClass.
    */

    pub(super) fn class_def(&mut self) {
        let cname = {
            let n = self.advance();
            self.lexeme(&n).to_string()
        };

        if self.eat_if(TokenType::Lpar) {
            while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
                self.expr();
                if !self.eat_if(TokenType::Comma) {
                    break;
                }
            }
            self.eat(TokenType::Rpar);
        }

        self.eat(TokenType::Colon);

        let saved_chunk = core::mem::take(&mut self.chunk);
        let saved_ver   = core::mem::take(&mut self.ssa_versions);
        self.ssa_versions = HashMap::new();

        self.compile_block();

        let body = core::mem::take(&mut self.chunk);
        self.chunk = saved_chunk;
        self.ssa_versions  = saved_ver;

        let ci = self.chunk.classes.len() as u16;
        self.chunk.classes.push(body);
        self.chunk.emit(OpCode::MakeClass, ci);

        let ver = self.increment_version(&cname);
        let i   = self.chunk.push_name(&Self::ssa_name(&cname, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    /*
    Function Definition
        Parses params/defaults, compiles body and emits MakeFunction or coroutine.
    */

    pub(super) fn func_def_inner(&mut self, decorators: u16, is_async: bool) {
        let fname = {
            let n = self.advance();
            self.lexeme(&n).to_string()
        };
        let (params, defaults) = self.parse_params();
        let body = self.compile_body(&params);

        let fi = self.chunk.functions.len() as u16;
        self.chunk.functions.push((params, body, defaults));
        self.chunk.emit(
            if is_async { OpCode::MakeCoroutine } else { OpCode::MakeFunction },
            fi,
        );

        for _ in 0..decorators {
            self.chunk.emit(OpCode::Call, 1);
        }

        let ver = self.increment_version(&fname);
        let i = self.chunk.push_name(&Self::ssa_name(&fname, ver));
        self.chunk.emit(OpCode::StoreName, i);
    }

    pub(super) fn parse_params(&mut self) -> (Vec<String>, u16) {
        self.advance();
        let mut params = Vec::new();
        let mut defaults = 0u16;
        while !matches!(self.peek(), Some(TokenType::Rpar) | None) {
            if self.eat_if(TokenType::Slash) {
                if matches!(self.peek(), Some(TokenType::Comma)) {
                    self.advance();
                }
                continue;
            }
            if self.eat_if(TokenType::Star) {
                let p = self.advance();
                params.push(format!("*{}", self.lexeme(&p)));
                self.drain_annotation();
            } else if self.eat_if(TokenType::DoubleStar) {
                let p = self.advance();
                params.push(format!("**{}", self.lexeme(&p)));
                self.drain_annotation();
            } else {
                let p = self.advance();
                params.push(self.lexeme(&p).to_string());
                self.drain_annotation();
                if self.eat_if(TokenType::Equal) {
                    self.expr();
                    defaults += 1;
                }
            }
            if matches!(self.peek(), Some(TokenType::Comma)) {
                self.advance();
            }
        }
        self.advance();
        if self.eat_if(TokenType::Rarrow) {
            while !matches!(self.peek(), Some(TokenType::Colon) | None) {
                self.advance();
            }
        }
        if matches!(self.peek(), Some(TokenType::Colon)) {
            self.advance();
        }
        (params, defaults)
    }

    pub(super) fn drain_annotation(&mut self) {
        if self.eat_if(TokenType::Colon) {
            while !matches!(
                self.peek(),
                Some(TokenType::Equal | TokenType::Comma | TokenType::Rpar) | None
            ) {
                self.advance();
            }
        }
    }

    pub(super) fn compile_body(&mut self, params: &[String]) -> SSAChunk {
        let saved_chunk = core::mem::take(&mut self.chunk);
        let saved_ver   = core::mem::take(&mut self.ssa_versions);

        self.ssa_versions = HashMap::new();
        for p in params {
            self.ssa_versions.insert(p.clone(), 0);
        }

        self.compile_block();

        let body = core::mem::take(&mut self.chunk);
        self.chunk = saved_chunk;
        self.ssa_versions = saved_ver;

        body
    }
}