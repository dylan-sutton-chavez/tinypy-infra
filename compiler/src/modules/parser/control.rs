// parser/control.rs

use super::Parser;
use super::types::OpCode;
use crate::modules::lexer::{Token, TokenType};
use alloc::{string::{String, ToString}, vec};

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {

    /*
    If Statement
        Compiles if/elif/else chains with SSA block merging and conditional jumps.
    */

    pub(super) fn if_stmt(&mut self) {
        self.advance();
        self.enter_block();
        self.if_body();
        self.commit_block();
    }

    pub(super) fn if_body(&mut self) {
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

    /*
    Match Statement
        Implements match/case with subject storage and equality-based dispatch.
    */

    pub(super) fn match_stmt(&mut self) {
        self.advance();
        self.expr();

        let ver  = self.increment_version("__match__");
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

    /*
    While Statement
        Builds while loops with break/continue support and optional else clause.
    */

    pub(super) fn while_stmt(&mut self) {
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
        for pos in self.loop_breaks.pop().unwrap_or_default() {
            self.patch(pos);
        }

        self.commit_block();
    }

    /*
    For Statement
        Parses for loops (sync or async) including variable unpacking and iterator logic.
    */

    pub(super) fn for_stmt_inner(&mut self, is_async: bool) {
        self.advance();

        let parens = self.eat_if(TokenType::Lpar);
        let mut vars     = Vec::new();
        let mut star_pos: Option<usize> = None;
        loop {
            if self.eat_if(TokenType::Star) {
                star_pos = Some(vars.len());
                let t = self.advance();
                vars.push(self.lexeme(&t).to_string());
            } else {
                let t = self.advance();
                vars.push(self.lexeme(&t).to_string());
            }
            if !self.eat_if(TokenType::Comma) {
                break;
            }
            if matches!(self.peek(), Some(TokenType::In | TokenType::Rpar)) {
                break;
            }
        }
        if parens {
            self.eat(TokenType::Rpar);
        }

        self.eat(TokenType::In);
        self.expr();
        self.chunk.emit(OpCode::GetIter, is_async as u16);

        self.enter_block();

        let loop_start = self.chunk.instructions.len() as u16;
        self.loop_starts.push(loop_start);
        self.loop_breaks.push(vec![]);

        self.chunk.emit(OpCode::ForIter, 0);
        let fi = self.chunk.instructions.len() - 1;

        if vars.len() == 1 && star_pos.is_none() {
            self.store_name(vars[0].clone());
        } else if let Some(sp) = star_pos {
            let before = sp as u16;
            let after  = (vars.len() - sp - 1) as u16;
            self.chunk.emit(OpCode::UnpackEx, (before << 8) | after);
            for var in vars.iter().rev() {
                self.store_name(var.clone());
            }
        } else {
            self.chunk.emit(OpCode::UnpackSequence, vars.len() as u16);
            for var in vars.iter().rev() {
                self.store_name(var.clone());
            }
        }

        self.eat(TokenType::Colon);
        self.compile_block();

        self.chunk.emit(OpCode::Jump, loop_start);
        self.patch(fi);

        if !is_async {
            if self.eat_if(TokenType::Else) {
                self.eat(TokenType::Colon);
                self.compile_block();
            }
        }

        self.loop_starts.pop();
        for pos in self.loop_breaks.pop().unwrap_or_default() {
            self.patch(pos);
        }

        self.commit_block();
    }

    /*
    Try Statement
        Handles try/except/else/finally with exception setup and cleanup jumps.
    */

    pub(super) fn try_stmt(&mut self) {
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

    /*
    With Statement
        Compiles with/as blocks (sync/async) including context manager enter/exit.
    */

    pub(super) fn with_stmt_inner(&mut self, is_async: bool) {
        self.advance();
        let operand = is_async as u16;
        loop {
            self.expr();
            self.chunk.emit(OpCode::SetupWith, operand);
            if self.eat_if(TokenType::As) {
                let t = self.advance();
                let name = self.lexeme(&t).to_string();
                self.store_name(name);
            }
            if !self.eat_if(TokenType::Comma) {
                break;
            }
        }
        self.eat(TokenType::Colon);
        self.compile_block();
        self.chunk.emit(OpCode::ExitWith, operand);
    }

    /*
    Import Statements
        Parses import and from-import syntax with optional aliases and star imports.
    */

    pub(super) fn import_stmt(&mut self) {
        self.advance();
        loop {
            let module  = self.dotted_name();
            let mod_idx = self.chunk.push_name(&module);
            self.chunk.emit(OpCode::Import, mod_idx);
            if self.eat_if(TokenType::As) {
                let t     = self.advance();
                let alias = self.lexeme(&t).to_string();
                self.store_name(alias);
            } else {
                let root = module.split('.').next().unwrap().to_string();
                self.store_name(root);
            }
            if !self.eat_if(TokenType::Comma) {
                break;
            }
        }
    }

    pub(super) fn from_stmt(&mut self) {
        self.advance();
        let module  = self.dotted_name();
        let mod_idx = self.chunk.push_name(&module);
        self.chunk.emit(OpCode::Import, mod_idx);
        self.eat(TokenType::Import);
        if self.eat_if(TokenType::Star) {
            let star = self.chunk.push_name("*");
            self.chunk.emit(OpCode::ImportFrom, star);
        } else {
            loop {
                let t        = self.advance();
                let name     = self.lexeme(&t).to_string();
                let name_idx = self.chunk.push_name(&name);
                self.chunk.emit(OpCode::ImportFrom, name_idx);
                if self.eat_if(TokenType::As) {
                    let t     = self.advance();
                    let alias = self.lexeme(&t).to_string();
                    self.store_name(alias);
                } else {
                    self.store_name(name);
                }
                if !self.eat_if(TokenType::Comma) {
                    break;
                }
            }
        }
        self.chunk.emit(OpCode::PopTop, 0);
    }

    /*
    Dotted Name Helper
        Builds dotted module paths used by import statements.
    */

    pub(super) fn dotted_name(&mut self) -> String {
        let t    = self.advance();
        let mut name = self.lexeme(&t).to_string();
        while self.eat_if(TokenType::Dot) {
            let t = self.advance();
            name.push('.');
            name.push_str(self.lexeme(&t));
        }
        name
    }
}