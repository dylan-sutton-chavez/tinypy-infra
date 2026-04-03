// parser/stmt.rs

use super::Parser;
use super::types::OpCode;
use crate::modules::lexer::{Token, TokenType};
use alloc::{string::{String, ToString}, vec, format};

impl<'src, I: Iterator<Item = Token>> Parser<'src, I> {

    /*
    Statement Dispatcher
        Routes each statement type (if/for/def/etc) to its specific handler.
    */

    pub(super) fn stmt(&mut self) -> bool {
        match self.peek() {
            Some(TokenType::If) => {
                self.if_stmt();
                false
            }
            Some(TokenType::For) => {
                self.for_stmt_inner(false);
                false
            }
            Some(TokenType::Def) => {
                self.advance();
                self.func_def_inner(0, false);
                false
            }
            Some(TokenType::With) => {
                self.with_stmt_inner(false);
                false
            }
            Some(TokenType::While) => {
                self.while_stmt();
                false
            }
            Some(TokenType::Match) => {
                self.match_stmt();
                false
            }
            Some(TokenType::Type) => {
                self.advance();
                let t = self.advance();
                let name = self.lexeme(&t).to_string();
                self.eat(TokenType::Equal);
                self.expr();
                let idx = self.chunk.push_name(&name);
                self.chunk.emit(OpCode::TypeAlias, idx);
                false
            }
            Some(TokenType::Yield) => {
                self.advance();
                if self.eat_if(TokenType::From) {
                    self.expr();
                    self.chunk.emit(OpCode::YieldFrom, 0);
                } else if matches!(self.peek(), Some(TokenType::Newline | TokenType::Endmarker)) {
                    self.chunk.emit(OpCode::LoadNone, 0);
                    self.chunk.emit(OpCode::Yield, 0);
                } else {
                    self.expr();
                    self.chunk.emit(OpCode::Yield, 0);
                }
                true
            }
            Some(TokenType::Async) => {
                self.advance();
                match self.peek() {
                    Some(TokenType::Def) => {
                        self.advance();
                        self.func_def_inner(0, true);
                    }
                    Some(TokenType::For)  => { self.for_stmt_inner(true); }
                    Some(TokenType::With) => { self.with_stmt_inner(true); }
                    _ => {}
                }
                false
            }
            Some(TokenType::Await) => {
                self.advance();
                self.expr();
                self.chunk.emit(OpCode::Await, 0);
                true
            }
            Some(TokenType::At) => {
                let mut count = 0u16;
                while self.eat_if(TokenType::At) {
                    self.expr();
                    count += 1;
                }
                if self.eat_if(TokenType::Async) {
                    self.advance();
                    self.func_def_inner(count, true);
                } else {
                    self.advance();
                    self.func_def_inner(count, false);
                }
                false
            }
            Some(TokenType::Class) => {
                self.advance();
                self.class_def();
                false
            }
            Some(TokenType::Pass) => {
                self.advance();
                false
            }
            Some(TokenType::Try) => {
                self.try_stmt();
                false
            }
            Some(TokenType::Import) => {
                self.import_stmt();
                false
            }
            Some(TokenType::From) => {
                self.from_stmt();
                false
            }
            Some(TokenType::Global) => {
                self.emit_name_list(OpCode::Global);
                false
            }
            Some(TokenType::Nonlocal) => {
                self.emit_name_list(OpCode::Nonlocal);
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
                let mut buf = [0u8; 128];
                let idx = self.chunk.push_name(
                    Self::ssa_name(&name, self.current_version(&name), &mut buf)
                );
                self.chunk.emit(OpCode::Del, idx);
                false
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
            Some(TokenType::Break) => {
                self.advance();
                if self.loop_breaks.is_empty() {
                    self.error("'break' outside loop");
                } else {
                    self.chunk.emit(OpCode::Jump, 0);
                    if let Some(breaks) = self.loop_breaks.last_mut() {
                        breaks.push(self.chunk.instructions.len() - 1);
                    }
                }
                false
            }
            Some(TokenType::Continue) => {
                self.advance();
                // A04:2021 – Insecure Design: safe guard against continue outside loop.
                if let Some(&start) = self.loop_starts.last() {
                    self.chunk.emit(OpCode::Jump, start);
                } else {
                    self.error("'continue' outside loop");
                }
                false
            }
            Some(TokenType::Star) => {
                self.advance();
                let t = self.advance();
                let mut targets = vec![format!("*{}", self.lexeme(&t))];
                while self.eat_if(TokenType::Comma) {
                    if !matches!(self.peek(), Some(TokenType::Name)) {
                        break;
                    }
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
                    if count > 1 {
                        self.chunk.emit(OpCode::BuildTuple, count);
                    }
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

    /*
    Statement Helpers
        Emits global/nonlocal lists and compiles indented statement blocks cleanly.
    */

    pub(super) fn emit_name_list(&mut self, op: OpCode) {
        self.advance();
        loop {
            let t = self.advance();
            let name = self.lexeme(&t).to_string();
            let idx = self.chunk.push_name(&name);
            self.chunk.emit(op, idx);
            if !self.eat_if(TokenType::Comma) {
                break;
            }
        }
    }

    pub(super) fn compile_block(&mut self) {
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
            if !indented {
                break;
            }
        }
    }

    /*
    Name Statement Handler
        Parses assignments, augmented ops, attribute access, indexing and calls on names.
    */

    pub(super) fn name_stmt(&mut self, t: Token) -> bool {
        let name = self.lexeme(&t).to_string();

        if self.eat_if(TokenType::Colon) {
            if matches!(self.peek(), Some(TokenType::Name)) {
                let ann = {
                    let t = self.advance();
                    self.lexeme(&t).to_string()
                };
                self.chunk.annotations.insert(name.clone(), ann);
            }
            if !matches!(self.peek(), Some(TokenType::Equal)) {
                return false;
            }
        }

        match self.peek() {
            Some(TokenType::Equal) => {
                self.assign(name);
                false
            }
            Some(t) if Self::augmented_op(&t).is_some() => {
                let op = Self::augmented_op(&t).unwrap();
                self.advance();
                self.emit_load_ssa(name.clone());
                self.expr();
                self.chunk.emit(op, 0);
                self.store_name(name);
                false
            }
            Some(TokenType::Lsqb) => {
                self.emit_load_ssa(name);
                self.advance();
                self.expr();
                self.eat(TokenType::Rsqb);
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    self.expr();
                    self.chunk.emit(OpCode::StoreItem, 0);
                    false
                } else {
                    self.chunk.emit(OpCode::GetItem, 0);
                    self.expr_tails();
                    true
                }
            }
            Some(TokenType::Dot) => {
                self.advance();
                let t = self.advance();
                let (attr_start, attr_end) = (t.start, t.end);
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.emit_load_ssa(name);
                    self.advance();
                    self.expr();
                    let idx = self.chunk.push_name(&self.source[attr_start..attr_end]);
                    self.chunk.emit(OpCode::StoreAttr, idx);
                    false
                } else if self.peek().and_then(|tok| Self::augmented_op(&tok)).is_some() {
                    let op = Self::augmented_op(&self.peek().unwrap()).unwrap();
                    self.advance();
                    self.emit_load_ssa(name.clone());
                    self.emit_load_ssa(name);
                    let idx = self.chunk.push_name(&self.source[attr_start..attr_end]);
                    self.chunk.emit(OpCode::LoadAttr, idx);
                    self.expr();
                    self.chunk.emit(op, 0);
                    self.chunk.emit(OpCode::StoreAttr, idx);
                    false
                } else {
                    self.emit_load_ssa(name);
                    let idx = self.chunk.push_name(&self.source[attr_start..attr_end]);
                    self.chunk.emit(OpCode::LoadAttr, idx);
                    self.expr_tails();
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
                    } else {
                        break;
                    }
                }
                if matches!(self.peek(), Some(TokenType::Equal)) {
                    self.advance();
                    self.expr();
                    let mut count = 1u16;
                    while self.eat_if(TokenType::Comma) {
                        if matches!(
                            self.peek(),
                            Some(TokenType::Newline | TokenType::Endmarker) | None
                        ) {
                            break;
                        }
                        self.expr();
                        count += 1;
                    }
                    if count > 1 {
                        self.chunk.emit(OpCode::BuildTuple, count);
                    }
                    if let Some(sp) = star_pos {
                        let before = sp as u16;
                        let after  = (targets.len() - sp - 1) as u16;
                        self.chunk.emit(OpCode::UnpackEx, (before << 8) | after);
                    } else {
                        self.chunk.emit(OpCode::UnpackSequence, targets.len() as u16);
                    }
                    for target in targets.into_iter().rev() {
                        self.store_name(target.trim_start_matches('*').to_string());
                    }
                    false
                } else {
                    for t in &targets {
                        self.emit_load_ssa(t.clone());
                    }
                    self.chunk.emit(OpCode::BuildTuple, targets.len() as u16);
                    true
                }
            }
            Some(TokenType::Lpar) => self.call(name),
            _ => {
                self.emit_load_ssa(name);
                self.expr_tails();
                true
            }
        }
    }

    pub(super) fn augmented_op(tok: &TokenType) -> Option<OpCode> {
        match tok {
            TokenType::PlusEqual => Some(OpCode::Add),
            TokenType::MinEqual => Some(OpCode::Sub),
            TokenType::StarEqual => Some(OpCode::Mul),
            TokenType::SlashEqual => Some(OpCode::Div),
            TokenType::DoubleSlashEqual => Some(OpCode::FloorDiv),
            TokenType::PercentEqual => Some(OpCode::Mod),
            TokenType::DoubleStarEqual => Some(OpCode::Pow),
            TokenType::AmperEqual => Some(OpCode::BitAnd),
            TokenType::VbarEqual => Some(OpCode::BitOr),
            TokenType::CircumflexEqual => Some(OpCode::BitXor),
            TokenType::LeftShiftEqual => Some(OpCode::Shl),
            TokenType::RightShiftEqual => Some(OpCode::Shr),
            _ => None,
        }
    }

    pub(super) fn assign(&mut self, name: String) {
        self.advance();
        self.expr();
        self.store_name(name);
    }
}