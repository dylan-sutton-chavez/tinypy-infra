// vm/mod.rs

pub mod types;
mod cache;
mod ops;
mod builtins;
mod collections;

pub use types::{Val, HeapObj, HeapPool, VmErr, Limits};

use types::*;
use cache::*;
use ops::cached_binop;

use crate::modules::parser::{OpCode, SSAChunk, Value};
use alloc::{string::{String, ToString}, vec::Vec, vec, rc::Rc, format, boxed::Box};
use hashbrown::HashMap;
use core::cell::RefCell;

/*
VM State
    Stack, heap, iterators, yield buffer, templates and sandbox counters.
*/

pub struct VM<'a> {
    pub(crate) stack:      Vec<Val>,
    pub(crate) heap:       HeapPool,
    pub(crate) iter_stack: Vec<IterFrame>,
    pub(crate) yields:     Vec<Val>,
    pub(crate) chunk:      &'a SSAChunk,
    templates:  Templates,
    budget:     usize,
    depth:      usize,
    max_calls:  usize,
    pub output: Vec<String>,
}

impl<'a> VM<'a> {
    pub fn new(chunk: &'a SSAChunk) -> Self { Self::with_limits(chunk, Limits::none()) }

    pub fn with_limits(chunk: &'a SSAChunk, limits: Limits) -> Self {
        Self {
            stack: Vec::with_capacity(256),
            iter_stack: Vec::with_capacity(16),
            yields: Vec::new(),
            chunk,
            heap: HeapPool::new(limits.heap),
            templates: Templates::new(),
            budget: limits.ops,
            depth: 0,
            max_calls: limits.calls,
            output: Vec::new(),
        }
    }

    pub fn run(&mut self) -> Result<Val, VmErr> {
        let mut slots = vec![Option::<Val>::None; self.chunk.names.len()];
        self.exec(self.chunk, &mut slots)
    }

    pub fn heap_usage(&self) -> usize { self.heap.usage() }
    pub fn cache_stats(&self) -> (usize, usize) {
        (self.templates.count(), self.chunk.instructions.len())
    }

    /*
    Stack Helpers
        Push, pop, pop2 and pop_n with underflow-safe error propagation.
    */

    #[inline] pub(crate) fn push(&mut self, v: Val) { self.stack.push(v); }

    #[inline] pub(crate) fn pop(&mut self) -> Result<Val, VmErr> {
        self.stack.pop().ok_or_else(|| VmErr::Runtime("stack underflow".into()))
    }
    #[inline] pub(crate) fn pop2(&mut self) -> Result<(Val, Val), VmErr> {
        let b = self.pop()?; let a = self.pop()?; Ok((a, b))
    }
    #[inline] pub(crate) fn pop_n(&mut self, n: usize) -> Result<Vec<Val>, VmErr> {
        let at = self.stack.len().checked_sub(n)
            .ok_or_else(|| VmErr::Runtime("stack underflow".into()))?;
        Ok(self.stack.split_off(at))
    }

    pub(crate) fn to_val(&mut self, v: &Value) -> Result<Val, VmErr> {
        Ok(match v {
            Value::Int(i) => Val::int(*i),
            Value::Float(f) => Val::float(*f),
            Value::Bool(b) => Val::bool(*b),
            Value::None => Val::none(),
            Value::Str(s) => self.heap.alloc(HeapObj::Str(s.clone()))?,
        })
    }

    /*
    Fast-Path Execution
        Runs specialized ops from inline cache or adaptive overlay directly.
    */

    #[inline]
    fn exec_fast(&mut self, fast: FastOp) -> Result<bool, VmErr> {
        let (a, b) = self.pop2()?;
        let hit = match fast {
            FastOp::AddInt if a.is_int() && b.is_int() => { self.push(Val::int(a.as_int() + b.as_int())); true }
            FastOp::AddFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() + b.as_float())); true }
            FastOp::SubInt if a.is_int() && b.is_int() => { self.push(Val::int(a.as_int() - b.as_int())); true }
            FastOp::SubFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() - b.as_float())); true }
            FastOp::MulInt if a.is_int() && b.is_int() => { self.push(Val::int(a.as_int() * b.as_int())); true }
            FastOp::MulFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() * b.as_float())); true }
            FastOp::LtInt if a.is_int() && b.is_int() => { self.push(Val::bool(a.as_int() < b.as_int())); true }
            FastOp::LtFloat  if a.is_float() && b.is_float() => { self.push(Val::bool(a.as_float() < b.as_float())); true }
            FastOp::EqInt if a.is_int() && b.is_int() => { self.push(Val::bool(a.as_int() == b.as_int())); true }
            FastOp::AddStr | FastOp::EqStr => {
                if a.is_heap() && b.is_heap() {
                    let (sa, sb) = match (self.heap.get(a), self.heap.get(b)) {
                        (HeapObj::Str(x), HeapObj::Str(y)) => (x.clone(), y.clone()),
                        _ => { self.push(a); self.push(b); return Ok(false); }
                    };
                    match fast {
                        FastOp::AddStr => { let v = self.heap.alloc(HeapObj::Str(format!("{}{}", sa, sb)))?; self.push(v); }
                        _ => { self.push(Val::bool(sa == sb)); }
                    }
                    true
                } else { false }
            }
            _ => false,
        };
        if !hit { self.push(a); self.push(b); }
        Ok(hit)
    }

    /*
    Main Dispatch Loop
        Fetches instructions by IP, routes each opcode to its handler arm.
    */

    pub(crate) fn exec(&mut self, chunk: &SSAChunk, slots: &mut Vec<Option<Val>>) -> Result<Val, VmErr> {
        let n = chunk.instructions.len();

        // Box per-frame caches to reduce stack frame size in debug builds
        let mut cache = Box::new(InlineCache::new(n));
        let mut adaptive = Box::new(Adaptive::new(n));
        let mut ip = 0usize;
        let mut phi_idx = 0usize;

        // SSA backward-compat alias table
        let prev_slots = {
            let mut ps: Vec<Option<usize>> = vec![None; chunk.names.len()];
            let mut name_map: HashMap<&str, usize> = HashMap::with_capacity(chunk.names.len());
            for (i, name) in chunk.names.iter().enumerate() { name_map.insert(name.as_str(), i); }
            for (i, name) in chunk.names.iter().enumerate() {
                if let Some(pos) = name.rfind('_') {
                    if let Ok(ver) = name[pos+1..].parse::<u32>() {
                        if ver > 0 {
                            let prev = format!("{}_{}", &name[..pos], ver - 1);
                            if let Some(&j) = name_map.get(prev.as_str()) { ps[i] = Some(j); }
                        }
                    }
                }
            }
            Box::new(ps)
        };

        loop {
            if ip >= n { return Ok(Val::none()); }

            // Adaptive / inline cache fast paths
            if let Some(fast) = adaptive.get(ip) {
                ip += 1;
                if self.exec_fast(fast)? { continue; }
                adaptive.deopt(ip - 1); cache.invalidate(ip - 1); ip -= 1;
            } else if let Some(fast) = cache.get(ip) {
                ip += 1;
                if self.exec_fast(fast)? { continue; }
                cache.invalidate(ip - 1); ip -= 1;
            }

            if ip >= n {
                return Err(VmErr::Runtime("instruction pointer out of bounds".into()));
            }

            let ins = &chunk.instructions[ip];
            let op  = ins.operand;
            let rip = ip;
            ip += 1;

            match ins.opcode {

                // Loads

                OpCode::LoadConst => { let v = self.to_val(&chunk.constants[op as usize])?; self.push(v); }
                OpCode::LoadName => { let slot = op as usize; self.push(slots[slot].ok_or_else(|| VmErr::Name(chunk.names[slot].clone()))?); }
                OpCode::StoreName => { let v = self.pop()?; let slot = op as usize; if let Some(prev) = prev_slots[slot] { slots[prev] = Some(v); } slots[slot] = Some(v); }
                OpCode::LoadTrue => self.push(Val::bool(true)),
                OpCode::LoadFalse => self.push(Val::bool(false)),
                OpCode::LoadNone => self.push(Val::none()),
                OpCode::LoadEllipsis => { let v = self.heap.alloc(HeapObj::Str("...".into()))?; self.push(v); }

                // Arithmetic (cached)

                OpCode::Add => { let (a, b) = self.pop2()?; cached_binop!(rip, &ins.opcode, &a, &b, cache, adaptive); let v = self.add_vals(a, b)?; self.push(v); }
                OpCode::Sub => { let (a, b) = self.pop2()?; cached_binop!(rip, &ins.opcode, &a, &b, cache, adaptive); let v = self.sub_vals(a, b)?; self.push(v); }
                OpCode::Mul => { let (a, b) = self.pop2()?; cached_binop!(rip, &ins.opcode, &a, &b, cache, adaptive); let v = self.mul_vals(a, b)?; self.push(v); }
                OpCode::Div => { let (a, b) = self.pop2()?; let v = self.div_vals(a, b)?; self.push(v); }
                OpCode::Mod => {
                    let (a, b) = self.pop2()?;
                    if !a.is_int() || !b.is_int() { return Err(VmErr::Type("mod requires int".into())); }
                    let d = b.as_int(); if d == 0 { return Err(VmErr::ZeroDiv); }
                    let r = a.as_int() % d;
                    self.push(Val::int(if r != 0 && (r < 0) != (d < 0) { r + d } else { r }));
                }
                OpCode::Pow => {
                    let (a, b) = self.pop2()?;
                    let v = match (a.is_int(), b.is_int(), a.is_float(), b.is_float()) {
                        (true, true, ..) => { let exp = b.as_int(); if exp >= 0 { Val::int(a.as_int().pow(exp as u32)) } else { Val::float(fpowi(a.as_int() as f64, exp as i32)) } }
                        (true, _, _, true) => Val::float(fpowf(a.as_int() as f64, b.as_float())),
                        (_,  true, true, _) => Val::float(fpowi(a.as_float(), b.as_int() as i32)),
                        (_, _, true, true)  => Val::float(fpowf(a.as_float(), b.as_float())),
                        _ => return Err(VmErr::Type("**".into())),
                    };
                    self.push(v);
                }
                OpCode::FloorDiv => {
                    let (a, b) = self.pop2()?;
                    if !a.is_int() || !b.is_int() { return Err(VmErr::Type("// requires int".into())); }
                    let d = b.as_int(); if d == 0 { return Err(VmErr::ZeroDiv); }
                    let (q, r) = (a.as_int() / d, a.as_int() % d);
                    self.push(Val::int(if r != 0 && (r < 0) != (d < 0) { q - 1 } else { q }));
                }
                OpCode::Minus => {
                    let v = self.pop()?;
                    if v.is_int() { self.push(Val::int(-v.as_int())); }
                    else if v.is_float() { self.push(Val::float(-v.as_float())); }
                    else { return Err(VmErr::Type("unary -".into())); }
                }

                // Bitwise

                OpCode::BitAnd => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() & b.as_int())); }
                OpCode::BitOr => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() | b.as_int())); }
                OpCode::BitXor => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() ^ b.as_int())); }
                OpCode::BitNot => { let v = self.pop()?; self.push(Val::int(!v.as_int())); }
                OpCode::Shl => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() << (b.as_int() & 63))); }
                OpCode::Shr => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() >> (b.as_int() & 63))); }

                // Comparison (cached)

                OpCode::Eq => { let (a,b) = self.pop2()?; cached_binop!(rip,&ins.opcode,&a,&b,cache,adaptive); self.push(Val::bool(self.eq_vals(a,b))); }
                OpCode::NotEq => { let (a,b) = self.pop2()?; self.push(Val::bool(!self.eq_vals(a,b))); }
                OpCode::Lt => { let (a,b) = self.pop2()?; cached_binop!(rip,&ins.opcode,&a,&b,cache,adaptive); let r=self.lt_vals(a,b)?; self.push(Val::bool(r)); }
                OpCode::Gt => { let (a,b) = self.pop2()?; let r=self.lt_vals(b,a)?; self.push(Val::bool(r)); }
                OpCode::LtEq => { let (a,b) = self.pop2()?; let r=self.lt_vals(b,a)?; self.push(Val::bool(!r)); }
                OpCode::GtEq => { let (a,b) = self.pop2()?; let r=self.lt_vals(a,b)?; self.push(Val::bool(!r)); }

                // Logic

                OpCode::And => { let (a,b) = self.pop2()?; self.push(if self.truthy(a) { b } else { a }); }
                OpCode::Or  => { let (a,b) = self.pop2()?; self.push(if self.truthy(a) { a } else { b }); }
                OpCode::Not => { let v = self.pop()?; self.push(Val::bool(!self.truthy(v))); }

                // Identity / membership

                OpCode::In => { let (a,b) = self.pop2()?; self.push(Val::bool( self.contains(b, a))); }
                OpCode::NotIn => { let (a,b) = self.pop2()?; self.push(Val::bool(!self.contains(b, a))); }
                OpCode::Is => { let (a,b) = self.pop2()?; self.push(Val::bool(a.0 == b.0)); }
                OpCode::IsNot => { let (a,b) = self.pop2()?; self.push(Val::bool(a.0 != b.0)); }

                // Control flow 

                OpCode::JumpIfFalse => {
                    let v = self.pop()?;
                    if !self.truthy(v) {
                        if self.budget == 0 { return Err(VmErr::Budget); }
                        self.budget -= 1;
                        let target = op as usize;
                        if target > chunk.instructions.len() { return Err(VmErr::Runtime("jump target out of bounds".into())); }
                        ip = target;
                    }
                }
                OpCode::Jump => {
                    if self.budget == 0 { return Err(VmErr::Budget); }
                    self.budget -= 1;
                    let target = op as usize;
                    if target > chunk.instructions.len() { return Err(VmErr::Runtime("jump target out of bounds".into())); }
                    ip = target;
                }
                OpCode::PopTop => { self.pop()?; }
                OpCode::ReturnValue => { return Ok(if self.stack.is_empty() { Val::none() } else { self.pop()? }); }

                // Yield

                OpCode::Yield => {
                    let v = self.pop()?;
                    self.yields.push(v);
                    self.push(Val::none());
                }

                // Collections (delegated)

                OpCode::BuildList  => { let v = self.pop_n(op as usize)?; let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(v))))?; self.push(val); }
                OpCode::BuildTuple => { let v = self.pop_n(op as usize)?; let val = self.heap.alloc(HeapObj::Tuple(v))?; self.push(val); }
                OpCode::BuildDict  => {
                    let mut p: Vec<(Val, Val)> = Vec::with_capacity(op as usize);
                    for _ in 0..op { let v = self.pop()?; let k = self.pop()?; p.push((k, v)); }
                    p.reverse();
                    let val = self.heap.alloc(HeapObj::Dict(Rc::new(RefCell::new(p))))?; self.push(val);
                }
                OpCode::BuildString => {
                    let parts = self.pop_n(op as usize)?;
                    let s: String = parts.iter().map(|v| self.display(*v)).collect();
                    let val = self.heap.alloc(HeapObj::Str(s))?; self.push(val);
                }
                OpCode::BuildSet => { self.build_set(op)?; }
                OpCode::BuildSlice => { self.build_slice(op)?; }
                OpCode::GetItem => { self.get_item()?; }
                OpCode::StoreItem => { self.store_item()?; }
                OpCode::UnpackSequence => {
                    let obj = self.pop()?; let expected = op as usize;
                    if !obj.is_heap() { return Err(VmErr::Type("cannot unpack non-sequence".into())); }
                    let items: Vec<Val> = match self.heap.get(obj) {
                        HeapObj::List(v) => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        HeapObj::Str(s) => {
                            let chars: Vec<char> = s.chars().collect();
                            if chars.len() != expected { return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, chars.len()))); }
                            let chars = chars; drop(s);
                            let mut out = Vec::with_capacity(chars.len());
                            for c in chars { out.push(self.heap.alloc(HeapObj::Str(c.to_string()))?); }
                            out
                        }
                        _ => return Err(VmErr::Type("unpack".into())),
                    };
                    if items.len() != expected { return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, items.len()))); }
                    for item in items.into_iter().rev() { self.push(item); }
                }
                OpCode::UnpackEx => { self.unpack_ex(op)?; }
                OpCode::FormatValue => {
                    if op == 1 { self.pop()?; }
                    let v = self.pop()?; let s = self.display(v);
                    let val = self.heap.alloc(HeapObj::Str(s))?; self.push(val);
                }

                // Iterators

                OpCode::GetIter => {
                    let obj = self.pop()?;
                    if !obj.is_heap() { return Err(VmErr::Type("not iterable".into())); }
                    let frame = match self.heap.get(obj) {
                        HeapObj::Range(s, e, st) => IterFrame::Range { cur: *s, end: *e, step: *st },
                        HeapObj::List(v)  => IterFrame::Seq { items: v.borrow().clone(), idx: 0 },
                        HeapObj::Tuple(v) => IterFrame::Seq { items: v.clone(), idx: 0 },
                        HeapObj::Dict(p) => IterFrame::Seq { items: p.borrow().iter().map(|(k, _)| *k).collect(), idx: 0 },
                        HeapObj::Set(s) => IterFrame::Seq { items: s.borrow().clone(), idx: 0 },
                        HeapObj::Str(s) => {
                            let chars: Vec<char> = s.chars().collect(); drop(s);
                            let mut items = Vec::with_capacity(chars.len());
                            for c in chars { items.push(self.heap.alloc(HeapObj::Str(c.to_string()))?); }
                            IterFrame::Seq { items, idx: 0 }
                        }
                        _ => return Err(VmErr::Type("not iterable".into())),
                    };
                    self.iter_stack.push(frame);
                }
                OpCode::ForIter => {
                    if self.budget == 0 { return Err(VmErr::Budget); }
                    self.budget -= 1;
                    match self.iter_stack.last_mut().and_then(|f| f.next_item()) {
                        Some(item) => self.push(item),
                        None => {
                            self.iter_stack.pop();
                            let target = op as usize;
                            if target > chunk.instructions.len() { return Err(VmErr::Runtime("for iter target out of bounds".into())); }
                            ip = target;
                        }
                    }
                }

                // SSA Phi

                OpCode::Phi => {
                    let target = op as usize;
                    let (ia, ib) = chunk.phi_sources[phi_idx]; phi_idx += 1;
                    let val = slots[ia as usize].or(slots[ib as usize]).unwrap_or(Val::none());
                    slots[target] = Some(val);
                }

                // Functions

                OpCode::MakeFunction | OpCode::MakeCoroutine => {
                    let val = self.heap.alloc(HeapObj::Func(op as usize))?; self.push(val);
                }
                OpCode::Call => {
                    let argc = op as usize;
                    if self.depth >= self.max_calls { return Err(VmErr::CallDepth); }
                    let mut args: Vec<Val> = (0..argc).map(|_| self.pop()).collect::<Result<_,_>>()?;
                    args.reverse();
                    let callee = self.pop()?;
                    if !callee.is_heap() { return Err(VmErr::Type("call non-function".into())); }
                    let fi = match self.heap.get(callee) {
                        HeapObj::Func(i) => *i,
                        _ => return Err(VmErr::Type("call non-function".into())),
                    };
                    if let Some(cached) = self.templates.lookup(fi, &args) {
                        self.push(cached); continue;
                    }
                    self.depth += 1;
                    let (params, body, fn_name) = &self.chunk.functions[fi];
                    let mut fn_slots: Vec<Option<Val>> = vec![None; body.names.len()];
                    let mut body_map: HashMap<&str, usize> = HashMap::with_capacity(body.names.len());
                    for (i, n) in body.names.iter().enumerate() { body_map.insert(n.as_str(), i); }
                    for (pi, p) in params.iter().enumerate() {
                        if pi < args.len() {
                            let pname = format!("{}_0", p.trim_start_matches('*'));
                            if let Some(&s) = body_map.get(pname.as_str()) { fn_slots[s] = Some(args[pi]); }
                        }
                    }
                    for (si, sv) in slots.iter().enumerate() {
                        if let Some(v) = sv {
                            if v.is_heap() {
                                if let HeapObj::Func(_) = self.heap.get(*v) {
                                    if let Some(&bs) = body_map.get(chunk.names[si].as_str()) { fn_slots[bs] = Some(*v); }
                                }
                            }
                        }
                    }
                    let name_idx = *fn_name;
                    if name_idx != u16::MAX {
                        let raw = &self.chunk.names[name_idx as usize];
                        let base = raw.rfind('_').filter(|&p| raw[p+1..].parse::<u32>().is_ok()).map(|p| &raw[..p]).unwrap_or(raw.as_str());
                        let versioned = format!("{}_0", base);
                        if let Some(&slot) = body_map.get(versioned.as_str()) {
                            if fn_slots[slot].is_none() { fn_slots[slot] = Some(callee); }
                        }
                    }

                    let yields_before = self.yields.len();
                    let result = self.exec(body, &mut fn_slots)?;
                    self.depth -= 1;

                    if self.yields.len() > yields_before {
                        let fn_yields = self.yields.split_off(yields_before);
                        let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(fn_yields))))?;
                        self.push(val);
                    } else {
                        self.templates.record(fi, &args, result);
                        self.push(result);
                    }
                }

                // Builtins (delegated)

                OpCode::CallPrint => { self.call_print(op)?; }
                OpCode::CallLen => { self.call_len()?; }
                OpCode::CallAbs => { self.call_abs()?; }
                OpCode::CallStr => { self.call_str()?; }
                OpCode::CallInt => { self.call_int()?; }
                OpCode::CallFloat => { self.call_float()?; }
                OpCode::CallBool => { self.call_bool()?; }
                OpCode::CallType => { self.call_type()?; }
                OpCode::CallChr => { self.call_chr()?; }
                OpCode::CallOrd => { self.call_ord()?; }
                OpCode::CallRange => { self.call_range(op)?; }
                OpCode::CallRound => { self.call_round(op)?; }
                OpCode::CallMin => { self.call_min(op)?; }
                OpCode::CallMax => { self.call_max(op)?; }
                OpCode::CallSum => { self.call_sum(op)?; }
                OpCode::CallSorted => { self.call_sorted()?; }
                OpCode::CallList => { self.call_list()?; }
                OpCode::CallTuple => { self.call_tuple()?; }
                OpCode::CallEnumerate => { self.call_enumerate()?; }
                OpCode::CallZip => { self.call_zip()?; }
                OpCode::CallIsInstance => { self.call_isinstance()?; }
                OpCode::CallInput => { self.call_input()?; }
                OpCode::CallDict => { self.call_dict(op)?; }
                OpCode::CallSet => { self.call_set(op)?; }

                // Implemented stubs

                OpCode::Assert => { let v = self.pop()?; if !self.truthy(v) { return Err(VmErr::Runtime("AssertionError".into())); } }
                OpCode::Del => { let slot = op as usize; if slot < slots.len() { slots[slot] = None; } }

                // No-op stubs (safe for sandbox/WASM)

                OpCode::Global | OpCode::Nonlocal => {}
                OpCode::TypeAlias => { self.pop()?; }
                OpCode::Import => { self.push(Val::none()); }
                OpCode::ImportFrom => { self.pop()?; self.push(Val::none()); }
                OpCode::SetupExcept | OpCode::PopExcept => {}
                OpCode::Raise | OpCode::RaiseFrom => { return Err(VmErr::Runtime("exception raised".into())); }
                OpCode::SetupWith | OpCode::ExitWith => {}
                OpCode::Await | OpCode::YieldFrom => {}
                OpCode::UnpackArgs => {}
                OpCode::MakeClass | OpCode::LoadAttr | OpCode::StoreAttr => {}
                OpCode::ListComp | OpCode::SetComp | OpCode::DictComp | OpCode::GenExpr => {}
            }
        }
    }
}