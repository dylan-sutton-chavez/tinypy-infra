/*
`vm.rs`
    Stack-based bytecode VM. Memory-pooled, sandboxed, OWASP A04:2021 hardened.
    Inline caching, type specialization, template memoization, adaptive bytecode metamorphosis.
*/

use crate::modules::parser::{OpCode, SSAChunk, Value};
use std::collections::HashMap;
use thiserror::Error;

// ── A04:2021 — runtime limits ──

const MAX_STACK: usize = 1_024;
const MAX_CALLS: usize = 256;
const MAX_HEAP: usize = 100_000;
const MAX_OPS: usize = 10_000_000;
const CACHE_THRESHOLD: u8 = 8;
const HOTSPOT_THRESHOLD: u32 = 1_000;
const TEMPLATE_THRESHOLD: u32 = 4;

// ── Type tags for specialization ──

fn type_tag(obj: &Obj) -> u8 {
    match obj {
        Obj::Int(_) => 1,   Obj::Float(_) => 2, Obj::Str(_) => 3,
        Obj::Bool(_) => 4,  Obj::None => 5,     Obj::List(_) => 6,
        Obj::Dict(_) => 7,  Obj::Tuple(_) => 8, Obj::Func(_) => 9,
    }
}

// ── Specialized fast-path operations ──

#[derive(Debug, Clone, Copy)]
enum FastOp {
    AddInt, AddFloat, AddStr,
    SubInt, SubFloat,
    MulInt, MulFloat,
    LtInt,  LtFloat,
    EqInt,  EqStr,
}

// ── Runtime values ──

#[derive(Debug, Clone)]
pub enum Obj {
    Int(i64), Float(f64), Str(String), Bool(bool), None,
    List(Vec<Obj>), Dict(Vec<(Obj, Obj)>), Tuple(Vec<Obj>), Func(usize),
}

impl Obj {
    fn truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b, Self::Int(i) => *i != 0, Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(), Self::None => false,
            Self::List(v) | Self::Tuple(v) => !v.is_empty(),
            Self::Dict(v) => !v.is_empty(), _ => true,
        }
    }

    fn int(&self) -> Result<i64, VmErr> {
        match self {
            Self::Int(i) => Ok(*i), Self::Bool(b) => Ok(*b as i64),
            _ => Err(VmErr::Type(format!("expected int, got {}", self.ty()))),
        }
    }

    fn ty(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",   Self::Float(_) => "float", Self::Str(_) => "str",
            Self::Bool(_) => "bool", Self::None => "NoneType",  Self::List(_) => "list",
            Self::Dict(_) => "dict", Self::Tuple(_) => "tuple", Self::Func(_) => "function",
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Int(i) => i.to_string(),
            Self::Float(f) if *f == f.floor() && f.is_finite() => format!("{:.1}", f),
            Self::Float(f) => f.to_string(),
            Self::Str(s) => s.clone(),
            Self::Bool(b) => if *b { "True" } else { "False" }.into(),
            Self::None => "None".into(),
            Self::List(v) => format!("[{}]", v.iter().map(|o| o.repr()).collect::<Vec<_>>().join(", ")),
            Self::Tuple(v) if v.len() == 1 => format!("({},)", v[0].repr()),
            Self::Tuple(v) => format!("({})", v.iter().map(|o| o.repr()).collect::<Vec<_>>().join(", ")),
            Self::Dict(p) => format!("{{{}}}", p.iter().map(|(k, v)| format!("{}: {}", k.repr(), v.repr())).collect::<Vec<_>>().join(", ")),
            Self::Func(i) => format!("<function {}>", i),
        }
    }

    fn repr(&self) -> String {
        match self { Self::Str(s) => format!("'{}'", s), o => o.display() }
    }
}

// ── Errors ──

#[derive(Debug, Error)]
pub enum VmErr {
    #[error("StackOverflow")]              StackOverflow,
    #[error("RecursionError: max depth")]  CallDepth,
    #[error("MemoryError: heap limit")]    Heap,
    #[error("RuntimeError: budget")]       Budget,
    #[error("NameError: '{0}'")]           Name(String),
    #[error("TypeError: {0}")]             Type(String),
    #[error("ValueError: {0}")]            Value(String),
    #[error("ZeroDivisionError")]          ZeroDiv,
    #[error("AssertionError")]             Assert,
    #[error("RuntimeError: {0}")]          Runtime(String),
}

// ── Memory pool — heap allocation tracking ──

struct Pool { count: usize }
impl Pool {
    fn new() -> Self { Self { count: 0 } }
    fn alloc(&mut self) -> Result<(), VmErr> { self.count += 1; if self.count > MAX_HEAP { Err(VmErr::Heap) } else { Ok(()) } }
    fn usage(&self) -> usize { self.count }
}

// ── Inline cache — per-instruction type specialization ──

#[derive(Clone)]
struct CacheSlot { hits: u8, ty_a: u8, ty_b: u8, fast: Option<FastOp> }
impl CacheSlot { fn empty() -> Self { Self { hits: 0, ty_a: 0, ty_b: 0, fast: None } } }

struct InlineCache { slots: Vec<CacheSlot> }

impl InlineCache {
    fn new(n: usize) -> Self { Self { slots: vec![CacheSlot::empty(); n] } }

    fn record(&mut self, ip: usize, op: &OpCode, ta: u8, tb: u8) -> Option<FastOp> {
        let s = match self.slots.get_mut(ip) {
            Some(s) => s,
            None => return None,
        };
        if s.ty_a == ta && s.ty_b == tb {
            s.hits = s.hits.saturating_add(1);
            if s.hits >= CACHE_THRESHOLD && s.fast.is_none() {
                s.fast = match (op, ta, tb) {
                    (OpCode::Add, 1, 1) => Some(FastOp::AddInt),   (OpCode::Add, 2, 2) => Some(FastOp::AddFloat),
                    (OpCode::Add, 3, 3) => Some(FastOp::AddStr),   (OpCode::Sub, 1, 1) => Some(FastOp::SubInt),
                    (OpCode::Sub, 2, 2) => Some(FastOp::SubFloat), (OpCode::Mul, 1, 1) => Some(FastOp::MulInt),
                    (OpCode::Mul, 2, 2) => Some(FastOp::MulFloat), (OpCode::Lt,  1, 1) => Some(FastOp::LtInt),
                    (OpCode::Lt,  2, 2) => Some(FastOp::LtFloat),  (OpCode::Eq,  1, 1) => Some(FastOp::EqInt),
                    (OpCode::Eq,  3, 3) => Some(FastOp::EqStr),    _ => None,
                };
            }
        } else { *s = CacheSlot { hits: 1, ty_a: ta, ty_b: tb, fast: None }; }
        s.fast
    }

    fn get(&self, ip: usize) -> Option<FastOp> { self.slots.get(ip).and_then(|s| s.fast) }
    fn invalidate(&mut self, ip: usize) { if let Some(s) = self.slots.get_mut(ip) { *s = CacheSlot::empty(); } }
    fn specialized_count(&self) -> usize { self.slots.iter().filter(|s| s.fast.is_some()).count() }
}

// ── Template table — memoized function results ──

struct TemplateEntry { result: Obj, hits: u32 }

struct TemplateTable { entries: HashMap<(usize, Vec<u8>), TemplateEntry> }

impl TemplateTable {
    fn new() -> Self { Self { entries: HashMap::new() } }

    fn lookup(&self, fi: usize, args: &[Obj]) -> Option<&Obj> {
        let e = self.entries.get(&(fi, args.iter().map(type_tag).collect()))?;
        if e.hits >= TEMPLATE_THRESHOLD { Some(&e.result) } else { None }
    }

    fn record(&mut self, fi: usize, args: &[Obj], result: &Obj) {
        let key = (fi, args.iter().map(type_tag).collect());
        let e = self.entries.entry(key).or_insert(TemplateEntry { result: result.clone(), hits: 0 });
        e.hits += 1;
        e.result = result.clone();
    }

    fn cached_count(&self) -> usize { self.entries.values().filter(|e| e.hits >= TEMPLATE_THRESHOLD).count() }
}

// ── Adaptive engine — hotspot detection + bytecode overlay ──

struct AdaptiveEngine { counts: Vec<u32>, overlay: Vec<Option<FastOp>> }

impl AdaptiveEngine {
    fn new(n: usize) -> Self { Self { counts: vec![0; n], overlay: vec![None; n] } }

    fn tick(&mut self, ip: usize) -> bool {
        if let Some(c) = self.counts.get_mut(ip) { *c += 1; *c == HOTSPOT_THRESHOLD } else { false }
    }

    fn rewrite(&mut self, ip: usize, fast: FastOp) { if let Some(s) = self.overlay.get_mut(ip) { *s = Some(fast); } }
    fn get(&self, ip: usize) -> Option<FastOp> { self.overlay.get(ip).and_then(|o| *o) }

    fn deopt(&mut self, ip: usize) {
        if let Some(s) = self.overlay.get_mut(ip) { *s = None; }
        if let Some(c) = self.counts.get_mut(ip) { *c = 0; }
    }

    fn hotspots(&self) -> Vec<usize> {
        self.counts
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c >= HOTSPOT_THRESHOLD)
            .map(|(i, _)| i)
            .collect()
    }

    fn rewritten_count(&self) -> usize { self.overlay.iter().filter(|o| o.is_some()).count() }
}

// ── VM ──

pub struct VM<'a> {
    stack: Vec<Obj>,
    chunk: &'a SSAChunk,
    pool: Pool,
    cache: InlineCache,
    templates: TemplateTable,
    adaptive: AdaptiveEngine,
    budget: usize,
    depth: usize,
    pub output: Vec<String>,
}

impl<'a> VM<'a> {
    pub fn new(chunk: &'a SSAChunk) -> Self {
        let n = chunk.instructions.len();
        Self {
            stack: Vec::with_capacity(256), chunk, pool: Pool::new(),
            cache: InlineCache::new(n), templates: TemplateTable::new(), adaptive: AdaptiveEngine::new(n),
            budget: MAX_OPS, depth: 0, output: Vec::new(),
        }
    }

    pub fn run(&mut self) -> Result<Obj, VmErr> { self.exec(self.chunk, &mut HashMap::new()) }
    pub fn cache_stats(&self) -> (usize, usize) { (self.cache.specialized_count(), self.cache.slots.len()) }
    pub fn heap_usage(&self) -> usize { self.pool.usage() }
    pub fn hotspots(&self) -> Vec<usize> { self.adaptive.hotspots() }
    pub fn templates_cached(&self) -> usize { self.templates.cached_count() }
    pub fn rewrites_active(&self) -> usize { self.adaptive.rewritten_count() }

    // ── Stack ──

    fn push(&mut self, v: Obj) -> Result<(), VmErr> { if self.stack.len() >= MAX_STACK { return Err(VmErr::StackOverflow); } self.stack.push(v); Ok(()) }
    fn pop(&mut self) -> Result<Obj, VmErr> { self.stack.pop().ok_or(VmErr::Runtime("underflow".into())) }
    fn pop2(&mut self) -> Result<(Obj, Obj), VmErr> { let b = self.pop()?; let a = self.pop()?; Ok((a, b)) }
    fn pop_n(&mut self, n: usize) -> Result<Vec<Obj>, VmErr> { let at = self.stack.len().checked_sub(n).ok_or(VmErr::Runtime("underflow".into()))?; Ok(self.stack.split_off(at)) }
    fn to_obj(&self, v: &Value) -> Obj { match v { Value::Int(i) => Obj::Int(*i), Value::Float(f) => Obj::Float(*f), Value::Str(s) => Obj::Str(s.clone()), Value::Bool(b) => Obj::Bool(*b), Value::None => Obj::None } }

    // ── Fast path — specialized ops, no type dispatch ──

    fn exec_fast(&mut self, fast: FastOp) -> Result<bool, VmErr> {
        let (a, b) = self.pop2()?;
        let result = match (fast, &a, &b) {
            (FastOp::AddInt,   Obj::Int(x),   Obj::Int(y))   => Obj::Int(x + y),
            (FastOp::AddFloat, Obj::Float(x), Obj::Float(y)) => Obj::Float(x + y),
            (FastOp::AddStr,   Obj::Str(x),   Obj::Str(y))   => Obj::Str(format!("{}{}", x, y)),
            (FastOp::SubInt,   Obj::Int(x),   Obj::Int(y))   => Obj::Int(x - y),
            (FastOp::SubFloat, Obj::Float(x), Obj::Float(y)) => Obj::Float(x - y),
            (FastOp::MulInt,   Obj::Int(x),   Obj::Int(y))   => Obj::Int(x * y),
            (FastOp::MulFloat, Obj::Float(x), Obj::Float(y)) => Obj::Float(x * y),
            (FastOp::LtInt,    Obj::Int(x),   Obj::Int(y))   => Obj::Bool(x < y),
            (FastOp::LtFloat,  Obj::Float(x), Obj::Float(y)) => Obj::Bool(x < y),
            (FastOp::EqInt,    Obj::Int(x),   Obj::Int(y))   => Obj::Bool(x == y),
            (FastOp::EqStr,    Obj::Str(x),   Obj::Str(y))   => Obj::Bool(x == y),
            _ => { self.push(a)?; self.push(b)?; return Ok(false); }
        };
        self.push(result)?;
        Ok(true)
    }

    // ── Cache + adaptive hook for binary ops ──

    fn cached_binop(&mut self, ip: usize, op: &OpCode, a: &Obj, b: &Obj) {
        if let Some(fast) = self.cache.record(ip, op, type_tag(a), type_tag(b)) {
            if self.adaptive.tick(ip) { self.adaptive.rewrite(ip, fast); }
        }
    }

    // ── Dispatch loop ──

    fn exec(&mut self, chunk: &SSAChunk, names: &mut HashMap<String, Obj>) -> Result<Obj, VmErr> {
        let mut ip = 0usize;
        let mut phi_idx = 0usize;

        loop {
            if ip >= chunk.instructions.len() { return Ok(Obj::None); }
            if self.budget == 0 { return Err(VmErr::Budget); }
            self.budget -= 1;

            // ── Adaptive overlay: rewritten instruction fast path ──
            if let Some(fast) = self.adaptive.get(ip) {
                ip += 1;
                if self.exec_fast(fast)? { continue; }
                self.adaptive.deopt(ip - 1);
                self.cache.invalidate(ip - 1);
                ip -= 1;
            }

            let ins = &chunk.instructions[ip];
            let op = ins.operand;
            let rip = ip;
            ip += 1;

            match ins.opcode {

                // ── Load / Store ──

                OpCode::LoadConst    => self.push(self.to_obj(&chunk.constants[op as usize]))?,
                OpCode::LoadName     => { let n = &chunk.names[op as usize]; self.push(names.get(n).cloned().ok_or_else(|| VmErr::Name(n.clone()))?)?; }
                OpCode::StoreName    => {
                    let v = self.pop()?;
                    let full = &chunk.names[op as usize];
                    names.insert(full.clone(), v.clone());
                    if let Some(pos) = full.rfind('_') {
                        if let Ok(ver) = full[pos + 1..].parse::<u32>() {
                            if ver > 0 { names.insert(format!("{}_{}", &full[..pos], ver - 1), v); }
                        }
                    }
                }
                OpCode::LoadTrue     => self.push(Obj::Bool(true))?,
                OpCode::LoadFalse    => self.push(Obj::Bool(false))?,
                OpCode::LoadNone | OpCode::LoadEllipsis => self.push(Obj::None)?,

                // ── Arithmetic — inline cache + adaptive rewrite ──

                OpCode::Add   => { let (a, b) = self.pop2()?; self.cached_binop(rip, &ins.opcode, &a, &b); self.push(self.add(a, b)?)?; }
                OpCode::Sub   => { let (a, b) = self.pop2()?; self.cached_binop(rip, &ins.opcode, &a, &b); self.push(self.sub(a, b)?)?; }
                OpCode::Mul   => { let (a, b) = self.pop2()?; self.cached_binop(rip, &ins.opcode, &a, &b); self.push(self.mul(a, b)?)?; }
                OpCode::Div   => { let (a, b) = self.pop2()?; self.push(self.div(a, b)?)?; }
                OpCode::Mod   => { let (a, b) = self.pop2()?; let d = b.int()?; if d == 0 { return Err(VmErr::ZeroDiv); } self.push(Obj::Int(a.int()? % d))?; }
                OpCode::Pow   => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()?.pow(b.int()? as u32)))?; }
                OpCode::FloorDiv => { let (a, b) = self.pop2()?; let d = b.int()?; if d == 0 { return Err(VmErr::ZeroDiv); } self.push(Obj::Int(a.int()? / d))?; }
                OpCode::Minus => { let v = self.pop()?; self.push(match v { Obj::Int(i) => Obj::Int(-i), Obj::Float(f) => Obj::Float(-f), _ => return Err(VmErr::Type("unary -".into())) })?; }

                // ── Bitwise ──

                OpCode::BitAnd => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()? & b.int()?))?; }
                OpCode::BitOr  => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()? | b.int()?))?; }
                OpCode::BitXor => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()? ^ b.int()?))?; }
                OpCode::BitNot => { let v = self.pop()?; self.push(Obj::Int(!v.int()?))?; }
                OpCode::Shl    => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()? << b.int()?))?; }
                OpCode::Shr    => { let (a, b) = self.pop2()?; self.push(Obj::Int(a.int()? >> b.int()?))?; }

                // ── Comparison — inline cache + adaptive rewrite ──

                OpCode::Eq    => { let (a, b) = self.pop2()?; self.cached_binop(rip, &ins.opcode, &a, &b); self.push(Obj::Bool(self.eq(&a, &b)))?; }
                OpCode::NotEq => { let (a, b) = self.pop2()?; self.push(Obj::Bool(!self.eq(&a, &b)))?; }
                OpCode::Lt    => { let (a, b) = self.pop2()?; self.cached_binop(rip, &ins.opcode, &a, &b); self.push(Obj::Bool(self.lt(&a, &b)?))?; }
                OpCode::Gt    => { let (a, b) = self.pop2()?; self.push(Obj::Bool(self.lt(&b, &a)?))?; }
                OpCode::LtEq  => { let (a, b) = self.pop2()?; self.push(Obj::Bool(!self.lt(&b, &a)?))?; }
                OpCode::GtEq  => { let (a, b) = self.pop2()?; self.push(Obj::Bool(!self.lt(&a, &b)?))?; }

                // ── Logical ──

                OpCode::And => { let (a, b) = self.pop2()?; self.push(if a.truthy() { b } else { a })?; }
                OpCode::Or  => { let (a, b) = self.pop2()?; self.push(if a.truthy() { a } else { b })?; }
                OpCode::Not => { let v = self.pop()?; self.push(Obj::Bool(!v.truthy()))?; }

                // ── Control flow ──

                OpCode::JumpIfFalse => { let v = self.pop()?; if !v.truthy() { ip = op as usize; } }
                OpCode::Jump        => { ip = op as usize; }
                OpCode::PopTop      => { self.pop()?; }
                OpCode::ReturnValue => { return Ok(if self.stack.is_empty() { Obj::None } else { self.pop()? }); }

                // ── Collections ──

                OpCode::BuildList   => { self.pool.alloc()?; let v = self.pop_n(op as usize)?; self.push(Obj::List(v))?; }
                OpCode::BuildTuple  => { let v = self.pop_n(op as usize)?; self.push(Obj::Tuple(v))?; }
                OpCode::BuildDict   => { let n = op as usize; let mut p = Vec::with_capacity(n); for _ in 0..n { let v = self.pop()?; let k = self.pop()?; p.push((k, v)); } p.reverse(); self.push(Obj::Dict(p))?; }
                OpCode::BuildString => { let parts = self.pop_n(op as usize)?; self.push(Obj::Str(parts.iter().map(|p| p.display()).collect()))?; }
                OpCode::GetItem     => { let idx = self.pop()?; let obj = self.pop()?; self.push(self.getitem(&obj, &idx)?)?; }
                OpCode::UnpackSequence => { let seq = self.pop()?; match seq { Obj::List(v) | Obj::Tuple(v) => { for i in v.into_iter().rev() { self.push(i)?; } } _ => return Err(VmErr::Type("unpack".into())) } }
                OpCode::FormatValue => { if op == 1 { self.pop()?; } let v = self.pop()?; self.push(Obj::Str(v.display()))?; }

                // ── Iterators ──

                OpCode::GetIter => { let obj = self.pop()?; self.push(Obj::Int(0))?; self.push(obj)?; }
                OpCode::ForIter => {
                    let iter = self.pop()?; let cur = self.pop()?;
                    let i = cur.int().unwrap_or(0) as usize;
                    match &iter {
                        Obj::List(v) | Obj::Tuple(v) if i < v.len() => {
                            let item = v[i].clone();
                            self.push(Obj::Int((i + 1) as i64))?;
                            self.push(iter)?;
                            self.push(item)?;
                        }
                        _ => { ip = op as usize; }
                    }
                }

                // ── Phi ──

                OpCode::Phi => {
                    let target = &chunk.names[op as usize];
                    let (ia, ib) = chunk.phi_sources[phi_idx];
                    phi_idx += 1;
                    let na = &chunk.names[ia as usize];
                    let nb = &chunk.names[ib as usize];
                    let val = names.get(na).or_else(|| names.get(nb)).cloned().unwrap_or(Obj::None);
                    names.insert(target.clone(), val);
                }

                // ── Functions — template memoization ──

                OpCode::MakeFunction | OpCode::MakeCoroutine => self.push(Obj::Func(op as usize))?,
                OpCode::Call => {
                    let argc = op as usize;
                    let args = self.pop_n(argc)?;
                    let func = self.pop()?;
                    match func {
                        Obj::Func(fi) => {
                            if self.depth >= MAX_CALLS { return Err(VmErr::CallDepth); }
                            if let Some(cached) = self.templates.lookup(fi, &args) { self.push(cached.clone())?; continue; }
                            self.depth += 1;
                            let (params, body, _) = &self.chunk.functions[fi];
                            let mut fn_ns = names.clone();
                            for (i, p) in params.iter().enumerate() {
                                if i < args.len() { fn_ns.insert(format!("{}_0", p.trim_start_matches('*')), args[i].clone()); }
                            }
                            let result = self.exec(body, &mut fn_ns)?;
                            self.depth -= 1;
                            self.templates.record(fi, &args, &result);
                            self.push(result)?;
                        }
                        _ => return Err(VmErr::Type(format!("'{}' not callable", func.ty()))),
                    }
                }

                // ── Builtins ──

                OpCode::CallPrint => { let v = self.pop()?; let s = v.display(); self.output.push(s.clone()); #[cfg(not(test))] println!("{}", s); }
                OpCode::CallLen   => { let o = self.pop()?; self.push(Obj::Int(match &o { Obj::Str(s) => s.len() as i64, Obj::List(v) | Obj::Tuple(v) => v.len() as i64, Obj::Dict(v) => v.len() as i64, _ => return Err(VmErr::Type("len()".into())) }))?; }
                OpCode::CallAbs   => { let o = self.pop()?; self.push(match o { Obj::Int(i) => Obj::Int(i.abs()), Obj::Float(f) => Obj::Float(f.abs()), _ => return Err(VmErr::Type("abs()".into())) })?; }
                OpCode::CallStr   => { let o = self.pop()?; self.push(Obj::Str(o.display()))?; }
                OpCode::CallInt   => { let o = self.pop()?; self.push(Obj::Int(match &o { Obj::Int(i) => *i, Obj::Float(f) => *f as i64, Obj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("int: '{}'", s)))?, _ => return Err(VmErr::Type("int()".into())) }))?; }
                OpCode::CallFloat => { let o = self.pop()?; self.push(Obj::Float(match &o { Obj::Float(f) => *f, Obj::Int(i) => *i as f64, Obj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("float: '{}'", s)))?, _ => return Err(VmErr::Type("float()".into())) }))?; }
                OpCode::CallBool  => { let o = self.pop()?; self.push(Obj::Bool(o.truthy()))?; }
                OpCode::CallType  => { let o = self.pop()?; self.push(Obj::Str(o.ty().into()))?; }
                OpCode::CallChr   => { let o = self.pop()?; self.push(Obj::Str(char::from_u32(o.int()? as u32).ok_or(VmErr::Value("chr()".into()))?.to_string()))?; }
                OpCode::CallOrd   => { let o = self.pop()?; match o { Obj::Str(s) if s.len() == 1 => self.push(Obj::Int(s.chars().next().unwrap() as i64))?, _ => return Err(VmErr::Type("ord()".into())) } }
                OpCode::CallRange => {
                    let args = self.pop_n(op as usize)?;
                    let (s, e, st) = match args.len() {
                        1 => (0, args[0].int()?, 1),
                        2 => (args[0].int()?, args[1].int()?, 1),
                        3 => (args[0].int()?, args[1].int()?, args[2].int()?),
                        _ => return Err(VmErr::Type("range()".into()))
                    };

                    if st == 0 {
                        return Err(VmErr::Value("step zero".into()));
                    }

                    self.pool.alloc()?;

                    let mut v = Vec::new();
                    let mut i = s;

                    if st > 0 {
                        while i < e {
                            v.push(Obj::Int(i));
                            i += st;
                        }
                    } else {
                        while i > e {
                            v.push(Obj::Int(i));
                            i += st;
                        }
                    }

                    self.push(Obj::List(v))?;
                }
                // ── Stubs ──

                OpCode::Global | OpCode::Nonlocal | OpCode::Del | OpCode::Assert
                | OpCode::Import | OpCode::ImportFrom | OpCode::UnpackArgs | OpCode::UnpackEx
                | OpCode::SetupExcept | OpCode::PopExcept | OpCode::Raise | OpCode::RaiseFrom
                | OpCode::SetupWith | OpCode::ExitWith | OpCode::Yield | OpCode::YieldFrom
                | OpCode::Await | OpCode::TypeAlias | OpCode::MakeClass
                | OpCode::LoadAttr | OpCode::StoreAttr | OpCode::StoreItem
                | OpCode::BuildSlice | OpCode::BuildSet
                | OpCode::ListComp | OpCode::SetComp | OpCode::DictComp | OpCode::GenExpr
                | OpCode::CallRound | OpCode::CallMin | OpCode::CallMax | OpCode::CallSum
                | OpCode::CallSorted | OpCode::CallEnumerate | OpCode::CallZip
                | OpCode::CallList | OpCode::CallTuple | OpCode::CallDict | OpCode::CallSet
                | OpCode::CallInput | OpCode::CallIsInstance
                | OpCode::In | OpCode::NotIn | OpCode::Is | OpCode::IsNot => {}
            }
        }
    }

    // ── Arithmetic ──

    fn add(&self, a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x), Obj::Int(y))     => Obj::Int(x + y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x + y),
            (Obj::Int(x), Obj::Float(y))   => Obj::Float(x as f64 + y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x + y as f64),
            (Obj::Str(x), Obj::Str(y))     => Obj::Str(format!("{}{}", x, y)),
            (a, b) => return Err(VmErr::Type(format!("{} + {}", a.ty(), b.ty()))),
        })
    }

    fn sub(&self, a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x), Obj::Int(y))     => Obj::Int(x - y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x - y),
            (Obj::Int(x), Obj::Float(y))   => Obj::Float(x as f64 - y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x - y as f64),
            (a, b) => return Err(VmErr::Type(format!("{} - {}", a.ty(), b.ty()))),
        })
    }

    fn mul(&self, a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x), Obj::Int(y))     => Obj::Int(x * y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x * y),
            (Obj::Int(x), Obj::Float(y))   => Obj::Float(x as f64 * y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x * y as f64),
            (Obj::Str(s), Obj::Int(n))     => Obj::Str(s.repeat(n.max(0) as usize)),
            (a, b) => return Err(VmErr::Type(format!("{} * {}", a.ty(), b.ty()))),
        })
    }

    fn div(&self, a: Obj, b: Obj) -> Result<Obj, VmErr> {
        let bv = match &b { Obj::Int(i) => *i as f64, Obj::Float(f) => *f, _ => return Err(VmErr::Type("div".into())) };
        if bv == 0.0 { return Err(VmErr::ZeroDiv); }
        let av = match &a { Obj::Int(i) => *i as f64, Obj::Float(f) => *f, _ => return Err(VmErr::Type("div".into())) };
        Ok(Obj::Float(av / bv))
    }

    // ── Comparison ──

    fn eq(&self, a: &Obj, b: &Obj) -> bool {
        match (a, b) {
            (Obj::Int(x), Obj::Int(y))     => x == y,
            (Obj::Float(x), Obj::Float(y)) => x == y,
            (Obj::Int(x), Obj::Float(y))   => (*x as f64) == *y,
            (Obj::Float(x), Obj::Int(y))   => *x == (*y as f64),
            (Obj::Str(x), Obj::Str(y))     => x == y,
            (Obj::Bool(x), Obj::Bool(y))   => x == y,
            (Obj::None, Obj::None)         => true,
            _ => false,
        }
    }

    fn lt(&self, a: &Obj, b: &Obj) -> Result<bool, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x), Obj::Int(y))     => x < y,
            (Obj::Float(x), Obj::Float(y)) => x < y,
            (Obj::Int(x), Obj::Float(y))   => (*x as f64) < *y,
            (Obj::Float(x), Obj::Int(y))   => *x < (*y as f64),
            (Obj::Str(x), Obj::Str(y))     => x < y,
            _ => return Err(VmErr::Type(format!("'<' {} and {}", a.ty(), b.ty()))),
        })
    }

    // ── Collection access ──

    fn getitem(&self, obj: &Obj, idx: &Obj) -> Result<Obj, VmErr> {
        match (obj, idx) {
            (Obj::List(v) | Obj::Tuple(v), Obj::Int(i)) => {
                let i = if *i < 0 { v.len() as i64 + i } else { *i } as usize;
                v.get(i).cloned().ok_or(VmErr::Value("index out of range".into()))
            }
            (Obj::Dict(p), key) => p.iter().find(|(k, _)| self.eq(k, key)).map(|(_, v)| v.clone()).ok_or(VmErr::Value("key not found".into())),
            (Obj::Str(s), Obj::Int(i)) => {
                let i = if *i < 0 { s.len() as i64 + i } else { *i } as usize;
                s.chars().nth(i).map(|c| Obj::Str(c.to_string())).ok_or(VmErr::Value("string index".into()))
            }
            _ => Err(VmErr::Type(format!("{}[{}]", obj.ty(), idx.ty()))),
        }
    }
}