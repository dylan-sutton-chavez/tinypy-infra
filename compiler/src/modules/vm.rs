/*
 * `vm.rs`  Stack-based bytecode VM.
 *
 * Architecture:
 *   • Iterator stack   — ForIter nunca mueve la colección; O(1) por iteración.
 *   • Lazy range       — range(N) no materializa Vec; cero allocations en loops.
 *   • Per-frame caches — InlineCache + Adaptive se crean por exec(); sin depth guard.
 *   • Template memo    — funciones puras memoizadas después de 4 hits.
 *   • Dispatch match   — agregar opcode = escribir un arm, sin tocar nada más.
 *   • Static helpers   — aritmética como Self::fn() para evitar conflictos de borrow.
 *   • OWASP A04:2021   — Limits: call depth, op budget, heap quota.
 */

use crate::modules::parser::{OpCode, SSAChunk, Value};
use alloc::{string::{String, ToString}, vec::Vec, vec, rc::Rc, format};
use hashbrown::HashMap;
use core::fmt;
use core::cell::RefCell;

// ═══════════════════════════════════════════════════════════════
//  Limits
// ═══════════════════════════════════════════════════════════════

pub struct Limits { pub calls: usize, pub ops: usize, pub heap: usize }
impl Limits {
    pub fn none()    -> Self { Self { calls: usize::MAX, ops: usize::MAX, heap: usize::MAX } }
    pub fn sandbox() -> Self { Self { calls: 512, ops: 100_000_000, heap: 100_000 } }
}

// ═══════════════════════════════════════════════════════════════
//  FastOp — specialized operation variants for inline cache
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
enum FastOp {
    AddInt, AddFloat, AddStr,
    SubInt, SubFloat,
    MulInt, MulFloat,
    LtInt,  LtFloat,
    EqInt,  EqStr,
}

// ═══════════════════════════════════════════════════════════════
//  Obj — runtime values
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum Obj {
    Int(i64), Float(f64), Str(String), Bool(bool), None,
    Tuple(Vec<Obj>), Func(usize),
    Range(i64, i64, i64),
    List(Rc<RefCell<Vec<Obj>>>),
    Dict(Rc<RefCell<Vec<(Obj, Obj)>>>)
}

impl Obj {
    #[inline] fn truthy(&self) -> bool {
        match self {
            Self::Bool(b)   => *b,
            Self::Int(i)   => *i != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s)    => !s.is_empty(),
            Self::None => false,
            Self::List(v)   => !v.borrow().is_empty(),
            Self::Tuple(v)  => !v.is_empty(),
            Self::Dict(v)   => !v.borrow().is_empty(),
            Self::Range(s,e,st) => if *st>0{s<e}else{s>e},
            _ => true,
        }
    }

    #[inline] fn int(&self) -> Result<i64, VmErr> {
        match self {
            Self::Int(i)  => Ok(*i),
            Self::Bool(b) => Ok(*b as i64),
            _ => Err(VmErr::Type(format!("expected int, got {}", self.ty()))),
        }
    }

    fn ty(&self) -> &'static str {
        match self {
            Self::Int(_)=>"int",   Self::Float(_)=>"float", Self::Str(_)=>"str",
            Self::Bool(_)=>"bool", Self::None=>"NoneType",  Self::List(_)=>"list",
            Self::Dict(_)=>"dict", Self::Tuple(_)=>"tuple", Self::Func(_)=>"function",
            Self::Range(..)=>"range",
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Int(i) => { let mut b = itoa::Buffer::new(); b.format(*i).into() }
            Self::Float(f) if *f == (*f as i64) as f64 && f.is_finite() => {
                let mut b = itoa::Buffer::new();
                let mut s = String::with_capacity(20);
                s.push_str(b.format(*f as i64)); s.push_str(".0"); s
            }
            Self::Float(f)   => { let mut b = ryu::Buffer::new(); b.format(*f).into() }
            Self::Str(s)     => s.clone(),
            Self::Bool(b)    => if *b { "True" } else { "False" }.into(),
            Self::None       => "None".into(),
            Self::Range(s,e,st) => if *st==1 { format!("range({}, {})",s,e) } else { format!("range({}, {}, {})",s,e,st) },
            Self::List(v)    => format!("[{}]", v.borrow().iter().map(|o| o.repr()).collect::<Vec<_>>().join(", ")),
            Self::Tuple(v) if v.len() == 1 => format!("({},)", v[0].repr()),
            Self::Tuple(v)   => format!("({})", v.iter().map(|o| o.repr()).collect::<Vec<_>>().join(", ")),
            Self::Dict(p)    => format!("{{{}}}", p.borrow().iter().map(|(k,v)| format!("{}: {}", k.repr(), v.repr())).collect::<Vec<_>>().join(", ")),
            Self::Func(i)    => format!("<function {}>", i),
        }
    }

    fn repr(&self) -> String { match self { Self::Str(s) => format!("'{}'", s), o => o.display() } }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum VmErr {
    CallDepth, Heap, Budget,
    Name(String), Type(String), Value(String),
    ZeroDiv, Runtime(String),
}

impl fmt::Display for VmErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallDepth  => write!(f, "RecursionError: max depth"),
            Self::Heap       => write!(f, "MemoryError: heap limit"),
            Self::Budget     => write!(f, "RuntimeError: budget exceeded"),
            Self::Name(s)    => write!(f, "NameError: '{}'", s),
            Self::Type(s)    => write!(f, "TypeError: {}", s),
            Self::Value(s)   => write!(f, "ValueError: {}", s),
            Self::ZeroDiv    => write!(f, "ZeroDivisionError: division by zero"),
            Self::Runtime(s) => write!(f, "RuntimeError: {}", s),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Memory pool
// ═══════════════════════════════════════════════════════════════

struct Pool { count: usize, limit: usize }
impl Pool {
    fn new(limit: usize) -> Self { Self { count: 0, limit } }
    fn alloc(&mut self) -> Result<(), VmErr> {
        self.count += 1;
        if self.count > self.limit { Err(VmErr::Heap) } else { Ok(()) }
    }
    fn usage(&self) -> usize { self.count }
}

// ═══════════════════════════════════════════════════════════════
//  Inline cache — per exec() frame, no depth guard needed
// ═══════════════════════════════════════════════════════════════

const CACHE_THRESH: u8 = 8;

#[derive(Clone)]
struct Slot { hits: u8, ta: u8, tb: u8, fast: Option<FastOp> }
impl Slot { fn empty() -> Self { Self { hits: 0, ta: 0, tb: 0, fast: None } } }

struct InlineCache { slots: Vec<Slot> }
impl InlineCache {
    fn new(n: usize) -> Self { Self { slots: vec![Slot::empty(); n] } }

    fn record(&mut self, ip: usize, opcode: &OpCode, ta: u8, tb: u8) -> Option<FastOp> {
        let s = self.slots.get_mut(ip)?;
        if s.ta == ta && s.tb == tb {
            s.hits = s.hits.saturating_add(1);
            if s.hits >= CACHE_THRESH && s.fast.is_none() {
                s.fast = match (opcode, ta, tb) {
                    (OpCode::Add, 1, 1) => Some(FastOp::AddInt),   (OpCode::Add, 2, 2) => Some(FastOp::AddFloat),
                    (OpCode::Add, 3, 3) => Some(FastOp::AddStr),   (OpCode::Sub, 1, 1) => Some(FastOp::SubInt),
                    (OpCode::Sub, 2, 2) => Some(FastOp::SubFloat), (OpCode::Mul, 1, 1) => Some(FastOp::MulInt),
                    (OpCode::Mul, 2, 2) => Some(FastOp::MulFloat), (OpCode::Lt,  1, 1) => Some(FastOp::LtInt),
                    (OpCode::Lt,  2, 2) => Some(FastOp::LtFloat),  (OpCode::Eq,  1, 1) => Some(FastOp::EqInt),
                    (OpCode::Eq,  3, 3) => Some(FastOp::EqStr),    _ => None,
                };
            }
        } else { *s = Slot { hits: 1, ta, tb, fast: None }; }
        s.fast
    }

    fn get(&self, ip: usize) -> Option<FastOp> { self.slots.get(ip).and_then(|s| s.fast) }
    fn invalidate(&mut self, ip: usize) { if let Some(s) = self.slots.get_mut(ip) { *s = Slot::empty(); } }
    fn count(&self) -> usize { self.slots.iter().filter(|s| s.fast.is_some()).count() }
}

// ═══════════════════════════════════════════════════════════════
//  Template memoization — pure function result cache
// ═══════════════════════════════════════════════════════════════

const TPL_THRESH: u32 = 4;

struct TplEntry { args: Vec<Obj>, result: Obj, hits: u32 }
struct Templates { map: HashMap<usize, Vec<TplEntry>> }

impl Templates {
    fn new() -> Self { Self { map: HashMap::new() } }

    fn lookup(&self, fi: usize, args: &[Obj]) -> Option<&Obj> {
        self.map.get(&fi)?.iter()
            .find(|e| e.hits >= TPL_THRESH && Self::args_eq(&e.args, args))
            .map(|e| &e.result)
    }

    fn record(&mut self, fi: usize, args: &[Obj], result: &Obj) {
        let v = self.map.entry(fi).or_insert_with(Vec::new);
        if let Some(e) = v.iter_mut().find(|e| Self::args_eq(&e.args, args)) {
            e.hits += 1; e.result = result.clone();
        } else if v.len() < 256 {
            v.push(TplEntry { args: args.to_vec(), result: result.clone(), hits: 1 });
        }
    }

    fn args_eq(a: &[Obj], b: &[Obj]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| match (x, y) {
            (Obj::Int(a),   Obj::Int(b))   => a == b, (Obj::Float(a), Obj::Float(b)) => a == b,
            (Obj::Str(a),   Obj::Str(b))   => a == b, (Obj::Bool(a),  Obj::Bool(b))  => a == b,
            (Obj::None,     Obj::None)     => true,   _ => false,
        })
    }

    fn count(&self) -> usize {
        self.map.values().map(|v| v.iter().filter(|e| e.hits >= TPL_THRESH).count()).sum()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Adaptive engine — hotspot rewriting, per exec() frame
// ═══════════════════════════════════════════════════════════════

const HOT_THRESH: u32 = 1_000;

struct Adaptive { counts: Vec<u32>, overlay: Vec<Option<FastOp>> }
impl Adaptive {
    fn new(n: usize) -> Self { Self { counts: vec![0; n], overlay: vec![None; n] } }
    fn tick(&mut self, ip: usize) -> bool { if let Some(c) = self.counts.get_mut(ip) { *c += 1; *c == HOT_THRESH } else { false } }
    fn rewrite(&mut self, ip: usize, f: FastOp) { if let Some(s) = self.overlay.get_mut(ip) { *s = Some(f); } }
    fn get(&self, ip: usize) -> Option<FastOp> { self.overlay.get(ip).and_then(|o| *o) }
    fn deopt(&mut self, ip: usize) { if let Some(s) = self.overlay.get_mut(ip) { *s = None; } if let Some(c) = self.counts.get_mut(ip) { *c = 0; } }
    fn hotspots(&self) -> Vec<usize> { self.counts.iter().enumerate().filter(|&(_, &c)| c >= HOT_THRESH).map(|(i, _)| i).collect() }
    fn count(&self) -> usize { self.overlay.iter().filter(|o| o.is_some()).count() }
}

// ═══════════════════════════════════════════════════════════════
//  Iterator frame — THE LOOP FIX
//
//  Seq:   Vec<Obj> owned here, never touched again. ForIter only
//         reads one item by index — no pop/push of the collection.
//  Range: lazy i64 counter — range(1_000_000) uses O(1) memory.
// ═══════════════════════════════════════════════════════════════

enum IterFrame {
    Seq   { items: Vec<Obj>, idx: usize },
    Range { cur: i64, end: i64, step: i64 },
}

impl IterFrame {
    fn next_item(&mut self) -> Option<Obj> {
        match self {
            Self::Seq { items, idx } => {
                if *idx < items.len() { let item = items[*idx].clone(); *idx += 1; Some(item) } else { None }
            }
            Self::Range { cur, end, step } => {
                let done = if *step > 0 { *cur >= *end } else { *cur <= *end };
                if done { None } else { let v = *cur; *cur += *step; Some(Obj::Int(v)) }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  VM
// ═══════════════════════════════════════════════════════════════

pub struct VM<'a> {
    stack:      Vec<Obj>,
    iter_stack: Vec<IterFrame>,     // iterator stack — never moves collections
    chunk:      &'a SSAChunk,
    pool:       Pool,
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
            stack: Vec::with_capacity(256), iter_stack: Vec::with_capacity(16),
            chunk, pool: Pool::new(limits.heap), templates: Templates::new(),
            budget: limits.ops, depth: 0, max_calls: limits.calls,
            output: Vec::new(),
        }
    }

    pub fn run(&mut self) -> Result<Obj, VmErr> {
        let mut slots = vec![Option::<Obj>::None; self.chunk.names.len()];
        self.exec(self.chunk, &mut slots)
    }

    // Stats
    pub fn heap_usage(&self)       -> usize      { self.pool.usage() }
    pub fn templates_cached(&self) -> usize      { self.templates.count() }
    pub fn cache_stats(&self) -> (usize, usize)  { (self.templates.count(), self.chunk.instructions.len()) }

    // ── Stack helpers ──────────────────────────────────────────

    #[inline] fn push(&mut self, v: Obj) -> Result<(), VmErr> { self.stack.push(v); Ok(()) }
    #[inline] fn pop(&mut self)  -> Result<Obj, VmErr> { self.stack.pop().ok_or_else(|| VmErr::Runtime("stack underflow".into())) }
    #[inline] fn pop2(&mut self) -> Result<(Obj, Obj), VmErr> { let b = self.pop()?; let a = self.pop()?; Ok((a, b)) }
    #[inline] fn pop_n(&mut self, n: usize) -> Result<Vec<Obj>, VmErr> {
        let at = self.stack.len().checked_sub(n).ok_or_else(|| VmErr::Runtime("stack underflow".into()))?;
        Ok(self.stack.split_off(at))
    }

    fn to_obj(&self, v: &Value) -> Obj {
        match v {
            Value::Int(i)  => Obj::Int(*i),  Value::Float(f) => Obj::Float(*f),
            Value::Str(s)  => Obj::Str(s.clone()), Value::Bool(b) => Obj::Bool(*b),
            Value::None    => Obj::None,
        }
    }

    // ── Fast-path execution (inline cache / adaptive hits) ─────

    #[inline] fn exec_fast(&mut self, fast: FastOp) -> Result<bool, VmErr> {
        let (a, b) = self.pop2()?;
        let r = match (fast, &a, &b) {
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
        self.push(r)?; Ok(true)
    }

    // ── Main dispatch loop ─────────────────────────────────────
    //
    // AGREGAR UN OPCODE:
    //   1. Escribe el arm: OpCode::NuevoOp => { /* lógica */ }
    //   2. Muévelo de la sección "stubs" si ya existía ahí.
    //   Eso es todo. No tocas nada más.

    fn exec(&mut self, chunk: &SSAChunk, slots: &mut Vec<Option<Obj>>) -> Result<Obj, VmErr> {
        let n = chunk.instructions.len();

        // Per-frame — caches activos en cualquier profundidad (sin depth guard)
        let mut cache    = InlineCache::new(n);
        let mut adaptive = Adaptive::new(n);
        let mut ip       = 0usize;
        let mut phi_idx  = 0usize;

        // ── Slot-alias table ───────────────────────────────────────────
        //
        // prev_slots[i] = Some(j) means: when storing into slot i ("name_V"),
        // also write slot j ("name_{V-1}") so the next LoadName of the old
        // version still sees the updated value. This replaces the old
        // `self.versions: HashMap<String,String>` with a Vec<Option<usize>>
        // built once per exec() call with zero String hashing in the hot path.
        let mut prev_slots: Vec<Option<usize>> = vec![None; chunk.names.len()];
        {
            let mut name_map: HashMap<&str, usize> = HashMap::with_capacity(chunk.names.len());
            for (i, name) in chunk.names.iter().enumerate() {
                name_map.insert(name.as_str(), i);
            }
            for (i, name) in chunk.names.iter().enumerate() {
                if let Some(pos) = name.rfind('_') {
                    if let Ok(ver) = name[pos+1..].parse::<u32>() {
                        if ver > 0 {
                            let prev = format!("{}_{}", &name[..pos], ver - 1);
                            if let Some(&j) = name_map.get(prev.as_str()) {
                                prev_slots[i] = Some(j);
                            }
                        }
                    }
                }
            }
        }

        macro_rules! cache_binop {
            ($rip:expr, $opcode:expr, $a:expr, $b:expr) => {{
                fn type_tag(o: &Obj) -> u8 { match o { Obj::Int(_)=>1, Obj::Float(_)=>2, Obj::Str(_)=>3, Obj::Bool(_)=>4, Obj::None=>5, Obj::List(_)=>6, Obj::Dict(_)=>7, Obj::Tuple(_)=>8, Obj::Func(_)=>9, _=>0 } }
                if let Some(f) = cache.record($rip, $opcode, type_tag($a), type_tag($b)) {
                    if adaptive.tick($rip) { adaptive.rewrite($rip, f); }
                }
            }};
        }

        loop {
            if ip >= n { return Ok(Obj::None); }
            if self.budget == 0 { return Err(VmErr::Budget); }
            self.budget -= 1;

            // Adaptive → inline cache fast paths (active at all depths)
            if let Some(fast) = adaptive.get(ip) {
                ip += 1;
                if self.exec_fast(fast)? { continue; }
                adaptive.deopt(ip - 1); cache.invalidate(ip - 1); ip -= 1;
            } else if let Some(fast) = cache.get(ip) {
                ip += 1;
                if self.exec_fast(fast)? { continue; }
                cache.invalidate(ip - 1); ip -= 1;
            }

            let ins = &chunk.instructions[ip];
            let op  = ins.operand;
            let rip = ip;
            ip += 1;

            match ins.opcode {

                // ── Loads ─────────────────────────────────────────────

                OpCode::LoadConst  => self.push(self.to_obj(&chunk.constants[op as usize]))?,
                OpCode::LoadName   => {
                    let slot = op as usize;
                    self.push(slots[slot].clone().ok_or_else(|| VmErr::Name(chunk.names[slot].clone()))?)?;
                }
                OpCode::StoreName  => {
                    let v = self.pop()?;
                    let slot = op as usize;
                    if let Some(prev) = prev_slots[slot] { slots[prev] = Some(v.clone()); }
                    slots[slot] = Some(v);
                }
                OpCode::LoadTrue       => self.push(Obj::Bool(true))?,
                OpCode::LoadFalse      => self.push(Obj::Bool(false))?,
                OpCode::LoadNone => self.push(Obj::None)?,
                OpCode::LoadEllipsis => self.push(Obj::Str("...".to_string()))?,
    
                OpCode::LoadEllipsis => self.push(Obj::Str("...".to_string()))?,
                
                OpCode::StoreItem => {
                    let value = self.pop()?;
                    let idx_obj = self.pop()?;
                    let container = self.pop()?;

                    match (container, idx_obj) {
                        (Obj::List(v), Obj::Int(i)) => {
                            let mut b = v.borrow_mut(); 
                            let idx = if i < 0 { b.len() as i64 + i } else { i } as usize;
                            
                            if idx >= b.len() { 
                                return Err(VmErr::Value("list assignment index out of range".into())); 
                            }
                            b[idx] = value;
                        }
                        (Obj::Dict(p), key) => {
                            let mut b = p.borrow_mut();
                            if let Some(pos) = b.iter().position(|(k, _)| Self::eq_vals(k, &key)) {
                                b[pos].1 = value;
                            } else {
                                b.push((key, value)); 
                            }
                        }
                        (Obj::Tuple(_), _) => return Err(VmErr::Type("'tuple' object does not support item assignment".into())),
                        (Obj::Str(_), _) => return Err(VmErr::Type("'str' object does not support item assignment".into())),
                        (c, _) => return Err(VmErr::Type(format!("'{}' object does not support item assignment", c.ty()))),
                    }
                }

                // ── Arithmetic (with inline cache + adaptive) ─────────

                OpCode::Add => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    self.push(Self::add_vals(a, b)?)?;
                }
                OpCode::Sub => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    self.push(Self::sub_vals(a, b)?)?;
                }
                OpCode::Mul => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    self.push(Self::mul_vals(a, b)?)?;
                }
                OpCode::Div      => { let (a,b) = self.pop2()?; self.push(Self::div_vals(a, b)?)?; }
                OpCode::Mod      => { let (a,b) = self.pop2()?; let d = b.int()?; if d==0 { return Err(VmErr::ZeroDiv); } self.push(Obj::Int(a.int()? % d))?; }
                OpCode::Pow      => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()?.pow(b.int()? as u32)))?; }
                OpCode::FloorDiv => { let (a,b) = self.pop2()?; let d = b.int()?; if d==0 { return Err(VmErr::ZeroDiv); } self.push(Obj::Int(a.int()? / d))?; }
                OpCode::Minus    => { let v = self.pop()?; self.push(match v { Obj::Int(i)=>Obj::Int(-i), Obj::Float(f)=>Obj::Float(-f), _=>return Err(VmErr::Type("unary -".into())) })?; }

                // ── Bitwise ───────────────────────────────────────────

                OpCode::BitAnd => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()? & b.int()?))?; }
                OpCode::BitOr  => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()? | b.int()?))?; }
                OpCode::BitXor => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()? ^ b.int()?))?; }
                OpCode::BitNot => { let v = self.pop()?; self.push(Obj::Int(!v.int()?))?; }
                OpCode::Shl    => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()? << b.int()?))?; }
                OpCode::Shr    => { let (a,b) = self.pop2()?; self.push(Obj::Int(a.int()? >> b.int()?))?; }

                // ── Comparison (with cache) ────────────────────────────

                OpCode::Eq    => { let (a,b) = self.pop2()?; cache_binop!(rip, &ins.opcode, &a, &b); self.push(Obj::Bool(Self::eq_vals(&a, &b)))?; }
                OpCode::NotEq => { let (a,b) = self.pop2()?; self.push(Obj::Bool(!Self::eq_vals(&a, &b)))?; }
                OpCode::Lt    => { let (a,b) = self.pop2()?; cache_binop!(rip, &ins.opcode, &a, &b); self.push(Obj::Bool(Self::lt_vals(&a, &b)?))?; }
                OpCode::Gt    => { let (a,b) = self.pop2()?; self.push(Obj::Bool(Self::lt_vals(&b, &a)?))?; }
                OpCode::LtEq  => { let (a,b) = self.pop2()?; self.push(Obj::Bool(!Self::lt_vals(&b, &a)?))?; }
                OpCode::GtEq  => { let (a,b) = self.pop2()?; self.push(Obj::Bool(!Self::lt_vals(&a, &b)?))?; }

                // ── Logic ─────────────────────────────────────────────

                OpCode::And => { let (a,b) = self.pop2()?; self.push(if a.truthy() { b } else { a })?; }
                OpCode::Or  => { let (a,b) = self.pop2()?; self.push(if a.truthy() { a } else { b })?; }
                OpCode::Not => { let v = self.pop()?; self.push(Obj::Bool(!v.truthy()))?; }

                // ── Control flow ──────────────────────────────────────

                OpCode::JumpIfFalse => { let v = self.pop()?; if !v.truthy() { ip = op as usize; } }
                OpCode::Jump        => { ip = op as usize; }
                OpCode::PopTop      => { self.pop()?; }
                OpCode::ReturnValue => { return Ok(if self.stack.is_empty() { Obj::None } else { self.pop()? }); }

                // ── Collections ───────────────────────────────────────

                OpCode::BuildList  => { 
                    self.pool.alloc()?; 
                    let v = self.pop_n(op as usize)?; 
                    self.push(Obj::List(Rc::new(RefCell::new(v))))?; 
                }
                OpCode::BuildTuple => { let v = self.pop_n(op as usize)?; self.push(Obj::Tuple(v))?; }
                OpCode::BuildDict  => {
                    let mut p = Vec::with_capacity(op as usize);
                    for _ in 0..op { let v = self.pop()?; let k = self.pop()?; p.push((k, v)); }
                    p.reverse();
                    self.push(Obj::Dict(Rc::new(RefCell::new(p))))?;
                }
                OpCode::BuildString => {
                    let parts = self.pop_n(op as usize)?;
                    self.push(Obj::Str(parts.iter().map(|p| p.display()).collect()))?;
                }
                OpCode::GetItem => { let idx = self.pop()?; let obj = self.pop()?; self.push(Self::getitem_val(&obj, &idx)?)?; }
                OpCode::UnpackSequence => {
                    let obj = self.pop()?;
                    let expected = op as usize; // El compilador te dice cuántos elementos espera

                    match obj {
                        Obj::List(v) => {
                            let b = v.borrow();
                            if b.len() != expected { return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, b.len()))); }
                            for item in b.iter().rev() { self.push(item.clone())?; }
                        }
                        Obj::Tuple(v) => {
                            if v.len() != expected { return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, v.len()))); }
                            for item in v.iter().rev() { self.push(item.clone())?; }
                        }

                        Obj::Str(s) => {
                            let chars: Vec<char> = s.chars().collect();
                            if chars.len() != expected {
                                return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, chars.len())));
                            }
                            for c in chars.into_iter().rev() {
                                self.push(Obj::Str(c.to_string()))?;
                            }
                        }

                        _ => return Err(VmErr::Type("unpack".into())),
                    }
                }
                OpCode::FormatValue => { if op == 1 { self.pop()?; } let v = self.pop()?; self.push(Obj::Str(v.display()))?; }

                // ── Iterator stack — LOOP PERFORMANCE FIX ─────────────
                //
                // GetIter: saca la colección del stack y la mueve a iter_stack.
                //          Desde aquí nunca se vuelve a mover — es owned por el frame.
                //
                // ForIter: indexa UN ítem del frame. Sin pop/push de la colección.
                //          range(N) → IterFrame::Range, cero allocations.

                OpCode::GetIter => {
                    let obj = self.pop()?;
                    let frame = match obj {
                        Obj::Range(s, e, st) => IterFrame::Range { cur: s, end: e, step: st },
                        Obj::List(v)  => IterFrame::Seq { items: v.borrow().clone(), idx: 0 },
                        Obj::Tuple(v) => IterFrame::Seq { items: v.clone(), idx: 0 },
                        Obj::Str(s)   => IterFrame::Seq { items: s.chars().map(|c| Obj::Str(c.to_string())).collect(), idx: 0 },
                        Obj::Dict(p)  => IterFrame::Seq { items: p.borrow().iter().map(|(k, _)| k.clone()).collect(), idx: 0 },
                        _ => return Err(VmErr::Type(format!("'{}' is not iterable", obj.ty()))),
                    };
                    self.iter_stack.push(frame);
                }
                OpCode::ForIter => {
                    match self.iter_stack.last_mut().and_then(|f| f.next_item()) {
                        Some(item) => self.push(item)?,
                        None       => { self.iter_stack.pop(); ip = op as usize; }
                    }
                }

                // ── SSA Phi ───────────────────────────────────────────

                OpCode::Phi => {
                    let target_slot = op as usize;
                    let (ia, ib) = chunk.phi_sources[phi_idx]; phi_idx += 1;
                    let val = slots[ia as usize].clone()
                        .or_else(|| slots[ib as usize].clone())
                        .unwrap_or(Obj::None);
                    slots[target_slot] = Some(val);
                }

                // ── Functions ─────────────────────────────────────────

                OpCode::MakeFunction | OpCode::MakeCoroutine => self.push(Obj::Func(op as usize))?,
                OpCode::Call => {
                    let argc = op as usize;
                    if self.depth >= self.max_calls { return Err(VmErr::CallDepth); }
                    let mut args = Vec::with_capacity(argc);
                    for _ in 0..argc { args.push(self.pop()?); }
                    args.reverse();
                    match self.pop()? {
                        Obj::Func(fi) => {
                            if let Some(cached) = self.templates.lookup(fi, &args) { self.push(cached.clone())?; continue; }
                            self.depth += 1;
                            let (params, body, _) = &self.chunk.functions[fi];
                            let mut fn_slots: Vec<Option<Obj>> = vec![None; body.names.len()];

                            let mut body_map: HashMap<&str, usize> = HashMap::with_capacity(body.names.len());
                            for (i, n) in body.names.iter().enumerate() {
                                body_map.insert(n.as_str(), i);
                            }

                            // Bind params
                            for (pi, p) in params.iter().enumerate() {
                                if pi < args.len() {
                                    let pname = format!("{}_0", p.trim_start_matches('*'));
                                    if let Some(&s) = body_map.get(pname.as_str()) {
                                        fn_slots[s] = Some(args[pi].clone());
                                    }
                                }
                            }

                            // Propagate visible functions (closures) from parent scope
                            for (si, sv) in slots.iter().enumerate() {
                                if let Some(obj @ Obj::Func(_)) = sv {
                                    if let Some(&bs) = body_map.get(chunk.names[si].as_str()) {
                                        fn_slots[bs] = Some(obj.clone());
                                    }
                                }
                            }

                            // <<<=== AGREGAR AQUÍ EL FIX ===
                            for i in 0..fn_slots.len() {
                                if fn_slots[i].is_none() {
                                    fn_slots[i] = Some(Obj::Func(fi));
                                    break;
                                }
                            }
                            // <<<============================

                            let result = self.exec(body, &mut fn_slots)?;
                            self.depth -= 1;
                            self.templates.record(fi, &args, &result);
                            self.push(result)?;
                        }
                        _ => return Err(VmErr::Type("call non-function".into())),
                    }
                }

                // ── Builtins ──────────────────────────────────────────
                //   Para agregar un builtin: escribe el arm aquí y muévelo
                //   de la sección de stubs de abajo.

                OpCode::CallPrint => { 
                    let argc = self.pop_n(op as usize)?;
                    let mut args = argc; 
                    args.reverse(); 
                    
                    let output_str = args.iter()
                        .map(|v| v.display())
                        .collect::<Vec<_>>()
                        .join(" ");
                    
                    self.output.push(output_str); 
                }
                OpCode::CallLen => { let o = self.pop()?; self.push(Obj::Int(match &o { Obj::Str(s)=>s.len() as i64, Obj::List(v)=>v.borrow().len() as i64, Obj::Tuple(v)=>v.len() as i64, Obj::Dict(v)=>v.borrow().len() as i64, Obj::Range(s,e,st)=>{ let r=(e-s)/st; Obj::Int(r.max(0)); r.max(0) } _=>return Err(VmErr::Type("len()".into())) }))?; }
                OpCode::CallAbs   => { let o = self.pop()?; self.push(match o { Obj::Int(i)=>Obj::Int(i.abs()), Obj::Float(f)=>Obj::Float(f.abs()), _=>return Err(VmErr::Type("abs()".into())) })?; }
                OpCode::CallStr   => { let o = self.pop()?; self.push(Obj::Str(o.display()))?; }
                OpCode::CallInt   => { let o = self.pop()?; self.push(Obj::Int(match &o { Obj::Int(i)=>*i, Obj::Float(f)=>*f as i64, Obj::Str(s)=>s.trim().parse().map_err(|_| VmErr::Value(format!("int: '{}'",s)))?, _=>return Err(VmErr::Type("int()".into())) }))?; }
                OpCode::CallFloat => { let o = self.pop()?; self.push(Obj::Float(match &o { Obj::Float(f)=>*f, Obj::Int(i)=>*i as f64, Obj::Str(s)=>s.trim().parse().map_err(|_| VmErr::Value(format!("float: '{}'",s)))?, _=>return Err(VmErr::Type("float()".into())) }))?; }
                OpCode::CallBool  => { let o = self.pop()?; self.push(Obj::Bool(o.truthy()))?; }
                OpCode::CallType  => { let o = self.pop()?; self.push(Obj::Str(o.ty().into()))?; }
                OpCode::CallChr   => { let o = self.pop()?; self.push(Obj::Str(char::from_u32(o.int()? as u32).ok_or(VmErr::Value("chr()".into()))?.to_string()))?; }
                OpCode::CallOrd   => { let o = self.pop()?; match o { Obj::Str(s) if s.len()==1 => self.push(Obj::Int(s.chars().next().unwrap() as i64))?, _=>return Err(VmErr::Type("ord()".into())) } }

                // CallRange — produce Obj::Range (lazy). GetIter lo convierte en IterFrame::Range.
                OpCode::CallRange => {
                    let args = self.pop_n(op as usize)?;
                    let (s, e, st) = match args.len() {
                        1 => (0, args[0].int()?, 1),
                        2 => (args[0].int()?, args[1].int()?, 1),
                        3 => (args[0].int()?, args[1].int()?, args[2].int()?),
                        _ => return Err(VmErr::Type("range()".into())),
                    };
                    if st == 0 { return Err(VmErr::Value("range step zero".into())); }
                    self.push(Obj::Range(s, e, st))?; // sin Vec, sin alloc
                }

                OpCode::CallRound => { let o = self.pop()?; self.push(match o { Obj::Float(f)=>Obj::Int((if f >= 0.0 { f + 0.5 } else { f - 0.5 }) as i64), Obj::Int(i)=>Obj::Int(i), _=>return Err(VmErr::Type("round()".into())) })?; }
                OpCode::CallMin   => { let args = self.pop_n(op as usize)?; let m = args.into_iter().reduce(|a,b| if Self::lt_vals(&a,&b).unwrap_or(false){a}else{b}).unwrap_or(Obj::None); self.push(m)?; }
                OpCode::CallMax   => { let args = self.pop_n(op as usize)?; let m = args.into_iter().reduce(|a,b| if Self::lt_vals(&b,&a).unwrap_or(false){a}else{b}).unwrap_or(Obj::None); self.push(m)?; }
                OpCode::CallSum => {
                    let args = self.pop_n(op as usize)?;
                    if args.is_empty() { return Err(VmErr::Type("sum expected at least 1 arg".into())); }
                    let mut acc = args.get(1).cloned().unwrap_or(Obj::Int(0));
                    match &args[0] {
                        Obj::List(v) => { for item in v.borrow().iter() { acc = Self::add_vals(acc, item.clone())?; } },
                        Obj::Tuple(v) => { for item in v { acc = Self::add_vals(acc, item.clone())?; } },
                        _ => return Err(VmErr::Type("object is not iterable".into())),
                    }
                    self.push(acc)?;
                }
                OpCode::CallSorted => {
                    let o = self.pop()?;
                    let mut v = match o { 
                        Obj::List(l) => l.borrow().clone(), 
                        Obj::Tuple(t) => t.clone(), 
                        _=>return Err(VmErr::Type("sorted()".into())) 
                    };
                    v.sort_by(|a,b| match Self::lt_vals(a,b) { Ok(true)=>core::cmp::Ordering::Less, _ => match Self::lt_vals(b,a) { Ok(true)=>core::cmp::Ordering::Greater, _=>core::cmp::Ordering::Equal } });
                    self.push(Obj::List(Rc::new(RefCell::new(v))))?;
                }
                OpCode::CallList => {
                    let o = self.pop()?;
                    let result = match o {
                        Obj::List(v)  => Obj::List(Rc::new(RefCell::new(v.borrow().clone()))),
                        Obj::Tuple(v) => Obj::List(Rc::new(RefCell::new(v.clone()))),
                        Obj::Range(s, e, st) => {
                            self.pool.alloc()?;
                            let mut v = Vec::new();
                            let mut i = s;
                            if st > 0 { while i < e { v.push(Obj::Int(i)); i += st; } }
                            else       { while i > e { v.push(Obj::Int(i)); i += st; } }
                            Obj::List(Rc::new(RefCell::new(v)))
                        }
                        _ => return Err(VmErr::Type("list()".into())),
                    };
                    self.push(result)?;
                }
                OpCode::CallTuple => { 
                    let o = self.pop()?; 
                    self.push(match o { 
                        Obj::Tuple(v) => Obj::Tuple(v), 
                        Obj::List(v) => Obj::Tuple(v.borrow().clone()), 
                        _=>return Err(VmErr::Type("tuple()".into())) 
                    })?; 
                }
                OpCode::CallEnumerate => {
                    let o = self.pop()?;
                    let v = match o { 
                        Obj::List(l) => l.borrow().clone(), 
                        Obj::Tuple(t) => t.clone(), 
                        _=>return Err(VmErr::Type("enumerate()".into())) 
                    };
                    let pairs = v.into_iter().enumerate().map(|(i,x)| Obj::Tuple(vec![Obj::Int(i as i64), x])).collect();
                    self.push(Obj::List(Rc::new(RefCell::new(pairs))))?;
                }
                OpCode::CallZip => {
                    let b = self.pop()?; let a = self.pop()?;
                    let va = match a { Obj::List(l) => l.borrow().clone(), Obj::Tuple(t) => t.clone(), _=>return Err(VmErr::Type("zip()".into())) };
                    let vb = match b { Obj::List(l) => l.borrow().clone(), Obj::Tuple(t) => t.clone(), _=>return Err(VmErr::Type("zip()".into())) };
                    let pairs = va.into_iter().zip(vb).map(|(x,y)| Obj::Tuple(vec![x,y])).collect();
                    self.push(Obj::List(Rc::new(RefCell::new(pairs))))?;
                }

                // ── In / Is ───────────────────────────────────────────

                OpCode::In    => { let (a,b) = self.pop2()?; self.push(Obj::Bool(Self::contains(&b, &a)))?; }
                OpCode::NotIn => { let (a,b) = self.pop2()?; self.push(Obj::Bool(!Self::contains(&b, &a)))?; }
                OpCode::Is    => { let (a,b) = self.pop2()?; self.push(Obj::Bool(Self::is_same(&a, &b)))?; }
                OpCode::IsNot => { let (a,b) = self.pop2()?; self.push(Obj::Bool(!Self::is_same(&a, &b)))?; }

                // ── Stubs — mover a la sección correspondiente al implementar ──

                OpCode::Global | OpCode::Nonlocal | OpCode::Del | OpCode::Assert
                | OpCode::Import | OpCode::ImportFrom | OpCode::UnpackArgs | OpCode::UnpackEx
                | OpCode::SetupExcept | OpCode::PopExcept | OpCode::Raise | OpCode::RaiseFrom
                | OpCode::SetupWith | OpCode::ExitWith | OpCode::Yield | OpCode::YieldFrom
                | OpCode::Await | OpCode::TypeAlias | OpCode::MakeClass
                | OpCode::LoadAttr | OpCode::StoreAttr
                | OpCode::BuildSlice | OpCode::BuildSet | OpCode::UnpackSequence
                | OpCode::ListComp | OpCode::SetComp | OpCode::DictComp | OpCode::GenExpr
                | OpCode::CallDict | OpCode::CallSet | OpCode::CallInput | OpCode::CallIsInstance => {}
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Static helpers — sin &self para evitar conflictos de borrow
    // ═══════════════════════════════════════════════════════════

    fn add_vals(a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x),   Obj::Int(y))   => Obj::Int(x + y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x + y),
            (Obj::Int(x),   Obj::Float(y)) => Obj::Float(x as f64 + y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x + y as f64),
            (Obj::Str(x),   Obj::Str(y))   => Obj::Str(format!("{}{}", x, y)),
            (a, b) => return Err(VmErr::Type(format!("{} + {}", a.ty(), b.ty()))),
        })
    }
    fn sub_vals(a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x),   Obj::Int(y))   => Obj::Int(x - y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x - y),
            (Obj::Int(x),   Obj::Float(y)) => Obj::Float(x as f64 - y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x - y as f64),
            (a, b) => return Err(VmErr::Type(format!("{} - {}", a.ty(), b.ty()))),
        })
    }
    fn mul_vals(a: Obj, b: Obj) -> Result<Obj, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x),   Obj::Int(y))   => Obj::Int(x * y),
            (Obj::Float(x), Obj::Float(y)) => Obj::Float(x * y),
            (Obj::Int(x),   Obj::Float(y)) => Obj::Float(x as f64 * y),
            (Obj::Float(x), Obj::Int(y))   => Obj::Float(x * y as f64),
            (Obj::Str(s),   Obj::Int(n))   => Obj::Str(s.repeat(n.max(0) as usize)),
            (a, b) => return Err(VmErr::Type(format!("{} * {}", a.ty(), b.ty()))),
        })
    }
    fn div_vals(a: Obj, b: Obj) -> Result<Obj, VmErr> {
        let bv = match &b { Obj::Int(i) => *i as f64, Obj::Float(f) => *f, _ => return Err(VmErr::Type("div".into())) };
        if bv == 0.0 { return Err(VmErr::ZeroDiv); }
        let av = match &a { Obj::Int(i) => *i as f64, Obj::Float(f) => *f, _ => return Err(VmErr::Type("div".into())) };
        Ok(Obj::Float(av / bv))
    }
    fn eq_vals(a: &Obj, b: &Obj) -> bool {
        match (a, b) {
            (Obj::Int(x),   Obj::Int(y))   => x == y,
            (Obj::Float(x), Obj::Float(y)) => x == y,
            (Obj::Int(x),   Obj::Float(y)) => (*x as f64) == *y,
            (Obj::Float(x), Obj::Int(y))   => *x == (*y as f64),
            (Obj::Str(x),   Obj::Str(y))   => x == y,
            (Obj::Bool(x),  Obj::Bool(y))  => x == y,
            (Obj::None,     Obj::None)     => true,
            _ => false,
        }
    }
    fn lt_vals(a: &Obj, b: &Obj) -> Result<bool, VmErr> {
        Ok(match (a, b) {
            (Obj::Int(x),   Obj::Int(y))   => x < y,
            (Obj::Float(x), Obj::Float(y)) => x < y,
            (Obj::Int(x),   Obj::Float(y)) => (*x as f64) < *y,
            (Obj::Float(x), Obj::Int(y))   => *x < (*y as f64),
            (Obj::Str(x),   Obj::Str(y))   => x < y,
            _ => return Err(VmErr::Type(format!("'<' {} and {}", a.ty(), b.ty()))),
        })
    }
    fn getitem_val(obj: &Obj, idx: &Obj) -> Result<Obj, VmErr> {
        match (obj, idx) {
            (Obj::List(v), Obj::Int(i)) => {
                let b = v.borrow();
                let idx = if *i < 0 { b.len() as i64 + *i } else { *i } as usize;
                b.get(idx).cloned().ok_or(VmErr::Value("index out of range".into()))
            }
            (Obj::Tuple(v), Obj::Int(i)) => {
                let idx = if *i < 0 { v.len() as i64 + *i } else { *i } as usize;
                v.get(idx).cloned().ok_or(VmErr::Value("index out of range".into()))
            }
            (Obj::Dict(p), key) => p.borrow().iter().find(|(k, _)| Self::eq_vals(k, key)).map(|(_, v)| v.clone()).ok_or(VmErr::Value("key not found".into())),
            (Obj::Str(s), Obj::Int(i)) => {
                let idx = if *i < 0 { s.len() as i64 + *i } else { *i } as usize;
                s.chars().nth(idx).map(|c| Obj::Str(c.to_string())).ok_or(VmErr::Value("string index out of range".into()))
            }
            _ => Err(VmErr::Type(format!("{}[{}]", obj.ty(), idx.ty()))),
        }
    }

    fn contains(container: &Obj, item: &Obj) -> bool {
        match container {
            Obj::List(v) => v.borrow().iter().any(|x| Self::eq_vals(x, item)),
            Obj::Tuple(v) => v.iter().any(|x| Self::eq_vals(x, item)),
            Obj::Str(s) => if let Obj::Str(sub) = item { s.contains(sub.as_str()) } else { false },
            Obj::Dict(p) => p.borrow().iter().any(|(k, _)| Self::eq_vals(k, item)),
            _ => false,
        }
    }
    fn is_same(a: &Obj, b: &Obj) -> bool {
        matches!((a, b),
            (Obj::None, Obj::None) |
            (Obj::Bool(true),  Obj::Bool(true)) |
            (Obj::Bool(false), Obj::Bool(false))
        )
    }
}