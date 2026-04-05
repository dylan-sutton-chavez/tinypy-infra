/*
 * `vm.rs`  Stack-based bytecode VM.
 *
 * Architecture:
 *   - Obj enum         : Tagged union replaces NaN-boxed Val; heap allocation is implicit via Rc.
 *   - Iterator stack   : ForIter never moves the collection; O(1) per iteration.
 *   - Lazy range       : range(N) does not materialize a Vec; zero allocations in loops.
 *   - Per-frame caches : InlineCache + Adaptive created per exec(); no depth guard needed.
 *   - Template memo    : pure functions memoized after 4 hits.
 *   - Dispatch match   : adding an opcode means writing one arm, nothing else.
 *   - Static helpers   : arithmetic as Self::fn() to avoid borrow conflicts with &mut self.
 *   - OWASP A04:2021   : Limits: call depth, op budget, heap quota.
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
//  Val — NaN-boxed value, 8 bytes, Copy, stack-allocated
//
//  IEEE 754 f64 layout:
//    S EEEEEEEEEEE FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
//    63 62......52 51..................................................0
//
//  Un quiet-NaN tiene exp=all-1 y bit-51=1. Usamos QNAN como máscara
//  base y metemos datos en los bits 0..50 + bit-63 (sign):
//
//    Float normal : (bits & QNAN) != QNAN
//    Int  (i48)   : bit63=1, bits62..51=QNAN_BITS  →  TAG_INT | (i & 0xFFFF_FFFF_FFFF)
//    None         : QNAN | 1
//    True         : QNAN | 2
//    False        : QNAN | 3
//    HeapIdx(u32) : QNAN | 4  (bits 0..31 = index)
// ═══════════════════════════════════════════════════════════════

const QNAN:      u64 = 0x7FFC_0000_0000_0000;
const SIGN:      u64 = 0x8000_0000_0000_0000;
const TAG_NONE:  u64 = QNAN | 1;
const TAG_TRUE:  u64 = QNAN | 2;
const TAG_FALSE: u64 = QNAN | 3;
const TAG_INT:   u64 = QNAN | SIGN;   // bit63=1 distingue int de heap
const TAG_HEAP:  u64 = QNAN | 4;      // bits 0..31 = índice HeapPool

#[derive(Clone, Copy, Debug)]
pub struct Val(u64);

impl PartialEq for Val {
    #[inline] fn eq(&self, o: &Self) -> bool { self.0 == o.0 }
}

impl Val {
    // ── Constructores ──────────────────────────────────────────

    #[inline(always)]
    pub fn float(f: f64) -> Self {
        let bits = f.to_bits();
        // Si el f64 ya es QNAN-shaped lo canonizamos para no colisionar con tags
        if (bits & QNAN) == QNAN { Self(QNAN) } else { Self(bits) }
    }

    #[inline(always)]
    pub fn int(i: i64) -> Self {
        // Guardamos 48 bits con signo. Rango: -140_737_488_355_328 .. 140_737_488_355_327
        Self(TAG_INT | (i as u64 & 0x0000_FFFF_FFFF_FFFF))
    }

    #[inline(always)] pub fn none()        -> Self { Self(TAG_NONE) }
    #[inline(always)] pub fn bool(b: bool) -> Self { Self(if b { TAG_TRUE } else { TAG_FALSE }) }
    #[inline(always)] pub fn heap(idx: u32)-> Self { Self(TAG_HEAP | ((idx as u64) << 4)) }

    // ── Inspectores — zero-cost, puras operaciones de bits ─────

    #[inline(always)] pub fn is_float(&self) -> bool { (self.0 & QNAN) != QNAN }
    #[inline(always)] pub fn is_int(&self)   -> bool { (self.0 & (QNAN | SIGN)) == TAG_INT }
    #[inline(always)] pub fn is_none(&self)  -> bool { self.0 == TAG_NONE }
    #[inline(always)] pub fn is_true(&self)  -> bool { self.0 == TAG_TRUE }
    #[inline(always)] pub fn is_false(&self) -> bool { self.0 == TAG_FALSE }
    #[inline(always)] pub fn is_bool(&self)  -> bool { self.0 == TAG_TRUE || self.0 == TAG_FALSE }
    #[inline(always)] pub fn is_heap(&self)  -> bool {
        (self.0 & QNAN) == QNAN && (self.0 & SIGN) == 0 && (self.0 & 0xF) >= 4
    }

    // ── Extractores ────────────────────────────────────────────

    #[inline(always)] pub fn as_float(&self) -> f64  { f64::from_bits(self.0) }
    #[inline(always)] pub fn as_int(&self)   -> i64  {
        let raw = (self.0 & 0x0000_FFFF_FFFF_FFFF) as i64;
        (raw << 16) >> 16   // sign-extend de 48 a 64 bits
    }
    #[inline(always)] pub fn as_bool(&self)  -> bool { self.0 == TAG_TRUE }
    #[inline(always)] pub fn as_heap(&self)  -> u32  { ((self.0 >> 4) & 0x0FFF_FFFF) as u32 }
}

// Tag numérico compacto para InlineCache (no necesita &HeapPool)
#[inline(always)]
fn val_tag(v: &Val) -> u8 {
    if v.is_int()   { 1 }
    else if v.is_float() { 2 }
    else if v.is_bool()  { 3 }
    else if v.is_none()  { 4 }
    else { 5 }  // heap — el cache trata todo heap igual; suficiente para Add/Lt/Eq
}

// ═══════════════════════════════════════════════════════════════
//  no_std math helpers (f64 methods like powi/powf/round need std)
// ═══════════════════════════════════════════════════════════════

#[inline]
fn fpowi(mut base: f64, exp: i32) -> f64 {
    if exp == 0 { return 1.0; }
    let neg = exp < 0;
    let mut e = (exp as i64).unsigned_abs() as u32;
    let mut r = 1.0;
    while e > 0 {
        if e & 1 != 0 { r *= base; }
        base *= base;
        e >>= 1;
    }
    if neg { 1.0 / r } else { r }
}

#[inline]
fn fround(x: f64) -> f64 {
    let i = x as i64;
    let t = i as f64;
    let d = x - t;
    if d >= 0.5 { t + 1.0 } else if d <= -0.5 { t - 1.0 } else { t }
}

fn fln(x: f64) -> f64 {
    let bits = f64::to_bits(x);
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let m = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    let t = (m - 1.0) / (m + 1.0);
    let t2 = t * t;
    2.0 * t * (1.0 + t2 * (1.0/3.0 + t2 * (1.0/5.0 + t2 * (1.0/7.0 + t2 / 9.0))))
        + exp as f64 * core::f64::consts::LN_2
}

fn fexp(x: f64) -> f64 {
    if x > 709.0 { return f64::INFINITY; }
    if x < -709.0 { return 0.0; }
    let k = (x * core::f64::consts::LOG2_E) as i64;
    let r = x - k as f64 * core::f64::consts::LN_2;
    let e = 1.0 + r * (1.0 + r * (0.5 + r * (1.0/6.0 + r * (1.0/24.0 + r * (1.0/120.0 + r / 720.0)))));
    f64::from_bits(((k + 1023) as u64) << 52) * e
}

#[inline]
fn fpowf(base: f64, exp: f64) -> f64 {
    let ei = exp as i32;
    if (ei as f64) == exp { return fpowi(base, ei); }
    if base <= 0.0 {
        if base == 0.0 { return if exp > 0.0 { 0.0 } else { f64::INFINITY }; }
        return f64::NAN;
    }
    fexp(exp * fln(base))
}

// ═══════════════════════════════════════════════════════════════
//  HeapObj — variantes que NO caben en 8 bytes
// ═══════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub enum HeapObj {
    Str(String),
    List(Rc<RefCell<Vec<Val>>>),
    Dict(Rc<RefCell<Vec<(Val, Val)>>>),
    Tuple(Vec<Val>),
    Func(usize),
    Range(i64, i64, i64),
}

// ═══════════════════════════════════════════════════════════════
//  HeapPool — arena indexada; Val::heap(idx) referencia un slot
// ═══════════════════════════════════════════════════════════════

pub struct HeapPool {
    objects: Vec<HeapObj>,
    limit:   usize,
}

impl HeapPool {
    pub fn new(limit: usize) -> Self { Self { objects: Vec::new(), limit } }

    pub fn alloc(&mut self, obj: HeapObj) -> Result<Val, VmErr> {
        if self.objects.len() >= self.limit { return Err(VmErr::Heap); }
        let idx = self.objects.len() as u32;
        self.objects.push(obj);
        Ok(Val::heap(idx))
    }

    #[inline(always)] pub fn get(&self, v: Val) -> &HeapObj {
        &self.objects[v.as_heap() as usize]
    }
    #[inline(always)] pub fn get_mut(&mut self, v: Val) -> &mut HeapObj {
        &mut self.objects[v.as_heap() as usize]
    }
    pub fn usage(&self) -> usize { self.objects.len() }
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
                    (OpCode::Add, 5, 5) => Some(FastOp::AddStr),   (OpCode::Sub, 1, 1) => Some(FastOp::SubInt),
                    (OpCode::Sub, 2, 2) => Some(FastOp::SubFloat), (OpCode::Mul, 1, 1) => Some(FastOp::MulInt),
                    (OpCode::Mul, 2, 2) => Some(FastOp::MulFloat), (OpCode::Lt,  1, 1) => Some(FastOp::LtInt),
                    (OpCode::Lt,  2, 2) => Some(FastOp::LtFloat),  (OpCode::Eq,  1, 1) => Some(FastOp::EqInt),
                    (OpCode::Eq,  5, 5) => Some(FastOp::EqStr),    _ => None,
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

struct TplEntry { args: Vec<Val>, result: Val, hits: u32 }
struct Templates { map: HashMap<usize, Vec<TplEntry>> }

impl Templates {
    fn new() -> Self { Self { map: HashMap::new() } }

    fn lookup(&self, fi: usize, args: &[Val]) -> Option<Val> {
        self.map.get(&fi)?.iter()
            .find(|e| e.hits >= TPL_THRESH && e.args.as_slice() == args)
            .map(|e| e.result)   // Val es Copy — sin clone
    }

    fn record(&mut self, fi: usize, args: &[Val], result: Val) {
        let v = self.map.entry(fi).or_default();
        if let Some(e) = v.iter_mut().find(|e| e.args.as_slice() == args) {
            e.hits += 1; e.result = result;
        } else if v.len() < 256 {
            v.push(TplEntry { args: args.to_vec(), result, hits: 1 });
        }
    }

    fn count(&self) -> usize {
        self.map.values().flat_map(|v| v.iter()).filter(|e| e.hits >= TPL_THRESH).count()
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
    fn count(&self) -> usize { self.overlay.iter().filter(|o| o.is_some()).count() }
}

// ═══════════════════════════════════════════════════════════════
//  Iterator frame
//
//  Seq:   Vec<Val> owned aquí, ForIter lee un item por índice.
//  Range: lazy i64 — range(1_000_000) usa O(1) memoria.
// ═══════════════════════════════════════════════════════════════

enum IterFrame {
    Seq   { items: Vec<Val>, idx: usize },
    Range { cur: i64, end: i64, step: i64 },
}

impl IterFrame {
    fn next_item(&mut self) -> Option<Val> {
        match self {
            Self::Seq { items, idx } => {
                if *idx < items.len() { let v = items[*idx]; *idx += 1; Some(v) } else { None }
                //                      ^^^^^ Val es Copy — cero clone
            }
            Self::Range { cur, end, step } => {
                let done = if *step > 0 { *cur >= *end } else { *cur <= *end };
                if done { None } else { let v = *cur; *cur += *step; Some(Val::int(v)) }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  VM
// ═══════════════════════════════════════════════════════════════

pub struct VM<'a> {
    stack:      Vec<Val>,       // 8 bytes/elem, Copy — sin heap-alloc en push/pop
    heap:       HeapPool,       // arena para Str/List/Dict/Tuple/Func/Range
    iter_stack: Vec<IterFrame>,
    yields:     Vec<Val>,
    chunk:      &'a SSAChunk,
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
            chunk,
            heap: HeapPool::new(limits.heap),
            templates: Templates::new(),
            yields: Vec::new(),
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

    // Stats
    pub fn heap_usage(&self)       -> usize           { self.heap.usage() }
    pub fn templates_cached(&self) -> usize           { self.templates.count() }
    pub fn cache_stats(&self)      -> (usize, usize)  { (self.templates.count(), self.chunk.instructions.len()) }

    // ── Stack helpers ──────────────────────────────────────────

    #[inline] fn push(&mut self, v: Val) { self.stack.push(v); }

    #[inline] fn pop(&mut self) -> Result<Val, VmErr> {
        self.stack.pop().ok_or_else(|| VmErr::Runtime("stack underflow".into()))
    }
    #[inline] fn pop2(&mut self) -> Result<(Val, Val), VmErr> {
        let b = self.pop()?; let a = self.pop()?; Ok((a, b))
    }
    #[inline] fn pop_n(&mut self, n: usize) -> Result<Vec<Val>, VmErr> {
        let at = self.stack.len().checked_sub(n)
            .ok_or_else(|| VmErr::Runtime("stack underflow".into()))?;
        Ok(self.stack.split_off(at))
    }

    fn to_val(&mut self, v: &Value) -> Result<Val, VmErr> {
        Ok(match v {
            Value::Int(i)   => Val::int(*i),
            Value::Float(f) => Val::float(*f),
            Value::Bool(b)  => Val::bool(*b),
            Value::None     => Val::none(),
            Value::Str(s)   => self.heap.alloc(HeapObj::Str(s.clone()))?,
        })
    }

    // ── Fast-path execution (inline cache / adaptive hits) ─────

    #[inline]
    fn exec_fast(&mut self, fast: FastOp) -> Result<bool, VmErr> {
        let (a, b) = self.pop2()?;
        let hit = match fast {
            FastOp::AddInt   if a.is_int()   && b.is_int()   => { self.push(Val::int(a.as_int() + b.as_int())); true }
            FastOp::AddFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() + b.as_float())); true }
            FastOp::SubInt   if a.is_int()   && b.is_int()   => { self.push(Val::int(a.as_int() - b.as_int())); true }
            FastOp::SubFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() - b.as_float())); true }
            FastOp::MulInt   if a.is_int()   && b.is_int()   => { self.push(Val::int(a.as_int() * b.as_int())); true }
            FastOp::MulFloat if a.is_float() && b.is_float() => { self.push(Val::float(a.as_float() * b.as_float())); true }
            FastOp::LtInt    if a.is_int()   && b.is_int()   => { self.push(Val::bool(a.as_int() < b.as_int())); true }
            FastOp::LtFloat  if a.is_float() && b.is_float() => { self.push(Val::bool(a.as_float() < b.as_float())); true }
            FastOp::EqInt    if a.is_int()   && b.is_int()   => { self.push(Val::bool(a.as_int() == b.as_int())); true }
            FastOp::AddStr | FastOp::EqStr => {
                if a.is_heap() && b.is_heap() {
                    let (sa, sb) = match (self.heap.get(a), self.heap.get(b)) {
                        (HeapObj::Str(x), HeapObj::Str(y)) => (x.clone(), y.clone()),
                        _ => { self.push(a); self.push(b); return Ok(false); }
                    };
                    match fast {
                        FastOp::AddStr => { let v = self.heap.alloc(HeapObj::Str(format!("{}{}", sa, sb)))?; self.push(v); }
                        _              => { self.push(Val::bool(sa == sb)); }
                    }
                    true
                } else { false }
            }
            _ => false,
        };
        if !hit { self.push(a); self.push(b); }
        Ok(hit)
    }

    // ── Main dispatch loop ─────────────────────────────────────
    //
    // AGREGAR UN OPCODE:
    //   1. Escribe el arm: OpCode::NuevoOp => { /* lógica */ }
    //   2. Muévelo de la sección "stubs" si ya existía ahí.
    //   Eso es todo. No tocas nada más.

    fn exec(&mut self, chunk: &SSAChunk, slots: &mut Vec<Option<Val>>) -> Result<Val, VmErr> {
        let n = chunk.instructions.len();

        // Box per-frame caches to shrink stack frame (~120 bytes saved per recursion)
        let mut cache    = Box::new(InlineCache::new(n));
        let mut adaptive = Box::new(Adaptive::new(n));
        let mut ip       = 0usize;
        let mut phi_idx  = 0usize;

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

        macro_rules! cache_binop {
            ($rip:expr, $opcode:expr, $a:expr, $b:expr) => {{
                let ta = val_tag($a);
                let tb = val_tag($b);
                if let Some(f) = cache.record($rip, $opcode, ta, tb) {
                    if adaptive.tick($rip) { adaptive.rewrite($rip, f); }
                }
            }};
        }

        loop {
            if ip >= n { return Ok(Val::none()); }

            // Adaptive → inline cache fast paths
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

                // ── Loads ─────────────────────────────────────────────

                OpCode::LoadConst => {
                    let v = self.to_val(&chunk.constants[op as usize])?;
                    self.push(v);
                }
                OpCode::LoadName => {
                    let slot = op as usize;
                    self.push(slots[slot].ok_or_else(|| VmErr::Name(chunk.names[slot].clone()))?);
                }
                OpCode::StoreName => {
                    let v = self.pop()?;
                    let slot = op as usize;
                    if let Some(prev) = prev_slots[slot] { slots[prev] = Some(v); }
                    slots[slot] = Some(v);
                }
                OpCode::LoadTrue     => self.push(Val::bool(true)),
                OpCode::LoadFalse    => self.push(Val::bool(false)),
                OpCode::LoadNone     => self.push(Val::none()),
                OpCode::LoadEllipsis => { let v = self.heap.alloc(HeapObj::Str("...".into()))?; self.push(v); }

                // ── StoreItem ──────────────────────────────────────────

                OpCode::StoreItem => {
                    let value   = self.pop()?;
                    let idx_val = self.pop()?;
                    let cont    = self.pop()?;
                    if !cont.is_heap() { return Err(VmErr::Type("item assignment on non-container".into())); }
                    match self.heap.get_mut(cont) {
                        HeapObj::List(v) => {
                            if !idx_val.is_int() { return Err(VmErr::Type("list index must be int".into())); }
                            let mut b = v.borrow_mut();
                            let i = idx_val.as_int();
                            let ui = if i < 0 { b.len() as i64 + i } else { i } as usize;
                            if ui >= b.len() { return Err(VmErr::Value("list assignment index out of range".into())); }
                            b[ui] = value;
                        }
                        HeapObj::Dict(p) => {
                            let mut b = p.borrow_mut();
                            if let Some(pos) = b.iter().position(|(k, _)| *k == idx_val) {
                                b[pos].1 = value;
                            } else {
                                b.push((idx_val, value));
                            }
                        }
                        HeapObj::Tuple(_) => return Err(VmErr::Type("'tuple' does not support item assignment".into())),
                        _ => return Err(VmErr::Type("item assignment".into())),
                    }
                }

                // ── Arithmetic (with inline cache + adaptive) ──────────

                OpCode::Add => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    let v = self.add_vals(a, b)?; self.push(v);
                }
                OpCode::Sub => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    let v = self.sub_vals(a, b)?; self.push(v);
                }
                OpCode::Mul => {
                    let (a, b) = self.pop2()?;
                    cache_binop!(rip, &ins.opcode, &a, &b);
                    let v = self.mul_vals(a, b)?; self.push(v);
                }
                OpCode::Div => {
                    let (a, b) = self.pop2()?;
                    let v = self.div_vals(a, b)?; self.push(v);
                }
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
                        (true, true, ..) => {
                            let exp = b.as_int();
                            if exp >= 0 { Val::int(a.as_int().pow(exp as u32)) }
                            else        { Val::float(fpowi(a.as_int() as f64, exp as i32)) }
                        }
                        (true,  _, _, true) => Val::float(fpowf(a.as_int() as f64, b.as_float())),
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
                    if      v.is_int()   { self.push(Val::int(-v.as_int())); }
                    else if v.is_float() { self.push(Val::float(-v.as_float())); }
                    else { return Err(VmErr::Type("unary -".into())); }
                }

                // ── Bitwise ───────────────────────────────────────────

                OpCode::BitAnd => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() & b.as_int())); }
                OpCode::BitOr  => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() | b.as_int())); }
                OpCode::BitXor => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() ^ b.as_int())); }
                OpCode::BitNot => { let v = self.pop()?; self.push(Val::int(!v.as_int())); }
                OpCode::Shl   => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() << (b.as_int() & 63))); }
                OpCode::Shr   => { let (a,b) = self.pop2()?; self.push(Val::int(a.as_int() >> (b.as_int() & 63))); }

                // ── Comparison (with cache) ────────────────────────────

                OpCode::Eq    => { let (a,b) = self.pop2()?; cache_binop!(rip,&ins.opcode,&a,&b); self.push(Val::bool(self.eq_vals(a,b))); }
                OpCode::NotEq => { let (a,b) = self.pop2()?; self.push(Val::bool(!self.eq_vals(a,b))); }
                OpCode::Lt    => { let (a,b) = self.pop2()?; cache_binop!(rip,&ins.opcode,&a,&b); let r=self.lt_vals(a,b)?; self.push(Val::bool(r)); }
                OpCode::Gt    => { let (a,b) = self.pop2()?; let r=self.lt_vals(b,a)?; self.push(Val::bool(r)); }
                OpCode::LtEq  => { let (a,b) = self.pop2()?; let r=self.lt_vals(b,a)?; self.push(Val::bool(!r)); }
                OpCode::GtEq  => { let (a,b) = self.pop2()?; let r=self.lt_vals(a,b)?; self.push(Val::bool(!r)); }

                // ── Logic ─────────────────────────────────────────────

                OpCode::And => { let (a,b) = self.pop2()?; self.push(if self.truthy(a) { b } else { a }); }
                OpCode::Or  => { let (a,b) = self.pop2()?; self.push(if self.truthy(a) { a } else { b }); }
                OpCode::Not => { let v = self.pop()?; self.push(Val::bool(!self.truthy(v))); }

                // ── Control flow ──────────────────────────────────────

                OpCode::JumpIfFalse => {
                    let v = self.pop()?;
                    if !self.truthy(v) {
                        if self.budget == 0 { return Err(VmErr::Budget); }
                        self.budget -= 1;
                        let target = op as usize;
                        if target > chunk.instructions.len() {
                            return Err(VmErr::Runtime("jump target out of bounds".into()));
                        }
                        ip = target;
                    }
                }
                OpCode::Jump => {
                    if self.budget == 0 { return Err(VmErr::Budget); }
                    self.budget -= 1;
                    let target = op as usize;
                    if target > chunk.instructions.len() {
                        return Err(VmErr::Runtime("jump target out of bounds".into()));
                    }
                    ip = target;
                }
                OpCode::PopTop      => { self.pop()?; }
                OpCode::ReturnValue => { return Ok(if self.stack.is_empty() { Val::none() } else { self.pop()? }); }
                OpCode::Yield => {
                    let v = self.pop()?;
                    self.yields.push(v);
                    self.push(Val::none());
                }

                // ── Collections ───────────────────────────────────────

                OpCode::BuildList => {
                    let v = self.pop_n(op as usize)?;
                    let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(v))))?;
                    self.push(val);
                }
                OpCode::BuildTuple => {
                    let v = self.pop_n(op as usize)?;
                    let val = self.heap.alloc(HeapObj::Tuple(v))?;
                    self.push(val);
                }
                OpCode::BuildDict => {
                    let mut p: Vec<(Val, Val)> = Vec::with_capacity(op as usize);
                    for _ in 0..op { let v = self.pop()?; let k = self.pop()?; p.push((k, v)); }
                    p.reverse();
                    let val = self.heap.alloc(HeapObj::Dict(Rc::new(RefCell::new(p))))?;
                    self.push(val);
                }
                OpCode::BuildString => {
                    let parts = self.pop_n(op as usize)?;
                    let s: String = parts.iter().map(|v| self.display(*v)).collect();
                    let val = self.heap.alloc(HeapObj::Str(s))?;
                    self.push(val);
                }
                OpCode::GetItem => {
                    let idx = self.pop()?; let obj = self.pop()?;
                    // Caso especial: Str[int] necesita alloc → manejado aquí
                    if obj.is_heap() && idx.is_int() {
                        if let HeapObj::Str(s) = self.heap.get(obj) {
                            let i = idx.as_int();
                            let len = s.chars().count() as i64;
                            let ui  = (if i < 0 { len + i } else { i }) as usize;
                            let c   = s.chars().nth(ui).ok_or(VmErr::Value("string index out of range".into()))?;
                            let val = self.heap.alloc(HeapObj::Str(c.to_string()))?;
                            self.push(val);
                            continue;
                        }
                    }
                    let v = self.getitem_val(obj, idx)?;
                    self.push(v);
                }
                OpCode::UnpackSequence => {
                    let obj      = self.pop()?;
                    let expected = op as usize;
                    if !obj.is_heap() { return Err(VmErr::Type("cannot unpack non-sequence".into())); }
                    let items: Vec<Val> = match self.heap.get(obj) {
                        HeapObj::List(v)  => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        HeapObj::Str(s)   => {
                            let chars: Vec<char> = s.chars().collect();
                            if chars.len() != expected {
                                return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, chars.len())));
                            }
                            // alloc fuera del borrow
                            let chars = chars; drop(s);
                            let mut out = Vec::with_capacity(chars.len());
                            for c in chars { out.push(self.heap.alloc(HeapObj::Str(c.to_string()))?); }
                            out
                        }
                        _ => return Err(VmErr::Type("unpack".into())),
                    };
                    if items.len() != expected {
                        return Err(VmErr::Value(format!("expected {} values to unpack, got {}", expected, items.len())));
                    }
                    for item in items.into_iter().rev() { self.push(item); }
                }
                OpCode::FormatValue => {
                    if op == 1 { self.pop()?; }
                    let v = self.pop()?;
                    let s = self.display(v);
                    let val = self.heap.alloc(HeapObj::Str(s))?;
                    self.push(val);
                }

                // ── Iterator stack ─────────────────────────────────────
                //
                // GetIter: mueve la colección a iter_stack — nunca se vuelve a mover.
                // ForIter: lee UN ítem por índice, sin mover la colección.

                OpCode::GetIter => {
                    let obj = self.pop()?;
                    if !obj.is_heap() { return Err(VmErr::Type("not iterable".into())); }
                    let frame = match self.heap.get(obj) {
                        HeapObj::Range(s, e, st) => IterFrame::Range { cur: *s, end: *e, step: *st },
                        HeapObj::List(v)  => IterFrame::Seq { items: v.borrow().clone(), idx: 0 },
                        HeapObj::Tuple(v) => IterFrame::Seq { items: v.clone(), idx: 0 },
                        HeapObj::Dict(p)  => IterFrame::Seq { items: p.borrow().iter().map(|(k, _)| *k).collect(), idx: 0 },
                        HeapObj::Str(s)   => {
                            let chars: Vec<char> = s.chars().collect();
                            drop(s); // liberar borrow antes de alloc
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
                            if target > chunk.instructions.len() {
                                return Err(VmErr::Runtime("for iter jump target out of bounds".into()));
                            }
                            ip = target;
                        }
                    }
                }

                // ── SSA Phi ───────────────────────────────────────────

                OpCode::Phi => {
                    let target = op as usize;
                    let (ia, ib) = chunk.phi_sources[phi_idx]; phi_idx += 1;
                    let val = slots[ia as usize].or(slots[ib as usize]).unwrap_or(Val::none());
                    slots[target] = Some(val);
                }

                // ── Functions ─────────────────────────────────────────

                OpCode::MakeFunction | OpCode::MakeCoroutine => {
                    let val = self.heap.alloc(HeapObj::Func(op as usize))?;
                    self.push(val);
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
                                    if let Some(&bs) = body_map.get(chunk.names[si].as_str()) {
                                        fn_slots[bs] = Some(*v);
                                    }
                                }
                            }
                        }
                    }
                    let name_idx = *fn_name;
                    if name_idx != u16::MAX {
                        let raw = &self.chunk.names[name_idx as usize];
                        // Strip any existing SSA version suffix (e.g. "fact_0" → "fact")
                        // before appending "_0", so we never double-version into "fact_0_0".
                        let base = raw.rfind('_')
                            .filter(|&p| raw[p+1..].parse::<u32>().is_ok())
                            .map(|p| &raw[..p])
                            .unwrap_or(raw.as_str());
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

                // ── Builtins ──────────────────────────────────────────

                OpCode::CallPrint => {
                    let mut args = self.pop_n(op as usize)?;
                    args.reverse();
                    let s = args.iter().map(|v| self.display(*v)).collect::<Vec<_>>().join(" ");
                    self.output.push(s);
                }
                OpCode::CallLen => {
                    let o = self.pop()?;
                    let n: i64 = if o.is_heap() { match self.heap.get(o) {
                        HeapObj::Str(s)    => s.chars().count() as i64,
                        HeapObj::List(v)   => v.borrow().len() as i64,
                        HeapObj::Tuple(v)  => v.len() as i64,
                        HeapObj::Dict(v)   => v.borrow().len() as i64,
                        HeapObj::Range(s,e,st) => { let st=*st; ((e-s+st-st.signum())/st).max(0) }
                        _ => return Err(VmErr::Type("len()".into())),
                    }} else { return Err(VmErr::Type("len()".into())); };
                    self.push(Val::int(n));
                }
                OpCode::CallAbs => {
                    let o = self.pop()?;
                    if      o.is_int()   { self.push(Val::int(o.as_int().abs())); }
                    else if o.is_float() { self.push(Val::float(o.as_float().abs())); }
                    else { return Err(VmErr::Type("abs()".into())); }
                }
                OpCode::CallStr => {
                    let o = self.pop()?; let s = self.display(o);
                    let v = self.heap.alloc(HeapObj::Str(s))?; self.push(v);
                }
                OpCode::CallInt => {
                    let o = self.pop()?;
                    let i = if o.is_int() { o.as_int() }
                        else if o.is_float() { o.as_float() as i64 }
                        else if o.is_bool()  { o.as_bool() as i64 }
                        else if o.is_heap() { match self.heap.get(o) {
                            HeapObj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("int: '{}'", s)))?,
                            _ => return Err(VmErr::Type("int()".into())),
                        }}
                        else { return Err(VmErr::Type("int()".into())); };
                    self.push(Val::int(i));
                }
                OpCode::CallFloat => {
                    let o = self.pop()?;
                    let f = if o.is_float()  { o.as_float() }
                        else if o.is_int()   { o.as_int() as f64 }
                        else if o.is_heap()  { match self.heap.get(o) {
                            HeapObj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("float: '{}'", s)))?,
                            _ => return Err(VmErr::Type("float()".into())),
                        }}
                        else { return Err(VmErr::Type("float()".into())); };
                    self.push(Val::float(f));
                }
                OpCode::CallBool  => { let o = self.pop()?; self.push(Val::bool(self.truthy(o))); }
                OpCode::CallType  => {
                    let o = self.pop()?; let s = self.type_name(o);
                    let v = self.heap.alloc(HeapObj::Str(s.into()))?; self.push(v);
                }
                OpCode::CallChr => {
                    let o = self.pop()?;
                    if !o.is_int() { return Err(VmErr::Type("chr()".into())); }
                    let c = char::from_u32(o.as_int() as u32).ok_or(VmErr::Value("chr()".into()))?;
                    let v = self.heap.alloc(HeapObj::Str(c.to_string()))?; self.push(v);
                }
                OpCode::CallOrd => {
                    let o = self.pop()?;
                    if o.is_heap() {
                        if let HeapObj::Str(s) = self.heap.get(o) {
                            let mut cs = s.chars();
                            if let (Some(c), None) = (cs.next(), cs.next()) {
                                self.push(Val::int(c as i64));
                                continue;
                            }
                        }
                    }
                    return Err(VmErr::Type("ord() requires string of length 1".into()));
                }
                OpCode::CallRange => {
                    let args = self.pop_n(op as usize)?;
                    let gi = |v: Val| -> Result<i64, VmErr> {
                        if v.is_int() { Ok(v.as_int()) } else { Err(VmErr::Type("range() args must be int".into())) }
                    };
                    let (s, e, st) = match args.len() {
                        1 => (0, gi(args[0])?, 1),
                        2 => (gi(args[0])?, gi(args[1])?, 1),
                        3 => (gi(args[0])?, gi(args[1])?, gi(args[2])?),
                        _ => return Err(VmErr::Type("range() takes 1-3 arguments".into())),
                    };
                    if st == 0 { return Err(VmErr::Value("range() step cannot be zero".into())); }
                    let val = self.heap.alloc(HeapObj::Range(s, e, st))?;
                    self.push(val);
                }
                OpCode::CallRound => {
                    let args = self.pop_n(op as usize)?;
                    let v = match (args.get(0), args.get(1)) {
                        (Some(o), Some(n)) if o.is_float() && n.is_int() => {
                            let factor = fpowi(10.0, n.as_int() as i32);
                            Val::float(fround(o.as_float() * factor) / factor)
                        }
                        (Some(o), None) if o.is_float() => Val::int(fround(o.as_float()) as i64),
                        (Some(o), _)    if o.is_int()   => *o,
                        _ => return Err(VmErr::Type("round()".into())),
                    };
                    self.push(v);
                }
                OpCode::CallMin => {
                    let args = self.pop_n(op as usize)?;
                    let items: Vec<Val> = if args.len() == 1 && args[0].is_heap() {
                        match self.heap.get(args[0]) {
                            HeapObj::List(v)  => v.borrow().clone(),
                            HeapObj::Tuple(v) => v.clone(),
                            _ => args,
                        }
                    } else { args };
                    if items.is_empty() { return Err(VmErr::Type("min() arg is empty sequence".into())); }
                    let mut m = items[0];
                    for x in &items[1..] { if self.lt_vals(*x, m)? { m = *x; } }
                    self.push(m);
                }
                OpCode::CallMax => {
                    let args = self.pop_n(op as usize)?;
                    let items: Vec<Val> = if args.len() == 1 && args[0].is_heap() {
                        match self.heap.get(args[0]) {
                            HeapObj::List(v)  => v.borrow().clone(),
                            HeapObj::Tuple(v) => v.clone(),
                            _ => args,
                        }
                    } else { args };
                    if items.is_empty() { return Err(VmErr::Type("max() arg is empty sequence".into())); }
                    let mut m = items[0];
                    for x in &items[1..] { if self.lt_vals(m, *x)? { m = *x; } }
                    self.push(m);
                }
                OpCode::CallSum => {
                    let args = self.pop_n(op as usize)?;
                    if args.is_empty() { return Err(VmErr::Type("sum() requires at least 1 argument".into())); }
                    let start = if args.len() > 1 { args[1] } else { Val::int(0) };
                    let items: Vec<Val> = if args[0].is_heap() { match self.heap.get(args[0]) {
                        HeapObj::List(v)  => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        _ => return Err(VmErr::Type("sum() argument is not iterable".into())),
                    }} else { return Err(VmErr::Type("sum() argument is not iterable".into())); };
                    let mut acc = start;
                    for item in items { acc = self.add_vals(acc, item)?; }
                    self.push(acc);
                }
                OpCode::CallSorted => {
                    let o = self.pop()?;
                    let mut items: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
                        HeapObj::List(v)  => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        _ => return Err(VmErr::Type("sorted() argument is not iterable".into())),
                    }} else { return Err(VmErr::Type("sorted() argument is not iterable".into())); };
                    let mut sort_err: Option<VmErr> = None;
                    items.sort_by(|&a, &b| {
                        if sort_err.is_some() { return core::cmp::Ordering::Equal; }
                        match self.lt_vals(a, b) {
                            Ok(true)  => core::cmp::Ordering::Less,
                            Ok(false) => match self.lt_vals(b, a) {
                                Ok(true)  => core::cmp::Ordering::Greater,
                                Ok(false) => core::cmp::Ordering::Equal,
                                Err(e)    => { sort_err = Some(e); core::cmp::Ordering::Equal }
                            },
                            Err(e) => { sort_err = Some(e); core::cmp::Ordering::Equal }
                        }
                    });
                    if let Some(e) = sort_err { return Err(e); }
                    let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(items))))?;
                    self.push(val);
                }
                OpCode::CallList => {
                    let o = self.pop()?;
                    let items: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
                        HeapObj::List(v)  => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        HeapObj::Range(s, e, st) => {
                            let (mut cur, end, step) = (*s, *e, *st);
                            let mut v = Vec::new();
                            if step > 0 { while cur < end { v.push(Val::int(cur)); cur += step; } }
                            else        { while cur > end { v.push(Val::int(cur)); cur += step; } }
                            v
                        }
                        _ => return Err(VmErr::Type("list()".into())),
                    }} else { return Err(VmErr::Type("list()".into())); };
                    let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(items))))?;
                    self.push(val);
                }
                OpCode::CallTuple => {
                    let o = self.pop()?;
                    let items: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
                        HeapObj::Tuple(v) => v.clone(),
                        HeapObj::List(v)  => v.borrow().clone(),
                        _ => return Err(VmErr::Type("tuple()".into())),
                    }} else { return Err(VmErr::Type("tuple()".into())); };
                    let val = self.heap.alloc(HeapObj::Tuple(items))?;
                    self.push(val);
                }
                OpCode::CallEnumerate => {
                    let o = self.pop()?;
                    let src: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
                        HeapObj::List(v)  => v.borrow().clone(),
                        HeapObj::Tuple(v) => v.clone(),
                        _ => return Err(VmErr::Type("enumerate()".into())),
                    }} else { return Err(VmErr::Type("enumerate()".into())); };
                    let mut pairs: Vec<Val> = Vec::with_capacity(src.len());
                    for (i, x) in src.into_iter().enumerate() {
                        let t = self.heap.alloc(HeapObj::Tuple(vec![Val::int(i as i64), x]))?;
                        pairs.push(t);
                    }
                    let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(pairs))))?;
                    self.push(val);
                }
                OpCode::CallZip => {
                    let b_val = self.pop()?; let a_val = self.pop()?;
                    let get_vec = |v: Val, hp: &HeapPool| -> Result<Vec<Val>, VmErr> {
                        if !v.is_heap() { return Err(VmErr::Type("zip()".into())); }
                        Ok(match hp.get(v) {
                            HeapObj::List(l)  => l.borrow().clone(),
                            HeapObj::Tuple(t) => t.clone(),
                            _ => return Err(VmErr::Type("zip()".into())),
                        })
                    };
                    let va = get_vec(a_val, &self.heap)?;
                    let vb = get_vec(b_val, &self.heap)?;
                    let mut pairs: Vec<Val> = Vec::with_capacity(va.len().min(vb.len()));
                    for (x, y) in va.into_iter().zip(vb) {
                        let t = self.heap.alloc(HeapObj::Tuple(vec![x, y]))?;
                        pairs.push(t);
                    }
                    let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(pairs))))?;
                    self.push(val);
                }

                // ── In / Is ───────────────────────────────────────────

                OpCode::In    => { let (a,b) = self.pop2()?; self.push(Val::bool( self.contains(b, a))); }
                OpCode::NotIn => { let (a,b) = self.pop2()?; self.push(Val::bool(!self.contains(b, a))); }
                // Is / IsNot: identidad de objeto — para Val inline es igualdad de bits,
                // para heap es mismo índice (misma referencia en el pool).
                OpCode::Is    => { let (a,b) = self.pop2()?; self.push(Val::bool(a.0 == b.0)); }
                OpCode::IsNot => { let (a,b) = self.pop2()?; self.push(Val::bool(a.0 != b.0)); }

                // ── Stubs — implementar cuando el parser los emita ─────

                OpCode::Assert => {
                    let v = self.pop()?;
                    if !self.truthy(v) { return Err(VmErr::Runtime("AssertionError".into())); }
                }
                OpCode::Del => {
                    let slot = op as usize;
                    if slot < slots.len() { slots[slot] = None; }
                }
                OpCode::CallIsInstance => {
                    let typ = self.pop()?; let obj = self.pop()?;
                    // Comparación por type_name string — suficiente para sandbox
                    let obj_ty = self.type_name(obj);
                    let matches = if typ.is_heap() { match self.heap.get(typ) {
                        HeapObj::Str(s) => s.as_str() == obj_ty,
                        _ => false,
                    }} else { false };
                    self.push(Val::bool(matches));
                }
                OpCode::CallInput => {
                    // En sandbox siempre retorna string vacío
                    let val = self.heap.alloc(HeapObj::Str(String::new()))?;
                    self.push(val);
                }

                OpCode::Global | OpCode::Nonlocal
                | OpCode::Import | OpCode::ImportFrom | OpCode::UnpackArgs | OpCode::UnpackEx
                | OpCode::SetupExcept | OpCode::PopExcept | OpCode::Raise | OpCode::RaiseFrom
                | OpCode::SetupWith | OpCode::ExitWith | OpCode::YieldFrom
                | OpCode::Await | OpCode::TypeAlias | OpCode::MakeClass
                | OpCode::LoadAttr | OpCode::StoreAttr
                | OpCode::BuildSlice | OpCode::BuildSet
                | OpCode::ListComp | OpCode::SetComp | OpCode::DictComp | OpCode::GenExpr
                | OpCode::CallDict | OpCode::CallSet => {}
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Helpers de valor — todos con acceso al HeapPool
    // ═══════════════════════════════════════════════════════════

    fn truthy(&self, v: Val) -> bool {
        if v.is_none() || v.is_false() { return false; }
        if v.is_true()  { return true; }
        if v.is_int()   { return v.as_int() != 0; }
        if v.is_float() { return v.as_float() != 0.0; }
        match self.heap.get(v) {
            HeapObj::Str(s)        => !s.is_empty(),
            HeapObj::List(l)       => !l.borrow().is_empty(),
            HeapObj::Tuple(t)      => !t.is_empty(),
            HeapObj::Dict(d)       => !d.borrow().is_empty(),
            HeapObj::Range(s,e,st) => if *st > 0 { s < e } else { s > e },
            HeapObj::Func(_)       => true,
        }
    }

    fn type_name(&self, v: Val) -> &'static str {
        if v.is_int()   { "int" }
        else if v.is_float() { "float" }
        else if v.is_bool()  { "bool" }
        else if v.is_none()  { "NoneType" }
        else { match self.heap.get(v) {
            HeapObj::Str(_)    => "str",
            HeapObj::List(_)   => "list",
            HeapObj::Dict(_)   => "dict",
            HeapObj::Tuple(_)  => "tuple",
            HeapObj::Func(_)   => "function",
            HeapObj::Range(..) => "range",
        }}
    }

    pub fn display(&self, v: Val) -> String {
        if v.is_int() {
            let mut b = itoa::Buffer::new(); return b.format(v.as_int()).into();
        }
        if v.is_float() {
            let f = v.as_float();
            if f.is_finite() && f == (f as i64) as f64 {
                let mut b = itoa::Buffer::new();
                let mut s = String::new(); s.push_str(b.format(f as i64)); s.push_str(".0"); return s;
            }
            let mut b = ryu::Buffer::new(); return b.format(f).into();
        }
        if v.is_true()  { return "True".into(); }
        if v.is_false() { return "False".into(); }
        if v.is_none()  { return "None".into(); }
        match self.heap.get(v) {
            HeapObj::Str(s)   => s.clone(),
            HeapObj::Func(i)  => format!("<function {}>", i),
            HeapObj::Range(s,e,st) => if *st == 1 { format!("range({}, {})", s, e) }
                                       else        { format!("range({}, {}, {})", s, e, st) },
            HeapObj::List(l)  => format!("[{}]", l.borrow().iter().map(|x| self.repr(*x)).collect::<Vec<_>>().join(", ")),
            HeapObj::Tuple(t) => if t.len() == 1 { format!("({},)", self.repr(t[0])) }
                                 else { format!("({})", t.iter().map(|x| self.repr(*x)).collect::<Vec<_>>().join(", ")) },
            HeapObj::Dict(d)  => format!("{{{}}}", d.borrow().iter()
                .map(|(k,v)| format!("{}: {}", self.repr(*k), self.repr(*v)))
                .collect::<Vec<_>>().join(", ")),
        }
    }

    fn repr(&self, v: Val) -> String {
        if v.is_heap() { if let HeapObj::Str(s) = self.heap.get(v) { return format!("'{}'", s); } }
        self.display(v)
    }

    fn eq_vals(&self, a: Val, b: Val) -> bool {
        // Fast path inline: comparación pura de bits para int/float/bool/none
        if a.is_int() && b.is_int()     { return a.as_int() == b.as_int(); }
        if a.is_float() && b.is_float() { return a.as_float() == b.as_float(); }
        if a.is_int() && b.is_float()   { return (a.as_int() as f64) == b.as_float(); }
        if a.is_float() && b.is_int()   { return a.as_float() == (b.as_int() as f64); }
        if !a.is_heap() && !b.is_heap() { return a.0 == b.0; }  // bool/none
        if a.is_heap() && b.is_heap() {
            if let (HeapObj::Str(x), HeapObj::Str(y)) = (self.heap.get(a), self.heap.get(b)) {
                return x == y;
            }
        }
        false
    }

    fn lt_vals(&self, a: Val, b: Val) -> Result<bool, VmErr> {
        if a.is_int() && b.is_int()     { return Ok(a.as_int() < b.as_int()); }
        if a.is_float() && b.is_float() { return Ok(a.as_float() < b.as_float()); }
        if a.is_int() && b.is_float()   { return Ok((a.as_int() as f64) < b.as_float()); }
        if a.is_float() && b.is_int()   { return Ok(a.as_float() < (b.as_int() as f64)); }
        if a.is_heap() && b.is_heap() {
            if let (HeapObj::Str(x), HeapObj::Str(y)) = (self.heap.get(a), self.heap.get(b)) {
                return Ok(x < y);
            }
        }
        Err(VmErr::Type(format!("'<' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    fn getitem_val(&self, obj: Val, idx: Val) -> Result<Val, VmErr> {
        if !obj.is_heap() { return Err(VmErr::Type("subscript on non-container".into())); }
        match self.heap.get(obj) {
            HeapObj::List(v) => {
                if !idx.is_int() { return Err(VmErr::Type("list indices must be integers".into())); }
                let b = v.borrow(); let i = idx.as_int();
                let ui = if i < 0 { b.len() as i64 + i } else { i } as usize;
                b.get(ui).copied().ok_or(VmErr::Value("list index out of range".into()))
            }
            HeapObj::Tuple(v) => {
                if !idx.is_int() { return Err(VmErr::Type("tuple indices must be integers".into())); }
                let i = idx.as_int();
                let ui = if i < 0 { v.len() as i64 + i } else { i } as usize;
                v.get(ui).copied().ok_or(VmErr::Value("tuple index out of range".into()))
            }
            HeapObj::Dict(p) => {
                p.borrow().iter().find(|(k, _)| self.eq_vals(*k, idx))
                    .map(|(_, v)| *v)
                    .ok_or(VmErr::Value("key not found".into()))
            }
            // Str[int] se maneja en el opcode GetItem directamente (necesita alloc)
            _ => Err(VmErr::Type("subscript".into())),
        }
    }

    fn contains(&self, container: Val, item: Val) -> bool {
        if !container.is_heap() { return false; }
        match self.heap.get(container) {
            HeapObj::List(v)  => v.borrow().iter().any(|x| self.eq_vals(*x, item)),
            HeapObj::Tuple(v) => v.iter().any(|x| self.eq_vals(*x, item)),
            HeapObj::Dict(p)  => p.borrow().iter().any(|(k, _)| self.eq_vals(*k, item)),
            HeapObj::Str(s)   => {
                if item.is_heap() { if let HeapObj::Str(sub) = self.heap.get(item) { return s.contains(sub.as_str()); } }
                false
            }
            _ => false,
        }
    }

    fn add_vals(&mut self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int()   && b.is_int()   { return Ok(Val::int(a.as_int() + b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() + b.as_float())); }
        if a.is_int()   && b.is_float() { return Ok(Val::float(a.as_int() as f64 + b.as_float())); }
        if a.is_float() && b.is_int()   { return Ok(Val::float(a.as_float() + b.as_int() as f64)); }
        if a.is_heap()  && b.is_heap()  {
            if let (HeapObj::Str(sa), HeapObj::Str(sb)) = (self.heap.get(a), self.heap.get(b)) {
                let s = format!("{}{}", sa, sb);
                return self.heap.alloc(HeapObj::Str(s));
            }
        }
        Err(VmErr::Type(format!("'+' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    fn sub_vals(&self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int()   && b.is_int()   { return Ok(Val::int(a.as_int() - b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() - b.as_float())); }
        if a.is_int()   && b.is_float() { return Ok(Val::float(a.as_int() as f64 - b.as_float())); }
        if a.is_float() && b.is_int()   { return Ok(Val::float(a.as_float() - b.as_int() as f64)); }
        Err(VmErr::Type(format!("'-' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    fn mul_vals(&mut self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int()   && b.is_int()   { return Ok(Val::int(a.as_int() * b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() * b.as_float())); }
        if a.is_int()   && b.is_float() { return Ok(Val::float(a.as_int() as f64 * b.as_float())); }
        if a.is_float() && b.is_int()   { return Ok(Val::float(a.as_float() * b.as_int() as f64)); }
        // str * int
        if a.is_heap() && b.is_int() {
            if let HeapObj::Str(s) = self.heap.get(a) {
                let repeated = s.repeat(b.as_int().max(0) as usize);
                return self.heap.alloc(HeapObj::Str(repeated));
            }
        }
        // int * str
        if a.is_int() && b.is_heap() {
            if let HeapObj::Str(s) = self.heap.get(b) {
                let repeated = s.repeat(a.as_int().max(0) as usize);
                return self.heap.alloc(HeapObj::Str(repeated));
            }
        }
        Err(VmErr::Type(format!("'*' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    fn div_vals(&self, a: Val, b: Val) -> Result<Val, VmErr> {
        let bv = if b.is_int() { b.as_int() as f64 }
            else if b.is_float() { b.as_float() }
            else { return Err(VmErr::Type("'/' requires numeric operands".into())); };
        if bv == 0.0 { return Err(VmErr::ZeroDiv); }
        let av = if a.is_int() { a.as_int() as f64 }
            else if a.is_float() { a.as_float() }
            else { return Err(VmErr::Type("'/' requires numeric operands".into())); };
        Ok(Val::float(av / bv))
    }
}