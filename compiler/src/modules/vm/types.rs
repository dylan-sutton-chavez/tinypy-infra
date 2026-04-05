// vm/types.rs

use alloc::{string::{String, ToString}, vec::Vec, format, rc::Rc};
use core::{fmt, cell::RefCell};

/*
Sandbox Limits
    Configurable call depth, operation budget and heap quota per execution.
*/

pub struct Limits { pub calls: usize, pub ops: usize, pub heap: usize }
impl Limits {
    pub fn none() -> Self { Self { calls: usize::MAX, ops: usize::MAX, heap: usize::MAX } }
    pub fn sandbox() -> Self { Self { calls: 512, ops: 100_000_000, heap: 100_000 } }
}

/*
Val
    NaN-boxed 8-byte value: int, float, bool, None or heap index inline.
*/

const QNAN: u64 = 0x7FFC_0000_0000_0000;
const SIGN: u64 = 0x8000_0000_0000_0000;
const TAG_NONE: u64 = QNAN | 1;
const TAG_TRUE: u64 = QNAN | 2;
const TAG_FALSE: u64 = QNAN | 3;
const TAG_INT: u64 = QNAN | SIGN;
const TAG_HEAP: u64 = QNAN | 4;

#[derive(Clone, Copy, Debug)]
pub struct Val(pub(crate) u64);

impl PartialEq for Val {
    #[inline] fn eq(&self, o: &Self) -> bool { self.0 == o.0 }
}

impl Val {
    #[inline(always)] pub fn float(f: f64) -> Self {
        let bits = f.to_bits();
        if (bits & QNAN) == QNAN { Self(QNAN) } else { Self(bits) }
    }
    #[inline(always)] pub fn int(i: i64) -> Self {
        Self(TAG_INT | (i as u64 & 0x0000_FFFF_FFFF_FFFF))
    }
    #[inline(always)] pub fn none() -> Self { Self(TAG_NONE) }
    #[inline(always)] pub fn bool(b: bool) -> Self { Self(if b { TAG_TRUE } else { TAG_FALSE }) }
    #[inline(always)] pub fn heap(idx: u32) -> Self { Self(TAG_HEAP | ((idx as u64) << 4)) }

    #[inline(always)] pub fn is_float(&self) -> bool { (self.0 & QNAN) != QNAN }
    #[inline(always)] pub fn is_int(&self) -> bool { (self.0 & (QNAN | SIGN)) == TAG_INT }
    #[inline(always)] pub fn is_none(&self) -> bool { self.0 == TAG_NONE }
    #[inline(always)] pub fn is_true(&self) -> bool { self.0 == TAG_TRUE }
    #[inline(always)] pub fn is_false(&self) -> bool { self.0 == TAG_FALSE }
    #[inline(always)] pub fn is_bool(&self) -> bool { self.0 == TAG_TRUE || self.0 == TAG_FALSE }
    #[inline(always)] pub fn is_heap(&self) -> bool {
        (self.0 & QNAN) == QNAN && (self.0 & SIGN) == 0 && (self.0 & 0xF) >= 4
    }

    #[inline(always)] pub fn as_float(&self) -> f64  { f64::from_bits(self.0) }
    #[inline(always)] pub fn as_int(&self) -> i64  {
        let raw = (self.0 & 0x0000_FFFF_FFFF_FFFF) as i64;
        (raw << 16) >> 16
    }
    #[inline(always)] pub fn as_bool(&self) -> bool { self.0 == TAG_TRUE }
    #[inline(always)] pub fn as_heap(&self) -> u32 { ((self.0 >> 4) & 0x0FFF_FFFF) as u32 }
}

/*
Tag Classifier
    Compact numeric tag for InlineCache type specialization.
*/

#[inline(always)]
pub fn val_tag(v: &Val) -> u8 {
    if v.is_int() { 1 } else if v.is_float() { 2 } else if v.is_bool() { 3 }
    else if v.is_none() { 4 } else { 5 }
}

/*
Heap Objects
    Str, List, Dict, Set, Tuple, Func, Range and Slice stored in arena.
*/

#[derive(Clone, Debug)]
pub enum HeapObj {
    Str(String),
    List(Rc<RefCell<Vec<Val>>>),
    Dict(Rc<RefCell<Vec<(Val, Val)>>>),
    Set(Rc<RefCell<Vec<Val>>>),
    Tuple(Vec<Val>),
    Func(usize),
    Range(i64, i64, i64),
    Slice(Val, Val, Val),
}

/*
Heap Pool
    Indexed arena where Val::heap(idx) references allocated objects by slot.
*/

pub struct HeapPool {
    objects: Vec<HeapObj>,
    limit: usize,
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

/*
Runtime Errors
    CallDepth, Heap, Budget, Name, Type, Value, ZeroDiv and Runtime variants.
*/

#[derive(Debug)]
pub enum VmErr {
    CallDepth, Heap, Budget,
    Name(String), Type(String), Value(String),
    ZeroDiv, Runtime(String),
}

impl fmt::Display for VmErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallDepth => write!(f, "RecursionError: max depth"),
            Self::Heap => write!(f, "MemoryError: heap limit"),
            Self::Budget => write!(f, "RuntimeError: budget exceeded"),
            Self::Name(s) => write!(f, "NameError: '{}'", s),
            Self::Type(s) => write!(f, "TypeError: {}", s),
            Self::Value(s) => write!(f, "ValueError: {}", s),
            Self::ZeroDiv => write!(f, "ZeroDivisionError: division by zero"),
            Self::Runtime(s) => write!(f, "RuntimeError: {}", s),
        }
    }
}

/*
Iterator Frame
    Seq or Range state consumed one item at a time by ForIter dispatch.
*/

pub enum IterFrame {
    Seq { items: Vec<Val>, idx: usize },
    Range { cur: i64, end: i64, step: i64 },
}

impl IterFrame {
    pub fn next_item(&mut self) -> Option<Val> {
        match self {
            Self::Seq { items, idx } => {
                if *idx < items.len() { let v = items[*idx]; *idx += 1; Some(v) } else { None }
            }
            Self::Range { cur, end, step } => {
                let done = if *step > 0 { *cur >= *end } else { *cur <= *end };
                if done { None } else { let v = *cur; *cur += *step; Some(Val::int(v)) }
            }
        }
    }
}

/*
Math Helpers
    Pure f64 implementations of powi, round, powf for no_std and WASM builds.
*/

#[inline]
pub fn fpowi(mut base: f64, exp: i32) -> f64 {
    if exp == 0 { return 1.0; }
    let neg = exp < 0;
    let mut e = (exp as i64).unsigned_abs() as u32;
    let mut r = 1.0;
    while e > 0 { if e & 1 != 0 { r *= base; } base *= base; e >>= 1; }
    if neg { 1.0 / r } else { r }
}

#[inline]
pub fn fround(x: f64) -> f64 {
    let i = x as i64; let t = i as f64; let d = x - t;
    if d >= 0.5 { t + 1.0 } else if d <= -0.5 { t - 1.0 } else { t }
}

pub fn fln(x: f64) -> f64 {
    let bits = f64::to_bits(x);
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let m = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000);
    let t = (m - 1.0) / (m + 1.0); let t2 = t * t;
    2.0 * t * (1.0 + t2 * (1.0/3.0 + t2 * (1.0/5.0 + t2 * (1.0/7.0 + t2 / 9.0))))
        + exp as f64 * core::f64::consts::LN_2
}

pub fn fexp(x: f64) -> f64 {
    if x > 709.0 { return f64::INFINITY; }
    if x < -709.0 { return 0.0; }
    let k = (x * core::f64::consts::LOG2_E) as i64;
    let r = x - k as f64 * core::f64::consts::LN_2;
    let e = 1.0 + r * (1.0 + r * (0.5 + r * (1.0/6.0 + r * (1.0/24.0 + r * (1.0/120.0 + r / 720.0)))));
    f64::from_bits(((k + 1023) as u64) << 52) * e
}

#[inline]
pub fn fpowf(base: f64, exp: f64) -> f64 {
    let ei = exp as i32;
    if (ei as f64) == exp { return fpowi(base, ei); }
    if base <= 0.0 {
        if base == 0.0 { return if exp > 0.0 { 0.0 } else { f64::INFINITY }; }
        return f64::NAN;
    }
    fexp(exp * fln(base))
}