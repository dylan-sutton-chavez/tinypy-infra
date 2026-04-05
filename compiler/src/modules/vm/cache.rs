// vm/cache.rs

/*
Specialization Caches
    InlineCache for type-stable ops, Adaptive for hotspot rewriting,
    Templates for pure function memoization after threshold hits.
*/

use super::types::{Val, VmErr};
use crate::modules::parser::OpCode;
use alloc::{vec, vec::Vec};
use hashbrown::HashMap;

// ═══════════════════════════════════════════════════════════════
//  FastOp — specialized operation variants for inline cache
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
pub enum FastOp {
    AddInt, AddFloat, AddStr,
    SubInt, SubFloat,
    MulInt, MulFloat,
    LtInt,  LtFloat,
    EqInt,  EqStr,
}

// ═══════════════════════════════════════════════════════════════
//  InlineCache — per exec() frame, records type pairs per IP
// ═══════════════════════════════════════════════════════════════

const CACHE_THRESH: u8 = 8;

#[derive(Clone)]
struct Slot { hits: u8, ta: u8, tb: u8, fast: Option<FastOp> }
impl Slot { fn empty() -> Self { Self { hits: 0, ta: 0, tb: 0, fast: None } } }

pub struct InlineCache { slots: Vec<Slot> }

impl InlineCache {
    pub fn new(n: usize) -> Self { Self { slots: vec![Slot::empty(); n] } }

    pub fn record(&mut self, ip: usize, opcode: &OpCode, ta: u8, tb: u8) -> Option<FastOp> {
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

    pub fn get(&self, ip: usize) -> Option<FastOp> { self.slots.get(ip).and_then(|s| s.fast) }
    pub fn invalidate(&mut self, ip: usize) { if let Some(s) = self.slots.get_mut(ip) { *s = Slot::empty(); } }
    pub fn count(&self) -> usize { self.slots.iter().filter(|s| s.fast.is_some()).count() }
}

// ═══════════════════════════════════════════════════════════════
//  Templates — pure function result cache after threshold
// ═══════════════════════════════════════════════════════════════

const TPL_THRESH: u32 = 4;

struct TplEntry { args: Vec<Val>, result: Val, hits: u32 }

pub struct Templates { map: HashMap<usize, Vec<TplEntry>> }

impl Templates {
    pub fn new() -> Self { Self { map: HashMap::new() } }

    pub fn lookup(&self, fi: usize, args: &[Val]) -> Option<Val> {
        self.map.get(&fi)?.iter()
            .find(|e| e.hits >= TPL_THRESH && e.args.as_slice() == args)
            .map(|e| e.result)
    }

    pub fn record(&mut self, fi: usize, args: &[Val], result: Val) {
        let v = self.map.entry(fi).or_default();
        if let Some(e) = v.iter_mut().find(|e| e.args.as_slice() == args) {
            e.hits += 1; e.result = result;
        } else if v.len() < 256 {
            v.push(TplEntry { args: args.to_vec(), result, hits: 1 });
        }
    }

    pub fn count(&self) -> usize {
        self.map.values().flat_map(|v| v.iter()).filter(|e| e.hits >= TPL_THRESH).count()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Adaptive — hotspot rewriting, promotes cache hits to overlay
// ═══════════════════════════════════════════════════════════════

const HOT_THRESH: u32 = 1_000;

pub struct Adaptive { counts: Vec<u32>, overlay: Vec<Option<FastOp>> }

impl Adaptive {
    pub fn new(n: usize) -> Self { Self { counts: vec![0; n], overlay: vec![None; n] } }
    pub fn tick(&mut self, ip: usize) -> bool {
        if let Some(c) = self.counts.get_mut(ip) { *c += 1; *c == HOT_THRESH } else { false }
    }
    pub fn rewrite(&mut self, ip: usize, f: FastOp) {
        if let Some(s) = self.overlay.get_mut(ip) { *s = Some(f); }
    }
    pub fn get(&self, ip: usize) -> Option<FastOp> { self.overlay.get(ip).and_then(|o| *o) }
    pub fn deopt(&mut self, ip: usize) {
        if let Some(s) = self.overlay.get_mut(ip) { *s = None; }
        if let Some(c) = self.counts.get_mut(ip) { *c = 0; }
    }
    pub fn count(&self) -> usize { self.overlay.iter().filter(|o| o.is_some()).count() }
}