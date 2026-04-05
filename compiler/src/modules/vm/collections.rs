// vm/collections.rs

/*
Collection Operations
    BuildSet, BuildSlice, UnpackEx, CallDict, CallSet,
    GetItem with slice dispatch, and StoreItem mutations.
*/

use super::VM;
use super::types::*;
use alloc::{string::{String, ToString}, vec::Vec, vec, rc::Rc, format};
use core::cell::RefCell;

impl<'a> VM<'a> {

    /*
    BuildSet
        Pops N items, deduplicates preserving order, pushes HeapObj::Set.
    */
    pub fn build_set(&mut self, op: u16) -> Result<(), VmErr> {
        let items = self.pop_n(op as usize)?;
        let mut seen = Vec::with_capacity(items.len());
        for v in items {
            if !seen.iter().any(|s| self.eq_vals(*s, v)) { seen.push(v); }
        }
        let val = self.heap.alloc(HeapObj::Set(Rc::new(RefCell::new(seen))))?;
        self.push(val); Ok(())
    }

    /*
    BuildSlice
        Pops 2 or 3 items (start, stop, [step]), pushes HeapObj::Slice.
    */
    pub fn build_slice(&mut self, op: u16) -> Result<(), VmErr> {
        let step  = if op == 3 { self.pop()? } else { Val::none() };
        let stop  = self.pop()?;
        let start = self.pop()?;
        let val = self.heap.alloc(HeapObj::Slice(start, stop, step))?;
        self.push(val); Ok(())
    }

    /*
    UnpackEx
        Extended unpacking with star target: a, *b, c = iterable.
        Operand encodes (before << 8) | after for positional counts.
    */
    pub fn unpack_ex(&mut self, op: u16) -> Result<(), VmErr> {
        let obj = self.pop()?;
        if !obj.is_heap() { return Err(VmErr::Type("cannot unpack".into())); }
        let items: Vec<Val> = match self.heap.get(obj) {
            HeapObj::List(v)  => v.borrow().clone(),
            HeapObj::Tuple(v) => v.clone(),
            _ => return Err(VmErr::Type("cannot unpack".into())),
        };
        let before = (op >> 8) as usize;
        let after  = (op & 0xFF) as usize;
        if items.len() < before + after {
            return Err(VmErr::Value("not enough values to unpack".into()));
        }
        let mid = items.len() - after;
        for &v in items[mid..].iter().rev() { self.push(v); }
        let star = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(
            items[before..mid].to_vec()
        ))))?;
        self.push(star);
        for &v in items[..before].iter().rev() { self.push(v); }
        Ok(())
    }

    /*
    CallDict
        Constructs dict from keyword args or empty; operand = pair count.
    */
    pub fn call_dict(&mut self, op: u16) -> Result<(), VmErr> {
        if op == 0 {
            let val = self.heap.alloc(HeapObj::Dict(Rc::new(RefCell::new(Vec::new()))))?;
            self.push(val);
        } else {
            let args = self.pop_n((op as usize) * 2)?;
            let mut pairs = Vec::with_capacity(op as usize);
            for chunk in args.chunks(2) { pairs.push((chunk[0], chunk[1])); }
            let val = self.heap.alloc(HeapObj::Dict(Rc::new(RefCell::new(pairs))))?;
            self.push(val);
        }
        Ok(())
    }

    /*
    CallSet
        Constructs set from iterable arg or empty set.
    */
    pub fn call_set(&mut self, op: u16) -> Result<(), VmErr> {
        if op == 0 {
            let val = self.heap.alloc(HeapObj::Set(Rc::new(RefCell::new(Vec::new()))))?;
            self.push(val);
        } else {
            let o = self.pop()?;
            let src: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
                HeapObj::List(v)  => v.borrow().clone(),
                HeapObj::Tuple(v) => v.clone(),
                HeapObj::Set(v)   => v.borrow().clone(),
                _ => return Err(VmErr::Type("set()".into())),
            }} else { return Err(VmErr::Type("set()".into())); };
            let mut seen = Vec::with_capacity(src.len());
            for v in src {
                if !seen.iter().any(|s| self.eq_vals(*s, v)) { seen.push(v); }
            }
            let val = self.heap.alloc(HeapObj::Set(Rc::new(RefCell::new(seen))))?;
            self.push(val);
        }
        Ok(())
    }

    /*
    GetItem Dispatch
        Handles Str[int], Slice subscript, and delegates to getitem_val.
    */
    pub fn get_item(&mut self) -> Result<bool, VmErr> {
        let idx = self.pop()?;
        let obj = self.pop()?;

        // Slice dispatch
        if idx.is_heap() {
            if let HeapObj::Slice(start, stop, step) = self.heap.get(idx).clone() {
                let v = self.slice_val(obj, start, stop, step)?;
                self.push(v);
                return Ok(true);
            }
        }

        // Str[int] needs heap alloc
        if obj.is_heap() && idx.is_int() {
            if let HeapObj::Str(s) = self.heap.get(obj) {
                let i = idx.as_int();
                let len = s.chars().count() as i64;
                let ui  = (if i < 0 { len + i } else { i }) as usize;
                let c   = s.chars().nth(ui).ok_or(VmErr::Value("string index out of range".into()))?;
                let val = self.heap.alloc(HeapObj::Str(c.to_string()))?;
                self.push(val);
                return Ok(true);
            }
        }

        let v = self.getitem_val(obj, idx)?;
        self.push(v);
        Ok(false)
    }

    /*
    Slice Value
        Extracts sub-sequence from list, tuple, or string using start:stop:step.
    */
    fn slice_val(&mut self, obj: Val, start: Val, stop: Val, step: Val) -> Result<Val, VmErr> {
        if !obj.is_heap() { return Err(VmErr::Type("slice on non-sequence".into())); }
        let st = if step.is_none() { 1 } else if step.is_int() { step.as_int() } else {
            return Err(VmErr::Type("slice step must be int".into()));
        };
        if st == 0 { return Err(VmErr::Value("slice step cannot be zero".into())); }

        let len = match self.heap.get(obj) {
            HeapObj::List(v)  => v.borrow().len() as i64,
            HeapObj::Tuple(v) => v.len() as i64,
            HeapObj::Str(s)   => s.chars().count() as i64,
            _ => return Err(VmErr::Type("not sliceable".into())),
        };

        let clamp = |v: Val, def: i64| -> i64 {
            if v.is_none() { def }
            else if v.is_int() { let i = v.as_int(); if i < 0 { (len + i).max(0) } else { i.min(len) } }
            else { def }
        };
        let (s, e) = if st > 0 {
            (clamp(start, 0), clamp(stop, len))
        } else {
            (clamp(start, len - 1), clamp(stop, -1))
        };

        let mut indices = Vec::new();
        let mut cur = s;
        if st > 0 { while cur < e { indices.push(cur as usize); cur += st; } }
        else      { while cur > e { indices.push(cur as usize); cur += st; } }

        let result: Vec<Val> = match self.heap.get(obj) {
            HeapObj::List(v) => {
                let b = v.borrow();
                indices.iter().filter_map(|&i| b.get(i).copied()).collect()
            }
            HeapObj::Tuple(v) => {
                indices.iter().filter_map(|&i| v.get(i).copied()).collect()
            }
            HeapObj::Str(s) => {
                let chars: Vec<char> = s.chars().collect();
                let sliced: String = indices.iter().filter_map(|&i| chars.get(i)).collect();
                return self.heap.alloc(HeapObj::Str(sliced));
            }
            _ => return Err(VmErr::Type("slice".into())),
        };
        self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(result))))
    }

    /*
    GetItem Value
        Index dispatch for list[int], tuple[int], dict[key].
    */
    pub fn getitem_val(&self, obj: Val, idx: Val) -> Result<Val, VmErr> {
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
            _ => Err(VmErr::Type("subscript".into())),
        }
    }

    /*
    StoreItem
        Mutates list[int], dict[key], or rejects tuple assignment.
    */
    pub fn store_item(&mut self) -> Result<(), VmErr> {
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
                } else { b.push((idx_val, value)); }
            }
            HeapObj::Tuple(_) => return Err(VmErr::Type("'tuple' does not support item assignment".into())),
            _ => return Err(VmErr::Type("item assignment".into())),
        }
        Ok(())
    }
}