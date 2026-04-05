// vm/builtins.rs

use super::VM;
use super::types::*;
use alloc::{string::{String, ToString}, vec::Vec, vec, rc::Rc, format};
use core::cell::RefCell;

impl<'a> VM<'a> {

    /*
    Print Builtin
        Pops N args, joins with space, appends to output buffer.
    */

    pub fn call_print(&mut self, op: u16) -> Result<(), VmErr> {
        let mut args = self.pop_n(op as usize)?;
        args.reverse();
        let s = args.iter().map(|v| self.display(*v)).collect::<Vec<_>>().join(" ");
        self.output.push(s);
        Ok(())
    }

    /*
    Len Builtin
        Returns element count for strings, lists, tuples, dicts, sets, ranges.
    */

    pub fn call_len(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let n: i64 = if o.is_heap() { match self.heap.get(o) {
            HeapObj::Str(s) => s.chars().count() as i64,
            HeapObj::List(v) => v.borrow().len() as i64,
            HeapObj::Tuple(v) => v.len() as i64,
            HeapObj::Dict(v) => v.borrow().len() as i64,
            HeapObj::Set(v) => v.borrow().len() as i64,
            HeapObj::Range(s,e,st) => { let st=*st; ((e-s+st-st.signum())/st).max(0) }
            _ => return Err(VmErr::Type("len()".into())),
        }} else { return Err(VmErr::Type("len()".into())); };
        self.push(Val::int(n)); Ok(())
    }

    /*
    Abs Builtin
        Returns absolute value for int and float operands.
    */
    pub fn call_abs(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        if o.is_int() { self.push(Val::int(o.as_int().abs())); }
        else if o.is_float() { self.push(Val::float(o.as_float().abs())); }
        else { return Err(VmErr::Type("abs()".into())); }
        Ok(())
    }

    /*
    Str Builtin
        Converts any value to its string representation via display.
    */
    pub fn call_str(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?; let s = self.display(o);
        let v = self.heap.alloc(HeapObj::Str(s))?; self.push(v); Ok(())
    }

    /*
    Int Builtin
        Converts float, bool, or parseable string to integer.
    */
    pub fn call_int(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let i = if o.is_int() { o.as_int() }
            else if o.is_float() { o.as_float() as i64 }
            else if o.is_bool() { o.as_bool() as i64 }
            else if o.is_heap() { match self.heap.get(o) {
                HeapObj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("int: '{}'", s)))?,
                _ => return Err(VmErr::Type("int()".into())),
            }}
            else { return Err(VmErr::Type("int()".into())); };
        self.push(Val::int(i)); Ok(())
    }

    /*
    Float Builtin
        Converts int or parseable string to floating point.
    */
    pub fn call_float(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let f = if o.is_float()  { o.as_float() }
            else if o.is_int() { o.as_int() as f64 }
            else if o.is_heap() { match self.heap.get(o) {
                HeapObj::Str(s) => s.trim().parse().map_err(|_| VmErr::Value(format!("float: '{}'", s)))?,
                _ => return Err(VmErr::Type("float()".into())),
            }}
            else { return Err(VmErr::Type("float()".into())); };
        self.push(Val::float(f)); Ok(())
    }

    pub fn call_bool(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?; self.push(Val::bool(self.truthy(o))); Ok(())
    }

    pub fn call_type(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?; let s = self.type_name(o);
        let v = self.heap.alloc(HeapObj::Str(s.into()))?; self.push(v); Ok(())
    }

    pub fn call_chr(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        if !o.is_int() { return Err(VmErr::Type("chr()".into())); }
        let c = char::from_u32(o.as_int() as u32).ok_or(VmErr::Value("chr()".into()))?;
        let v = self.heap.alloc(HeapObj::Str(c.to_string()))?; self.push(v); Ok(())
    }

    pub fn call_ord(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        if o.is_heap() {
            if let HeapObj::Str(s) = self.heap.get(o) {
                let mut cs = s.chars();
                if let (Some(c), None) = (cs.next(), cs.next()) {
                    self.push(Val::int(c as i64)); return Ok(());
                }
            }
        }
        Err(VmErr::Type("ord() requires string of length 1".into()))
    }

    /*
    Range Builtin
        Creates lazy Range(start, end, step) with 1-3 int arguments.
    */
    pub fn call_range(&mut self, op: u16) -> Result<(), VmErr> {
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
        self.push(val); Ok(())
    }

    /*
    Round Builtin
        Rounds float to nearest int or to N decimal places.
    */
    pub fn call_round(&mut self, op: u16) -> Result<(), VmErr> {
        let args = self.pop_n(op as usize)?;
        let v = match (args.get(0), args.get(1)) {
            (Some(o), Some(n)) if o.is_float() && n.is_int() => {
                let factor = fpowi(10.0, n.as_int() as i32);
                Val::float(fround(o.as_float() * factor) / factor)
            }
            (Some(o), None) if o.is_float() => Val::int(fround(o.as_float()) as i64),
            (Some(o), _) if o.is_int() => *o,
            _ => return Err(VmErr::Type("round()".into())),
        };
        self.push(v); Ok(())
    }

    /*
    Min/Max Builtins
        Returns smallest or largest item from args or single iterable.
    */
    pub fn call_min(&mut self, op: u16) -> Result<(), VmErr> {
        let args = self.pop_n(op as usize)?;
        let items = self.unwrap_single_iterable(args)?;
        if items.is_empty() { return Err(VmErr::Type("min() arg is empty sequence".into())); }
        let mut m = items[0];
        for x in &items[1..] { if self.lt_vals(*x, m)? { m = *x; } }
        self.push(m); Ok(())
    }

    pub fn call_max(&mut self, op: u16) -> Result<(), VmErr> {
        let args = self.pop_n(op as usize)?;
        let items = self.unwrap_single_iterable(args)?;
        if items.is_empty() { return Err(VmErr::Type("max() arg is empty sequence".into())); }
        let mut m = items[0];
        for x in &items[1..] { if self.lt_vals(m, *x)? { m = *x; } }
        self.push(m); Ok(())
    }

    /*
    Sum Builtin
        Sums iterable elements with optional start value.
    */
    pub fn call_sum(&mut self, op: u16) -> Result<(), VmErr> {
        let args = self.pop_n(op as usize)?;
        if args.is_empty() { return Err(VmErr::Type("sum() requires at least 1 argument".into())); }
        let start = if args.len() > 1 { args[1] } else { Val::int(0) };
        let items = self.extract_iterable(args[0])?;
        let mut acc = start;
        for item in items { acc = self.add_vals(acc, item)?; }
        self.push(acc); Ok(())
    }

    /*
    Sorted Builtin
        Returns new sorted list from iterable via comparison.
    */
    pub fn call_sorted(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let mut items = self.extract_iterable(o)?;
        let mut sort_err: Option<VmErr> = None;
        items.sort_by(|&a, &b| {
            if sort_err.is_some() { return core::cmp::Ordering::Equal; }
            match self.lt_vals(a, b) {
                Ok(true) => core::cmp::Ordering::Less,
                Ok(false) => match self.lt_vals(b, a) {
                    Ok(true) => core::cmp::Ordering::Greater,
                    Ok(false) => core::cmp::Ordering::Equal,
                    Err(e) => { sort_err = Some(e); core::cmp::Ordering::Equal }
                },
                Err(e) => { sort_err = Some(e); core::cmp::Ordering::Equal }
            }
        });
        if let Some(e) = sort_err { return Err(e); }
        let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(items))))?;
        self.push(val); Ok(())
    }

    /*
    List/Tuple Builtins
        Converts iterable to list or tuple, materializing lazy ranges.
    */
    pub fn call_list(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let items = self.extract_iterable_full(o)?;
        let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(items))))?;
        self.push(val); Ok(())
    }

    pub fn call_tuple(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let items: Vec<Val> = if o.is_heap() { match self.heap.get(o) {
            HeapObj::Tuple(v) => v.clone(),
            HeapObj::List(v)  => v.borrow().clone(),
            _ => return Err(VmErr::Type("tuple()".into())),
        }} else { return Err(VmErr::Type("tuple()".into())); };
        let val = self.heap.alloc(HeapObj::Tuple(items))?;
        self.push(val); Ok(())
    }

    /*
    Enumerate Builtin
        Wraps iterable items as (index, value) tuple pairs.
    */
    pub fn call_enumerate(&mut self) -> Result<(), VmErr> {
        let o = self.pop()?;
        let src = self.extract_iterable(o)?;
        let mut pairs: Vec<Val> = Vec::with_capacity(src.len());
        for (i, x) in src.into_iter().enumerate() {
            let t = self.heap.alloc(HeapObj::Tuple(vec![Val::int(i as i64), x]))?;
            pairs.push(t);
        }
        let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(pairs))))?;
        self.push(val); Ok(())
    }

    /*
    Zip Builtin
        Pairs elements from two iterables into tuple list.
    */
    pub fn call_zip(&mut self) -> Result<(), VmErr> {
        let b_val = self.pop()?; let a_val = self.pop()?;
        let va = self.extract_iterable(a_val)?;
        let vb = self.extract_iterable(b_val)?;
        let mut pairs: Vec<Val> = Vec::with_capacity(va.len().min(vb.len()));
        for (x, y) in va.into_iter().zip(vb) {
            let t = self.heap.alloc(HeapObj::Tuple(vec![x, y]))?;
            pairs.push(t);
        }
        let val = self.heap.alloc(HeapObj::List(Rc::new(RefCell::new(pairs))))?;
        self.push(val); Ok(())
    }

    /*
    IsInstance Builtin
        Compares type_name string for sandbox-level type checking.
    */
    pub fn call_isinstance(&mut self) -> Result<(), VmErr> {
        let typ = self.pop()?; let obj = self.pop()?;
        let obj_ty = self.type_name(obj);
        let matches = if typ.is_heap() { match self.heap.get(typ) {
            HeapObj::Str(s) => s.as_str() == obj_ty,
            _ => false,
        }} else { false };
        self.push(Val::bool(matches)); Ok(())
    }

    /*
    Input Builtin
        Returns empty string in sandbox; no stdin access in WASM.
    */
    pub fn call_input(&mut self) -> Result<(), VmErr> {
        let val = self.heap.alloc(HeapObj::Str(String::new()))?;
        self.push(val); Ok(())
    }

    // ── Shared helpers ─────────────────────────────────────────

    /*
    Iterable Unwrap
        If single-arg is list/tuple, returns its items; otherwise returns args as-is.
    */
    fn unwrap_single_iterable(&self, args: Vec<Val>) -> Result<Vec<Val>, VmErr> {
        if args.len() == 1 && args[0].is_heap() {
            match self.heap.get(args[0]) {
                HeapObj::List(v) => return Ok(v.borrow().clone()),
                HeapObj::Tuple(v) => return Ok(v.clone()),
                _ => {}
            }
        }
        Ok(args)
    }

    /*
    Extract Iterable
        Extracts Vec<Val> from list, tuple, or set heap objects.
    */
    fn extract_iterable(&self, o: Val) -> Result<Vec<Val>, VmErr> {
        if !o.is_heap() { return Err(VmErr::Type("argument is not iterable".into())); }
        Ok(match self.heap.get(o) {
            HeapObj::List(v) => v.borrow().clone(),
            HeapObj::Tuple(v) => v.clone(),
            HeapObj::Set(v) => v.borrow().clone(),
            _ => return Err(VmErr::Type("argument is not iterable".into())),
        })
    }

    /*
    Extract Iterable Full
        Like extract_iterable but also materializes Range objects.
    */
    fn extract_iterable_full(&self, o: Val) -> Result<Vec<Val>, VmErr> {
        if !o.is_heap() { return Err(VmErr::Type("list()".into())); }
        Ok(match self.heap.get(o) {
            HeapObj::List(v) => v.borrow().clone(),
            HeapObj::Tuple(v) => v.clone(),
            HeapObj::Set(v) => v.borrow().clone(),
            HeapObj::Range(s, e, st) => {
                let (mut cur, end, step) = (*s, *e, *st);
                let mut v = Vec::new();
                if step > 0 { while cur < end { v.push(Val::int(cur)); cur += step; } }
                else { while cur > end { v.push(Val::int(cur)); cur += step; } }
                v
            }
            _ => return Err(VmErr::Type("list()".into())),
        })
    }
}