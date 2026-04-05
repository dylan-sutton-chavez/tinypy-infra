// vm/ops.rs

use super::types::*;
use alloc::{string::{String, ToString}, vec::Vec, format};

/*
Cache Binop Macro
    Pops two, records type pair in inline cache, promotes to adaptive overlay.
*/

macro_rules! cached_binop {
    ($rip:expr, $opcode:expr, $a:expr, $b:expr, $cache:expr, $adaptive:expr) => {{
        let ta = val_tag($a);
        let tb = val_tag($b);
        if let Some(f) = $cache.record($rip, $opcode, ta, tb) {
            if $adaptive.tick($rip) { $adaptive.rewrite($rip, f); }
        }
    }};
}
pub(crate) use cached_binop;

/*
Build Collection Macro
    Pops N stack items, wraps in Rc<RefCell<Vec>> heap object, pushes result.
*/

macro_rules! build_collection {
    ($vm:expr, $op:expr, $variant:ident) => {{
        let v = $vm.pop_n($op as usize)?;
        let val = $vm.heap.alloc(HeapObj::$variant(alloc::rc::Rc::new(core::cell::RefCell::new(v))))?;
        $vm.push(val);
    }};
}
pub(crate) use build_collection;

/*
VM Value Helpers
    All methods that need &self or &mut self access to HeapPool.
*/

use super::VM;

impl<'a> VM<'a> {
    pub fn truthy(&self, v: Val) -> bool {
        if v.is_none() || v.is_false() { return false; }
        if v.is_true() { return true; }
        if v.is_int() { return v.as_int() != 0; }
        if v.is_float() { return v.as_float() != 0.0; }
        match self.heap.get(v) {
            HeapObj::Str(s) => !s.is_empty(),
            HeapObj::List(l) => !l.borrow().is_empty(),
            HeapObj::Tuple(t) => !t.is_empty(),
            HeapObj::Dict(d) => !d.borrow().is_empty(),
            HeapObj::Set(s) => !s.borrow().is_empty(),
            HeapObj::Range(s,e,st) => if *st > 0 { s < e } else { s > e },
            HeapObj::Func(_) => true,
            HeapObj::Slice(..) => true,
        }
    }

    pub fn type_name(&self, v: Val) -> &'static str {
        if v.is_int() { "int" }
        else if v.is_float() { "float" }
        else if v.is_bool() { "bool" }
        else if v.is_none() { "NoneType" }
        else { match self.heap.get(v) {
            HeapObj::Str(_) => "str",
            HeapObj::List(_) => "list",
            HeapObj::Dict(_) => "dict",
            HeapObj::Set(_) => "set",
            HeapObj::Tuple(_) => "tuple",
            HeapObj::Func(_) => "function",
            HeapObj::Range(..) => "range",
            HeapObj::Slice(..) => "slice",
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
        if v.is_true() { return "True".into(); }
        if v.is_false() { return "False".into(); }
        if v.is_none() { return "None".into(); }
        match self.heap.get(v) {
            HeapObj::Str(s) => s.clone(),
            HeapObj::Func(i) => format!("<function {}>", i),
            HeapObj::Range(s,e,st) => if *st == 1 { format!("range({}, {})", s, e) } else { format!("range({}, {}, {})", s, e, st) },
            HeapObj::List(l) => format!("[{}]", l.borrow().iter().map(|x| self.repr(*x)).collect::<Vec<_>>().join(", ")),
            HeapObj::Tuple(t) => if t.len() == 1 { format!("({},)", self.repr(t[0])) } else { format!("({})", t.iter().map(|x| self.repr(*x)).collect::<Vec<_>>().join(", ")) },
            HeapObj::Dict(d) => format!("{{{}}}", d.borrow().iter()
                .map(|(k,v)| format!("{}: {}", self.repr(*k), self.repr(*v)))
                .collect::<Vec<_>>().join(", ")),
            HeapObj::Set(s) => format!("{{{}}}", s.borrow().iter()
                .map(|x| self.repr(*x)).collect::<Vec<_>>().join(", ")),
            HeapObj::Slice(s, e, st) => format!("slice({}, {}, {})",
                self.display(*s), self.display(*e), self.display(*st)),
        }
    }

    pub fn repr(&self, v: Val) -> String {
        if v.is_heap() { if let HeapObj::Str(s) = self.heap.get(v) { return format!("'{}'", s); } }
        self.display(v)
    }

    pub fn eq_vals(&self, a: Val, b: Val) -> bool {
        if a.is_int() && b.is_int() { return a.as_int() == b.as_int(); }
        if a.is_float() && b.is_float() { return a.as_float() == b.as_float(); }
        if a.is_int() && b.is_float() { return (a.as_int() as f64) == b.as_float(); }
        if a.is_float() && b.is_int() { return a.as_float() == (b.as_int() as f64); }
        if !a.is_heap() && !b.is_heap() { return a.0 == b.0; }
        if a.is_heap() && b.is_heap() {
            if let (HeapObj::Str(x), HeapObj::Str(y)) = (self.heap.get(a), self.heap.get(b)) {
                return x == y;
            }
        }
        false
    }

    pub fn lt_vals(&self, a: Val, b: Val) -> Result<bool, VmErr> {
        if a.is_int() && b.is_int() { return Ok(a.as_int() < b.as_int()); }
        if a.is_float() && b.is_float() { return Ok(a.as_float() < b.as_float()); }
        if a.is_int() && b.is_float() { return Ok((a.as_int() as f64) < b.as_float()); }
        if a.is_float() && b.is_int() { return Ok(a.as_float() < (b.as_int() as f64)); }
        if a.is_heap() && b.is_heap() {
            if let (HeapObj::Str(x), HeapObj::Str(y)) = (self.heap.get(a), self.heap.get(b)) {
                return Ok(x < y);
            }
        }
        Err(VmErr::Type(format!("'<' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    pub fn contains(&self, container: Val, item: Val) -> bool {
        if !container.is_heap() { return false; }
        match self.heap.get(container) {
            HeapObj::List(v) => v.borrow().iter().any(|x| self.eq_vals(*x, item)),
            HeapObj::Tuple(v) => v.iter().any(|x| self.eq_vals(*x, item)),
            HeapObj::Dict(p)  => p.borrow().iter().any(|(k, _)| self.eq_vals(*k, item)),
            HeapObj::Set(s) => s.borrow().iter().any(|x| self.eq_vals(*x, item)),
            HeapObj::Str(s) => {
                if item.is_heap() { if let HeapObj::Str(sub) = self.heap.get(item) { return s.contains(sub.as_str()); } }
                false
            }
            _ => false,
        }
    }

    pub fn add_vals(&mut self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int() && b.is_int() { return Ok(Val::int(a.as_int() + b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() + b.as_float())); }
        if a.is_int() && b.is_float() { return Ok(Val::float(a.as_int() as f64 + b.as_float())); }
        if a.is_float() && b.is_int() { return Ok(Val::float(a.as_float() + b.as_int() as f64)); }
        if a.is_heap() && b.is_heap() {
            if let (HeapObj::Str(sa), HeapObj::Str(sb)) = (self.heap.get(a), self.heap.get(b)) {
                let s = format!("{}{}", sa, sb);
                return self.heap.alloc(HeapObj::Str(s));
            }
        }
        Err(VmErr::Type(format!("'+' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    pub fn sub_vals(&self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int() && b.is_int() { return Ok(Val::int(a.as_int() - b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() - b.as_float())); }
        if a.is_int() && b.is_float() { return Ok(Val::float(a.as_int() as f64 - b.as_float())); }
        if a.is_float() && b.is_int() { return Ok(Val::float(a.as_float() - b.as_int() as f64)); }
        Err(VmErr::Type(format!("'-' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    pub fn mul_vals(&mut self, a: Val, b: Val) -> Result<Val, VmErr> {
        if a.is_int() && b.is_int() { return Ok(Val::int(a.as_int() * b.as_int())); }
        if a.is_float() && b.is_float() { return Ok(Val::float(a.as_float() * b.as_float())); }
        if a.is_int() && b.is_float() { return Ok(Val::float(a.as_int() as f64 * b.as_float())); }
        if a.is_float() && b.is_int() { return Ok(Val::float(a.as_float() * b.as_int() as f64)); }
        if a.is_heap() && b.is_int() {
            if let HeapObj::Str(s) = self.heap.get(a) {
                let r = s.repeat(b.as_int().max(0) as usize);
                return self.heap.alloc(HeapObj::Str(r));
            }
        }
        if a.is_int() && b.is_heap() {
            if let HeapObj::Str(s) = self.heap.get(b) {
                let r = s.repeat(a.as_int().max(0) as usize);
                return self.heap.alloc(HeapObj::Str(r));
            }
        }
        Err(VmErr::Type(format!("'*' not supported between '{}' and '{}'", self.type_name(a), self.type_name(b))))
    }

    pub fn div_vals(&self, a: Val, b: Val) -> Result<Val, VmErr> {
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