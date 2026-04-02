use crate::modules::{lexer::lexer, parser::Parser, vm::{VM, Limits}};

#[cfg(target_arch = "wasm32")]
mod runtime {
    use lol_alloc::LeakingPageAllocator;
    use super::{lexer, Parser, VM, Limits};

    #[global_allocator]
    static A: LeakingPageAllocator = LeakingPageAllocator;

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! { core::arch::wasm32::unreachable() }

    const SZ: usize = 1 << 20;
    static mut SRC: [u8; SZ] = [0; SZ];
    static mut OUT: [u8; SZ] = [0; SZ];

    #[unsafe(no_mangle)] pub unsafe extern "C" fn src_ptr() -> *mut u8   { core::ptr::addr_of_mut!(SRC) as *mut u8 }
    #[unsafe(no_mangle)] pub unsafe extern "C" fn out_ptr() -> *const u8 { core::ptr::addr_of!(OUT)     as *const u8 }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn run(len: usize) -> usize {
        let len = len.min(SZ);
        let src = match core::str::from_utf8(core::slice::from_raw_parts(core::ptr::addr_of!(SRC) as *const u8, len)) {
            Ok(s)  => s,
            Err(e) => return write_out(&alloc::format!("input rejected: not valid utf-8 at byte {}", e.valid_up_to())),
        };
        let (chunk, errs) = Parser::new(src, lexer(src)).parse();
        let out: alloc::string::String = if !errs.is_empty() {
            errs.iter().map(|e| alloc::format!("syntax error at line {}: {}", e.line + 1, e.msg)).collect::<alloc::vec::Vec<_>>().join("\n")
        } else {
            let mut vm = VM::with_limits(&chunk, Limits::sandbox());
            vm.run().map(|_| vm.output.join("\n")).unwrap_or_else(|e| alloc::format!("execution failed: {}", e))
        };
        write_out(&out)
    }

    unsafe fn write_out(s: &str) -> usize {
        let b = s.as_bytes();
        let n = b.len().min(SZ);
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(OUT) as *mut u8, n).copy_from_slice(&b[..n]);
        n
    }
}

#[cfg(all(test, feature = "wasm-tests"))]
mod tests {
    use crate::modules::{lexer::lexer, parser::Parser, vm::VM};

    #[derive(serde::Deserialize)]
    struct Case { src: String, output: Vec<String>, result: String }

    #[test]
    fn vm_cases() {
        let cases: Vec<Case> = serde_json::from_str(include_str!("../tests/cases/vm_cases.json")).expect("invalid JSON");
        for case in cases {
            let (chunk, errs) = Parser::new(&case.src, lexer(&case.src)).parse();
            assert!(errs.is_empty(), "parse error on {:?}: {:?}", case.src, errs.iter().map(|e| &e.msg).collect::<Vec<_>>());
            let mut vm = VM::new(&chunk);
            match vm.run() {
                Ok(obj) => {
                    assert_eq!(obj.display(), case.result, "result mismatch on: {:?}", case.src);
                    assert_eq!(vm.output, case.output, "output mismatch on: {:?}", case.src);
                }
                Err(e) => panic!("VM error on {:?}: {}", case.src, e),
            }
        }
    }
}