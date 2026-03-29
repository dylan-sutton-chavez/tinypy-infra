#[cfg(test)]
mod vm_test {

    use compiler::modules::lexer::lexer;
    use compiler::modules::parser::Parser;
    use compiler::modules::vm::VM;

    #[derive(serde::Deserialize)]
    struct Case {
        src: String,
        output: Vec<String>,
        result: String,
    }

    #[test]
    fn test_cases() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("cases/vm_cases.json")).expect("invalid JSON");

        for case in cases {
            let (chunk, _errors) = Parser::new(&case.src, lexer(&case.src)).parse();
            let mut vm = VM::new(&chunk);
            let result = vm.run();

            match result {
                Ok(obj) => {
                    assert_eq!(obj.display(), case.result, "result mismatch on: {:?}", case.src);
                    assert_eq!(vm.output, case.output, "output mismatch on: {:?}", case.src);
                }
                Err(e) => panic!("VM error on {:?}: {}", case.src, e),
            }
        }
    }

    #[test]
    fn test_inline_cache() {
        // 20 iterations of int+int → cache should specialize Add to AddInt
        let src = "s = 0\nfor i in range(20):\n    s = s + i";
        let (chunk, _) = Parser::new(src, lexer(src)).parse();
        let mut vm = VM::new(&chunk);
        let _ = vm.run();

        let (specialized, total) = vm.cache_stats();
        assert!(specialized > 0, "expected specialized cache slots after 20 int+int adds");
        assert!(total > 0);
    }

    #[test]
    fn test_template_memoization() {
        // Call same function 5 times with same arg types → template caches result
        let src = "def f(x):\n    return x * 2\na = f(5)\nb = f(5)\nc = f(5)\nd = f(5)\ne = f(5)\nprint(e)";
        let (chunk, _) = Parser::new(src, lexer(src)).parse();
        let mut vm = VM::new(&chunk);
        let _ = vm.run();

        assert_eq!(vm.output, vec!["10"]);
        assert!(vm.templates_cached() > 0, "expected template cached after 5 calls");
    }

    #[test]
    fn test_adaptive_not_triggered() {
        // 20 iterations < 1000 threshold → no hotspot, no rewrite
        let src = "s = 0\nfor i in range(20):\n    s = s + 1";
        let (chunk, _) = Parser::new(src, lexer(src)).parse();
        let mut vm = VM::new(&chunk);
        let _ = vm.run();

        assert_eq!(vm.hotspots().len(), 0, "20 iters should not trigger hotspot (threshold=1000)");
        assert_eq!(vm.rewrites_active(), 0);
    }

    #[test]
    fn test_heap_tracking() {
        // range(10) allocates a list → heap count > 0
        let src = "x = range(10)";
        let (chunk, _) = Parser::new(src, lexer(src)).parse();
        let mut vm = VM::new(&chunk);
        let _ = vm.run();

        assert!(vm.heap_usage() > 0, "expected heap allocation from range()");
    }
}