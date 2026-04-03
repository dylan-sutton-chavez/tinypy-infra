## Edge Python

Single-pass SSA compiler for Python 3.13: logos lexer, token-to-bytecode parser, adaptive VM with inline caching, template memoization, and configurable sandbox limits.

---

### Architecture

- **Lexer**: DFA-driven tokenization, offset-indexed, zero-alloc
- **Parser**: Single-pass SSA, phi nodes, precedence climbing, direct bytecode emission
- **VM**: Adaptive stack machine, inline caching, template memoization
- **Sandbox**: Configurable recursion, operation, and heap limits

### Quick Start

Build and Install:

```bash
cd compiler/

cargo build --release
./target/release/edge -c 'print("Hello, world!")'
```

Add to `$PATH`:

```bash
realpath target/release/edge

echo 'export PATH="/path/to/compiler/target/release:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Benchmark

Recursive Fibonacci — `fib(30)` (~2.7M calls):

```python
def fib(n):

    if n < 2: return n
    
    return fib(n-1) + fib(n-2)

print(fib(45)) # fibonacci sequence forty five -> 1,134,903,170
```

| Runtime      | fib(45) real | fib(45) user | sys      | fib(90) real |
|--------------|--------------|--------------|----------|--------------|
| CPython 3.13 | 1m56.345s    | 1m56.324s    | 0m0.009s | n/a          |
| Edge Python  | 0m0.011s     | 0m0.000s     | 0m0.003s | 0m0.013s     |

*10,577x faster than CPython on recursive fib(45), where fib(90) completes in 13ms.*

### Usage

| Command                         | Description                                       |
|---------------------------------|---------------------------------------------------|
| `edge script.py`                | Run with no limits                                |
| `edge --sandbox script.py`      | Run with sandbox (512 calls, 100M ops, 100K heap) |
| `edge -d --sandbox script.py`   | Debug output (verbosity level 1)                  |
| `edge -dd --sandbox script.py`  | Debug output (verbosity level 2)                  |

### Building for WebAssembly

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release --no-default-features --features wasm
```

*Exported functions: `src_ptr()`, `out_ptr()`, `run(len: usize)` -> `usize`*

### Project Structure

```bash
├── Cargo.lock
├── Cargo.toml
├── README.md
├── src
│   ├── lib.rs
│   ├── main.rs
│   ├── modules
│   │   ├── lexer
│   │   │   ├── mod.rs
│   │   │   ├── scan.rs
│   │   │   └── tables.rs
│   │   ├── parser
│   │   │   ├── control.rs
│   │   │   ├── expr.rs
│   │   │   ├── literals.rs
│   │   │   ├── mod.rs
│   │   │   ├── stmt.rs
│   │   │   └── types.rs
│   │   └── vm.rs
│   └── wasm.rs
└── tests
    ├── cases
    │   ├── lexer_cases.json
    │   ├── parser_cases.json
    │   └── vm_cases.json
    ├── integration_test.rs
    ├── lexer_test.rs
    ├── parser_test.rs
    └── vm_test.rs
```

### Tests

```bash
cargo test
cargo test -- --ignored
cargo test --features wasm-tests
```

### License

MIT OR Apache-2.0