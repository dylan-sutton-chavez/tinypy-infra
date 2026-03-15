*Update this documentation upon completion of the compiler (https://edgepython.com/resources/architecture)*

## Project Tree

```bash
├── Cargo.toml
├── README.md
├── src
│   ├── lib.rs
│   ├── main.rs
│   └── modules
│       ├── compiler.rs
│       ├── lexer.rs
│       ├── opcodes.rs
│       ├── parser.rs
│       └── vm.rs
└── tests
```

```bash
compiler.rs
  Tokenizes Python source into a stream of spanned Token variants.

lexer.rs
  Reads raw bytes, emits tokens with start/end positions.
  No strings, no copies — offsets into the original buffer only.

opcodes.rs
  One enum with every opcode: ADD_INT, LOAD, STORE, JUMP, etc.
  Shared by compiler.rs (emit) and vm.rs (execute). Nothing else.

parser.rs
  Consumes tokens, understands grammar (expressions, statements, blocks).
  Produces a minimal AST or feeds directly into compiler.rs.

vm.rs
  Executes bytecode instruction by instruction.
  Owns the call stack, local variables, inline cache, and quickening.
  The only file that runs at runtime.
```

*upx packer*