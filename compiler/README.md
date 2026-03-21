*Update this documentation upon completion of the compiler (https://edgepython.com/resources/architecture)*

```bash

lexer.rs
  Tokenizes Python source into a stream of spanned Token variants.

parser.rs
  Single-pass SSA bytecode emitter. No AST. Variables versioned on assignment (new def per write), phi-joined (select reaching defs) at control flow boundaries.
```

*upx packer*