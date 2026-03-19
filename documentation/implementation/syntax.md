---
title: "Syntax"
description: "Single pass parser."
---

## Overview

Single pass parser consuming lexer token stream and emitting bytecode directly. No AST materialization, each construct parsed and emitted in one traversal.

## Bytecode Model

Each instruction pairs an `OpCode` with a `u16` operand.

|      OpCode     |    Operand     |
|-----------------|----------------|
| LoadConst       | constant index |
| LoadName        | name index     |
| StoreName       | name index     |
| Call            | argument count |
| PopTop          |                |
| ReturnValue     |                |
| BuildString     | part count     |
| FormatValue     |                |
| Minus           |                |
| CallPrint       | argument count |
| CallLen         | argument count |
| CallAbs         | argument count |
| CallStr         | argument count |
| CallInt         | argument count |
| CallRange       | 3              |

## Expression Parsing

`expr()` advances one token and dispatches on its kind. Every expression leaves exactly one value on the stack.

* Supported: `Name`, `String`, `Int`, `Float`, `True`, `False`, `None`, `FstringStart`, `Minus`.

## Type Annotations

Type annotations (`name: type = value`) are parsed but ignored. Only the value is emitted.

```python
value: int = 42
x = 42
```

## FString Interpolation

FStrings parse from `FstringStart -> FstringMiddle -> FstringEnd` token sequence. Each `FstringMiddle` scanned for `{name}` expressions (`f"Hey, {name}."`).

Supported: simple name interpolation `{name}` only.

## References

* Single pass compilation: dl.acm.org/doi/10.1145/512950.512973
* Bytecode efficiency: dl.acm.org/doi/10.1145/1328195.1328197
* Object: craftinginterpreters.com
* Fstring (RustPython): github.com/RustPython/RustPython/blob/main/compiler/parser/src/fstring.rs 
* Fstring (Ruff): github.com/astral-sh/ruff/blob/main/crates/ruff_python_parser/src/string.rs