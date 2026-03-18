---
title: "design"
description: "Explanation of edge python design"
---

## Overview

Introducing edge python, a Rust compiler weighing less than 100 KB, based on adaptive bytecode interpretation to achieve speeds close to native Rust.

## Terms

- bytes: the compiler reads source as raw bytes, minimizing copies into strings.
- spans: instead of extracting substrings, the lexer marks where each token starts and ends in the original buffer.
- tokens: the parser consumes spanned markers: kind, start, end. Structure and position emerge from offsets alone.
- bytecode: the parser emits opcodes directly as it reads tokens, collapsing parsing and code generation into a single pass.
- quickening: the VM rewrites its own instructions as it runs. Once operand types are known, generic opcodes are replaced in-place with faster specialized ones. The bytecode never looks the same twice.
- copy-and-patch: when quickening identifies a hotspot, the VM copies a precompiled native template into executable memory and patches the variable slots with real values. No code generation at runtime.

## Basic Architecture

```txt
bytes -> spans -> tokens -> bytecode -> [inline caching + quickening] -> copy-and-patch -> native code
```

$$
\Gamma_{compiler} = \mathcal{C}_{patch} \circ \mathcal{V}_{quickening} \circ \mathcal{P}_{parser} \circ \mathcal{L}_{lexer}
$$

## References

- Formally verified linear-time lexing: [2510.18479](https://arxiv.org/abs/2510.18479)
- Deterministic parser with fused lexing: [2304.05276](https://arxiv.org/abs/2304.05276)
- Structure and performance of efficient interpreters: [dl.acm.org/doi/10.1145/1328195.1328197](https://dl.acm.org/doi/10.1145/1328195.1328197)
- Specializing adaptive interpreter: [2211.07633](https://arxiv.org/abs/2211.07633)
- Copy and patch compilation: [dl.acm.org/doi/10.1145/3485513](https://dl.acm.org/doi/10.1145/3485513)