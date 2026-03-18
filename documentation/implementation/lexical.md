---
title: "lexical"
description: "Formal specification of Edge Python lexical grammar: token definitions, indentation model, encoding rules, and lexer safety limits."
---

## Tokens Definition

Token set derived directly from Python `token` and `keyword` modules. To update the syntax after any Python upgrade, new tokens require changes to `lexer.rs` and its wrappers.

F-strings are decomposed into a three-token sequence rather than a single `String` token: `FstringStart -> FstringMiddle -> FstringEnd`. Tooling that consumes the token stream should handle this sequence explicitly.

```python
"""
Version:
    Python 3.13.12
"""

import logging

logging.basicConfig(
    level = logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S", 
    format = "[%(levelname)s] (%(asctime)s): %(message)s"
)

from keyword import kwlist, softkwlist
from token import EXACT_TOKEN_TYPES, tok_name

logging.info(kwlist) # Keywords.
logging.info(softkwlist) # Soft keywords

logging.info(list(EXACT_TOKEN_TYPES.keys())) # Operators and Delimitors.

logging.info(list(tok_name.values())) # Token names.
```

## Indentation Model

The lexer emits `Nl` for blank lines, comments, and lines inside brackets. For all other lines, it emits `Newline` followed by `Indent`, `Dedent`, or nothing depending on whether indentation increased, decreased, or stayed the same. Mixing spaces and tabs halts the lexer with `Endmarker`.

## Soft Keyword Disambiguation

`match`, `case`, and `type` can also be used as identifiers. The lexer resolves the ambiguity by checking what follows: if the next token is `(` `)` `]` `:` `=` `,` `Newline` or `EOF`, they are emitted as `Name`.

## Lexer Safety Limits

Based on OWASP standards, the 04:2021 was adapted to prevent asymmetric DoS attacks, using limiters:

| Constant | Value | Behavior when exceeded |
| --- | --- | --- |
| `MAX_INDENT_DEPTH` | 100 | Emits `Endmarker`, halts |
| `MAX_FSTRING_DEPTH` | 200 | Excess `{` silently clamped |

## Integration Tests

Tests live in `lexer_test.rs` and load cases from `cases/lexer_cases.json`. Each case is a pair of `[source, expected_tokens]`, the lexer output is compared directly against the expected token list. `test_cases` verifies token kinds across all cases. `test_spans` asserts that each token carries the correct byte offsets: regular tokens point to their exact position in the source buffer.

## Module Usage and Output

```rust
`lexer.rs`
    Tokenizes Python source into a stream of spanned Token variants.

    Usage:
        mod modules {
            pub mod lexer;
        }

        let tokens: Vec<String> = modules::lexer::lexer("name: str = 'Dylan'\nprint(f'Hey, I am: {name}.')")
            .map(|t| format!("{:?} {} [{}-{}]", t.kind, t.line, t.start, t.end,)) // Transforms each Token into a `String`.
            .collect(); // Combine them all into one vector.

        info!("{:?}", tokens);

    Output:
        2026-03-17T03:50:42.560Z INFO  [compiler] ["Name 0 [0-4]", "Colon 0 [4-5]", "Name 0 [6-9]", "Equal 0 [10-11]", "String 0 [12-19]", "Newline 0 [19-20]", "Name 1 [20-25]", "Lpar 1 [25-26]", "FstringStart 1 [26-27]", "FstringMiddle 1 [26-28]", "FstringEnd 1 [26-28]", "Rpar 1 [47-48]", "Endmarker 1 [47-48]"]
```