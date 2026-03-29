/*
`lexer.rs`
    Tokenizes Python source into offset-indexed tokens. Zero-copy, zero-alloc hot path, DFA-compiled via logos.

    Usage:
        ```rust
        mod modules {
            pub mod lexer;
        }

        let tokens: Vec<String> = modules::lexer::lexer("name: str = 'Dylan'\nprint(f'Hey, I am: {name}.')")
            .map(|t| format!("{:?} {} [{}-{}]", t.kind, t.line, t.start, t.end,)) // Transforms each Token into a `String`.
            .collect(); // Combine them all into one vector.

        info!("{:?}", tokens);
        ```

    Output:
        ````bash
        2026-03-17T03:50:42.560Z INFO  [compiler] ["Name 0 [0-4]", "Colon 0 [4-5]", "Name 0 [6-9]", "Equal 0 [10-11]", "String 0 [12-19]", "Newline 0 [19-20]", "Name 1 [20-25]", "Lpar 1 [25-26]", "FstringStart 1 [26-27]", "FstringMiddle 1 [26-28]", "FstringEnd 1 [26-28]", "Rpar 1 [47-48]", "Endmarker 1 [47-48]"]
        ```
*/

use logos::{Lexer, Logos};

use std::cmp::Ordering;
use std::collections::VecDeque;

// A04:2021 - Prevent asymetric DoS via deeply data structures: `handle_indent`, `lex_fstring_body`.
const MAX_INDENT_DEPTH: usize = 100;
const MAX_FSTRING_DEPTH: usize = 200;
const MAX_SOURCE_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Default)]
pub struct LexerState {
    /*
    Pending queue, indentation stack, bracket depth, line counter, and f-string context.
    */
    pending: VecDeque<(TokenType, usize, usize, usize)>,
    indent_stack: Vec<usize>,
    nesting: u32,
    line: usize,
    fstring_stack: Vec<(u8, bool, usize, u32)>
}

#[derive(Debug)]
pub struct Token {
    /*
    Token kind with line number and byte-offset span (start, end) into source.
    */
    pub kind: TokenType,
    pub line: usize,
    pub start: usize,
    pub end: usize,
}

// Track bracket nesting depth to suppress INDENT/DEDENT inside expressions.
fn open_bracket(lex: &mut Lexer<TokenType>) {
    lex.extras.nesting += 1;
}
fn close_bracket(lex: &mut Lexer<TokenType>) {
    lex.extras.nesting = lex.extras.nesting.saturating_sub(1);
}

fn handle_indent(lex: &mut Lexer<TokenType>) -> logos::Skip {
    /*
    Emits Indent/Dedent/Newline tokens or suppresses them inside bracketed expressions.
    */

    let s = lex.span();
    let current_line = lex.extras.line;

    lex.extras.line += 1;

    if lex.extras.nesting > 0 {
        lex.extras
            .pending
            .push_back((TokenType::Nl, current_line, s.start, s.end));
        return logos::Skip;
    }

    let bytes = lex.remainder().as_bytes();

    let mut level = 0usize;
    let mut has_space = false;
    let mut has_tab = false;

    while level < bytes.len() && (bytes[level] == b' ' || bytes[level] == b'\t') {
        has_space |= bytes[level] == b' ';
        has_tab |= bytes[level] == b'\t';
        level += 1;
    }

    if has_space && has_tab {
        lex.extras
            .pending
            .push_back((TokenType::Newline, current_line, s.start, s.end));
        lex.extras
            .pending
            .push_back((TokenType::Endmarker, current_line, s.start, s.end));
        return logos::Skip;
    }

    if matches!(bytes.get(level), Some(b'\n' | b'\r' | b'#')) {
        lex.extras
            .pending
            .push_back((TokenType::Nl, current_line, s.start, s.end));
        return logos::Skip;
    }

    let line = s.end + level;
    let current = *lex.extras.indent_stack.last().unwrap_or(&0);

    lex.extras
        .pending
        .push_back((TokenType::Newline, current_line, s.start, s.end));

    match level.cmp(&current) {
        Ordering::Greater => {
            if lex.extras.indent_stack.len() >= MAX_INDENT_DEPTH {
                lex.extras
                    .pending
                    .push_back((TokenType::Endmarker, current_line, s.start, s.end));
                return logos::Skip;
            }
            lex.extras.indent_stack.push(level);
            lex.extras
                .pending
                .push_back((TokenType::Indent, lex.extras.line, line, line));
        }

        Ordering::Less => {
            while lex.extras.indent_stack.last().is_some_and(|&t| t > level) {
                lex.extras.indent_stack.pop();
                lex.extras
                    .pending
                    .push_back((TokenType::Dedent, lex.extras.line, line, line));
            }
        }

        Ordering::Equal => {}
    }

    logos::Skip
}

fn lex_fstring_body(lex: &mut Lexer<TokenType>, quote: u8, triple: bool, body_start: usize) {
    /*
    Scans f-string bytes, emitting text segments and suspending at `{` for expression lexing.
    */

    let bytes = lex.remainder().as_bytes();

    let mut pos = 0usize;

    while pos < bytes.len() {
        let closes = if triple {
            bytes.get(pos..pos + 3) == Some(&[quote, quote, quote])
        } else {
            bytes[pos] == quote
        };

        if closes {
            if pos > 0 {
                lex.extras.pending.push_back((
                    TokenType::FstringMiddle,
                    lex.extras.line,
                    body_start,
                    body_start + pos,
                ));
            }

            let quote_len = if triple { 3 } else { 1 };

            lex.bump(pos + quote_len);
            lex.extras.pending.push_back((
                TokenType::FstringEnd,
                lex.extras.line,
                body_start + pos,
                body_start + pos + quote_len,
            ));

            return;
        }

        match bytes[pos] {
            b'\\' => pos = (pos + 2).min(bytes.len()),

            b'{' if bytes.get(pos + 1) != Some(&b'{') => {
                if pos > 0 {
                    lex.extras.pending.push_back((
                        TokenType::FstringMiddle,
                        lex.extras.line,
                        body_start,
                        body_start + pos,
                    ));
                }

                if lex.extras.fstring_stack.len() >= MAX_FSTRING_DEPTH {
                    lex.extras.pending.push_back((
                        TokenType::Endmarker,
                        lex.extras.line,
                        body_start + pos,
                        body_start + pos,
                    ));
                    lex.bump(pos + 1);
                    return;
                }

                lex.extras.pending.push_back((
                    TokenType::Lbrace,
                    lex.extras.line,
                    body_start + pos,
                    body_start + pos + 1,
                ));
                lex.extras.fstring_stack.push((
                    quote,
                    triple,
                    body_start + pos + 1,
                    lex.extras.nesting,
                ));
                lex.bump(pos + 1);

                return;
            }

            _ => pos += 1,
        }
    }
}

fn lex_name_or_fstring(lex: &mut Lexer<TokenType>) -> Option<()> {
    /*
    Reclassifies `f`/`fr`/`rf` identifiers as f-string starts when followed by a quote.
    */

    let s = lex.span();
    let slice = lex.slice().as_bytes();

    let is_fprefix = match slice.len() {
        1 => matches!(slice[0], b'f' | b'F'),
        2 => matches!(
            (slice[0], slice[1]),
            (b'f' | b'F', b'r' | b'R') | (b'r' | b'R', b'f' | b'F')
        ),
        _ => return Some(()),
    };

    if !is_fprefix {
        return Some(());
    }

    let Some(&q) = lex.remainder().as_bytes().first() else {
        return Some(());
    };

    if !matches!(q, b'"' | b'\'') {
        return Some(());
    }

    let triple = lex.remainder().as_bytes().get(1) == Some(&q)
        && lex.remainder().as_bytes().get(2) == Some(&q);
    let quote_len = if triple { 3 } else { 1 };

    lex.bump(quote_len);

    let body_start = s.end + quote_len;
    lex.extras.pending.push_back((
        TokenType::FstringStart,
        lex.extras.line,
        s.start,
        body_start,
    ));

    lex_fstring_body(lex, q, triple, body_start);

    None
}

fn close_fstring_expr(lex: &mut Lexer<TokenType>) -> logos::Skip {
    /*
    Closes `}`, distinguishes nested braces from f-string expression boundaries via saved nesting.
    */

    let span = lex.span();

    if let Some(&(_, _, _, saved_nesting)) = lex.extras.fstring_stack.last() {
        if lex.extras.nesting > saved_nesting {
            lex.extras.nesting -= 1;
            lex.extras.pending.push_back((
                TokenType::Rbrace,
                lex.extras.line,
                span.start,
                span.end,
            ));
        } else {
            let (quote, triple, _, _) = lex.extras.fstring_stack.pop().unwrap();
            lex.extras.pending.push_back((
                TokenType::Rbrace,
                lex.extras.line,
                span.start,
                span.end,
            ));
            lex_fstring_body(lex, quote, triple, span.end);
        }
    } else {
        lex.extras.nesting = lex.extras.nesting.saturating_sub(1);
        lex.extras
            .pending
            .push_back((TokenType::Rbrace, lex.extras.line, span.start, span.end));
    }

    logos::Skip
}

#[derive(Logos, Debug, PartialEq, Clone, Copy)]
#[logos(extras = LexerState)]
#[logos(skip r"[ \t\r]+")]
pub enum TokenType {
    /*
    Keywords
    */
    #[token("False")]
    False,
    #[token("None")]
    None,
    #[token("True")]
    True,
    #[token("and")]
    And,
    #[token("as")]
    As,
    #[token("assert")]
    Assert,
    #[token("async")]
    Async,
    #[token("await")]
    Await,
    #[token("break")]
    Break,
    #[token("class")]
    Class,
    #[token("continue")]
    Continue,
    #[token("def")]
    Def,
    #[token("del")]
    Del,
    #[token("elif")]
    Elif,
    #[token("else")]
    Else,
    #[token("except")]
    Except,
    #[token("finally")]
    Finally,
    #[token("for")]
    For,
    #[token("from")]
    From,
    #[token("global")]
    Global,
    #[token("if")]
    If,
    #[token("import")]
    Import,
    #[token("in")]
    In,
    #[token("is")]
    Is,
    #[token("lambda")]
    Lambda,
    #[token("nonlocal")]
    Nonlocal,
    #[token("not")]
    Not,
    #[token("or")]
    Or,
    #[token("pass")]
    Pass,
    #[token("raise")]
    Raise,
    #[token("return")]
    Return,
    #[token("try")]
    Try,
    #[token("while")]
    While,
    #[token("with")]
    With,
    #[token("yield")]
    Yield,

    /*
    Soft keywords
    */
    #[token("case")]
    Case,
    #[token("match")]
    Match,
    #[token("type")]
    Type,
    #[token("_", priority = 3)]
    Underscore,

    /*
    Operators
    */
    #[token("**=")]
    DoubleStarEqual,
    #[token("//=")]
    DoubleSlashEqual,
    #[token("<<=")]
    LeftShiftEqual,
    #[token(">>=")]
    RightShiftEqual,

    #[token("!=")]
    NotEqual,
    #[token("%=")]
    PercentEqual,
    #[token("&=")]
    AmperEqual,
    #[token("**")]
    DoubleStar,
    #[token("*=")]
    StarEqual,
    #[token("+=")]
    PlusEqual,
    #[token("-=")]
    MinEqual,
    #[token("->")]
    Rarrow,
    #[token("...")]
    Ellipsis,
    #[token("//")]
    DoubleSlash,
    #[token("/=")]
    SlashEqual,
    #[token(":=")]
    ColonEqual,
    #[token("<<")]
    LeftShift,
    #[token("<=")]
    LessEqual,
    #[token("==")]
    EqEqual,
    #[token(">=")]
    GreaterEqual,
    #[token(">>")]
    RightShift,
    #[token("@=")]
    AtEqual,
    #[token("^=")]
    CircumflexEqual,
    #[token("|=")]
    VbarEqual,

    #[token("!")]
    Exclamation,
    #[token("%")]
    Percent,
    #[token("&")]
    Amper,
    #[token("*")]
    Star,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token(".")]
    Dot,
    #[token("/")]
    Slash,
    #[token("<")]
    Less,
    #[token("=")]
    Equal,
    #[token(">")]
    Greater,
    #[token("@")]
    At,
    #[token("^")]
    Circumflex,
    #[token("|")]
    Vbar,
    #[token("~")]
    Tilde,
    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    #[token(";")]
    Semi,

    /*
    Delimitors
    */
    #[token("(", open_bracket)]
    Lpar,
    #[token(")", close_bracket)]
    Rpar,
    #[token("[", open_bracket)]
    Lsqb,
    #[token("]", close_bracket)]
    Rsqb,
    #[token("{", open_bracket)]
    Lbrace,
    #[token("}", close_fstring_expr)]
    Rbrace,

    /*
    Token names
    */
    #[regex(r"[\p{L}\p{Nl}_][\p{L}\p{Nl}\p{Mn}\p{Mc}\p{Nd}\p{Pc}_]*", lex_name_or_fstring)] 
    Name,

    #[regex(r"[0-9][0-9_]*[jJ]")]
    #[regex(r"[0-9][0-9_]*\.[0-9_]*([eE][+-]?[0-9][0-9_]*)?[jJ]")]
    #[regex(r"\.[0-9][0-9_]*([eE][+-]?[0-9][0-9_]*)?[jJ]")]
    Complex,

    #[regex(r"[0-9][0-9_]*\.[0-9_]*([eE][+-]?[0-9][0-9_]*)?")]
    #[regex(r"\.[0-9][0-9_]*([eE][+-]?[0-9][0-9_]*)?")]
    #[regex(r"[0-9][0-9_]*[eE][+-]?[0-9][0-9_]*")]
    Float,

    #[regex(r"0[xX][0-9a-fA-F][0-9a-fA-F_]*")]
    #[regex(r"0[oO][0-7][0-7_]*")]
    #[regex(r"0[bB][01][01_]*")]
    #[regex(r"[1-9][0-9_]*|0")]
    Int,

    #[regex(r#"[bBrRuU]{0,2}"""([^"\\]|\\.)*""""#)]
    #[regex(r#"[bBrRuU]{0,2}'''([^'\\]|\\.)*'''"#)]
    #[regex(r#"[bBrRuU]{0,2}"([^"\\\n]|\\.)*""#)]
    #[regex(r#"[bBrRuU]{0,2}'([^'\\\n]|\\.)*'"#)]
    String,

    FstringStart,
    FstringMiddle,
    FstringEnd,

    #[regex(r"#[^\n]*", allow_greedy = true)]
    Comment,

    #[token("\n", handle_indent)]
    Newline,

    Indent,
    Dedent,

    Nl,

    Endmarker,
}

pub fn lexer(source: &str) -> impl Iterator<Item = Token> + '_ {
    /*
    Produces a parser-ready token stream with indentation, soft keywords, and f-string boundaries resolved.
    */

    let source_len = source.len();

    let mut lex = TokenType::lexer(source);
    let mut done = false;

    if source_len > MAX_SOURCE_SIZE {
        lex.extras
            .pending
            .push_back((TokenType::Endmarker, 0, source_len, source_len));
    }

    let mut stream = std::iter::from_fn(move || {
        if let Some(tok) = lex.extras.pending.pop_front() {
            return Some(tok);
        }

        let tok = match lex.next() {
            Some(Ok(tok)) => {
                let s = lex.span();
                (tok, lex.extras.line, s.start, s.end)
            }
            Some(Err(_)) if lex.extras.pending.is_empty() => (
                TokenType::Endmarker,
                lex.extras.line,
                source_len,
                source_len,
            ),
            Some(Err(_)) => return lex.extras.pending.pop_front(),
            None if !done => {
                done = true;
                (
                    TokenType::Endmarker,
                    lex.extras.line,
                    source_len,
                    source_len,
                )
            }
            None => return None,
        };

        if lex.extras.pending.is_empty() {
            Some(tok)
        } else {
            lex.extras.pending.push_back(tok);
            lex.extras.pending.pop_front()
        }
    })
    .peekable();

    let mut ended = false;

    std::iter::from_fn(move || {
        let (tok, line, start, end) = stream.next()?;

        if ended {
            return None;
        }
        if tok == TokenType::Endmarker {
            ended = true;
        }

        let is_soft_keyword = matches!(tok, TokenType::Match | TokenType::Case | TokenType::Type);
        let next_demotes = matches!(
            stream.peek(),
            Some((
                TokenType::Lpar
                    | TokenType::Colon
                    | TokenType::Equal
                    | TokenType::Comma
                    | TokenType::Rpar
                    | TokenType::Rsqb
                    | TokenType::Newline,
                _,
                _,
                _
            )) | None
        );

        let kind = if is_soft_keyword && next_demotes {
            TokenType::Name
        } else {
            tok
        };

        Some(Token {
            kind,
            line,
            start,
            end,
        })
    })
}
