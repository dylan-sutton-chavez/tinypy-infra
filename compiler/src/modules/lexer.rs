/* 
`lexer.rs`
    Tokenizes Python source into a stream of spanned Token variants.
*/

use logos::{Logos, Lexer};

use std::collections::VecDeque;
use std::cmp::Ordering;

// A04:2021 Prevent asymetric DoS via deeply data structures: `handle_indent`, `lex_fstring_body`.
const MAX_INDENT_DEPTH: usize = 100;
const MAX_FSTRING_DEPTH: usize = 200;

#[derive(Default)]
pub struct LexerState {

    /*
    Structure for: pending token queue, indentation stack, bracket nesting depth.
    */

    pending: VecDeque<(TokenType, usize, usize)>,
    indent_stack: Vec<usize>,
    nesting: u32

}

#[derive(Debug)]
pub struct Token {

    /* 
    Structure: kind (token type), start and end for indexes of the kind.
    */

    pub kind: TokenType,
    pub start: usize,
    pub end: usize

}

// Track bracket nesting depth to suppress INDENT/DEDENT inside expressions.
fn open_bracket(lex: &mut Lexer<TokenType>) { lex.extras.nesting += 1; }
fn close_bracket(lex: &mut Lexer<TokenType>) { lex.extras.nesting = lex.extras.nesting.saturating_sub(1); }

fn handle_indent (lex: &mut Lexer<TokenType>) -> logos::Skip {

    /*
    Decides `if \n` is a statement boundary or inside brackets.
    */

    let s = lex.span();

    let src = lex.remainder();
    let indent: Vec<u8> = src.bytes().take_while(|&b| b == b' ' || b == b'\t').collect();
    let level   = indent.len();
    let line = s.end + level;

    let next   = src[indent.len()..].chars().next();
    
    if lex.extras.nesting > 0 { lex.extras.pending.push_back((TokenType::Nl, s.start, s.end)); return logos::Skip; }
    if indent.contains(&b' ') && indent.contains(&b'\t') { lex.extras.pending.push_back((TokenType::Newline, s.start, s.end)); lex.extras.pending.push_back((TokenType::Endmarker, 0, 0)); return logos::Skip; }
    if matches!(next, Some('\n' | '\r' | '#')) { lex.extras.pending.push_back((TokenType::Nl, s.start, s.end)); return logos::Skip; }

    let current = *lex.extras.indent_stack.last().unwrap_or(&0);

    lex.extras.pending.push_back((TokenType::Newline, s.start, s.end));

    match level.cmp(&current) {

        Ordering::Greater => {
            if lex.extras.indent_stack.len() >= MAX_INDENT_DEPTH { lex.extras.pending.push_back((TokenType::Endmarker, 0, 0)); return logos::Skip; }
            lex.extras.indent_stack.push(level);
            lex.extras.pending.push_back((TokenType::Indent, line, line));
        },
        
        Ordering::Less => while lex.extras.indent_stack.last().is_some_and(|&t| t > level) {
            lex.extras.indent_stack.pop();
            lex.extras.pending.push_back((TokenType::Dedent, line, line));
        },
    
        Ordering::Equal => {}
    
    }

    logos::Skip

}

fn lex_fstring_body (lex: &mut Lexer<TokenType>, quote: u8, triple: bool) {

    /*
    Lex f-string body, pushing FstringMiddle and FstringEnd to pending.
    */

    let s = lex.span();

    let mut depth = 0usize;
    let mut had_expr = false;
    let mut pos = 0usize;
    
    let bytes = lex.remainder().as_bytes();

    while pos < bytes.len() {
        
        let closes = if triple {
            bytes.get(pos..pos + 3) == Some(&[quote, quote, quote])
        } else {
            bytes[pos] == quote && depth == 0
        };

        if closes {
            if had_expr { lex.extras.pending.push_back((TokenType::FstringMiddle, s.start, s.end)); }

            lex.bump(pos + if triple { 3 } else { 1 });
            lex.extras.pending.push_back((TokenType::FstringEnd, s.start, s.end));
            
            return;
        
        }

        match bytes[pos] {
            b'\\' => pos += 2,
            b'{' => { had_expr = true; depth = (depth + 1).min(MAX_FSTRING_DEPTH); pos += 1; }
            b'}' => { depth = depth.saturating_sub(1); pos += 1; }
            _ => pos += 1
        }

    }

}

fn lex_name_or_fstring(lex: &mut Lexer<TokenType>) -> Option<()> {

    /*
    Detects f-string prefixes within identifier matches and delegates to lex_fstring_body .
    */

    let s = lex.span();

    if !matches!(lex.slice().to_ascii_lowercase().as_str(), "f" | "fr" | "rf") { return Some(()); }

    let Some(&q) = lex.remainder().as_bytes().first() else { return Some(()); };
    if !matches!(q, b'"' | b'\'') { return Some(()); }

    let triple = lex.remainder().as_bytes().get(1) == Some(&q);

    lex.bump(if triple { 3 } else { 1 });
    lex.extras.pending.push_back((TokenType::FstringStart, s.start, s.end));
    
    lex_fstring_body(lex, q, triple);

    None

}

#[derive(Logos, Debug, PartialEq)]
#[logos(extras = LexerState)]
#[logos(skip r"[ \t\r]+")]
pub enum TokenType {

    /* 
    Keywords
    */

    #[token("False")] False,
    #[token("None")] None,
    #[token("True")] True,
    #[token("and")] And,
    #[token("as")] As,
    #[token("assert")] Assert,
    #[token("async")] Async,
    #[token("await")] Await,
    #[token("break")] Break,
    #[token("class")] Class,
    #[token("continue")] Continue,
    #[token("def")] Def,
    #[token("del")] Del,
    #[token("elif")] Elif,
    #[token("else")] Else,
    #[token("except")] Except,
    #[token("finally")] Finally,
    #[token("for")] For,
    #[token("from")] From,
    #[token("global")] Global,
    #[token("if")] If,
    #[token("import")] Import,
    #[token("in")] In,
    #[token("is")] Is,
    #[token("lambda")] Lambda,
    #[token("nonlocal")] Nonlocal,
    #[token("not")] Not,
    #[token("or")] Or,
    #[token("pass")] Pass,
    #[token("raise")] Raise,
    #[token("return")] Return,
    #[token("try")] Try,
    #[token("while")] While,
    #[token("with")] With,
    #[token("yield")] Yield,

    /*
    Soft keywords
    */

    #[token("case")] Case,
    #[token("match")] Match,
    #[token("type")] Type,
    #[token("_", priority = 3)] Underscore,

    /*
    Operators
    */

    #[token("**=")] DoubleStarEqual,
    #[token("//=")] DoubleSlashEqual,
    #[token("<<=")] LeftShiftEqual,
    #[token(">>=")] RightShiftEqual,

    #[token("!=")] NotEqual,
    #[token("%=")] PercentEqual,
    #[token("&=")] AmperEqual,
    #[token("**")] DoubleStar,
    #[token("*=")] StarEqual,
    #[token("+=")] PlusEqual,
    #[token("-=")] MinEqual,
    #[token("->")] Rarrow,
    #[token("...")] Ellipsis,
    #[token("//")] DoubleSlash,
    #[token("/=")] SlashEqual,
    #[token(":=")] ColonEqual,
    #[token("<<")] LeftShift,
    #[token("<=")] LessEqual,
    #[token("==")] EqEqual,
    #[token(">=")] GreaterEqual,
    #[token(">>")] RightShift,
    #[token("@=")] AtEqual,
    #[token("^=")] CircumflexEqual,
    #[token("|=")] VbarEqual,

    #[token("!")] Exclamation,
    #[token("%")] Percent,
    #[token("&")] Amper,
    #[token("*")] Star,
    #[token("+")] Plus,
    #[token("-")] Minus,
    #[token(".")] Dot,
    #[token("/")] Slash,
    #[token("<")] Less,
    #[token("=")] Equal,
    #[token(">")] Greater,
    #[token("@")] At,
    #[token("^")] Circumflex,
    #[token("|")] Vbar,
    #[token("~")] Tilde,
    #[token(",")] Comma,
    #[token(":")] Colon,
    #[token(";")] Semi,

    /*
    Delimitors
    */

    #[token("(", open_bracket)]  Lpar,
    #[token(")", close_bracket)] Rpar,
    #[token("[", open_bracket)]  Lsqb,
    #[token("]", close_bracket)] Rsqb,
    #[token("{", open_bracket)]  Lbrace,
    #[token("}", close_bracket)] Rbrace,

    /*
    Token names
    */

    #[regex(r"[a-zA-Z_][a-zA-Z0-9_]*", lex_name_or_fstring)] Name,

    #[regex(r"[0-9]+[jJ]")]
    #[regex(r"[0-9]+\.[0-9]*([eE][+-]?[0-9]+)?[jJ]")]
    #[regex(r"\.[0-9]+([eE][+-]?[0-9]+)?[jJ]")]
    Complex,

    #[regex(r"[0-9]+\.[0-9]*([eE][+-]?[0-9]+)?")]
    #[regex(r"\.[0-9]+([eE][+-]?[0-9]+)?")]
    #[regex(r"[0-9]+[eE][+-]?[0-9]+")]
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

    #[regex(r"#[^\n]*", allow_greedy = true)] Comment,

    #[token("\n", handle_indent )] Newline,

    Indent,
    Dedent,

    Nl,

    Endmarker

}

pub fn lexer(source: &str) -> impl Iterator<Item = Token> + '_ {

    /* 
    Tokenizes Python source into a parser-ready stream, handling indentation and soft keywords.
    */

    let mut lex  = TokenType::lexer(source);
    let mut done = false;

    let mut stream = std::iter::from_fn(move || {

        if let Some(tok) = lex.extras.pending.pop_front() { return Some(tok); }

        let result = match lex.next() {
            Some(Ok(tok)) => { let s = lex.span(); Some((tok, s.start, s.end)) },
            Some(Err(_))  => lex.extras.pending.is_empty().then_some((TokenType::Endmarker, 0, 0)),
            None if !done => { done = true; Some((TokenType::Endmarker, 0, 0)) }
            _ => None,
        };
        
        if let Some(t) = result { lex.extras.pending.push_back(t); }
        
        lex.extras.pending.pop_front()

    }).peekable();

    let mut ended = false;

    std::iter::from_fn(move || {
    
        if ended { return None; }
    
        let (tok, start, end) = stream.next()?;
    
        if tok == TokenType::Endmarker { ended = true; }

        let as_name = matches!(tok, TokenType::Match | TokenType::Case | TokenType::Type) && matches!(stream.peek(), Some((
            TokenType::Lpar | TokenType::Colon | TokenType::Equal |
            TokenType::Comma | TokenType::Rpar | TokenType::Rsqb  |
            TokenType::Newline, _, _
        )) | None);

        let kind = if as_name { TokenType::Name } else { tok };

        Some(Token { kind, start, end })
    
    })

}