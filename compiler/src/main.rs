use log::{LevelFilter, info};
use simple_logger::SimpleLogger;

fn initialize_logger() {
    /*
    Initialize the needed dependencies app.
    */

    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .expect("An error ocurred on the initialization of logging system.");

    info!("Logging system initialized correctly.");
}

mod modules {
    pub mod lexer;
    pub mod parser;
}

fn main() {
    /*
    Initialization point for the CDK.
    */

    initialize_logger();
}


/* 
use compiler::modules::lexer::lexer;
use compiler::modules::parser::Parser;
use compiler::modules::vm::VM;

fn main() {
    let src = std::env::args().nth(1)
        .map(|f| std::fs::read_to_string(f).expect("cannot read file"))
        .unwrap_or_else(|| {
            eprintln!("usage: edge-python <file.py>");
            std::process::exit(1);
        });

    let (chunk, errors) = Parser::new(&src, lexer(&src)).parse();
    if !errors.is_empty() {
        for e in &errors { eprintln!("line {}:{}: {}", e.line + 1, e.col, e.msg); }
        std::process::exit(1);
    }

    let mut vm = VM::new(&chunk);
    if let Err(e) = vm.run() { eprintln!("{}", e); std::process::exit(1); }
}
*/