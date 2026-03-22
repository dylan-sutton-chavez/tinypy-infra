use log::{info, LevelFilter};
use simple_logger::SimpleLogger;

fn initialize_logger () {

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

    let source = "def add(a, b): a + b\nresult = add(1, 2)";

    let chunk = modules::parser::Parser::new(source, modules::lexer::lexer(source)).parse();

    // Instructions.
    for (i, ins) in chunk.instructions.iter().enumerate() {
        info!("{:03} {:?} {}", i, ins.opcode, ins.operand);
    }

    let tokens: Vec<String> = modules::lexer::lexer(source)
        .map(|t| format!("{:?} [{}-{}]", t.kind, t.start, t.end))
        .collect();

    info!("{:?}", tokens);

    info!("constants: {:?}", chunk.constants);
    info!("names: {:?}", chunk.names);

}