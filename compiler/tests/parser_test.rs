#[cfg(test)]
mod parser_test {

    use compiler::modules::lexer::lexer;
    use compiler::modules::parser::{Parser, Value};

    fn compile(src: &str) -> compiler::modules::parser::SSAChunk {

        let tokens = lexer(src);
        Parser::new(src, tokens).parse()
    
    }

    #[test]
    fn test_cases() {

        let raw = include_str!("cases/parser_cases.json");
        let cases: Vec<(String, Vec<String>, Vec<String>, Vec<(String, u16)>)> =
            serde_json::from_str(raw).expect("invalid JSON");

        for (src, expected_constants, expected_names, expected_instructions) in cases {

            let SSAChunk = compile(&src);

            let got_constants: Vec<String> = SSAChunk.constants.iter().map(|v| match v {
                Value::Str(s) => s.clone(),
                Value::Int(i) => i.to_string(),
                Value::Float(f) => f.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::None => "None".to_string(),
                Value::Range(start, stop, step) => format!("Range({}, {}, {})", start, stop, step),
            }).collect();

            let got_instructions: Vec<(String, u16)> = SSAChunk.instructions.iter()
                .map(|i| (format!("{:?}", i.opcode), i.operand))
                .collect();

            assert_eq!(got_constants, expected_constants, "constants mismatch on: {:?}", src);
            assert_eq!(SSAChunk.names, expected_names, "names mismatch on: {:?}", src);
            assert_eq!(got_instructions, expected_instructions, "bytecode mismatch on: {:?}", src);

        }

    }

}