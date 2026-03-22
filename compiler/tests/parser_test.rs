#[cfg(test)]
mod parser_test {

    use std::collections::HashMap;
    use compiler::modules::lexer::lexer;
    use compiler::modules::parser::{Parser, Value};

    #[derive(serde::Deserialize)]
    struct Case {
        src:          String,
        constants:    Vec<String>,
        names:        Vec<String>,
        instructions: Vec<(String, u16)>,
        annotations:  HashMap<String, String>,
    }

    fn compile(src: &str) -> compiler::modules::parser::SSAChunk {
        let tokens = lexer(src);
        Parser::new(src, tokens).parse()
    }

    #[test]
    fn test_cases() {

        let raw = include_str!("cases/parser_cases.json");
        let cases: Vec<Case> = serde_json::from_str(raw).expect("invalid JSON");

        for case in cases {

            let SSAChunk = compile(&case.src);

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

            assert_eq!(got_constants,    case.constants,    "constants mismatch on: {:?}", case.src);
            assert_eq!(SSAChunk.names,   case.names,        "names mismatch on: {:?}", case.src);
            assert_eq!(got_instructions, case.instructions, "bytecode mismatch on: {:?}", case.src);
            assert_eq!(SSAChunk.annotations, case.annotations, "annotations mismatch on: {:?}", case.src);

        }

    }

}