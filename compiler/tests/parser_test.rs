#[cfg(test)]
mod parser_test {

    use std::collections::HashMap;
    use compiler::modules::lexer::lexer;
    use compiler::modules::parser::{Parser, Value};

    #[derive(serde::Deserialize)]
    struct Case {
        src: String,
        constants: Vec<String>,
        names: Vec<String>,
        instructions: Vec<(String, u16)>,
        annotations: HashMap<String, String>,
        #[serde(default)]
        functions: usize,
        #[serde(default)]
        classes: usize,
        #[serde(default)]
        errors: Vec<String>
    }

    #[test]
    fn test_cases() {

        /* 
        Loads parser cases from JSON and asserts constants, names, instructions, annotations, functions, and classes match. 
        */

        let cases: Vec<Case> = serde_json::from_str(include_str!("cases/parser_cases.json")).expect("invalid JSON");

        for case in cases {
        
            let (chunk, diagnostics) = Parser::new(&case.src, lexer(&case.src)).parse();

            let constants: Vec<String> = chunk.constants.iter().map(|v| match v {
                Value::Str(s) => s.clone(),
                Value::Int(i) => i.to_string(),
                Value::Float(f) => f.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::None => "None".to_string(),
            }).collect();

            let instructions: Vec<(String, u16)> = chunk.instructions.iter()
                .map(|i| (format!("{:?}", i.opcode), i.operand))
                .collect();

            assert_eq!(constants, case.constants, "constants mismatch on: {:?}", case.src);
            assert_eq!(chunk.names, case.names, "names mismatch on: {:?}", case.src);
            assert_eq!(instructions, case.instructions, "bytecode mismatch on: {:?}", case.src);
            assert_eq!(chunk.annotations,case.annotations, "annotations mismatch on: {:?}", case.src);
            assert_eq!(chunk.functions.len(), case.functions,"functions mismatch on: {:?}", case.src);
            assert_eq!(chunk.classes.len(), case.classes, "classes mismatch on: {:?}", case.src);

            if !case.errors.is_empty() {
                let actual: Vec<String> = diagnostics.iter().map(|e| e.msg.clone()).collect();
                assert_eq!(actual, case.errors, "errors mismatch on: {:?}", case.src);
            }
    
        }
    
    }

}