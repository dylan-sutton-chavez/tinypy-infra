#[cfg(test)]
mod lexer_test {

    /*
    Loads lexer test cases from JSON and asserts token output matches expected values.
    */

    use compiler::modules::lexer::{lexer};

    #[test]
    fn test_cases() {

        /*
        Using a formatted vector: [source, expected_tokens], the lexer builds its structure and compares it against the expected token output.
        */

        let raw = include_str!("cases/lexer_cases.json");
        let cases: Vec<(String, Vec<String>)> = serde_json::from_str(raw).expect("invalid JSON");

        for (src, expected) in cases {
            let got: Vec<String> = lexer(&src).map(|t| format!("{:?}", t)).collect();
            assert_eq!(got, expected, "failed on: {:?}", src);
        }

    }

}