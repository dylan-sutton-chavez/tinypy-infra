#[cfg(test)]
mod lexer_test {

    /*
    Loads lexer test cases from JSON and asserts token output matches expected values.
    */

    use compiler::modules::lexer::{lexer, TokenType};

    #[test]
    fn test_cases() {

        /*
        Using a formatted vector: [source, expected_tokens], the lexer builds its structure and compares it against the expected token output.
        */

        let raw = include_str!("cases/lexer_cases.json");
        let cases: Vec<(String, Vec<String>)> = serde_json::from_str(raw).expect("invalid JSON");

        for (src, expected) in cases {
            let got: Vec<String> = lexer(&src).map(|t| format!("{:?}", t.kind)).collect();
            assert_eq!(got, expected, "failed on: {:?}", src);
        }

    }

    #[test]
    fn test_spans() {

        /*
        Asserts token byte positions against known source offsets.
        */

        let cases = vec![
            ("1 + 1", vec![
                (TokenType::Int, 0, 1),
                (TokenType::Plus, 2, 3),
                (TokenType::Int, 4, 5),
                (TokenType::Endmarker, 0, 0),
            ])
        ];

        for (src, expected) in cases {

            let got: Vec<(TokenType, usize, usize)> = lexer(src).map(|t| (t.kind, t.start, t.end)).collect();
            assert_eq!(got, expected, "failed on: {:?}", src);

        }

    }

}