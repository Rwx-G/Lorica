#![no_main]
use libfuzzer_sys::fuzz_target;
use lorica_waf::{WafEngine, WafMode};

fuzz_target!(|data: &[u8]| {
    let engine = WafEngine::new();

    if let Ok(input) = std::str::from_utf8(data) {
        // Split input into path and query
        let (path, query) = if let Some(pos) = input.find('?') {
            (&input[..pos], Some(&input[pos + 1..]))
        } else {
            (input, None)
        };

        // Fuzz both detection and blocking modes
        let _ = engine.evaluate(WafMode::Detection, path, query, &[], "fuzz.local");
        let _ = engine.evaluate(WafMode::Blocking, path, query, &[], "fuzz.local");

        // Also fuzz with headers
        let headers = vec![("user-agent", input), ("x-custom", input)];
        let _ = engine.evaluate(WafMode::Blocking, "/", Some(input), &headers, "fuzz.local");
    }
});
