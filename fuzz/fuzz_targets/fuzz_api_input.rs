#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Fuzz JSON parsing for various API request types
        let _ = serde_json::from_str::<serde_json::Value>(input);

        // Fuzz model parsing
        let _ = serde_json::from_str::<lorica_config::models::GlobalSettings>(input);
        let _ = input.parse::<lorica_config::models::LoadBalancing>();
        let _ = input.parse::<lorica_config::models::TopologyType>();
        let _ = input.parse::<lorica_config::models::WafMode>();
        let _ = input.parse::<lorica_config::models::HealthStatus>();
    }
});
