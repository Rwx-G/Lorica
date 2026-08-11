// Vendored from the `captcha` crate v1.0.0 (`src/fonts/mod.rs`).
// See `../VENDORING.md` for the deltas vs upstream. The only code
// delta here is the base64 decode call: upstream targeted base64
// 0.13 (`base64::decode`); Lorica is on base64 0.22, whose API routes
// through an `Engine`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub trait Font {
    fn png_as_base64(&self, letter: char) -> Option<&String>;

    fn chars(&self) -> Vec<char>;

    /// Returns None if letter does not exist or if letter could not decoded.
    fn png(&self, letter: char) -> Option<Vec<u8>> {
        match self.png_as_base64(letter) {
            None => None,
            Some(s) => match STANDARD.decode(s) {
                Err(_) => None,
                Ok(v) => Some(v),
            },
        }
    }
}

pub struct Default {
    data: HashMap<char, String>,
}

impl Default {
    pub fn new() -> Default {
        let json = include_str!("font_default.json").to_string();

        Default {
            data: serde_json::from_str(&json).expect("invalid json"),
        }
    }
}

impl Font for Default {
    fn png_as_base64(&self, letter: char) -> Option<&String> {
        self.data.get(&letter)
    }

    fn chars(&self) -> Vec<char> {
        self.data.keys().cloned().collect()
    }
}
