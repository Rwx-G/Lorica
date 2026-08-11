// Vendored from the `captcha` crate v1.0.0 (`src/filters/noise.rs`).

use rand::{rng, Rng};

use super::super::images::{Image, Pixl};
use super::Filter;

pub struct Noise {
    prob: f32,
}

impl Noise {
    pub fn new(prob: f32) -> Noise {
        Noise { prob }
    }
}

impl Filter for Noise {
    fn apply(&self, i: &mut Image) {
        let mut rng = rng();
        for y in 0..i.height() {
            for x in 0..i.width() {
                if rng.random::<f32>() <= self.prob {
                    i.put_pixel(x, y, Pixl::black());
                }
            }
        }
    }
}
