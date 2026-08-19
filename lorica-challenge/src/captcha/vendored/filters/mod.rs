//! Filters to disturb and transform CAPTCHAs.
//!
//! Vendored from the `captcha` crate v1.0.0 (`src/filters/`). Only
//! the filters exercised by the Lorica wrapper are kept (Noise, Wave,
//! Dots). See `../../VENDORING.md` for the deltas vs upstream.

mod dots;
mod noise;
mod wave;

use super::images::Image;

pub use self::dots::Dots;
pub use self::noise::Noise;
pub use self::wave::Wave;

pub trait Filter {
    fn apply(&self, i: &mut Image);
}
