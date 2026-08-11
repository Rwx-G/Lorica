// Vendored from the `captcha` crate v1.0.0 by Daniel Etzold, MIT
// licensed. See `../LICENSE` for the original license text and
// `../VENDORING.md` for the exact list of deltas vs upstream.
//
// Dead-code + clippy allow, scoped to the vendored subtree only (the
// `captcha` wrapper module above stays fully linted). The vendored core
// keeps upstream's full builder surface (`set_font`, `add_text_area`,
// `extract`, `set_color`, ...) even though the Lorica wrapper exercises
// only a subset, and it keeps upstream's own style (all-caps enum
// variants, manual `Result`->`Option` conversions, unwrap-after-check)
// rather than re-linting it. Both allows exist so a future re-sync with
// upstream stays a diff instead of a rewrite; the cost is zero at
// runtime.
#![allow(dead_code)]
#![allow(clippy::all)]

pub mod filters;
mod fonts;
mod images;

pub use self::filters::Filter;
use self::fonts::{Default, Font};
use self::images::{Image, Pixl};

use rand::prelude::*;
use rand::rng;
use rand::rngs::ThreadRng;
use std::cmp::{max, min};

/// Represents the area which contains text in a CAPTCHA.
#[derive(Clone, Debug)]
pub struct Geometry {
    /// The minimum x coordinate of the area which contains text (inclusive).
    pub left: u32,
    /// The maximum x coordinate of the area which contains text (inclusive).
    pub right: u32,
    /// The minimum y coordinate of the area which contains text (inclusive).
    pub top: u32,
    /// The maximum y coordinate of the area which contains text (inclusive).
    pub bottom: u32,
}

impl Geometry {
    pub fn new(left: u32, right: u32, top: u32, bottom: u32) -> Geometry {
        Geometry {
            left,
            right,
            top,
            bottom,
        }
    }
}

pub type Captcha = RngCaptcha<ThreadRng>;

/// A CAPTCHA.
pub struct RngCaptcha<T> {
    img: Image,
    font: Box<dyn Font>,
    text_area: Geometry,
    chars: Vec<char>,
    use_font_chars: Vec<char>,
    color: Option<[u8; 3]>,
    rng: T,
}

impl<T: rand::Rng + rand::RngCore> RngCaptcha<T> {
    pub fn from_rng(rng: T) -> RngCaptcha<T> {
        let w = 400;
        let h = 300;
        let f = Box::new(Default::new());
        RngCaptcha::<T> {
            use_font_chars: f.chars(),
            img: Image::new(w, h),
            font: f,
            text_area: Geometry {
                left: w / 4,
                right: w / 4,
                top: h / 2,
                bottom: h / 2,
            },
            chars: vec![],
            color: None,
            rng,
        }
    }

    /// Returns an empty CAPTCHA.
    pub fn new() -> Captcha {
        Captcha::from_rng(rng())
    }

    /// Applies the filter `f` to the CAPTCHA.
    ///
    /// This method is used to add noise, grids, etc or to transform the shape of the CAPTCHA.
    pub fn apply_filter<F: Filter>(&mut self, f: F) -> &mut Self {
        f.apply(&mut self.img);
        self
    }

    /// Sets another font that is used for the characters.
    ///
    /// Calling this method does not have an effect on the font of the characters which have already
    /// been added to the CAPTCHA. The new font is only applied to the characters which are written
    /// to the CAPTCHA after this method is called.
    ///
    /// If characters have been set via set_chars(), this method will overwrite the setting.
    pub fn set_font<F: Font + 'static>(&mut self, f: F) -> &mut Self {
        self.font = Box::new(f);
        self.use_font_chars = self.font.chars();
        self
    }

    pub fn set_color(&mut self, color: [u8; 3]) -> &mut Self {
        self.color = Some(color);
        self
    }

    /// Sets the characters that should be used when generating a CAPTCHA.
    ///
    /// Important: The characters have to exist for the current font. You can get all characters
    /// which are supported by the current font by calling supported_chars().
    pub fn set_chars(&mut self, c: &[char]) -> &mut Self {
        self.use_font_chars = c.to_vec();
        self
    }

    fn random_char_as_image(&mut self) -> Option<(char, Image)> {
        match self.use_font_chars.choose(&mut self.rng) {
            None => None,
            Some(c) => match self.font.png(*c) {
                None => None,
                Some(p) => Image::from_png(p).map(|i| (*c, i)),
            },
        }
    }

    /// Adds a random character using the current font.
    pub fn add_char(&mut self) -> &mut Self {
        if let Some((c, i)) = self.random_char_as_image() {
            let x = self.text_area.right;
            let y = (self.text_area.bottom + self.text_area.top) / 2 - i.height() / 2;
            self.img.add_image(x, y, &i);

            self.text_area.top = min(self.text_area.top, y);
            self.text_area.right = x + i.width() - 1;
            self.text_area.bottom = max(self.text_area.bottom, y + i.height() - 1);
            self.chars.push(c);
        }

        self
    }

    /// Adds a red box to the CAPTCHA representing the area which contains text.
    pub fn add_text_area(&mut self) -> &mut Self {
        for y in self.text_area.top..self.text_area.bottom {
            self.img.put_pixel(self.text_area.left, y, Pixl::red());
            self.img.put_pixel(self.text_area.right, y, Pixl::red());
        }
        for x in self.text_area.left..self.text_area.right {
            self.img.put_pixel(x, self.text_area.top, Pixl::red());
            self.img.put_pixel(x, self.text_area.bottom, Pixl::red());
        }
        self
    }

    /// Returns the geometry of the area which contains text in the CAPTCHA.
    pub fn text_area(&self) -> Geometry {
        self.text_area.clone()
    }

    /// Crops the CAPTCHA to the given geometry.
    pub fn extract(&mut self, area: Geometry) -> &mut Self {
        let w = area.right - area.left;
        let h = area.bottom - area.top;
        let mut i = Image::new(w, h);
        for (y, iy) in (area.top..area.bottom).zip(0..h + 1) {
            for (x, ix) in (area.left..area.right).zip(0..w + 1) {
                i.put_pixel(ix, iy, self.img.get_pixel(x, y));
            }
        }
        self.img = i;
        self
    }

    /// Crops the CAPTCHA to the given width and height with the text centered withing this
    /// box.
    pub fn view(&mut self, w: u32, h: u32) -> &mut Self {
        let mut a = self.text_area();
        a.left = (a.right + a.left) / 2 - w / 2;
        a.right = a.left + w;
        a.top = (a.bottom + a.top) / 2 - h / 2;
        a.bottom = a.top + h;
        self.extract(a);
        self
    }

    /// Returns the characters that have been added to this CAPTCHA.
    pub fn chars(&self) -> Vec<char> {
        self.chars.clone()
    }

    /// Returns the characters that have been added to this CAPTCHA collected into a string.
    pub fn chars_as_string(&self) -> String {
        self.chars.iter().collect()
    }

    /// Adds the given number of random characters to the CAPTCHA using the current font.
    pub fn add_chars(&mut self, n: u32) -> &mut Self {
        for _ in 0..n {
            self.add_char();
        }
        self
    }

    fn apply_transformations(&self) -> Image {
        let mut i = self.img.clone();
        if self.color.is_some() {
            i.set_color(&self.color.unwrap());
        }
        i
    }

    /// Returns the CAPTCHA as a png image.
    ///
    /// Returns `None` on error.
    pub fn as_png(&self) -> Option<Vec<u8>> {
        let i = self.apply_transformations();
        i.as_png()
    }

    /// Returns a tuple which contains the characters that have been added to this CAPTCHA
    /// as a string and the image encoded as a PNG.
    ///
    /// Returns `None` on error.
    pub fn as_tuple(&self) -> Option<(String, Vec<u8>)> {
        self.as_png().map(|p| (self.chars_as_string(), p))
    }

    /// Returns the supported characters of the current font.
    pub fn supported_chars(&self) -> Vec<char> {
        self.font.chars()
    }
}
