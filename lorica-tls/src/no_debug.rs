// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Inline replacement for the `no_debug = "3.1.0"` crate (audit
//! SC-L-3). The upstream crate is a single-file macro that was
//! flagged unmaintained since 2022 and represents a supply-chain
//! takeover surface disproportionate to its trivial scope. This
//! module reproduces the subset of the API the Lorica workspace
//! uses: the `NoDebug<T>` wrapper (with `Deref` / `DerefMut` / `From`
//! for transparent access), plus empty stand-ins for `Ellipses` and
//! `WithTypeInfo` so the public `pub use` in `lib.rs` stays
//! backwards-compatible.

use std::fmt;
use std::ops::{Deref, DerefMut};

/// Wraps a value and replaces its `Debug` formatting with a fixed
/// placeholder ("..."), so a parent `#[derive(Debug)]` struct can
/// redact a field that is uninteresting or prints a huge blob.
///
/// Behaviour matches `no_debug::NoDebug` from the upstream crate:
/// `Deref` / `DerefMut` yield the inner value transparently, `From<T>`
/// wraps eagerly. Construction via `NoDebug(value)` also works
/// (tuple-struct syntax).
pub struct NoDebug<T>(pub T);

impl<T> NoDebug<T> {
    /// Wrap `value` so its `Debug` output is replaced with "...".
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Unwrap and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for NoDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("...")
    }
}

impl<T> Deref for NoDebug<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NoDebug<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<T> for NoDebug<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Default> Default for NoDebug<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Clone> Clone for NoDebug<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Tag stand-in for the upstream `no_debug::Ellipses` marker. Lorica
/// does not read this type; kept as a re-exported unit so the
/// public `pub use no_debug::Ellipses` in `lib.rs` stays valid.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ellipses;

/// Tag stand-in for the upstream `no_debug::WithTypeInfo` marker.
/// Same rationale as [`Ellipses`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WithTypeInfo;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_inner() {
        let n: NoDebug<Vec<u32>> = NoDebug::new(vec![1, 2, 3]);
        assert_eq!(format!("{:?}", n), "...");
    }

    #[test]
    fn deref_passes_through() {
        let n = NoDebug::new(String::from("secret"));
        assert_eq!(n.len(), 6);
        assert_eq!(&*n, "secret");
    }

    #[test]
    fn deref_mut_allows_mutation() {
        let mut n = NoDebug::new(String::from("hello"));
        n.push_str(" world");
        assert_eq!(&*n, "hello world");
    }

    #[test]
    fn into_inner_unwraps() {
        let n = NoDebug::new(42u32);
        assert_eq!(n.into_inner(), 42);
    }

    #[test]
    fn from_wraps_eagerly() {
        let n: NoDebug<i32> = 7.into();
        assert_eq!(*n, 7);
    }
}
