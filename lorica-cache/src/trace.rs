// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! No-op distributed tracing stubs
//!
//! These types replace the former `cf-rustracing` / `cf-rustracing-jaeger`
//! dependency with zero-cost no-op implementations that expose the same
//! public API surface.

use std::time::SystemTime;

use crate::{CacheMeta, CachePhase, HitStatus};

/// A no-op tracing tag.
#[derive(Debug, Clone)]
pub struct Tag {
    _private: (),
}

impl Tag {
    /// Create a tag (does nothing).
    pub fn new<V>(_key: &'static str, _value: V) -> Self {
        Tag { _private: () }
    }
}

/// A no-op span handle.
#[derive(Debug, Clone)]
pub struct SpanHandle {
    _private: (),
}

/// A no-op tracing span.
#[derive(Debug)]
pub struct Span {
    _private: (),
}

impl Span {
    /// Return an inactive (no-op) span.
    pub fn inactive() -> Self {
        Span { _private: () }
    }

    /// Create a child span (no-op). The callback is accepted but never invoked
    /// in the real cf-rustracing either when the span is inactive.
    pub fn child<F>(&self, _name: &'static str, _f: F) -> Span
    where
        F: FnOnce(SpanBuilder) -> Span,
    {
        Span::inactive()
    }

    /// Return a handle to this span (no-op).
    pub fn handle(&self) -> SpanHandle {
        SpanHandle { _private: () }
    }

    /// Set a single tag via a closure (no-op).
    pub fn set_tag<F: FnOnce() -> Tag>(&mut self, _f: F) {}

    /// Set multiple tags via a closure (no-op).
    pub fn set_tags<I, F>(&mut self, _f: F)
    where
        I: IntoIterator<Item = Tag>,
        F: FnOnce() -> I,
    {
    }

    /// Set a custom finish time (no-op).
    pub fn set_finish_time<F: FnOnce() -> SystemTime>(&mut self, _f: F) {}
}

/// Placeholder so `Span::child` closure signature compiles.
#[derive(Debug)]
pub struct SpanBuilder {
    _private: (),
}

impl SpanBuilder {
    /// Start the span (no-op).
    pub fn start(self) -> Span {
        Span::inactive()
    }
}

#[derive(Debug)]
pub(crate) struct CacheTraceCTX {
    // parent span
    pub cache_span: Span,
    // only spans across multiple calls need to store here
    pub miss_span: Span,
    pub hit_span: Span,
}

pub fn tag_span_with_meta(_span: &mut Span, _meta: &CacheMeta) {
    // no-op
}

impl CacheTraceCTX {
    pub fn new() -> Self {
        CacheTraceCTX {
            cache_span: Span::inactive(),
            miss_span: Span::inactive(),
            hit_span: Span::inactive(),
        }
    }

    pub fn enable(&mut self, cache_span: Span) {
        self.cache_span = cache_span;
    }

    pub fn get_cache_span(&self) -> SpanHandle {
        self.cache_span.handle()
    }

    #[inline]
    pub fn child(&self, name: &'static str) -> Span {
        self.cache_span.child(name, |o| o.start())
    }

    pub fn start_miss_span(&mut self) {
        self.miss_span = self.child("miss");
    }

    pub fn get_miss_span(&self) -> SpanHandle {
        self.miss_span.handle()
    }

    pub fn finish_miss_span(&mut self) {
        self.miss_span.set_finish_time(SystemTime::now);
    }

    pub fn start_hit_span(&mut self, phase: CachePhase, hit_status: HitStatus) {
        self.hit_span = self.child("hit");
        self.hit_span.set_tag(|| Tag::new("phase", phase.as_str()));
        self.hit_span
            .set_tag(|| Tag::new("status", hit_status.as_str()));
    }

    pub fn get_hit_span(&self) -> SpanHandle {
        self.hit_span.handle()
    }

    pub fn finish_hit_span(&mut self) {
        self.hit_span.set_finish_time(SystemTime::now);
    }

    pub fn log_meta_in_hit_span(&mut self, meta: &CacheMeta) {
        tag_span_with_meta(&mut self.hit_span, meta);
    }

    pub fn log_meta_in_miss_span(&mut self, meta: &CacheMeta) {
        tag_span_with_meta(&mut self.miss_span, meta);
    }
}
