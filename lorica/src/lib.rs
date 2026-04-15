// Copyright 2024 Cloudflare, Inc.
// Copyright 2026 Rwx-G (Lorica)
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

#![warn(clippy::all)]
#![allow(clippy::new_without_default)]
#![allow(clippy::type_complexity)]
#![allow(clippy::match_wild_err_arm)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::upper_case_acronyms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Lorica
//!
//! A modern, secure, dashboard-first reverse proxy built in Rust.
//! Forked from Cloudflare's Pingora.
//!
//! # Features
//! - HTTP/1.x and HTTP/2
//! - TLS termination with rustls (no OpenSSL)
//! - Zero downtime upgrade
//!
//! # Usage
//! This crate provides low level service and protocol implementation and abstraction.
//!
//! If looking to build a (reverse) proxy, see [`lorica-proxy`](https://docs.rs/lorica-proxy) crate.

pub mod connection_filter;
pub mod geoip;
pub mod mtls;
pub mod otel;
pub mod proxy_wiring;
pub mod reload;

pub use lorica_core::*;

/// HTTP header objects that preserve http header cases
pub mod http {
    pub use lorica_http::*;
}

#[cfg(feature = "lb")]
#[cfg_attr(docsrs, doc(cfg(feature = "lb")))]
/// Load balancing recipes
pub mod lb {
    pub use lorica_lb::*;
}

#[cfg(feature = "proxy")]
#[cfg_attr(docsrs, doc(cfg(feature = "proxy")))]
/// Proxying recipes
pub mod proxy {
    pub use lorica_proxy::*;
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
/// Timeouts and other useful time utilities
pub mod time {
    pub use lorica_timeout::*;
}

/// A useful set of types for getting started
pub mod prelude {
    pub use lorica_core::prelude::*;
    pub use lorica_http::prelude::*;
    pub use lorica_timeout::*;

    #[cfg(feature = "lb")]
    #[cfg_attr(docsrs, doc(cfg(feature = "lb")))]
    pub use lorica_lb::prelude::*;

    #[cfg(feature = "proxy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "proxy")))]
    pub use lorica_proxy::prelude::*;

    #[cfg(feature = "time")]
    #[cfg_attr(docsrs, doc(cfg(feature = "time")))]
    pub use lorica_timeout::*;
}
