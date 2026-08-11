//! Tower / axum middleware: session cookie authentication,
//! role-based authorization, and per-IP rate limiting.

pub mod auth;
pub mod authorize;
pub mod rate_limit;
