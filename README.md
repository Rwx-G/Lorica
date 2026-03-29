# Lorica

![Version](https://img.shields.io/badge/version-0.3.0--dev-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Status](https://img.shields.io/badge/status-early%20development-orange)

A modern, secure, dashboard-first reverse proxy built in Rust. Single binary, embedded control plane, optional WAF. Powered by [Pingora](https://github.com/cloudflare/pingora).

## What It Does

- Proxies HTTP/1.1, HTTP/2, and WebSocket traffic to your backends
- Terminates TLS with rustls - no OpenSSL, no historical CVE surface
- Isolates workers in separate processes: if one crashes, others continue
- Hot-reloads configuration without dropped connections
- Exposes a native REST API and web dashboard on a localhost-only management port
- Optional WAF layer based on OWASP Core Rule Set
- Dual SLA monitoring: passive (real traffic) and active (synthetic probes)
- Built-in load testing with safety guards

## What It Is Not

- Not a web server - Lorica routes traffic and protects it, it does not serve your content
- Not Nginx with a UI bolted on - the dashboard is the product, designed from day one
- Not a framework you have to finish yourself - single binary, `apt install`, done

## Status

Early development. See [docs/](docs/) for project documentation.

## License

Apache-2.0 - see [LICENSE](LICENSE).

Built on [Pingora](https://github.com/cloudflare/pingora) by Cloudflare (Apache-2.0).
Architectural patterns inspired by [Sozu](https://github.com/sozu-proxy/sozu) by Clever Cloud (concepts only, no code reuse).
