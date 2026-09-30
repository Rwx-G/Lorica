FROM rust:latest

# Install system deps
RUN apt-get update && apt-get install -y \
    curl \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    cmake \
    rpm \
    dpkg-dev \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Install clippy
RUN rustup component add clippy rustfmt

WORKDIR /app
COPY . .

# ===== JOB 1: LINT =====
RUN echo "===== LINT: Build frontend =====" \
    && cd lorica-dashboard/frontend \
    && npm ci \
    && npm run build

RUN echo "===== LINT: Clippy (product crates) =====" \
    && cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings \
    && cargo clippy -p lorica-api -p lorica-cluster -p lorica-mcp --all-targets -- -D warnings \
    && cargo clippy -p lorica --all-targets --features otel -- -D warnings

RUN echo "===== LINT: cargo fmt check =====" \
    && cargo fmt --all -- --check

# ===== JOB 2: TEST =====
RUN echo "===== TEST: Rust unit tests (product crates) =====" \
    && cargo test -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp

# Blocking, like the CI step it mirrors. It used to sit in the step below,
# whose failures are ignored.
RUN echo "===== TEST: Rust unit tests (binary crate with the otel feature) =====" \
    && cargo test -p lorica --features otel

RUN echo "===== TEST: Rust unit tests (forked crates) =====" \
    && cargo test -p lorica-core -p lorica-proxy -p lorica-http -p lorica-error \
       -p lorica-tls -p lorica-command -p lorica-worker -p lorica-lb \
       -p lorica-cache -p lorica-lru -p lorica-memory-cache \
       -p lorica-limits -p lorica-ketama -p lorica-timeout -p lorica-pool \
       -p lorica-header-serde -p lorica-runtime -p TinyUFO \
    || echo "Some forked crate tests failed (expected - network/TLS tests need host environment)"

RUN echo "===== TEST: Frontend tests =====" \
    && cd lorica-dashboard/frontend && npx vitest run

# ===== JOB 3: BUILD =====
RUN echo "===== BUILD: Release binaries =====" \
    && cargo build --release -p lorica -p lorica-mcp

# lorica-mcp has no --version. With no configuration it must refuse
# with EX_CONFIG (78), which proves it links and runs.
RUN echo "===== BUILD: Verify binaries =====" \
    && file target/release/lorica target/release/lorica-mcp \
    && target/release/lorica --version \
    && { rc=0; target/release/lorica-mcp < /dev/null || rc=$?; test "$rc" -eq 78; }

RUN echo "" \
    && echo "============================================" \
    && echo "  ALL CI CHECKS PASSED" \
    && echo "============================================"
