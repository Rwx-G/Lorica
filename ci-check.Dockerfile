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

# What this runs of .github/workflows/ci.yml, and what it does not.
#
# Run: the frontend build, check and lint of the Lint job; every
# `run: cargo fmt|clippy|test` line of the workflow, read from it rather
# than copied here, in the workflow's order and with the RUSTFLAGS its
# toolchain action exports; the frontend tests; the release build and
# the binary check of Build & Package.
#
# Not run: Semgrep, cargo audit, the lorica-mcp dependency check, the
# seccomp regression probes (they need systemd-run), coverage, the Docker
# e2e suite, the packages and their install and upgrade jobs (they need a
# host booted with systemd; dist/tests holds the scripts), the tag
# signature check and the release.
#
# The crate lists used to be copied into this file. The copy drifted: six
# of the fourteen product crates were tested here, `lorica` not at all,
# and two product crates sat in a forked-crate step whose failures were
# ignored, while this file said it mirrored CI.

# ===== JOB 1: LINT =====
RUN echo "===== LINT: Build, check and lint the frontend =====" \
    && cd lorica-dashboard/frontend \
    && npm ci \
    && npm run build \
    && npm run check \
    && npm run lint

# The frontend is built above, so the crates embedding it skip the rebuild,
# as they do in CI, where every cargo step sets SKIP_FRONTEND_BUILD.
ENV SKIP_FRONTEND_BUILD=1 RUSTFLAGS="-D warnings"

# ===== JOBS 1 and 2: every cargo gate the workflow runs =====
RUN grep -E '^\s+run: cargo (fmt|clippy|test)' .github/workflows/ci.yml \
        | sed -E 's/^\s+run: //' | tr -d '\r' > /tmp/ci-cargo-gates \
    && test -s /tmp/ci-cargo-gates \
    && while read -r gate; do \
           echo "===== CI: $gate =====" && sh -c "$gate" || exit 1; \
       done < /tmp/ci-cargo-gates

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
    && echo "  THE CI CHECKS LISTED AT THE TOP PASSED" \
    && echo "============================================"
