# Stage 1: Build frontend
FROM node:22-slim AS frontend
WORKDIR /app/lorica-dashboard/frontend
COPY lorica-dashboard/frontend/package.json lorica-dashboard/frontend/package-lock.json* ./
RUN npm ci
COPY lorica-dashboard/frontend/ ./
RUN npm run build

# Stage 2: Build Rust binary
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY lorica/ lorica/
COPY lorica-api/ lorica-api/
COPY lorica-cache/ lorica-cache/
COPY lorica-config/ lorica-config/
COPY lorica-core/ lorica-core/
COPY lorica-dashboard/ lorica-dashboard/
COPY lorica-error/ lorica-error/
COPY lorica-header-serde/ lorica-header-serde/
COPY lorica-http/ lorica-http/
COPY lorica-ketama/ lorica-ketama/
COPY lorica-lb/ lorica-lb/
COPY lorica-limits/ lorica-limits/
COPY lorica-lru/ lorica-lru/
COPY lorica-memory-cache/ lorica-memory-cache/
COPY lorica-notify/ lorica-notify/
COPY lorica-pool/ lorica-pool/
COPY lorica-proxy/ lorica-proxy/
COPY lorica-runtime/ lorica-runtime/
COPY lorica-timeout/ lorica-timeout/
COPY lorica-tls/ lorica-tls/
COPY lorica-command/ lorica-command/
COPY lorica-shmem/ lorica-shmem/
COPY lorica-waf/ lorica-waf/
COPY lorica-worker/ lorica-worker/
COPY lorica-bench/ lorica-bench/
COPY lorica-geoip/ lorica-geoip/
COPY lorica-challenge/ lorica-challenge/
COPY tinyufo/ tinyufo/

# Copy pre-built frontend into the dashboard crate
COPY --from=frontend /app/lorica-dashboard/frontend/dist/ lorica-dashboard/frontend/dist/

# Build with SKIP_FRONTEND_BUILD since we already built it. Cargo
# features can be toggled at build time via the `LORICA_FEATURES`
# build arg (e.g. `--build-arg LORICA_FEATURES=otel`); defaults to
# the crate's default feature set.
ARG LORICA_FEATURES=""
ENV SKIP_FRONTEND_BUILD=1
RUN if [ -n "$LORICA_FEATURES" ]; then \
        cargo build --release -p lorica --features "$LORICA_FEATURES"; \
    else \
        cargo build --release -p lorica; \
    fi

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates socat curl sqlite3 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false lorica
RUN mkdir -p /var/lib/lorica && chown lorica:lorica /var/lib/lorica

COPY --from=builder /app/target/release/lorica /usr/local/bin/lorica
COPY tests-e2e-docker/entrypoint.sh /entrypoint.sh
COPY tests-e2e-docker/entrypoint-workers.sh /entrypoint-workers.sh
COPY tests-e2e-docker/entrypoint-geoip.sh /entrypoint-geoip.sh
COPY tests-e2e-docker/entrypoint-otel.sh /entrypoint-otel.sh
COPY tests-e2e-docker/entrypoint-otel-workers.sh /entrypoint-otel-workers.sh
RUN chmod +x /entrypoint.sh /entrypoint-workers.sh /entrypoint-geoip.sh /entrypoint-otel.sh /entrypoint-otel-workers.sh

# Pre-create the `/shared` mount point owned by the non-root lorica
# user so the entrypoint can write `/shared/admin_password` after the
# volume is mounted over it. Without this, a freshly-created Docker
# named volume inherits the parent directory's owner (root), and the
# subsequent write silently fails because the lorica user cannot
# write to a root-owned directory.
RUN mkdir -p /shared && chown lorica:lorica /shared

EXPOSE 9443 8080 8443

# Drop root for defense-in-depth. The exposed ports (9443/8080/8443)
# are all above 1024 so binding does not need CAP_NET_BIND_SERVICE,
# and the entrypoints no longer rely on `su` to switch users.
USER lorica
ENTRYPOINT ["/entrypoint.sh"]
