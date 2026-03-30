# Stage 1: Build frontend
FROM node:22-slim AS frontend
WORKDIR /app/lorica-dashboard/frontend
COPY lorica-dashboard/frontend/package.json lorica-dashboard/frontend/package-lock.json* ./
RUN npm ci
COPY lorica-dashboard/frontend/ ./
RUN npm run build

# Stage 2: Build Rust binary
FROM rust:1.88-bookworm AS builder
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
COPY lorica-pool/ lorica-pool/
COPY lorica-proxy/ lorica-proxy/
COPY lorica-runtime/ lorica-runtime/
COPY lorica-timeout/ lorica-timeout/
COPY lorica-tls/ lorica-tls/
COPY tinyufo/ tinyufo/

# Copy pre-built frontend into the dashboard crate
COPY --from=frontend /app/lorica-dashboard/frontend/dist/ lorica-dashboard/frontend/dist/

# Build with SKIP_FRONTEND_BUILD since we already built it
ENV SKIP_FRONTEND_BUILD=1
RUN cargo build --release -p lorica

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates socat && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false lorica
RUN mkdir -p /var/lib/lorica && chown lorica:lorica /var/lib/lorica

COPY --from=builder /app/target/release/lorica /usr/local/bin/lorica
COPY tests-e2e-docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9443 8080 8443

ENTRYPOINT ["/entrypoint.sh"]
