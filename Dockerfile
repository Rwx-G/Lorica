# Production multi-stage Dockerfile for Lorica.
# Produces a minimal Debian-slim image with the lorica binary.
#
# Build:
#   docker build -t lorica .
#
# Run:
#   docker run -p 8080:8080 -p 8443:8443 -p 9443:9443 \
#     -v lorica-data:/var/lib/lorica lorica

# Stage 1: Build frontend
FROM node:22-slim AS frontend
WORKDIR /app/lorica-dashboard/frontend
COPY lorica-dashboard/frontend/package.json lorica-dashboard/frontend/pnpm-lock.yaml* lorica-dashboard/frontend/package-lock.json* ./
RUN npm i -g pnpm && (pnpm install --frozen-lockfile 2>/dev/null || npm ci)
COPY lorica-dashboard/frontend/ ./
RUN npm run build

# Stage 2: Build Rust binary
FROM rust:1-bookworm AS builder
RUN apt-get update && \
    apt-get install -y cmake pkg-config protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Copy workspace root files
COPY Cargo.toml Cargo.lock ./

# Copy all workspace crates
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
COPY lorica-worker/ lorica-worker/
COPY lorica-command/ lorica-command/
COPY lorica-bench/ lorica-bench/
COPY lorica-notify/ lorica-notify/
COPY lorica-waf/ lorica-waf/
COPY tinyufo/ tinyufo/

# Copy pre-built frontend
COPY --from=frontend /app/lorica-dashboard/frontend/dist/ lorica-dashboard/frontend/dist/
ENV SKIP_FRONTEND_BUILD=1

RUN cargo build --release --bin lorica

# Stage 3: Minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin -d /var/lib/lorica lorica && \
    mkdir -p /var/lib/lorica && \
    chown lorica:lorica /var/lib/lorica

COPY --from=builder /app/target/release/lorica /usr/bin/lorica

USER lorica
VOLUME /var/lib/lorica

EXPOSE 8080 8443 9443

ENTRYPOINT ["lorica"]
CMD ["--data-dir", "/var/lib/lorica"]
