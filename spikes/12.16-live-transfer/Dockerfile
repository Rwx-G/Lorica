# Runtime for the spike: the binary comes from the cargo target volume,
# this image only adds iproute2 for tc netem. Run with --init and
# --cap-add NET_ADMIN (netem on the container's own loopback).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*
