# Load generators and measurement tools of the Story 12.12 performance
# phase (D-i, D-j), also used by the L4 phase's DNS load generator
# (12.5 IV2). Test image only.
#
# - iperf3 and dnsperf come from Debian bookworm, distribution-signed.
# - oha is a pinned upstream release binary, checked against the SHA-256
#   recorded below before it is installed. Upstream publishes the same
#   digest on the release asset; Story 12.12 "Resolved" records both.
# - python3 runs the standard-library tools Lot M adds next to this file.
#
# amd64 only: the pinned oha asset is the linux-amd64 build.
FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG OHA_VERSION=1.16.0
ARG OHA_SHA256=620bb9e16fb53eabc9a3fc45f88bdb41fefa3fee5c05e75892011ce320391716

# iperf3's postinst asks whether to start a system daemon; the
# non-interactive frontend takes the default (no daemon).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsperf \
        iperf3 \
        python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --retry 3 -o /usr/local/bin/oha \
        "https://github.com/hatoo/oha/releases/download/v${OHA_VERSION}/oha-linux-amd64" \
    && echo "${OHA_SHA256}  /usr/local/bin/oha" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/oha

COPY l4_connect_latency.py udp_echo_peers.py /opt/perf/

RUN useradd -r -u 10001 -s /usr/sbin/nologin perf
WORKDIR /perf
USER perf
CMD ["sleep", "infinity"]
