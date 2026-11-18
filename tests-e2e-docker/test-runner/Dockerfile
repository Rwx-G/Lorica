FROM alpine:3.20
# python3 is used by the bot-protection smoke to mine the JS PoW
# challenge from a shell (SHA-256 search until N leading zero bits).
# Alpine's python3 is ~10 MiB - still lightweight for the test-runner
# image.
# socat is used by the log-sinks profile: the syslog-collector service
# reuses this image with an entrypoint override that runs a plain socat
# TCP listener appending received frames to /shared/syslog.log.
# iproute2 gives the L4 phase `ss` (Story 12.2), openssh-client the SSH
# stream client (Story 12.11); both approved in Story 12.12 D-p.
RUN apk add --no-cache bash curl iproute2 jq openssh-client openssl python3 socat sqlite
RUN adduser -D -s /sbin/nologin testuser
# The management API now serves TLS with an auto-generated self-signed
# cert (Story 8.8). Every test curl targets an internal, trusted
# endpoint, so accept self-signed certs globally rather than sprinkling
# `-k` across every script. `CURL_HOME` is honored before `$HOME`, so a
# single world-readable curlrc covers every service regardless of which
# user it runs as (the audit smoke runs as root to tamper the mounted
# DB; others run as testuser).
ENV CURL_HOME=/etc/curl
RUN mkdir -p /etc/curl && printf 'insecure\n' > /etc/curl/.curlrc && chmod 0644 /etc/curl/.curlrc
WORKDIR /tests
COPY helpers.sh run-tests.sh run-tests-workers.sh run-otel-smoke.sh run-geoip-smoke.sh run-bot-smoke.sh run-rdns-smoke.sh run-cert-export-smoke.sh run-ai-bot-smoke.sh run-rbac-smoke.sh run-audit-smoke.sh run-hot-upgrade-smoke.sh run-log-sinks-smoke.sh run-log-sinks-workers-smoke.sh run-acme-smoke.sh run-cluster-smoke.sh run-cluster-restart-smoke.sh run-cluster-revocation-smoke.sh run-automation-smoke.sh run-capture-smoke.sh run-capture-workers-smoke.sh run-adcs-smoke.sh capture-helpers.sh ./
RUN chmod +x run-tests.sh run-tests-workers.sh run-otel-smoke.sh run-geoip-smoke.sh run-bot-smoke.sh run-rdns-smoke.sh run-cert-export-smoke.sh run-ai-bot-smoke.sh run-rbac-smoke.sh run-audit-smoke.sh run-hot-upgrade-smoke.sh run-log-sinks-smoke.sh run-log-sinks-workers-smoke.sh run-acme-smoke.sh run-cluster-smoke.sh run-cluster-restart-smoke.sh run-cluster-revocation-smoke.sh run-automation-smoke.sh run-capture-smoke.sh run-capture-workers-smoke.sh run-adcs-smoke.sh helpers.sh capture-helpers.sh
# The L4 phase's in-container tools and its report (Story 12.12 D-c).
COPY l4/ l4/
USER testuser
ENTRYPOINT ["bash", "run-tests.sh"]
