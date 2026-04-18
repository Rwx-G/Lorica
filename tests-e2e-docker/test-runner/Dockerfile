FROM alpine:3.20
# python3 is used by the bot-protection smoke to mine the JS PoW
# challenge from a shell (SHA-256 search until N leading zero bits).
# Alpine's python3 is ~10 MiB — still lightweight for the test-runner
# image.
RUN apk add --no-cache curl jq bash python3 openssl
RUN adduser -D -s /sbin/nologin testuser
WORKDIR /tests
COPY helpers.sh run-tests.sh run-tests-workers.sh run-otel-smoke.sh run-geoip-smoke.sh run-bot-smoke.sh run-rdns-smoke.sh ./
RUN chmod +x run-tests.sh run-tests-workers.sh run-otel-smoke.sh run-geoip-smoke.sh run-bot-smoke.sh run-rdns-smoke.sh helpers.sh
USER testuser
ENTRYPOINT ["bash", "run-tests.sh"]
