FROM alpine:3.20
RUN apk add --no-cache curl jq bash
RUN adduser -D -s /sbin/nologin testuser
WORKDIR /tests
COPY helpers.sh run-tests.sh run-tests-workers.sh run-otel-smoke.sh ./
RUN chmod +x run-tests.sh run-tests-workers.sh run-otel-smoke.sh helpers.sh
USER testuser
ENTRYPOINT ["bash", "run-tests.sh"]
