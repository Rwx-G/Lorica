FROM alpine:3.20
RUN apk add --no-cache curl jq bash
WORKDIR /tests
COPY run-tests.sh .
RUN chmod +x run-tests.sh
ENTRYPOINT ["bash", "run-tests.sh"]
