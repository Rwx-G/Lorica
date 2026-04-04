FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /backend-h2 .

FROM alpine:3.19
RUN adduser -D -s /sbin/nologin appuser
COPY --from=builder /backend-h2 /backend-h2
USER appuser
CMD ["/backend-h2"]
