# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM golang:latest AS builder

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}

WORKDIR /app

COPY . .

RUN go clean -modcache && \
    go mod download && \
    go build -o swayrider-api ./cmd/swayrider-api

# Runtime stage
FROM --platform=$TARGETPLATFORM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/swayrider-api .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
