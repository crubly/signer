FROM golang:1.24-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/signer-server ./cmd/server

FROM debian:bookworm-slim AS zsign-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make git ca-certificates pkg-config libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /zsign \
    && cd /zsign/build/linux \
    && make \
    && cp /zsign/bin/zsign /usr/local/bin/zsign

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl libssl3 zlib1g zip unzip \
    && curl -fsSL https://www.apple.com/appleca/AppleIncRootCertificate.cer -o /tmp/apple_root.cer \
    && openssl x509 -inform der -in /tmp/apple_root.cer -out /usr/local/share/ca-certificates/apple-root-ca.crt \
    && curl -fsSL https://www.apple.com/certificateauthority/AppleRootCA-G3.cer -o /tmp/apple_g3.cer \
    && openssl x509 -inform der -in /tmp/apple_g3.cer -out /usr/local/share/ca-certificates/apple-root-ca-g3.crt \
    && rm -f /tmp/apple_root.cer /tmp/apple_g3.cer \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=zsign-builder /usr/local/bin/zsign /usr/local/bin/zsign
COPY --from=go-builder /out/signer-server /usr/local/bin/signer-server

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8095
CMD ["/usr/local/bin/signer-server"]
