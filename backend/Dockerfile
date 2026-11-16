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
    ca-certificates libssl3 zlib1g zip unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=zsign-builder /usr/local/bin/zsign /usr/local/bin/zsign
COPY --from=go-builder /out/signer-server /usr/local/bin/signer-server

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8095
CMD ["/usr/local/bin/signer-server"]
