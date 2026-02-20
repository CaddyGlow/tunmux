FROM rust:1-bookworm AS builder

ARG TUNMUX_GIT_TAG=dev
ENV TUNMUX_GIT_TAG=${TUNMUX_GIT_TAG}

WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/tunmux /usr/local/bin/tunmux

ENTRYPOINT ["/usr/local/bin/tunmux"]
