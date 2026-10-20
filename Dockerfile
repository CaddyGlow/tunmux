FROM rust:1-bookworm AS builder

ARG TUNMUX_GIT_TAG=dev
ENV TUNMUX_GIT_TAG=${TUNMUX_GIT_TAG}

WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src ./src
COPY launchd ./launchd
COPY systemd ./systemd
COPY benches ./benches
COPY tests ./tests
COPY LICENSE README.md ./
COPY third_party ./third_party

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r tunmux && useradd -r -m -g tunmux -s /sbin/nologin tunmux

COPY --from=builder /app/target/release/tunmux /usr/local/bin/tunmux

COPY --from=builder /app/LICENSE /app/README.md /usr/share/doc/tunmux/

USER tunmux

ENTRYPOINT ["/usr/local/bin/tunmux"]
