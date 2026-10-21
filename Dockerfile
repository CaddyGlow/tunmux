FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY launchd ./launchd
COPY systemd ./systemd
COPY benches ./benches
COPY tests ./tests
COPY LICENSE README.md ./
COPY xtask ./xtask
COPY tunmux-build-version ./tunmux-build-version

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
