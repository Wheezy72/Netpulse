# =============================================================================
# Stage 1: builder — compile the release binary. libpcap-dev is the only
# build-time C dependency; libpcap is dynamically linked into the binary.
# =============================================================================
FROM rust:stable AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libpcap-dev \
       pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation separately from application source so that
# Docker layer caching skips the (slow) dependency build when only src/ changes.
COPY Cargo.toml ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && cargo build --release 2>/dev/null; rm -rf src

COPY src ./src
RUN cargo build --release


# =============================================================================
# Stage 2: runtime — Debian slim with libpcap only. No compiler, no source.
# =============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libpcap0.8 \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/probe /usr/local/bin/probe

ENTRYPOINT ["/usr/local/bin/probe"]

