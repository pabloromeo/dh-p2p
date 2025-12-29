# syntax=docker/dockerfile:1
#
# Multi-stage image that builds the Rust binary and ships a slim runtime.
# Runtime flags are passed directly to the app (see `ENTRYPOINT`).
FROM rust:1.82-bullseye AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo fetch --locked

# Build
COPY src ./src
RUN cargo build --release --locked

FROM debian:bullseye-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/dh-p2p /usr/local/bin/dh-p2p

# Default to info logs; override with -e RUST_LOG=trace, etc.
ENV RUST_LOG=info

# Default listener port (change with -p/--port)
EXPOSE 1554/tcp

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "dh-p2p"]
# Show CLI help if no args are provided. Override with runtime args, e.g.:
# docker run --rm -p 1554:1554 ghcr.io/you/dh-p2p <SERIAL> -p 0.0.0.0:1554:554 -v
CMD ["--help"]

