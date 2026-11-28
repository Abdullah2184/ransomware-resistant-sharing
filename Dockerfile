# syntax=docker/dockerfile:1.7
# Multi-stage build for RRDS runtime services (`gateway`, `indexer`, `migrate`).
#
# Build per-role images for `infra/compose/gateway.yaml` and `infra/compose/indexer.yaml`:
#   docker build --target gateway -t rrds-gateway:local .
#   docker build --target indexer -t rrds-indexer:local .
#   docker build --target migrate -t rrds-migrate:local .

FROM rust:1.99.1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps ./apps
COPY crates ./crates
COPY services ./services

RUN cargo build --release --locked \
    -p gateway \
    -p indexer \
    -p metadata-store --bin rrds-migrate

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin rrds
USER 10001:10001
WORKDIR /app

FROM runtime-base AS gateway
COPY --from=builder /src/target/release/gateway /usr/local/bin/gateway
ENV RRDS_ENV=production
ENV DATABASE_MIGRATION_MODE=verify
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]

FROM runtime-base AS indexer
COPY --from=builder /src/target/release/indexer /usr/local/bin/indexer
ENV RRDS_ENV=production
ENV DATABASE_MIGRATION_MODE=verify
ENTRYPOINT ["/usr/local/bin/indexer"]

FROM runtime-base AS migrate
COPY --from=builder /src/target/release/rrds-migrate /usr/local/bin/rrds-migrate
ENTRYPOINT ["/usr/local/bin/rrds-migrate"]
