FROM rust:1-slim AS builder
WORKDIR /app
# Path dependencies of the client (RaptorQ FEC, and the client <-> relay link
# protocol), resolved as ../fec and ../relay-link.
COPY fec/Cargo.toml ./fec/
COPY fec/src ./fec/src
COPY relay-link/Cargo.toml ./relay-link/
COPY relay-link/src ./relay-link/src
COPY client/Cargo.toml client/Cargo.lock ./client/
COPY client/src ./client/src
WORKDIR /app/client
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/client/target/release/client /usr/local/bin/client
WORKDIR /data
# Defaults match the CLI's own local-dev defaults (see code/client/src/main.rs);
# override SERVER_ADDR to reach a relay that isn't on localhost (e.g. the
# "server" Compose service). Session/identity state is written under /data
# so it can be mounted as a volume per peer.
ENV SERVER_ADDR=127.0.0.1:4430
ENV E2E_STATE_FILE=/data/client_state.json
ENTRYPOINT ["client"]
