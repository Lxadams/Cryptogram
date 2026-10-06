FROM rust:1-slim AS builder
WORKDIR /app
# Path dependencies of the client: RaptorQ FEC (../fec), the link protocol
# (../cell), and the relay, which its tests run in-process (../server; Cargo
# needs its manifest even though a release build doesn't compile it).
COPY fec/Cargo.toml ./fec/
COPY fec/src ./fec/src
COPY cell/Cargo.toml ./cell/
COPY cell/src ./cell/src
COPY server/Cargo.toml ./server/
COPY server/src ./server/src
COPY client/Cargo.toml client/Cargo.lock ./client/
COPY client/src ./client/src
WORKDIR /app/client
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/client/target/release/client /usr/local/bin/client
WORKDIR /data
# Defaults match the CLI's own local-dev defaults (see code/client/src/main.rs);
# override SERVER_ADDR to reach a relay that isn't on localhost (an IP
# address is used as is; a name is looked up over DNS-over-HTTPS). The
# relay's keys come from SERVER_PUBKEY (or the one argument) and
# SERVER_ACCESS_KEY. Session/identity state is written under /data so it can
# be mounted as a volume per peer.
ENV SERVER_ADDR=127.0.0.1:4430
ENV E2E_STATE_FILE=/data/client_state.json
ENTRYPOINT ["client"]
