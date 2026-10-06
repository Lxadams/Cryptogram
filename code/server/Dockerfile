FROM rust:1-slim AS builder
WORKDIR /app
# The link protocol, shared with the client (path dependency ../cell).
COPY cell/Cargo.toml ./cell/
COPY cell/src ./cell/src
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src
WORKDIR /app/server
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/server/target/release/server /usr/local/bin/server
# Keys live in /data (a volume): the self-signed certificate and its key, or
# none if TLS_CERT/TLS_KEY point at a real certificate (e.g. Let's Encrypt's,
# mounted read-only), and the access key. They must survive redeploys: the
# app ships with the key's pin and the access key.
WORKDIR /data
ENV BIND_ADDR=0.0.0.0:443
# QUIC (HTTP/3 to anyone without the app's access key).
EXPOSE 443/udp
CMD ["server"]