FROM rust:1-slim AS builder
WORKDIR /app
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src
WORKDIR /app/server
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/server/target/release/server /usr/local/bin/server
WORKDIR /data
ENV BIND_ADDR=0.0.0.0:443
EXPOSE 443/udp
EXPOSE 443/tcp
CMD ["server"]