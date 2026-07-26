FROM rust:1-slim AS builder
WORKDIR /app
COPY utils ./utils
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src
WORKDIR /app/server
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/server/target/release/server /usr/local/bin/server
EXPOSE 8080/udp
CMD ["server"]