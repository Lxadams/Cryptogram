# Bookworm, as the runtime image below: a newer glibc in the builder would
# leave the binary needing symbols bookworm lacks (any bundled C code picks
# up glibc 2.38's __isoc23_strtol, as the client's SQLCipher does).
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
# Path dependency of the server (the client <-> relay link protocol), resolved
# as ../relay-link.
COPY relay-link/Cargo.toml ./relay-link/
COPY relay-link/src ./relay-link/src
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src
WORKDIR /app/server
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/server/target/release/server /usr/local/bin/server
# The relay runs as a user of its own, which can write only /data (where
# its identity key lives). Port 443 is below 1024, which an unprivileged
# user can bind once net.ipv4.ip_unprivileged_port_start is 0: Docker's
# default since 20.10, and deploy.yml sets it too. An identity file a
# root-run relay created in an existing volume is still readable.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin relay \
    && mkdir -p /data && chown relay:relay /data
WORKDIR /data
ENV BIND_ADDR=0.0.0.0:443
EXPOSE 443/udp
USER relay
CMD ["server"]