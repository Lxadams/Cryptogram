# Docker

`docker-compose.yml` here defines three services. Run all commands below from
this `code/` directory.

## server

Relay server, listens on UDP 443.

```
docker compose up -d server
docker compose logs -f server
```

The logs print a line like:

```
Server Static Pubkey: 9900a0fda7a1b91c336362ed794fafb4b5fa27fcae4712ac43440c602b0b9942
```

Every client needs that hex string to authenticate the relay during its
handshake. The identity itself is persisted in the `server_identity`
volume, so it stays the same across restarts (`docker compose restart
server`) — only removing the volume (`docker compose down -v`) resets it.

## client

Interactive CLI peer. Run with `docker compose run`, not `up` — it's a
stdin REPL, not a long-running service.

```
SERVER_PUBKEY=<hex from server logs> docker compose run --rm client
```

Once connected it prints your own routing token + Ed25519 pubkey, then
accepts commands:

```
connect <their_routing_token_hex> <their_ed25519_pub_hex>
msg <routing_token_hex> <message text...>
```

Session/identity state persists in the `client_state` volume, shared by
every `docker compose run client` invocation — fine for one peer. To run
several independent peers at once (e.g. to test two people messaging each
other, like `runpeer.sh` does for the desktop app), give each run its own
volume instead of the shared one:

```
SERVER_PUBKEY=<hex> docker compose run --rm -v alice_state:/data client
SERVER_PUBKEY=<hex> docker compose run --rm -v bob_state:/data client
```

## frontend-builder

Not a running service — `FROM scratch` with no shell, nothing to `docker
run`. It compiles the Tauri desktop shell into a Linux bundle
(`.deb`/AppImage) via `docker build`, mainly useful for CI. Kept out of
`docker compose up` by its `build-only` profile.

```
docker compose build frontend-builder
docker compose create frontend-builder
docker cp $(docker compose ps -a -q frontend-builder):/bundle ./frontend-bundle
docker compose rm -f frontend-builder
```

`./frontend-bundle/` then contains the built `.deb` and AppImage. This
only produces the Linux bundle — Windows/macOS builds need native
runners, since a Linux container can't cross-compile Tauri's GUI shell.
