# Deployment

How to run the relay (and the CLI) somewhere other than your own shell. There are three ways:

1. **Docker Compose** on any machine: the relay, the CLI client, and a Linux bundle build of the desktop app.
2. **EC2 via GitHub Actions**: every push to the `production` branch deploys the relay automatically.
3. **EC2 by hand**: the same deploy, run from WSL or Linux without CI.

To run everything locally without Docker, see the [README quick start](../README.md#quick-start).

---

## 1. Docker Compose

[`code/docker-compose.yml`](../code/docker-compose.yml) defines three services. Every image is built with `code/` as the build context, so run all commands from `code/`.

### server

The relay listens on UDP 443 inside the container (`BIND_ADDR=0.0.0.0:443`), and the port is published on the host.

```bash
docker compose up -d server
docker compose logs -f server
```

The log prints a line like this:

```
Server Static Pubkey: 9900a0fda7a1b91c336362ed794fafb4b5fa27fcae4712ac43440c602b0b9942
```

Every client needs this hex string to authenticate the relay. The identity is stored in the `server_identity` volume (mounted at `/data`), so it survives `docker compose restart server`. Only removing the volume with `docker compose down -v` creates a new one.

### client

This is the interactive CLI peer. Use `docker compose run` rather than `up`: it's a stdin REPL, not a long-running service.

```bash
SERVER_PUBKEY=<hex from the server logs> docker compose run --rm client
```

Inside Compose it reaches the relay at `server:443`. Once connected it prints its routing token and Ed25519 public key, then accepts `connect` and `msg` commands. They're described in the [client README](../code/client/README.md#cli).

The client's state lives in the `client_state` volume, which every `docker compose run client` shares. That's fine for one peer. To run several independent peers, give each run its own volume:

```bash
SERVER_PUBKEY=<hex> docker compose run --rm -v alice_state:/data client
SERVER_PUBKEY=<hex> docker compose run --rm -v bob_state:/data client
```

The CLI saves its keys as **plaintext** JSON in that volume (see [cryptography.md §9](cryptography.md#9-open-issues), H1).

### frontend-builder

This service is build-only. Its final image is `FROM scratch`, with no shell and nothing to run. It compiles the Tauri desktop app into a Linux `.deb` and AppImage. The `build-only` profile keeps it out of `docker compose up`.

```bash
docker compose build frontend-builder
docker compose create frontend-builder
docker cp $(docker compose ps -a -q frontend-builder):/bundle ./frontend-bundle
docker compose rm -f frontend-builder
```

Alternatively, without Compose:

```bash
docker buildx build -f frontend/Dockerfile --target artifacts --output type=local,dest=./frontend-bundle .
```

This only makes Linux bundles. Windows and macOS builds need a native machine or runner (`cargo tauri build`), because a Linux container can't cross-compile Tauri's GUI shell.

---

## 2. EC2: one-time setup

These steps apply to both the CI deploy and the manual one.

- **Install Docker.** EC2 instances don't have it by default, and the deploy doesn't install it. SSH in once and run:
  ```bash
  sudo apt-get update && sudo apt-get install -y docker.io
  sudo usermod -aG docker ubuntu   # so docker works without sudo
  ```
  Log out and back in for the group change to take effect.
- **Open UDP 443** in the instance's security group, with source `0.0.0.0/0`. This is a public relay by design. Leave SSH (22) open to `0.0.0.0/0` as well: GitHub Actions runners have no fixed IP you could allow-list.
- **Use an Elastic IP.** A plain public IP changes when the instance is stopped and started, which would break `EC2_HOST` and every client's saved relay address. An Elastic IP is free while it's attached to a running instance.
- **Instance size.** The image is built in CI and EC2 only loads it, so a free-tier `t2.micro` or `t3.micro` (1 GB RAM) is enough.

---

## 3. EC2 via GitHub Actions

[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml) runs on every push to the **`production`** branch. It:

1. builds the server image: `docker build -t server:latest -f code/server/Dockerfile code`;
2. saves it as `server.tar.gz` and uploads it as a workflow artifact (kept for 2 days);
3. copies it to `/home/ubuntu/` on the instance with `scp`;
4. over SSH: loads the image, replaces the running `server` container, runs `docker image prune -f`, and prints the last 20 log lines.

### GitHub secrets

| Secret | Value |
|---|---|
| `EC2_HOST` | The Elastic IP or DNS name of the instance |
| `EC2_USER` | `ubuntu` for the standard Ubuntu AMI. The copy step always targets `/home/ubuntu/`. |
| `EC2_SSH_KEY` | The **contents** of the key pair's `.pem` file, including the `-----BEGIN…-----` lines. Not a path. |
| `EC2_SSH_PORT` | Optional. Only needed if SSH isn't on port 22. |

---

## 4. EC2 by hand

This does the same as the workflow, run from WSL Ubuntu or Linux. It's useful for a first deploy, or for testing a change before you push to `production`. Remember that the next push to `production` will overwrite whatever you deployed by hand.

**Prerequisites:** Docker running locally, and the instance's `.pem` key stored inside the WSL filesystem. Don't keep it under `/mnt/c/...`, where SSH can't set the file permissions it requires.

```bash
chmod 400 /path/to/key.pem
```

**1. Build and package** (from the repo root; this is the same build CI runs):

```bash
docker build -t server:latest -f code/server/Dockerfile code
docker save server:latest | gzip > server.tar.gz
```

To record which commit is deployed, tag the image with it instead, e.g. `server:$(git rev-parse --short HEAD)`, and use that tag in the commands below.

**2. Copy to the instance:**

```bash
scp -i /path/to/key.pem server.tar.gz ubuntu@<EC2_HOST>:/home/ubuntu/
```

**3. Load and run** (on the instance, via `ssh -i /path/to/key.pem ubuntu@<EC2_HOST>`):

```bash
gunzip -f server.tar.gz
docker load -i server.tar
docker stop server || true
docker rm server || true
docker run -d \
  --name server \
  --restart unless-stopped \
  -p 443:443/udp \
  -v server_identity:/data \
  -e RUST_LOG=info \
  server:latest
rm server.tar
docker image prune -f
```

Keep `-v server_identity:/data` even for a one-off deploy. Without it, every `docker rm` and `docker run` creates a new relay identity, and every client would need the new pubkey.

Steps 2 and 3 can be run as a single command:

```bash
scp -i /path/to/key.pem server.tar.gz ubuntu@<EC2_HOST>:/home/ubuntu/ && \
ssh -i /path/to/key.pem ubuntu@<EC2_HOST> '
  set -e
  gunzip -f server.tar.gz
  docker load -i server.tar
  docker rm -f server 2>/dev/null || true
  docker run -d --name server --restart unless-stopped -p 443:443/udp \
    -v server_identity:/data -e RUST_LOG=info server:latest
  rm server.tar
  docker image prune -f
'
```

---

## 5. After a deploy

**Get the relay's pubkey** for your clients:

```bash
ssh ubuntu@<EC2_HOST> "docker logs server 2>&1 | grep 'Static Pubkey'"
```

On a first boot the log shows:

```
No existing server identity found. Generating new Ed25519 keypair...
UDP server listening on 0.0.0.0:443
Server Static Pubkey: <hex>
```

On later deploys the first line is missing and the pubkey stays the same, which confirms that the `server_identity` volume is working.

**Point clients at the relay.** Both front ends read the relay address from `SERVER_ADDR`, with a default of `127.0.0.1:4430`:

```bash
SERVER_ADDR=<EC2_HOST>:443 ./runpeer.sh                                        # desktop app
SERVER_ADDR=<EC2_HOST>:443 cargo run --manifest-path code/client/Cargo.toml -- <pubkey>   # CLI
```

Then paste the pubkey into the desktop app's Connect screen.

**Disk space.** A free-tier root volume is 8 GB. The deploy prunes dangling images each time, but check `df -h` on the instance now and then.

**Logging.** `RUST_LOG` is set on the container but has no effect: the relay's log level is fixed at `info` in `main.rs`. At that level the relay logs every packet's source address and routing token, so on a public deployment these logs are sensitive.
