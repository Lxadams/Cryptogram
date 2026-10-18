# Manually deploying the server to EC2 (no GitHub Actions)

Does the same thing as `.github/workflows/deploy.yml` — build the server's
Docker image and ship it to EC2 — but run by hand from WSL Ubuntu. Useful
for a first deploy, or when you want to test a change before pushing to
`production`.

Assumes the instance's security group is already open on UDP 443 + SSH 22
(see [`ec2-deployment.md`](ec2-deployment.md)). If Docker isn't installed on
the instance yet, start with step 0.

## Prerequisites on WSL

- Docker installed and running in WSL (`docker --version` to check).
- Your EC2 key pair's `.pem` file, saved somewhere in WSL (not Windows'
  `/mnt/c/...` — permissions don't work right there for SSH keys).
- The EC2 instance's public IP or Elastic IP (`EC2_HOST` below).

Lock down the key's permissions once — SSH refuses to use a key that's
readable by anyone else:
```
chmod 400 /path/to/your-key.pem
```

## 0. Install Docker on the instance (first time only)

A fresh EC2 instance doesn't come with Docker. SSH in:
```
ssh -i /path/to/your-key.pem ubuntu@<EC2_HOST>
```

Then, on the instance (standard Ubuntu AMI):
```
sudo apt-get update && sudo apt-get install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
exit
```

`systemctl enable` starts Docker on every boot, which is what lets
`--restart unless-stopped` (step 4) bring the relay back after the instance
reboots. The `usermod` lets you run `docker` without `sudo`, but only takes
effect on a new login — hence the `exit`. SSH back in and check:
```
docker ps
```

An empty table means you're set. `permission denied ... docker.sock` means
the group change hasn't applied yet — log out and back in again.

## 1. Build the image

From the repo root:
```
docker build -t server:latest -f code/server/Dockerfile code
```

This is the exact same build the CI workflow runs — same Dockerfile, same
build context (`code/`).

## 2. Save it to a tarball

```
docker save server:latest | gzip > server.tar.gz
```

## 3. Copy it to EC2

```
scp -i /path/to/your-key.pem server.tar.gz ubuntu@<EC2_HOST>:/home/ubuntu/
```

## 4. Load and run it on EC2

SSH in:
```
ssh -i /path/to/your-key.pem ubuntu@<EC2_HOST>
```

Then, on the instance:
```
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
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --ulimit core=0 \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  server:latest
rm server.tar
docker image prune -f
```

The `-v server_identity:/data` matters even for a one-off manual deploy —
without it, the container regenerates a fresh Ed25519 identity on every
`docker rm`+`run`, and every client would need the new pubkey each time.

The flags after it lock the relay down. The filesystem is read-only apart from
that volume, the relay has no capabilities, and there are no core dumps (it
holds messages and keys in RAM only). The `--sysctl` lets the image's
unprivileged user bind port 443; it's Docker's default since 20.10 anyway.

## 5. Verify it's up

Still on the instance (or from WSL via `ssh ... "..."`):
```
docker logs server --tail 20
```

You should see the same three lines the container prints on a fresh boot:
```
No existing server identity found. Generating new Ed25519 keypair...
UDP server listening on 0.0.0.0:443
Server Static Pubkey: <hex>
```

On a *re*-deploy against an existing `server_identity` volume, the first
line won't appear (identity already exists) and the pubkey should be
identical to last time — that's the persistence working.

## Doing steps 3+4 in one shot

Once you've done it manually a couple of times, you can collapse the scp
+ ssh into a single command from WSL:
```
scp -i /path/to/your-key.pem server.tar.gz ubuntu@<EC2_HOST>:/home/ubuntu/ && \
ssh -i /path/to/your-key.pem ubuntu@<EC2_HOST> '
  gunzip -f server.tar.gz &&
  docker load -i server.tar &&
  docker stop server || true &&
  docker rm server || true
  docker run -d --name server --restart unless-stopped -p 443:443/udp \
    -v server_identity:/data -e RUST_LOG=info \
    --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 server:latest &&
  rm server.tar && docker image prune -f
'
```

## Worth knowing

- **No record of which commit is deployed.** The GitHub Actions version at
  least ties a deploy to a specific push; a manual deploy doesn't unless
  you tag the image yourself. If you're doing this more than a couple of
  times, tag with the git commit so you can tell what's actually running:
  ```
  docker build -t server:$(git rev-parse --short HEAD) -f code/server/Dockerfile code
  ```
  (then adjust the `docker save`/`docker run` tag to match).
- **This doesn't replace the GitHub Actions workflow** — pushing to
  `production` will still trigger `deploy.yml` and overwrite whatever you
  deployed manually. Use this for testing, not as your permanent deploy
  path, unless you disable/remove the workflow.
