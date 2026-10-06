# Manually deploying the server to EC2 (no GitHub Actions)

Does the same thing as `.github/workflows/deploy.yml` — build the server's
Docker image and ship it to EC2 — but run by hand from WSL Ubuntu. Useful
for a first deploy, or when you want to test a change before pushing to
`production`.

Assumes the one-time EC2 setup (Docker installed, security group open on
UDP 443 + SSH 22) from [`ec2-deployment.md`](ec2-deployment.md) is already
done.

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
  -p 443:443/tcp \
  -v server_identity:/data \
  -e RUST_LOG=info \
  server:latest
rm server.tar
docker image prune -f
```

The `-v server_identity:/data` matters even for a one-off manual deploy —
without it, the container regenerates a fresh Ed25519 identity on every
`docker rm`+`run`, and every client would need the new pubkey each time.

## 5. Verify it's up

Still on the instance (or from WSL via `ssh ... "..."`):
```
docker logs server --tail 20
```

You should see the same four lines the container prints on a fresh boot:
```
No existing server identity found. Generating new Ed25519 keypair...
UDP server listening on 0.0.0.0:443
Server Static Pubkey: <hex>
HTTP pubkey endpoint listening on http://0.0.0.0:443/pubkey
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
  docker run -d --name server --restart unless-stopped -p 443:443/udp -p 443:443/tcp \
    -v server_identity:/data -e RUST_LOG=info server:latest &&
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
