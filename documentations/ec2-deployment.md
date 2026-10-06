# Deploying the server to EC2

Notes for `.github/workflows/deploy.yml`, which builds the server's Docker
image in CI and ships it to an EC2 instance on every push to `production`.
This is written for a first-time EC2 deploy — things that aren't obvious
from the workflow file alone.

## One-time EC2 setup

**Docker isn't installed on EC2 by default.** The workflow assumes `docker`
already exists on the instance; it doesn't install it. Before the first
deploy, SSH in once and run:

```
sudo apt-get update && sudo apt-get install -y docker.io
sudo usermod -aG docker ubuntu   # so you don't need sudo for docker commands
```

Log out/in for the group change to apply — or just use `sudo docker` for
any manual checks in the meantime.

**Security group must allow inbound UDP 443.** EC2's default security
group only opens SSH (22). Add an explicit inbound rule for UDP port 443
(the relay: QUIC), source `0.0.0.0/0` — this is a public relay by design. The
relay serves nothing over TCP. SSH (22) also needs
to stay open to `0.0.0.0/0`, since GitHub Actions runners have no fixed IP
you can allowlist. TCP 80 is only needed while getting a certificate (below).

**Use an Elastic IP.** A plain EC2 public IP changes if you ever stop/start
the instance — that would silently break `EC2_HOST` in your secrets and
every client's saved connection info. An Elastic IP (free while attached
to a running instance) keeps it stable.

**Instance size:** since building happens in CI and EC2 only loads a
prebuilt image, a free-tier `t2.micro`/`t3.micro` (1GB RAM) is genuinely
fine here — you're not compiling Rust on it.

## Domain and certificate

Anyone who connects to the relay without the app's access key gets an
ordinary HTTP/3 website, so it needs what an ordinary website has: a domain
name and a real certificate. (Without them it uses a self-signed certificate,
which works for the app but gives the relay away to anyone who looks.)

1. **A domain.** Point an `A` record (e.g. `relay.example.com`) at the
   Elastic IP. Optionally add an `HTTPS` record advertising HTTP/3
   (`relay.example.com. 300 IN HTTPS 1 . alpn="h3"`), which lets browsers
   reach the site over QUIC directly, since it isn't served over TCP.
2. **A Let's Encrypt certificate, keeping its key on renewal.** The app pins
   the certificate's *key*, so renewals must reuse it (`--reuse-key`), or
   every copy of the app stops trusting the relay. With the DNS at Route 53
   no port needs opening:
   ```
   sudo apt-get install -y certbot python3-certbot-dns-route53
   sudo certbot certonly --dns-route53 -d relay.example.com \
     --key-type ecdsa --reuse-key \
     --deploy-hook "docker restart server"
   ```
   Otherwise open TCP 80 in the security group for the duration and use
   `--standalone` instead of `--dns-route53`. certbot's timer renews it from
   then on, and the deploy hook restarts the relay to load the new
   certificate (same key, so nothing changes for the app).
3. **Tell the deploy about it:** add a `RELAY_DOMAIN` secret
   (`relay.example.com`). The workflow then mounts `/etc/letsencrypt` into
   the container and points the relay at the certificate (`TLS_CERT`,
   `TLS_KEY`).

## GitHub secrets you need

| Secret | Value |
|---|---|
| `EC2_HOST` | The Elastic IP or DNS name of the instance |
| `EC2_USER` | `ubuntu` for the standard Ubuntu AMI |
| `EC2_SSH_KEY` | The *contents* of the `.pem` private key from your EC2 key pair — not a path, paste the whole thing including `-----BEGIN...-----` |
| `EC2_SSH_PORT` | Optional, only if you're not using port 22 |
| `RELAY_DOMAIN` | Optional: the relay's domain, once it has a Let's Encrypt certificate (see above). Without it the relay uses a self-signed certificate. |

## After the first successful deploy

Clients ship with the relay's key pin and access key rather than asking the
relay for them. Read them on the instance:

```
ssh ubuntu@<EC2_HOST> "docker exec server server --print-pubkey; docker exec server server --print-access-key"
```

and build the app with them, the relay's address and its domain:

```
SERVER_ADDR=<Elastic IP>:443 SERVER_NAME=relay.example.com \
SERVER_PUBKEY=<pin> SERVER_ACCESS_KEY=<key> ./runpeer-lan.sh --mobile <Elastic IP>:443
```

Giving the app the IP (rather than the domain) means it never looks the
relay up at all; with the domain in `SERVER_ADDR` it looks it up over
DNS-over-HTTPS. The access key and the self-signed certificate (if used)
persist across deploys in the `server_identity` volume mounted at `/data`,
and a Let's Encrypt certificate keeps its key with `--reuse-key`, so both
values stay the same on every future deploy. If the key does change (a
certificate made without `--reuse-key`, or the volume deleted), every app
must be rebuilt with the new pin.

## Ongoing maintenance

**Disk space is finite on free tier** (default 8GB root volume). The
deploy script runs `docker image prune -f` after every load to clean up
dangling layers from the previous deploy, but it's worth checking `df -h`
on the instance occasionally — base image layers and the Rust toolchain
aren't tiny.
