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
group only opens SSH (22). Add an explicit inbound rule for UDP port 443,
source `0.0.0.0/0` — this is a public relay by design. SSH (22) also needs
to stay open to `0.0.0.0/0`, since GitHub Actions runners have no fixed IP
you can allowlist.

**Use an Elastic IP.** A plain EC2 public IP changes if you ever stop/start
the instance — that would silently break `EC2_HOST` in your secrets and
every client's saved connection info. An Elastic IP (free while attached
to a running instance) keeps it stable.

**Instance size:** since building happens in CI and EC2 only loads a
prebuilt image, a free-tier `t2.micro`/`t3.micro` (1GB RAM) is genuinely
fine here — you're not compiling Rust on it.

## GitHub secrets you need

| Secret | Value |
|---|---|
| `EC2_HOST` | The Elastic IP or DNS name of the instance |
| `EC2_USER` | `ubuntu` for the standard Ubuntu AMI |
| `EC2_SSH_KEY` | The *contents* of the `.pem` private key from your EC2 key pair — not a path, paste the whole thing including `-----BEGIN...-----` |
| `EC2_SSH_PORT` | Optional, only if you're not using port 22 |

## After the first successful deploy

Grab the server's pubkey for your clients with:

```
ssh ubuntu@<EC2_HOST> "docker logs server 2>&1 | grep 'Static Pubkey'"
```

The identity persists across deploys via the `server_identity` named
volume mounted at `/data` — this pubkey should stay the same on every
future deploy, not change per push.

## Ongoing maintenance

**Disk space is finite on free tier** (default 8GB root volume). The
deploy script runs `docker image prune -f` after every load to clean up
dangling layers from the previous deploy, but it's worth checking `df -h`
on the instance occasionally — base image layers and the Rust toolchain
aren't tiny.
