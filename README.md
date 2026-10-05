# E2E-Messenger
**COMPX374 Industry Project**

E2E-Messenger is a proof-of-concept end-to-end encrypted messenger that routes everything through a blind UDP relay. A Rust core handles all the cryptography and networking:

- a **hybrid post-quantum handshake**: X25519 plus Kyber-768, authenticated with Ed25519;
- a **hash ratchet** that mixes in a fresh Kyber secret every 5 messages;
- **link encryption** to a relay that routes by opaque 16-byte tokens, keeps everything in RAM, and never sees message text.

Two front ends use the core: a **Leptos + Tauri desktop app** and a **terminal CLI**. Contacts are added by scanning a QR code or pasting a contact code. There are no accounts and no phone numbers.

The long-term aim is a messenger that keeps working on hostile networks, with heavy packet loss, traffic analysis and censorship. Two parts of that design, forward error correction and constant-rate cover traffic, aren't built yet. The table below shows what is.

## Project status

| Area | Status on `main` |
|---|---|
| Hybrid PQ session setup (X25519 + Kyber-768, Ed25519-signed) | ✅ Implemented |
| Hash ratchet, out-of-order delivery, Kyber mixed in every 5 messages | ✅ Implemented |
| Blind relay: link encryption, token routing, RAM-only offline queue | ✅ Implemented |
| Desktop app: login, multiple identities, contacts, chat, online indicator | ✅ Implemented |
| Encrypted local storage (Argon2id + SQLCipher) and saved chat history | ✅ Desktop app. The CLI and relay still keep keys in plaintext. |
| QR contact exchange (show and scan) | 🟡 Implemented; not yet tested with a real camera |
| RaptorQ forward error correction | ❌ Not on `main`. Each message is one UDP datagram, sent once. |
| Constant-rate tunnel and dummy traffic | ❌ Not implemented |
| Mobile (Android/iOS) | ❌ Not started. Tauri can target mobile. |
| Group chat | ❌ Stretch goal |

Known weaknesses are listed in [cryptography.md §9](documentations/cryptography.md#9-open-issues). Plans are in [roadmap.md](documentations/roadmap.md).

## Repository layout

```
code/
├── client/             Protocol library (lib.rs) + terminal CLI (main.rs)
├── server/             Blind UDP relay
├── frontend/           Leptos UI (WASM)
│   └── src-tauri/      Tauri desktop shell running the client library
└── docker-compose.yml  Relay, CLI, and a Linux bundle build of the desktop app
documentations/         Design docs (listed below)
runserver.sh            Build and run the relay locally (Linux)
runpeer.sh              Start one desktop peer (run once per peer)
runchecks.sh            clippy + fmt for code/server
.github/workflows/      CI (pr_build.yml) and EC2 deploy (deploy.yml)
```

## Quick start

These steps assume Linux. Prerequisites for the desktop app are in [code/frontend/README.md](code/frontend/README.md#prerequisites).

1. **Start the relay** and copy the `Server Static Pubkey` it prints. The script asks for `sudo` once, to run `setcap` on the binary.
   ```bash
   ./runserver.sh
   ```
2. **Start two desktop peers**, each in its own terminal. The first one builds the app; the second starts almost straight away.
   ```bash
   ./runpeer.sh
   ```
3. In each window:
   - **create an identity**, then **log in**;
   - **paste the relay pubkey** and click Connect.
4. **Pair the two peers:** in one window click *Present QR code*; in the other, click *Scan QR code* or paste the routing token and Ed25519 key. Once the contact shows **established**, you can send messages.

Other ways to run it:

- **Without the GUI:** use the CLI. See [code/client/README.md](code/client/README.md#cli).
- **In Docker or on EC2:** see [documentations/deployment.md](documentations/deployment.md).
- **Against a remote relay:** start peers with `SERVER_ADDR=<host>:443 ./runpeer.sh`.

## Building and testing

Each crate builds and tests on its own. CI ([`.github/workflows/pr_build.yml`](.github/workflows/pr_build.yml)) runs four checks in each of `code/server`, `code/client`, `code/frontend` and `code/frontend/src-tauri`, on every push and pull request to `main`:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo build --verbose
cargo test --verbose
```

| Crate | Tests |
|---|---|
| `code/client` | 64 |
| `code/server` | 6 |
| `code/frontend` | 6 |
| `code/frontend/src-tauri` | 14 |

The client crate builds SQLCipher with a vendored OpenSSL, which needs **Perl and make**. On Windows that means Strawberry Perl and `nmake`. See the [client README](code/client/README.md#building-and-testing).

## Documentation

| Document | What's in it |
|---|---|
| [Architecture](documentations/architecture.md) | Components, topology, wire format, message flows, local storage, what the relay can see |
| [Cryptography](documentations/cryptography.md) | Every protocol step, local secret storage, hardening history, open issues, test inventory |
| [Deployment](documentations/deployment.md) | Docker Compose, EC2 via GitHub Actions, EC2 by hand |
| [Roadmap and decisions](documentations/roadmap.md) | Progress against the original plan, next steps, design decisions (UDP, ratchet, Leptos + Tauri, …) |
| [Learning guide](documentations/learning-guide.md) | Concepts to study for each part of the project |
| [Client](code/client/README.md) · [Server](code/server/README.md) · [Desktop app](code/frontend/README.md) | How each crate is laid out, built, configured and tested |
| [Links](documentations/Links.txt) | Shared notebook and project proposal (Waikato SharePoint) |

## Conventions

* Put all client-side and server-side code in the `code/` folder.
* Create a [GitHub Issue](https://github.com/Lxadams/E2E-Messanger/issues) for each task you take on, including non-coding tasks.
  * Title format: **`Firstname - short task description`**.
  * Add one of `priority-low`, `priority-medium` or `priority-high`, plus any other labels that apply.
* Create your own branch before you change anything. Name it **`firstname/branch-name`**.
* Pull from `main` regularly (`git pull origin main`). When your work is ready, open a pull request using the [PR template](.github/pull_request_template.md). Never push directly to `main`.
* After your pull request is merged, delete your branch using the **Delete branch** button on GitHub.
* Pushing to the `production` branch deploys the relay to EC2 (see [deployment.md](documentations/deployment.md#3-ec2-via-github-actions)).
