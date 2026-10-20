# E2E-Messenger
**Compx374 Industry Project** 

## Project Overview

E2E-Messenger is a highly secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. The app is called **Cryptogram**. Built with a high-performance **Rust cryptography and networking core** behind a **Leptos UI** (Rust compiled to WebAssembly) in a **Tauri shell**, for desktop and Android, this project demonstrates novel approaches to metadata obfuscation, network reliability without TCP, and Post-Quantum cryptography.

The architecture is designed to survive hostile network conditions: heavy packet loss (it's tested at 70% each way), jamming, and eventually Deep Packet Inspection (DPI) censorship firewalls, while leaking as little metadata as it can about who is communicating, or when. DPI resistance and cover traffic are still planned; see the [Stage 3 roadmap](documentations/stage-3-roadmap.md).

## Setup
- Run the server locally using `runserver.sh`. You might be prompted to enter your password since it uses `sudo`.
- Start a desktop peer with `runpeer.sh`, once per peer, each in its own terminal. It uses the local relay by default; for one elsewhere, give its address and key: `runpeer.sh -ip <ip> -p <port> -pk <hex>`.
- To test across devices on the same network (other PCs, Android phones), run the server with `runserver-lan.sh` and each client with `runpeer-lan.sh --pc <server-ip>` or `runpeer-lan.sh --mobile <server-ip>`. Android also needs the one-time toolchain setup in [`code/frontend/ANDROID.md`](code/frontend/ANDROID.md).
- To try that over a bad network, run `runserver-lan-lossy.sh` instead. It drops 70% of packets each way (or `runserver-lan-lossy.sh 0.5` for 50%), and typing a new loss while it runs changes it. Clients connect to it exactly as to `runserver-lan.sh`'s relay. Port 4431 reaches the relay with no loss, to jam only one side.
- To build the phone app on its own, run `build-apk.sh` (this machine's relay by default, or `-ip <ip> -p <port> -pk <hex>` for another), then `install-apk.sh` to install it over USB. To test without a second phone, build with `build-apk.sh --emulator` and run `run-emulator.sh`.
- To run the server/client in Docker instead, or build the desktop frontend's Linux bundle via Docker, see [`code/README.md`](code/README.md).
- To build the app for an Android phone, see [`code/frontend/ANDROID.md`](code/frontend/ANDROID.md).

## Where to read more
- [`documentations/README.md`](documentations/README.md): how it works, and what's built so far.
- [`documentations/Logan-info.md`](documentations/Logan-info.md): a message's path from one phone to another, and the packet formats.
- [`documentations/Frontend-UI-info.md`](documentations/Frontend-UI-info.md): how the UI works.
- [`documentations/stage-3-roadmap.md`](documentations/stage-3-roadmap.md): what comes next.

## Conventions
* For client-side or server-side code, please place all implementations in the `code/` folder.
* Please create tasks for yourself (including non-coding tasks) by going to [GitHub Issues](https://github.com/Lxadams/E2E-Messanger/issues). Issue titles should follow the format **`Firstname - short task description`**. After creating an issue, assign it one of the following labels: [`priority-low`,`priority-medium`,`priority-high`], as well as any other applicable labels from the **Labels** list.
* Please create your own branch before making any changes to the repository. Branch names should follow the format **`firstname/branch-name`**.
* Please pull the latest changes from the `main` branch regularly (`git pull origin main`). When your work is ready, open a pull request. Pushing directly to the `main` branch is strictly prohibited.
* After your pull request has been merged, please delete your branch by clicking the **Delete branch** button on GitHub.