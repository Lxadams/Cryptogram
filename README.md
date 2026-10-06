# E2E-Messenger
**Compx374 Industry Project** 

## Project Overview

E2E-Messenger is a highly secure, extreme-loss tolerant tactical messenger designed as a Proof of Concept (PoC) for rugged operational environments. Built with a high-performance **Rust cryptography and networking core** accessed via a **Mobile UI (Android/Kotlin)**, this project demonstrates novel approaches to metadata obfuscation, network reliability without TCP, and Post-Quantum cryptography.

The architecture is explicitly designed to survive hostile network conditions, including **95% packet loss** and Deep Packet Inspection (DPI) censorship firewalls, without leaking metadata about who is communicating or when.

Please visit the `documentations/` folder for more details.

## Setup
- Run the server locally using `runserver.sh`. You might be prompted to enter your password since it uses `sudo`.
- To run the server/client in Docker instead, or build the desktop frontend's Linux bundle via Docker, see [`code/README.md`](code/README.md).
- To build the app for an Android phone, see [`code/frontend/ANDROID.md`](code/frontend/ANDROID.md).

## Conventions
* For client-side or server-side code, please place all implementations in the `code/` folder.
* Please create tasks for yourself (including non-coding tasks) by going to [GitHub Issues](https://github.com/Lxadams/E2E-Messanger/issues). Issue titles should follow the format **`Firstname - short task description`**. After creating an issue, assign it one of the following labels: [`priority-low`,`priority-medium`,`priority-high`], as well as any other applicable labels from the **Labels** list.
* Please create your own branch before making any changes to the repository. Branch names should follow the format **`firstname/branch-name`**.
* Please pull the latest changes from the `main` branch regularly (`git pull origin main`). When your work is ready, open a pull request. Pushing directly to the `main` branch is strictly prohibited.
* After your pull request has been merged, please delete your branch by clicking the **Delete branch** button on GitHub.