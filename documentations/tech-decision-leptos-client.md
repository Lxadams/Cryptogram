# Proposed Tech Decision: Leptos instead of Android Studio/Kotlin for the Client

**Status:** Proposed — needs to be raised with and confirmed by the team before the existing roadmap docs are updated.

This note captures a proposed change to the client platform choice made throughout `doable-roadmap.md`, `mobile-ui-ffi-roadmap.md`, `UI-FFI_keyConcepts.md`, and both top-level READMEs, which currently describe a native Android Studio/Kotlin app bridged to the Rust core via `uniffi`/JNI.

## Decision

Build the client UI with **Leptos** (a Rust web framework compiling to WebAssembly) instead of a native Android Studio/Kotlin app.

## Reasoning: a webapp that runs on all devices, not just Android

* **Reach:** a webapp runs on any device with a modern browser — desktop, iOS, Android, tablets — instead of being limited to Android hardware/emulators for development, testing, and demoing. The original plan locked the whole team and every demo to Android-only distribution.
* **Single-language stack:** the crypto/networking core is already Rust. Leptos keeps the UI in Rust as well, removing the FFI boundary (`uniffi`/JNI) that the original Android roadmap spent significant effort on — no per-ABI cross-compilation (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`), no callback marshaling across a JNI boundary, no `uniffi` codegen step.
* **Lower setup cost for the team:** no Android Studio/Gradle/emulator installation required to contribute to or test the UI.

## Open question this decision does not yet resolve

The current architecture (`doable-roadmap.md`, `doable-cryptographic-flow.md`) is built around the client opening a **raw UDP socket** (`tokio::net::UdpSocket`) directly to the relay on port 443. A pure-browser WASM target has **no raw socket access** — browsers only expose WebSocket, WebTransport, or WebRTC data channels to JS/WASM. This needs to be settled before Phase 2/3 transport work begins:

* **Option A:** Adapt the relay/transport layer to a browser-reachable protocol (WebTransport is the closest analogue to "UDP-like" semantics with unreliable datagrams).
* **Option B:** Deploy Leptos inside a native shell (e.g. Tauri, which supports desktop + Android + iOS) so the Rust core keeps real OS socket access and the raw-UDP design can stay as-is — Leptos would then only replace Kotlin as the UI layer, not the transport.

This has not been decided yet and should be resolved before committing engineering time to Phase 2/3 transport work, since it changes what "the relay" and "the metronome" actually talk to.

## Next steps

* Raise this with the full team (affects Student 1 / Mobile UI & FFI Lead's roadmap most directly, and the Server Lead if Option A is chosen).
* Once confirmed, update `doable-roadmap.md`, `mobile-ui-ffi-roadmap.md`, `UI-FFI_keyConcepts.md`, both top-level `README.md` files, and `code/client/README.md` to reflect the agreed platform and transport approach.

NOTE: option B seems like the best one to me, considering we want UDP - Rowan
