# Tech Decision: Leptos instead of Android Studio/Kotlin for the Client

**Status:** Adopted and built (updated 20 October 2026). The team took **Option B** below: a Leptos UI inside a Tauri shell, keeping the raw UDP transport. The first desktop prototype landed on 7 August 2026 and the Android build on 6 October 2026. The app, now called Cryptogram, runs this way on desktop and Android. When this note was written (28 July 2026) it was a proposal that the team still had to confirm.

This note records a change to the client platform choice made throughout `doable-roadmap.md`, `mobile-ui-ffi-roadmap.md`, `UI-FFI_keyConcepts.md`, and both top-level READMEs, which described a native Android Studio/Kotlin app bridged to the Rust core via `uniffi`/JNI.

## Decision

Build the client UI with **Leptos** (a Rust web framework compiling to WebAssembly) instead of a native Android Studio/Kotlin app.

## Reasoning: a webapp that runs on all devices, not just Android

* **Reach:** a webapp runs on any device with a modern browser — desktop, iOS, Android, tablets — instead of being limited to Android hardware/emulators for development, testing, and demoing. The original plan locked the whole team and every demo to Android-only distribution.
* **Single-language stack:** the crypto/networking core is already Rust. Leptos keeps the UI in Rust as well, removing the FFI boundary (`uniffi`/JNI) that the original Android roadmap spent significant effort on — no per-ABI cross-compilation (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`), no callback marshaling across a JNI boundary, no `uniffi` codegen step.
* **Lower setup cost for the team:** no Android Studio/Gradle/emulator installation required to contribute to or test the UI.

## The open question, and how it was settled

The architecture (`doable-roadmap.md`, `doable-cryptographic-flow.md`) is built around the client opening a **raw UDP socket** (`tokio::net::UdpSocket`) directly to the relay on port 443. A pure-browser WASM target has **no raw socket access** — browsers only expose WebSocket, WebTransport, or WebRTC data channels to JS/WASM. This needed to be settled before Phase 2/3 transport work began:

* **Option A:** Adapt the relay/transport layer to a browser-reachable protocol (WebTransport is the closest analogue to "UDP-like" semantics with unreliable datagrams).
* **Option B:** Deploy Leptos inside a native shell (e.g. Tauri, which supports desktop + Android + iOS) so the Rust core keeps real OS socket access and the raw-UDP design can stay as-is — Leptos would then only replace Kotlin as the UI layer, not the transport.

**Settled: Option B.** The relay and the transport were left as they were.

## What was built

* **The UI** (`code/frontend/src/`) is Leptos, compiled to WebAssembly by Trunk. It holds no keys and opens no sockets: it calls 24 named Tauri commands.
* **The shell** (`code/frontend/src-tauri/`) owns the one `Client` from the `client` crate, its UDP socket to the relay, and the background loops. The same WASM and CSS run on desktop and Android.
* **The QR scanner** runs in the WASM too (`getUserMedia` and `rqrr`), so there's no native scanner plugin.
* **Android** still has a little Kotlin, but no `uniffi`. `MessageService` is a foreground service that keeps the process and its socket alive while someone is logged in. `NativeBridge` is a thread that waits on one JNI call, `nextEvent()`, for what the Rust side reports, and starts and stops the service and posts notifications.
* **Not needed after all:** `uniffi`, CameraX and ML Kit. Per-ABI builds are still needed for Android, but `cargo tauri android build` does them.

How it works is in [Frontend-UI-info.md](Frontend-UI-info.md), and the Android build is in [../code/frontend/ANDROID.md](../code/frontend/ANDROID.md).

## Next steps

* **Done:** the team confirmed Option B, and the app was built on it, desktop and Android.
* **The older plans** (`doable-roadmap.md`, `mobile-ui-ffi-roadmap.md`, `UI-FFI_keyConcepts.md`) are kept as records of what was planned. Each now starts with a status section saying what was built instead.
* **Still open:** iOS. Tauri supports it, but nobody has built or tested the app there.

NOTE: option B seems like the best one to me, considering we want UDP - Rowan
