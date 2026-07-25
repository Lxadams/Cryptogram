# Student 1 (Mobile UI & FFI Lead): Concept Study Guide

Not a schedule — a map of what you actually need to *understand* to do this role well. Organized by concept area, each with why it matters for this project specifically and what to go learn. Some sections are core to your lead role; a few are "know enough to integrate," where you don't need Logan's or Student 3's depth but do need to not be blindsided by their black boxes.

---

## 1. Foreign Function Interfaces (FFI) — Core

This is the single most important concept for your role. Everything else builds on it.

- **What FFI actually is:** a contract that lets code in one language call code in another, by agreeing on calling conventions and memory layout at a binary level (not source level). Kotlin doesn't "understand" Rust — it calls into a compiled `.so` library through a very narrow, C-compatible interface.
- **Why you can't just write Kotlin:** UDP sockets, RaptorQ math, and the crypto operations are either impossible or far too slow in pure Kotlin. The Rust core exists because performance and correctness matter for cryptographic and networking code — you need to understand *why* that boundary exists, not just that it does.
- **`uniffi-rs` specifically:** it's a code generator. You (or the crypto team) define an interface (either in a `.udl` file or via Rust proc-macro attributes), and `uniffi` generates the Kotlin bindings, plus the JNI glue underneath, automatically. Learn:
  - How `uniffi` maps Rust types to Kotlin types (e.g. `Result<T, E>` → Kotlin exceptions or sealed classes, `Vec<u8>` → `ByteArray`, Rust `enum` → Kotlin `sealed class`)
  - The difference between the UDL-file approach and the proc-macro approach — pick one and understand *why* it was picked
  - How `uniffi` handles async Rust functions (this matters a lot here, since almost everything you call — encrypt, send, receive — is inherently async)
- **Raw JNI as a fallback concept:** even if you never touch raw JNI directly, understand what `uniffi` is doing for you under the hood — JNI is the actual Java-native bridge Android provides; `uniffi` is a convenience layer on top of it. Knowing this helps you debug when something in the generated bindings misbehaves, since the error will sometimes surface at the JNI layer, not the `uniffi` layer.
- **Ownership across the boundary:** Rust's ownership/borrowing model doesn't exist in Kotlin. When data crosses the boundary (e.g. a `ByteArray` for a key), it's being copied, not shared — understand this so you don't assume changes on one side reflect on the other.

---

## 2. Threading & Async Models Across the Boundary — Core

This is where most of your hardest bugs will live, especially once the metronome and message callbacks are wired in.

- **Rust's async model (`tokio`):** the crypto/transport/FEC code runs on Rust's own async runtime, with its own thread pool, independent of Android's main thread. You need to understand this exists as a separate execution context from anything in Kotlin.
- **Kotlin's threading model (coroutines, `Dispatchers`):** Android UI can only be touched from the main thread. Learn `Dispatchers.Main` vs `Dispatchers.IO`/`Default`, and how `StateFlow`/`LiveData` safely propagate values from background threads to UI-observing code.
- **Callback FFI (Rust calling *into* Kotlin):** this is the trickiest part of the whole project for your role. When Rust receives a message or a metronome tick fires, it needs to notify Kotlin — this happens via a callback interface that `uniffi` generates, invoked from whatever thread Rust's runtime happens to be running on (not the main thread). Learn:
  - How `uniffi` callback interfaces work (Kotlin implements an interface, passes it into Rust, Rust invokes methods on it from a background thread)
  - Why you must marshal that callback's result onto the main thread before touching any View or Compose state
  - The classic Android crash this produces if you get it wrong: *"Only the original thread that created a view hierarchy can touch its views"*
- **Why this needs to be designed once, not improvised repeatedly:** the metronome, incoming messages, and connection-status updates *all* cross this same boundary. Understanding the pattern once means applying it three times instead of debugging it three times.

---

## 3. Android Foreground Services & Process Lifecycle — Core

- **Why Doze mode exists:** Android aggressively suspends background work to save battery. A `sleep(100ms)` loop that isn't inside a Foreground Service will get throttled or killed — understand this isn't a bug, it's designed OS behavior you have to work around, not defeat.
- **Foreground Service mechanics:** what `startForeground()` actually does (tells Android "this process is doing user-visible, ongoing work"), why it requires a persistent notification, and what `foregroundServiceType` declarations are for (Android has gotten stricter about declaring *what kind* of foreground work you're doing across recent versions — check current requirements rather than assuming last year's rules).
- **Service lifecycle vs Activity lifecycle:** a Service can outlive the Activity that started it. Understand `onStartCommand()` return values (`START_STICKY` vs `START_NOT_STICKY`) and what each implies for your metronome thread if Android kills and restarts the service.
- **OEM-specific aggressive battery management:** understand that Samsung (and other OEMs) layer *additional* battery restrictions on top of stock Android, which can kill your Foreground Service even when you've done everything "correctly" per Android's own APIs. This is why you'll likely need a battery-optimization-exemption prompt, and why testing only on one device/OEM can be misleading.

---

## 4. Camera & QR Code Handling — Core

- **CameraX basics:** Android's modern camera abstraction layer. Understand the preview/analysis use-case split — you show a live preview *and* run frame analysis (barcode detection) simultaneously.
- **Barcode/QR decoding (ML Kit or ZXing):** understand these operate on raw frame data and return decoded bytes/strings. Learn how each library handles binary payloads specifically — QR codes are often assumed to hold text, but you're encoding raw key bytes, so understand how your chosen library's API handles byte-array payloads rather than assuming string-only.
- **QR code capacity and encoding modes:** QR codes have a finite data capacity that depends on encoding mode (numeric, alphanumeric, byte, or Kanji) and error-correction level. Since you're packing raw binary (a public key bundle), you'll be using byte-mode — understand roughly how much data fits at a given QR version/error-correction level, so the payload format (however many bytes of keys + token) is known to physically fit before you build the rest around it.
- **Runtime permissions:** Android requires requesting `CAMERA` permission at runtime (not just declaring it in the manifest) from API 23 onward. Understand the request/callback flow and how to handle a user who denies it.

---

## 5. What You Need to Understand About the Crypto (Black-Box Level)

You are not the crypto lead — Logan owns the actual math. But you're the one building UI and passing data across the FFI boundary for it, so you need functional literacy, not implementation depth.

- **Public key bundles as opaque(ish) byte blobs:** you don't need to understand the math behind Ed25519/X25519/ML-KEM, but you do need to know *what shape* the data is that you're QR-encoding and passing into `import_peer_bundle()` — fixed-size byte arrays, concatenated in an agreed order.
- **What a "session" is, conceptually:** the Double Ratchet maintains ongoing state per-conversation. You need to understand it *has* state (so your UI reflects "connected"/"paired" meaningfully) without needing to understand the ratchet math itself.
- **The "Blunt Force" Session Reset (new in the current roadmap):** this is directly relevant to you, since Task 4.1b is joint Rust-Crypto-and-UI. Understand conceptually:
  - A session reset happens automatically every 100 messages, or manually via a UI button
  - It involves a new Kyber encapsulation and a full ratchet-state reboot on both ends — meaning there's a brief window where the "session" is being torn down and rebuilt
  - Your job: expose a manual "reset session" UI action, and — more importantly — show the user *some* indication while a reset is in-flight (e.g. a brief "re-securing connection" state), since messages sent mid-reset need sensible UI handling (queued/pending, not silently dropped)
  - You don't need to know why Kyber encapsulation is used for this, just that a reset is a distinct, visible event with a before/during/after state your UI must represent
- **Why this matters for you specifically:** if you don't understand that a reset is happening, a "connected" indicator that stays green throughout looks fine to you but is actually lying to the user during a state where messages could be delayed.

---

## 6. Data Handling & Local Storage — Core-Adjacent

- **Android Encrypted Shared Preferences / SQLCipher:** the roadmap specifies these (not Knox/hardware-backed storage) for the MVP. Understand at a basic level what "encrypted at rest" actually protects against (a stolen/rooted device reading raw files) versus what it doesn't (an unlocked, actively-used device) — this matters if you're ever asked to justify the security model in your report/demo.
- **Android Keystore (context, not necessarily used directly):** worth knowing this exists as the "real" hardware-backed option you're deliberately *not* using for MVP scope reasons, so you can articulate the tradeoff if asked.

---

## 7. Enough About Networking to Not Be Surprised — Adjacent

You're not building the transport layer, but callbacks and UI state depend on it, so:

- **Why raw UDP over port 443 (not QUIC):** the current roadmap cut QUIC in favor of raw UDP for extreme-loss tolerance — port 443 is chosen so casual traffic inspection sees "probably HTTPS-shaped traffic" on a common port, even though it isn't actually QUIC/TLS underneath. Understand this is a much weaker obfuscation claim than the original QUIC-based design and don't oversell it in the demo narrative.
- **The metronome/constant-rate concept:** fixed-interval packet emission (dummy packets when idle) exists to prevent traffic-timing analysis. You need to understand this only well enough to know *why* the Foreground Service can't just fire on-demand — it fires on a strict clock regardless of whether there's a real message to send.
- **RaptorQ at a conceptual level:** you don't need the math, but understand the shape of the guarantee: any sufficient subset of transmitted symbols reconstructs the original message, which is *why* the app can tolerate 90-95% packet loss without traditional retransmission/ACKs. This is relevant to how you frame "message sent" vs "message delivered" states in the UI — delivery confirmation works differently here than in a normal chat app.

---

## 8. Build Tooling & Cross-Compilation — Core

- **Rust's Android targets:** `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` — understand why multiple targets are needed (different device architectures) rather than a single build.
- **`cargo-ndk`:** a tool that wraps `cargo build` to produce the right `.so` outputs for each Android ABI, placed where the Android Gradle build expects them (`jniLibs/<abi>/`).
- **Why this matters for debugging:** if a build works on your emulator but crashes on a teammate's physical device, an architecture/target mismatch is one of the first things to check — not just "the code is broken."

---

## Summary: Depth Required By Area

| Area | Depth needed |
|---|---|
| FFI / uniffi-rs | Deep — this is your core competency |
| Threading/async across the boundary | Deep — highest bug density in the project |
| Foreground Services / Android lifecycle | Deep |
| Camera/QR | Deep |
| Crypto internals (ratchet math, KEM math) | Shallow — functional literacy only |
| Session reset behavior | Medium — enough to build correct UI states |
| Networking/RaptorQ internals | Shallow — enough to reason about UI delivery states |
| Local encrypted storage | Shallow — enough to explain the security model |
| Cross-compilation tooling | Medium — enough to diagnose build/target issues |
