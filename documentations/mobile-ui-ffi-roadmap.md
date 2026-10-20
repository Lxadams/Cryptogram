# Mobile UI & FFI Lead: Detailed Personal Roadmap

## Status, 20 October 2026

This is the July 2026 plan, kept as a record of what was planned. The Kotlin and `uniffi` app it describes was never built. It was replaced by a **Leptos** UI (Rust compiled to WebAssembly) in a **Tauri** shell, the same code on desktop and Android (see [tech-decision-leptos-client.md](tech-decision-leptos-client.md)). How the app works is in [Frontend-UI-info.md](Frontend-UI-info.md), and how to build it for Android is in [../code/frontend/ANDROID.md](../code/frontend/ANDROID.md).

**What still applies:**
- **The foreground service (weeks 5 and 7).** `MessageService` runs while someone is logged in, with an ongoing "Connected" notification (`foregroundServiceType="specialUse"`), so Android keeps the process and its UDP socket alive. Tapping a notification brings the app back. It returns `START_NOT_STICKY`: if Android kills the process, nobody can log in again without their passcode, and the relay holds messages until then. There's no battery-optimisation prompt yet; that is Stage 3 item 1.6.
- **Runtime permissions (week 2).** `CAMERA` is in the manifest, and Android asks for it when the scanner first opens. Notification permission is asked for at launch on Android 13 and newer.
- **The Android lifecycle (week 7).** Swiping the app away doesn't log you out: the backend keeps running for the service, and reopening the app loads a fresh UI that goes straight back to your chats. Rotation doesn't recreate the activity.
- **A background thread talking to Kotlin (week 6).** It runs the other way round from a `uniffi` callback: a Kotlin thread in `NativeBridge` blocks in the JNI call `nextEvent()` until Rust reports something (logged in, logged out, a message), and posts each event to the main thread.

**What doesn't:**
- **`uniffi`, Android Studio and `cargo-ndk` (week 1).** The UI calls 24 Tauri commands instead, and `cargo tauri android build` cross-compiles the Rust and builds the APK. The SDK command-line tools and the NDK are still needed.
- **CameraX and ML Kit (weeks 2 and 3).** The QR code is drawn and scanned in the WASM (`qrcode`, then `getUserMedia` and `rqrr`). The device's `BarcodeDetector`, which is ML Kit on Android, is an option that's off by default. The code is `CG2:` + Base45 of the routing token and the Ed25519 key, a 29×29 QR code, and both people scan each other.
- **The metronome (weeks 5 and 6).** It wasn't built, so the service runs no timer. A constant-rate tunnel is planned for Stage 3 Phase 1.
- **Fetching queued packets on app open (weeks 8 and 9).** There's no fetch request. When the app comes back on screen, the backend syncs with the relay at once, and the relay resends whatever is queued.
- **The 90% loss demo (week 12).** It was tested at 70% loss each way, through a loss-injecting proxy (`runserver-lan-lossy.sh`). The app can also simulate loss itself, and its **Network stats** setting shows the loss each way.

---

Scoped from the team's E2E Messenger MVP roadmap. This breaks your three phases (1, 2, 4) into weekly, task-level detail — what to build, what "done" looks like, and where you're blocked waiting on teammates.

---

## Phase 1: Rust Core Bootstrapping & QR Exchange (Weeks 1-4)

### Week 1 — Project Skeleton & Toolchain

**Goal:** Android Studio project exists, Rust compiles, and you can call one trivial Rust function from Kotlin.

- [ ] Decide Kotlin (native) vs React Native — **do this in week 1, not later**, it changes your FFI path entirely. Given `uniffi-rs` targets Kotlin directly, native Android is the lower-friction choice unless the team has a strong RN reason.
- [ ] Install Android Studio, Android NDK, and set `ANDROID_NDK_HOME`
- [ ] Set up Rust cross-compilation targets:
  ```
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- [ ] Create the Rust core crate (`core/` or similar) as a `cdylib` + `lib` crate
- [ ] Add `uniffi` and `uniffi-bindgen` to `Cargo.toml`
- [ ] Write a single dummy function (e.g. `fn ping() -> String`) and confirm it round-trips: Rust → generated Kotlin bindings → called from a bare Android Activity, output shown in a `TextView` or Logcat
- [ ] Set up `cargo-ndk` (or manual `cargo build --target ...`) to produce `.so` files for each ABI, placed under `app/src/main/jniLibs/<abi>/`

**Dependency on others:** None yet — this is purely your setup work, but Logan and Student 3 will start adding real Rust functions in week 2, so your bridge needs to exist first. Communicate the crate structure (module names, where `uniffi` UDL/proc-macro definitions live) to them early so they don't fight you on file layout.

**Risk to flag now:** `uniffi` UDL-file vs proc-macro API — proc-macros are newer and less boilerplate but worse documented. Pick one as a team and stick with it; mixing is painful.

---

### Week 2 — Real FFI Surface + Camera Permission Plumbing

**Goal:** The FFI contract for crypto functions is defined (even if Logan's implementations are stubs), and camera access works.

- [ ] Work with Logan to define the actual FFI interface signatures you'll need, e.g.:
  ```rust
  fn generate_identity_keypair() -> IdentityKeys; // Ed25519 + X25519
  fn export_public_bundle() -> Vec<u8>; // what gets QR-encoded
  fn import_peer_bundle(data: Vec<u8>) -> Result<(), CryptoError>;
  ```
  You don't need real crypto yet — Logan can return dummy bytes. You just need the **shape** of the API locked so you can build UI against it.
- [ ] Add `CAMERA` permission to `AndroidManifest.xml`, implement runtime permission request flow (Android 6+ requires this at runtime, not just manifest)
- [ ] Pick a QR library: **ML Kit Barcode Scanning** (Google's, well-maintained, on-device) vs **ZXing** (older, more manual). ML Kit is the better default in 2026 unless you have a reason to avoid Google Play Services dependency.
- [ ] Get a basic CameraX preview rendering in an Activity/Fragment (no scanning logic yet, just prove the camera feed shows up)

**Dependency on others:** Logan needs to have committed *something* callable — even a stub — by end of week 2, or you'll be blocked on QR data format decisions.

---

### Week 3 — QR Generation + Scanning End-to-End

**Goal:** Two emulators/devices can generate a QR code and scan each other's, exchanging real (or stubbed) key bundles.

- [ ] Generate a QR code from your local public key bundle. Use `zxing-android-embedded` or ML Kit's writer to render the QR as a Bitmap, display it in an `ImageView`
- [ ] Implement the scanner flow: CameraX + ML Kit barcode analyzer, detect QR, decode bytes, pass into `import_peer_bundle()`
- [ ] Decide and document the QR payload format now — this matters because it needs to fit comfortably in a QR code's data capacity. Suggest: a fixed binary layout (not JSON, too bulky) — e.g. `[1 byte version][32 bytes Ed25519 pub][32 bytes X25519 pub][16 bytes rendezvous token]`. Confirm this with Logan since he owns key generation.
- [ ] Handle the trust-establishment UX: what does the user see after a successful scan? (e.g. "Connected with [name/fingerprint]" confirmation screen) — this is also your first real UI screen beyond scaffolding.
- [ ] Error states: malformed QR, camera permission denied, scan timeout

**Checkpoint for end of Phase 1:** You should be able to demo, on two physical/emulated devices: open app → generate QR → scan peer's QR → see "paired" confirmation. Doesn't need real crypto underneath yet, just the plumbing.

---

## Phase 2: Foreground Service & Metronome Integration (Weeks 5-7)

### Week 5 — Foreground Service Skeleton

**Goal:** A Foreground Service exists, shows a persistent notification, and survives basic Doze testing.

- [ ] Create an Android `Service` subclass, declare `foregroundServiceType="dataSync"` (or `connectedDevice`, check current Android target SDK requirements — this has gotten stricter release over release) in the manifest
- [ ] Implement `startForeground()` with a persistent, low-priority notification ("Messenger is running")
- [ ] Wire service lifecycle to app lifecycle: start on chat screen open, allow explicit stop
- [ ] Test Doze mode behavior: `adb shell dumpsys deviceidle force-idle`, confirm the service isn't killed
- [ ] Confirm the service can host a background thread — this is where the Rust metronome will eventually live

**Dependency on others:** Student 3 owns the actual 100ms `tokio` metronome loop in Rust. You don't need it working yet — build the service shell against a dummy loop (e.g. Kotlin `Handler.postDelayed` ticking every 100ms and logging) so you're not blocked.

---

### Week 6 — Wiring the Real Metronome In

**Goal:** Student 3's Rust metronome thread runs inside your Foreground Service, not just a Kotlin stand-in.

- [ ] Replace the dummy Kotlin ticker with a call into Rust — likely a blocking/spawned call like `start_metronome(callback)` where the FFI layer needs a way to call back into Kotlin (uniffi supports callback interfaces — confirm the pattern with Logan/Student 3 since this is a three-way dependency)
- [ ] Handle thread lifecycle carefully: the Rust thread must start when the service starts and stop cleanly when the service is destroyed (no orphaned threads running after app "quit")
- [ ] Surface metronome/network state to UI — even a simple connection-status dot (green/red/yellow) in the chat header, since users on 90%-loss networks need *some* feedback that a "dead" chat isn't the app crashing

**Risk to flag now:** callback FFI (Rust calling back into Kotlin across the JNI boundary repeatedly, every 100ms) can be more fragile/slower than one-directional calls. Test this early rather than discovering it during integration week.

---

### Week 7 — UI Resilience Under Foreground Service Constraints

**Goal:** UI correctly reflects and survives real service behavior (backgrounding, rotation, process death).

- [ ] Handle configuration changes (screen rotation) without restarting the service or losing chat state
- [ ] Handle the case where Android kills and restarts the service (`START_STICKY` vs `START_NOT_STICKY` — you want sticky, but decide what "restart" means for reconnecting to the relay)
- [ ] Battery optimization exemption prompt — many OEMs (Samsung especially) aggressively kill background services regardless of Foreground Service status; you likely need to prompt users to disable battery optimization for the app
- [ ] Basic notification tap-through: tapping the persistent notification returns to the chat screen

**Checkpoint for end of Phase 2:** Two devices maintain a "connected" indicator continuously while backgrounded, driven by the real Rust metronome, surviving screen-off and rotation.

---

## Phase 3 (Not your lead, but your touchpoint) — Weeks 8-9

You're not driving this phase (Student 4 owns the relay, Rust core team owns Task 3.3), but flag time for:
- [ ] Wiring the "fetch queued offline packets on app open" call (Task 3.3) into your app's launch/resume lifecycle — this is a small but real UI-layer hook you'll need to add once Rust core exposes it
- [ ] Basic UI state for "reconnecting to relay" / "offline queue syncing" if that's not instantaneous

Use these two weeks to also get ahead on Phase 4 — build static chat UI (message bubbles, input bar, timestamps) against mock data, so integration week isn't your first time touching layout.

---

## Phase 4: Integration & Extreme Loss Demo (Weeks 10-12)

### Week 10 — Wire the Full Pipeline

**Goal:** Task 4.1 — Type → Ratchet Encrypt → RaptorQ slice → Metronome Transmit, all connected.

- [ ] Connect the chat input UI to `ratchet_encrypt()` (Logan's FFI surface)
- [ ] Confirm the output of that call is handed to Student 3's RaptorQ slicing function correctly (this is a Rust-to-Rust internal call in most designs, but confirm you're not accidentally routing bytes back through Kotlin unnecessarily — extra JNI hops here would hurt performance for no reason)
- [ ] Incoming message path: metronome receives → RaptorQ reassembles → ratchet decrypts → callback into Kotlin → append to chat UI
- [ ] Build a real (not mock) message list UI: bubbles, sender distinction, delivery/pending states — pending state matters a lot here given the deliberate high-loss environment

**This week is the highest FFI-callback density of the whole project** — incoming messages need to push from Rust into UI reactively. If you're using Jetpack Compose, this likely means a `StateFlow`/`MutableState` updated from a callback thread — remember callbacks from Rust land on a background thread, not the main thread, so you'll need `Dispatchers.Main` / `runOnUiThread` wrapping or you'll get "only the original thread that created a view hierarchy can touch its views" crashes.

### Week 11 — UX Polish

**Goal:** Task 4.2 — the whole flow from QR scan to chat feels like a coherent app, not a stitched demo.

- [ ] Onboarding flow: first-launch → generate identity → show your QR → prompt to scan peer's
- [ ] Visual polish pass on chat screen (this is also a good week to loop back to the `frontend-design` conventions if you want the demo to look intentional rather than default Material)
- [ ] Loading/error states audited end-to-end: no dead spinners, no silent failures
- [ ] Consider a simple "connection quality" indicator tied to actual loss rate if Student 3/4 can expose that metric — strong visual proof for the demo

### Week 12 — Demo Prep & Loss Testing

**Goal:** Task 4.3 — reliable live demo under artificial 90% packet loss.

- [ ] Coordinate with Student 4 on how loss will be simulated (e.g. `tc netem` on the relay's network interface, or a loss-injecting proxy) and rehearse the demo multiple times under those exact conditions — not just "it worked once"
- [ ] Make sure UI clearly communicates *what's happening* during high loss (messages visibly "in flight" or retrying, not just a spinner) — for a demo, legibility of the resilience story matters as much as the resilience itself
- [ ] Have a fallback plan/recording in case live demo networking misbehaves in front of an audience
- [ ] Freeze scope — resist last-minute UI changes during demo week

---

## Cross-Cutting Things Worth Deciding Early (Not Week-Specific)

- **State management approach** (if Compose: `ViewModel` + `StateFlow`; if RN: whatever store you pick) — decide once, don't relitigate mid-project
- **Threading discipline for FFI callbacks** — establish a single pattern for "Rust calls back into Kotlin" early in Phase 1 so you're not solving it three separate times in Phases 2 and 4
- **Logging/debug visibility** — since you're integrating three other people's Rust modules, a simple in-app debug log view (even hidden behind a long-press) will save you enormous time diagnosing "is this a UI bug or an FFI bug or a crypto bug" during Phase 4

---

## Suggested Personal Milestones Summary

| Week | Deliverable |
|---|---|
| 1 | Rust ↔ Kotlin FFI hello-world working |
| 2 | Camera permission + preview working, FFI crypto contract agreed with Logan |
| 3 | Full QR generate → scan → paired confirmation demo |
| 5 | Foreground Service running with dummy ticker, survives Doze |
| 6 | Real Rust metronome driving the service via callback FFI |
| 7 | UI resilient to rotation/backgrounding/service restart |
| 8-9 | Static chat UI built ahead; offline-queue-fetch hook wired |
| 10 | Full send/receive pipeline connected |
| 11 | Polished onboarding-to-chat flow |
| 12 | Demo-ready under 90% loss, rehearsed |
