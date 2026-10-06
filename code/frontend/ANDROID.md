# Running the frontend on an Android phone

How to build this Tauri app as an Android APK and install it on a phone.
Written for Ubuntu, including WSL2 on Windows.

- **Once per machine:** steps 1–4 (toolchain).
- **Once per repo:** step 5 (generate the Android project). Already done:
  `src-tauri/gen/android/` is committed.
- **Every build:** steps 6–8 (set the relay address, build, install).

**Shortcut:** once steps 1–4 are done, run
`./runpeer-lan.sh --mobile <relay-ip-or-host[:port]>` from the repo root.
It does steps 5–8 for you. Without a port it uses 4430, so for a relay on
443 write `relay.example.com:443`.

## 1. Base toolchain

Skip this if `./runpeer.sh` already works on this machine.

```bash
sudo apt update
sudo apt install -y build-essential pkg-config perl make curl unzip
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
cargo install tauri-cli --version "^2" --locked
```

`perl` and `make` are needed because SQLCipher (in `code/client`) compiles
its own OpenSSL from source.

## 2. Java

```bash
sudo apt install -y openjdk-21-jdk
```

The Android project's build tools (Gradle 8.14, Android Gradle Plugin 8.11)
need JDK 17 or newer.

## 3. Android SDK and NDK

You don't need Android Studio for this.

1. Download **"Command line tools only"** for Linux from
   <https://developer.android.com/studio#command-line-tools-only>.
   On WSL, your Windows Downloads folder is `/mnt/c/Users/<you>/Downloads`.
2. Unpack it to where `sdkmanager` expects to live:
   ```bash
   mkdir -p ~/Android/Sdk/cmdline-tools
   unzip /path/to/commandlinetools-linux-*_latest.zip -d ~/Android/Sdk/cmdline-tools
   mv ~/Android/Sdk/cmdline-tools/cmdline-tools ~/Android/Sdk/cmdline-tools/latest
   ```
3. Install the SDK pieces:
   ```bash
   SDKM=~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager
   $SDKM --list | grep -E '^\s*ndk;'      # pick the newest version without -rc/-beta
   $SDKM "platform-tools" "platforms;android-36" "ndk;<version>"
   yes | $SDKM --licenses
   ```
   `android-36` matches `compileSdk` in
   `src-tauri/gen/android/app/build.gradle.kts`. If that file says a
   different number, install that platform instead. Accepting the licenses
   lets Gradle download build-tools and anything else it needs on its own.

## 4. Environment variables and Rust target

Add this to `~/.bashrc`, then open a new terminal:

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=$HOME/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk/<version>   # the version you installed in step 3
export PATH=$PATH:$ANDROID_HOME/platform-tools
export RANLIB_aarch64_linux_android=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib
```

The last line is for SQLCipher's OpenSSL build. It otherwise looks for
`aarch64-linux-android-ranlib`, a tool the NDK no longer includes.

Then add the Rust target for 64-bit ARM, which nearly every phone from the
last several years uses:

```bash
rustup target add aarch64-linux-android
```

For an old 32-bit phone, also add `armv7-linux-androideabi` and build with
`--target armv7` in step 7.

## 5. Generate the Android project (once per repo)

**Already done.** `src-tauri/gen/android/` is committed, so skip this
step. It's only needed if that folder is ever deleted and regenerated with:

```bash
cd code/frontend
cargo tauri android init
```

Regenerating overwrites hand-written changes, which you'd need to restore
from git afterwards. They're all under
`src-tauri/gen/android/app/src/main/`:

- `AndroidManifest.xml`: the camera, notification and foreground-service
  permissions, the `MessageService` declaration, backups switched off, and
  no Android TV launcher entry.
- `java/.../MainActivity.kt`, `NativeBridge.kt` and `MessageService.kt`:
  background receiving and notifications (see
  [Receiving in the background](#receiving-in-the-background)), plus
  keeping the UI clear of the status bar, navigation bar and keyboard.
- `res/values/strings.xml`, `res/drawable/ic_stat_message.xml` and
  `res/xml/data_extraction_rules.xml`.

The folder's own `.gitignore` already excludes build output.

## 6. Set the relay address

An Android app can't be launched with environment variables. Instead, the
relay address is read when you **build** the app and baked into it (see
`server_addr_raw()` in `src-tauri/src/commands.rs`):

```bash
export SERVER_ADDR=relay.example.com:443   # TODO: replace with the production relay
```

- The format is `host:port`, using a hostname or an IP. Don't include
  `https://`: the app talks to the relay over a raw UDP socket.
- If you change it, build again. Cargo notices the new value and recompiles.
- If it isn't set, the app falls back to `127.0.0.1:4430`. On a phone that
  address is the phone itself, so the app won't connect.
- The phone must be able to reach that host on that UDP port.
- The relay must run the same version of `code/server` as the app. Older
  relays send each message only once, without waiting for the phone to
  confirm it, so messages sent while the phone is asleep get lost.

## 7. Build the APK

```bash
cd code/frontend
cargo tauri android build --debug --apk --target aarch64
```

- The first build is slow. It compiles every Rust dependency for ARM, and
  Gradle downloads itself and its plugins.
- When it finishes, it prints the APK's location. This is usually
  `src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk`.
- `--debug` signs the APK automatically with this machine's debug key,
  which is all you need to install it on your own phone. A release build
  needs a signing keystore set up first.
- A debug build installs as `nz.ac.waikato.compx374.e2e_messenger.debug`
  (`debugApplicationIdSuffix` in `src-tauri/tauri.conf.json`). That makes it
  a separate app from any release build, with its own identities.
- Use `build`, not `cargo tauri android dev`. Dev mode loads the UI from a
  `trunk serve` running on your PC, so the phone would have to reach your
  dev server. Under WSL, `trunk serve`'s file watcher has also crashed
  (`notify-rs inotify loop panicked`). `build` uses `trunk build` instead
  and packages the UI inside the APK.

## 8. Install it on the phone

**Option A: copy the file over** (no USB debugging needed)

1. Get the APK onto the phone. On WSL you can copy it to Windows first with
   `cp <apk path> /mnt/c/Users/<you>/Downloads/e2e-messenger.apk`, then move
   it to the phone over USB file transfer, Google Drive, or similar.
2. Open the APK on the phone. When Android asks, allow "Install unknown
   apps" for the app you opened it from.

**Option B: `adb`** (quicker when you reinstall often)

1. On the phone, open Settings → About phone and tap **Build number** seven
   times. On Samsung it's under About phone → Software information. Then go
   to Developer options and turn on **USB debugging**.
2. Connect the phone by USB and accept the prompt that appears on it.
3. Run the install. From the repo root, `./install-apk.sh` does it for you:
   it installs the newest build, waits for the phone and its prompt, and
   uses Windows' `adb` on WSL. With several phones connected, pick one with
   `-s <serial>` or use `--all`. To do it by hand instead:
   - **Native Linux:** `adb install -r <apk path>`
   - **WSL:** WSL can't see USB devices without extra setup (usbipd-win), so
     use `adb` on Windows instead. Install Android platform-tools for
     Windows, copy the APK to `C:` as in Option A, and run this in
     PowerShell:
     `adb install -r C:\Users\<you>\Downloads\e2e-messenger.apk`

`-r` replaces an existing install and keeps its data.

## 9. First run

1. Allow notifications when Android asks (Android 13 and newer). Without
   them, the app still receives messages in the background but can't tell
   you about them.
2. **Create identity**, then log in, the same way as on desktop.
3. On the **Connect** screen, paste the relay's public key. It's the
   `Server Static Pubkey:` line the server prints when it starts. Typing 64
   hex characters on a phone is painful, so send it to yourself through a
   notes or chat app and paste it.
4. Add contacts with **Scan QR code** (Android asks for camera permission
   the first time) or by pasting a routing token and Ed25519 key.

## Receiving in the background

While you're logged in and connected, the app runs a foreground service
that keeps it connected to the relay when it's not on screen. Android
shows this as an ongoing "Connected" notification.

- A message that arrives while the app is in the background shows a "New
  message" notification. It names the sender but never shows the text.
  Opening the app clears it.
- While the app isn't on screen, it stops telling your contacts you're
  online, to save battery. They see you as offline until you open it
  again, but their messages still reach you.
- Swiping the app away from the recent-apps screen doesn't log you out. The
  app keeps receiving, and reopening it goes straight back to your chats.
- **Log out** stops the service and the notification.
- If Android kills the app anyway, or the phone restarts, nothing is
  received until you open the app and log in again. Logging in needs your
  passcode, so this can't happen automatically. The relay holds messages
  for up to 7 days, and they arrive once you're back.
- In deep sleep (screen off and phone still for a while), Android may pause
  the app's network access until the phone next wakes. Messages then arrive
  late but aren't lost. Some phone makers also stop background apps more
  aggressively. If messages only arrive when you open the app, set
  Settings → Apps → e2e-messenger → Battery to **Unrestricted**.

## How it differs from desktop

- **One login per identity.** Desktop uses a file lock to stop two copies
  of the app logging into the same identity. Android has no file locking
  (`try_acquire_session_lock` in `src-tauri/src/commands.rs`), but only one
  copy of the app can run there anyway, and the app itself still won't
  delete the identity you're logged into.
- **No backups.** Android's cloud backup and phone-to-phone transfer are
  switched off for this app, so identities never leave the phone.

## Updating the app

Build again (step 7) and install over the top, using `adb install -r` or by
opening the new APK. Identities and chats survive an update but **not** an
uninstall. Backups are off (see
[How it differs from desktop](#how-it-differs-from-desktop)), so
reinstalling doesn't bring them back.

An APK built on a different computer is signed with a different debug key.
Android refuses to install it over the existing app ("App not installed" /
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`), and the only fix is to uninstall
first, which deletes that phone's identities. Build every version on the
same machine to avoid this.

## Optional: test against a relay on your own PC

Use this if the production relay isn't running yet. The phone and the PC
must be on the same Wi-Fi.

1. Start the relay from the repo root with `./runserver-lan.sh`. The
   regular `runserver.sh` only listens on `127.0.0.1`, which the phone
   can't reach. `runserver-lan.sh` listens on all network interfaces and
   prints this machine's IP.
2. **WSL2 only:** by default WSL sits behind a private network that the
   phone can't see into. `runserver-lan.sh` warns you about this, and these
   are the steps it suggests.
   1. Add these lines to `C:\Users\<you>\.wslconfig`:
      ```ini
      [wsl2]
      networkingMode=mirrored
      ```
   2. Run `wsl --shutdown` in PowerShell, then reopen WSL.
   3. Allow inbound UDP on port 4430 (PowerShell as administrator):
      ```powershell
      New-NetFirewallHyperVRule -Name E2E-Relay -DisplayName "E2E relay (UDP 4430)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol UDP -LocalPorts 4430
      ```
3. Build with `./runpeer-lan.sh --mobile`. With no IP given, it bakes in
   this machine's IP. If the IP changes later, build again.
4. If the phone still can't connect, your Wi-Fi may block devices from
   talking to each other. This is common on campus and office networks.
   Turn on the phone's hotspot, connect the PC to it, and run steps 1 and 3
   again.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `android init`/`build` can't find the SDK or NDK | Run `echo $ANDROID_HOME $NDK_HOME` in the same terminal. `NDK_HOME` must point at the versioned folder inside `ndk/`. |
| `aarch64-linux-android-ranlib: not found` while building `openssl-sys` | `RANLIB_aarch64_linux_android` isn't set (step 4). |
| Gradle complains about the Java version | `JAVA_HOME` must point at JDK 17 or newer. |
| The app opens but Connect fails or times out | `SERVER_ADDR` wasn't exported when you built (export it and build again), or the phone can't reach that host over UDP. |
| "App not installed" | See [Updating the app](#updating-the-app). |
| No notifications for new messages | Notifications were denied. Allow them in Settings → Apps → e2e-messenger → Notifications. |
| Messages only arrive when you open the app | The relay is an older version (see step 6), or the phone is stopping the app in the background (see [Receiving in the background](#receiving-in-the-background)). |
| The QR scanner says the camera is blocked | Camera permission was denied. Grant it in Settings → Apps → e2e-messenger → Permissions. |
