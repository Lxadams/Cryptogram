#!/usr/bin/env bash
# Runs the frontend against a relay elsewhere on your network (see
# ./runserver-lan.sh) instead of one on 127.0.0.1:
#
#   ./runpeer-lan.sh --pc     [server]   # desktop peer, same as ./runpeer.sh
#   ./runpeer-lan.sh --mobile [server]   # build the Android app and install it
#
# [server] is the relay's IP or hostname, optionally with :port (default
# 4430). Leave it out when the relay runs on this machine.
#
# --mobile bakes the address into the app (see server_addr_raw() in
# code/frontend/src-tauri/src/commands.rs), so build again if the relay's IP
# changes. The relay's key pin and access key are baked in too
# (relay_config()): read from the relay's own files when it runs on this
# machine, otherwise pass what it prints with --print-pubkey and
# --print-access-key:
#
#   SERVER_PUBKEY=<hex> SERVER_ACCESS_KEY=<hex> ./runpeer-lan.sh --mobile 192.168.1.20
# It needs the Android toolchain from code/frontend/ANDROID.md
# steps 1-4, and does the rest of that guide itself.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$REPO_ROOT/code/frontend"
DEFAULT_PORT=4430

usage() {
  echo "usage: $0 --pc|--mobile [server-ip[:port]]" >&2
  exit 1
}

# This machine's address on the network: the source IP of its default route.
lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

[ $# -ge 1 ] && [ $# -le 2 ] || usage
mode="$1"
server="${2:-}"
case "$mode" in --pc | --mobile) ;; *) usage ;; esac

if [ -z "${SERVER_PUBKEY:-}" ] || [ -z "${SERVER_ACCESS_KEY:-}" ]; then
  if [ -n "$server" ]; then
    echo "error: set SERVER_PUBKEY and SERVER_ACCESS_KEY to what the relay at $server" >&2
    echo "prints with 'server --print-pubkey' and 'server --print-access-key'." >&2
    exit 1
  fi
  SERVER_PUBKEY="${SERVER_PUBKEY:-$(cd "$REPO_ROOT/code/server" && cargo run -q -- --print-pubkey)}"
  SERVER_ACCESS_KEY="${SERVER_ACCESS_KEY:-$(cd "$REPO_ROOT/code/server" && cargo run -q -- --print-access-key)}"
fi
export SERVER_PUBKEY SERVER_ACCESS_KEY

if [ -z "$server" ]; then
  if command -v wslinfo >/dev/null && [ "$(wslinfo --networking-mode)" != mirrored ]; then
    echo "error: WSL is in NAT mode, so other devices can't reach a relay on this machine." >&2
    echo "Pass the relay's IP, or switch WSL to mirrored networking (./runserver-lan.sh prints how)." >&2
    exit 1
  fi
  server="$(lan_ip)"
  if [ -z "$server" ]; then
    echo "error: couldn't work out this machine's IP; pass the relay's IP instead." >&2
    exit 1
  fi
fi
case "$server" in *:*) ;; *) server="$server:$DEFAULT_PORT" ;; esac
export SERVER_ADDR="$server"
echo "Relay: $SERVER_ADDR"

if [ "$mode" = --pc ]; then
  exec "$REPO_ROOT/runpeer.sh"
fi

for var in JAVA_HOME ANDROID_HOME NDK_HOME; do
  if [ -z "${!var:-}" ]; then
    echo "error: $var isn't set; see code/frontend/ANDROID.md steps 2-4." >&2
    exit 1
  fi
done

cd "$FRONTEND_DIR"
rustup target list --installed | grep -x aarch64-linux-android >/dev/null || rustup target add aarch64-linux-android

# One-time setup (ANDROID.md step 5): generate the Android project and let
# the QR scanner use the camera.
MANIFEST=src-tauri/gen/android/app/src/main/AndroidManifest.xml
if [ ! -d src-tauri/gen/android ]; then
  cargo tauri android init --ci
  echo "Generated src-tauri/gen/android/; commit it so nobody else has to."
fi
if ! grep -q 'android.permission.CAMERA' "$MANIFEST"; then
  sed -i '/android.permission.INTERNET/a\    <uses-permission android:name="android.permission.CAMERA" />' "$MANIFEST"
fi

cargo tauri android build --debug --apk --target aarch64
apk="$(find src-tauri/gen/android/app/build/outputs/apk -name '*debug*.apk' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
echo "Built $apk (relay $SERVER_ADDR and its keys baked in)."

# Install over USB if a phone is connected; otherwise leave the APK where
# it's easy to get onto the phone (ANDROID.md step 8).
if command -v adb >/dev/null && [ "$(adb get-state 2>/dev/null)" = device ]; then
  adb install -r "$apk"
  exit
fi
win_home="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r' || true)"
if [ -z "$win_home" ]; then
  echo "No phone found over adb. Copy $apk to the phone and open it to install."
  exit
fi
# WSL can't see USB devices, so use the Windows side: copy the APK to
# Downloads and install with Windows' adb if it has one.
win_apk="$(wslpath "$win_home")/Downloads/e2e-messenger.apk"
cp "$apk" "$win_apk"
if command -v adb.exe >/dev/null && [ "$(adb.exe get-state 2>/dev/null | tr -d '\r')" = device ]; then
  adb.exe install -r "$(wslpath -w "$win_apk")"
else
  echo "Copied to $(wslpath -w "$win_apk"). Get it onto the phone and open it to install."
fi
