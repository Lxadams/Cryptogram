#!/usr/bin/env bash
# Rebuilds the Android APK with a relay's address and public key baked in
# (see server_addr_raw() and relay_pubkey_hex() in
# code/frontend/src-tauri/src/commands.rs). Builds only; install the result
# with ./install-apk.sh.
#
#   ./build-apk.sh                                  # the relay on this computer
#   ./build-apk.sh -ip 3.24.135.209 -p 443 -pk <hex>   # a relay elsewhere
#   ./build-apk.sh --emulator                       # also runs on the emulator
#
#   -ip <ip>    the relay's IP or hostname (default: this machine's network IP)
#   -p <port>   the relay's UDP port (default: 4430)
#   -pk <hex>   the relay's "Server Static Pubkey" (default: the local
#               relay's; required with -ip, as the app refuses any relay but
#               the one it was built for)
#
# --emulator adds x86_64 code (the emulator's CPU) next to the phones'
# arm64, so one APK installs on both. See ./run-emulator.sh.
#
# Without -ip, run the relay with ./runserver-lan.sh so the phone can reach
# it, and rebuild whenever this machine's IP changes. Uses JAVA_HOME,
# ANDROID_HOME and NDK_HOME if set (code/frontend/ANDROID.md step 4),
# otherwise looks for them in their usual places.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$REPO_ROOT/code/frontend"

usage() {
  echo "usage: $0 [-ip <ip> -pk <pubkey-hex>] [-p <port>] [--emulator]" >&2
  exit 1
}

targets=(aarch64)
ip=""
port=4430
pubkey=""
while [ $# -gt 0 ]; do
  case "$1" in
    -ip) [ $# -ge 2 ] || usage; ip="$2"; shift 2 ;;
    -p) [ $# -ge 2 ] || usage; port="$2"; shift 2 ;;
    -pk) [ $# -ge 2 ] || usage; pubkey="$2"; shift 2 ;;
    --emulator) targets+=(x86_64); shift ;;
    *) usage ;;
  esac
done
case "$port" in '' | *[!0-9]*) echo "error: -p needs a port number, not '$port'." >&2; exit 1 ;; esac
if [ -n "$pubkey" ] && ! [[ "$pubkey" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: -pk needs the relay's 64-character hex public key." >&2
  exit 1
fi
if [ -n "$ip" ] && [ -z "$pubkey" ]; then
  echo "error: -ip needs -pk too: the \"Server Static Pubkey\" that relay prints." >&2
  exit 1
fi

# This machine's address on the network: the source IP of its default route.
lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

remote=false
if [ -n "$ip" ]; then
  remote=true
else
  if command -v wslinfo >/dev/null && [ "$(wslinfo --networking-mode)" != mirrored ]; then
    echo "error: WSL is in NAT mode, so a phone can't reach a relay on this machine." >&2
    echo "Switch WSL to mirrored networking (./runserver-lan.sh prints how), or pass -ip." >&2
    exit 1
  fi
  ip="$(lan_ip)"
  if [ -z "$ip" ]; then
    echo "error: couldn't work out this machine's IP. Is it on a network? Or pass -ip." >&2
    exit 1
  fi
fi
export SERVER_ADDR="$ip:$port"
# The key given with -pk, else the local relay's; never one left in the
# environment for another relay: the app refuses any relay but the one it
# was built for.
if [ -n "$pubkey" ]; then
  SERVER_PUBKEY="$pubkey"
else
  SERVER_PUBKEY="$(cd "$REPO_ROOT/code/server" && cargo run -q -- --print-pubkey)"
fi
export SERVER_PUBKEY
echo "Relay: $SERVER_ADDR"
echo "Key:   $SERVER_PUBKEY"

# Android toolchain: the environment's, or the usual install locations.
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
if [ -z "${NDK_HOME:-}" ]; then
  NDK_HOME="$({ find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true; } | sort -V | tail -1)"
fi
if [ -z "${JAVA_HOME:-}" ]; then
  if command -v javac >/dev/null; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
  else
    for dir in "$HOME"/java-* /usr/lib/jvm/*; do
      if [ -x "$dir/bin/javac" ]; then JAVA_HOME="$dir"; break; fi
    done
  fi
fi
export NDK_HOME JAVA_HOME="${JAVA_HOME:-}"
for var in JAVA_HOME ANDROID_HOME NDK_HOME; do
  if [ ! -d "${!var}" ]; then
    echo "error: no $var found; see code/frontend/ANDROID.md steps 2-4." >&2
    exit 1
  fi
done
# SQLCipher's OpenSSL build looks for a ranlib the NDK no longer ships
# (ANDROID.md step 4).
ranlib="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib"
export RANLIB_aarch64_linux_android="${RANLIB_aarch64_linux_android:-$ranlib}"
export RANLIB_x86_64_linux_android="${RANLIB_x86_64_linux_android:-$ranlib}"

cd "$FRONTEND_DIR"
if [ ! -d src-tauri/gen/android ]; then
  echo "error: src-tauri/gen/android is missing; run ./runpeer-lan.sh --mobile once to generate it." >&2
  exit 1
fi
target_args=()
for t in "${targets[@]}"; do
  rustup target list --installed | grep -x "$t-linux-android" >/dev/null || rustup target add "$t-linux-android"
  target_args+=(--target "$t")
done

cargo tauri android build --debug --apk "${target_args[@]}"
apk="$(find src-tauri/gen/android/app/build/outputs/apk -name '*debug*.apk' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)"
echo
echo "Built $FRONTEND_DIR/$apk"
echo "  relay $SERVER_ADDR and its key baked in"
if $remote; then
  echo "Install it with ./install-apk.sh."
else
  echo "Install it with ./install-apk.sh, and run the relay with ./runserver-lan.sh."
fi
