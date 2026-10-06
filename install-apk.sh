#!/usr/bin/env bash
# Installs an already-built Android APK on a phone over USB, without
# rebuilding. Build one first with ./runpeer-lan.sh --mobile (or see
# code/frontend/ANDROID.md).
#
#   ./install-apk.sh               # newest debug APK, on the connected phone
#   ./install-apk.sh path/to.apk   # a specific APK
#   ./install-apk.sh -s SERIAL     # one phone, when several are connected
#   ./install-apk.sh --all         # every connected phone
#
# Waits up to 2 minutes (WAIT_SECONDS) for a phone to be plugged in and for
# "Allow USB debugging" to be accepted on it. Installs over the top, which
# keeps the app's identities and chats. On WSL it uses Windows' adb, since
# WSL can't see USB devices.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APK_DIR="$REPO_ROOT/code/frontend/src-tauri/gen/android/app/build/outputs/apk"
WAIT_SECONDS="${WAIT_SECONDS:-120}"

usage() {
  sed -n '6,9p' "$0" | sed 's/^# *//' >&2
  exit 1
}

serial=""
all=false
apk=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) [ $# -ge 2 ] || usage; serial="$2"; shift 2 ;;
    --all) all=true; shift ;;
    -*) usage ;;
    *) [ -z "$apk" ] || usage; apk="$1"; shift ;;
  esac
done

# The APK: the one given, or the newest debug build.
if [ -z "$apk" ]; then
  apk="$(find "$APK_DIR" -name '*debug*.apk' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)"
  if [ -z "$apk" ]; then
    echo "error: no APK under $APK_DIR. Build one first: ./runpeer-lan.sh --mobile" >&2
    exit 1
  fi
fi
if [ ! -f "$apk" ]; then
  echo "error: $apk doesn't exist." >&2
  exit 1
fi
echo "APK: $apk (built $(date -r "$apk" '+%Y-%m-%d %H:%M'))"

# adb: Windows' on WSL, otherwise on PATH or in the Android SDK.
apk_arg="$apk"
if grep -qi microsoft /proc/version 2>/dev/null && command -v adb.exe >/dev/null; then
  ADB=adb.exe
  # Windows' adb needs a Windows path, so copy the APK there first.
  win_home="$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")"
  cp "$apk" "$win_home/Downloads/e2e-messenger.apk"
  apk_arg="$(wslpath -w "$win_home/Downloads/e2e-messenger.apk")"
elif command -v adb >/dev/null; then
  ADB=adb
elif [ -x "${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb" ]; then
  ADB="${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb"
else
  echo "error: adb not found. Install Android platform-tools (ANDROID.md step 3)." >&2
  exit 1
fi

# Serials of connected phones in a given state ("device" = ready).
phones() {
  "$ADB" devices | tr -d '\r' | awk -v state="$1" 'NR > 1 && $2 == state { print $1 }'
}

# Wait for a phone. If one sits at "unauthorized" (the phone hasn't shown or
# accepted the prompt), restart adb once, which makes the phone ask again.
"$ADB" start-server >/dev/null 2>&1 || true
devices=""
said=""
unauthorized_for=0
for _ in $(seq "$WAIT_SECONDS"); do
  devices="$(phones device)"
  [ -z "$serial" ] || devices="$(grep -x -- "$serial" <<<"$devices" || true)"
  [ -z "$devices" ] || break
  if [ -n "$(phones unauthorized)" ]; then
    msg="Phone connected: unlock it and tap Allow on \"Allow USB debugging?\""
    unauthorized_for=$((unauthorized_for + 1))
    if [ "$unauthorized_for" -eq 15 ]; then
      echo "Asking the phone again..."
      "$ADB" kill-server >/dev/null 2>&1 || true
      "$ADB" start-server >/dev/null 2>&1 || true
    fi
  elif [ -n "$serial" ] && [ -n "$(phones device)" ]; then
    msg="Waiting for $serial (other phones are connected; see: $ADB devices)..."
  else
    msg="Waiting for a phone on USB with USB debugging on (ANDROID.md step 8)..."
  fi
  [ "$msg" = "$said" ] || { echo "$msg"; said="$msg"; }
  sleep 1
done
if [ -z "$devices" ]; then
  echo "error: no phone ready after ${WAIT_SECONDS}s." >&2
  exit 1
fi

model() {
  "$ADB" -s "$1" shell getprop ro.product.model | tr -d '\r'
}

if [ "$(wc -l <<<"$devices")" -gt 1 ] && ! $all; then
  echo "Several phones are connected. Pick one with -s, or use --all:" >&2
  for s in $devices; do echo "  -s $s   ($(model "$s"))" >&2; done
  exit 1
fi

status=0
for s in $devices; do
  echo "Installing on $(model "$s") ($s)..."
  if out="$("$ADB" -s "$s" install -r "$apk_arg" 2>&1)" && grep -q '^Success' <<<"$out"; then
    echo "  Done. Identities and chats are kept; log in again in the app."
    continue
  fi
  status=1
  sed 's/^/  /' <<<"$out" >&2
  if grep -q INSTALL_FAILED_UPDATE_INCOMPATIBLE <<<"$out"; then
    pkg="$(grep -o 'Existing package [^ ]*' <<<"$out" | awk '{ print $3 }')"
    cat >&2 <<EOF
  The app on this phone was built on a different computer, so Android won't
  update it. Uninstalling it first works, but DELETES its identities and
  chats (see "Updating the app" in code/frontend/ANDROID.md):
    $ADB -s $s uninstall ${pkg:-nz.ac.waikato.compx374.e2e_messenger.debug}
EOF
  fi
done
exit "$status"
