#!/usr/bin/env bash
# Starts an Android emulator with the app installed, so you can test with
# one phone (or none) instead of two. The first run downloads the emulator
# and creates it ("e2e-test"); later runs reuse it, keeping its identities
# and chats.
#
#   ./build-apk.sh --emulator   # first, and again after code changes
#   ./run-emulator.sh
#
# The emulator reaches the relay at this computer's IP, the same as a
# phone, so one APK works on both. Run the relay with ./runserver-lan.sh.
# Its back camera is this computer's webcam: to have it scan a phone's QR
# code, hold the phone up to the webcam. A phone can scan the emulator's QR
# code straight off the screen.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APK_DIR="$REPO_ROOT/code/frontend/src-tauri/gen/android/app/build/outputs/apk"
APP_ID=nz.ac.waikato.compx374.e2e_messenger.debug
AVD=e2e-test
IMAGE="system-images;android-35;google_apis;x86_64"

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
# sdkmanager and avdmanager need Java: the environment's, or a usual place.
if [ -z "${JAVA_HOME:-}" ]; then
  if command -v javac >/dev/null; then
    JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
  else
    for dir in "$HOME"/java-* /usr/lib/jvm/*; do
      if [ -x "$dir/bin/javac" ]; then JAVA_HOME="$dir"; break; fi
    done
  fi
fi
export JAVA_HOME="${JAVA_HOME:-}"
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager"
EMULATOR="$ANDROID_HOME/emulator/emulator"
ADB="$ANDROID_HOME/platform-tools/adb"

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "error: can't use /dev/kvm, so the emulator would be far too slow." >&2
  echo "Add yourself to the kvm group (sudo usermod -aG kvm \$USER), then log in again." >&2
  exit 1
fi

# The APK has to include the emulator's x86_64 code.
apk="$(find "$APK_DIR" -name '*debug*.apk' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)"
if [ -z "$apk" ] || ! unzip -Z1 "$apk" 'lib/x86_64/*' >/dev/null 2>&1; then
  echo "error: no APK that runs on the emulator. Build one with ./build-apk.sh --emulator" >&2
  exit 1
fi

# One-time setup: the emulator and its system image, then the device.
if [ ! -x "$EMULATOR" ] || [ ! -d "$ANDROID_HOME/system-images/android-35/google_apis/x86_64" ]; then
  echo "Downloading the Android emulator (about 1.5 GB, once)..."
  "$SDKMANAGER" --install emulator "$IMAGE"
fi
if ! grep -qx "$AVD" <<<"$("$EMULATOR" -list-avds)"; then
  echo no | "$AVDMANAGER" create avd -n "$AVD" -k "$IMAGE" -d pixel_6
  config="$HOME/.android/avd/$AVD.avd/config.ini"
  set_config() {
    sed -i "/^$1=/d" "$config"
    echo "$1=$2" >>"$config"
  }
  set_config hw.camera.back webcam0 # for scanning QR codes
  set_config hw.keyboard yes        # type with this computer's keyboard
  set_config hw.ramSize 2048
fi

running() {
  "$ADB" devices | awk '$1 ~ /^emulator-/ && $2 == "device" && !found { print $1; found = 1 }'
}

serial="$(running)"
if [ -z "$serial" ]; then
  log="$HOME/.android/avd/$AVD.log"
  echo "Starting the emulator (log: $log)..."
  # Detached, so it keeps running after this script exits.
  setsid nohup "$EMULATOR" -avd "$AVD" -netdelay none -netspeed full >"$log" 2>&1 &
  for _ in $(seq 180); do
    serial="$(running)"
    [ -z "$serial" ] || [ "$("$ADB" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != 1 ] || break
    serial=""
    sleep 1
  done
  if [ -z "$serial" ]; then
    echo "error: the emulator didn't finish starting within 3 minutes; see $log" >&2
    exit 1
  fi
fi

"$REPO_ROOT/install-apk.sh" -s "$serial" "$apk"
"$ADB" -s "$serial" shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
echo "The app is open on the emulator ($serial)."
