#!/usr/bin/env bash
# Measures what the app costs in battery while someone is logged in: the
# link to the relay sends and receives cells about 4 times a second each
# way, all the time, under a partial wake lock (see MessageService.kt). It
# uses Android's own accounting (batterystats), on a phone over USB or the
# emulator.
#
#   ./measure-battery.sh             # 30 minutes
#   ./measure-battery.sh 60          # minutes
#   ./measure-battery.sh -s SERIAL   # one device, when several are connected
#
# Before running: install the app, log in and press Connect, then leave it
# (the screen may turn off; that's the case that matters). Pass --baseline
# to measure with nobody logged in instead, for comparison.
#
# It tells Android the device is unplugged (USB power would otherwise stop
# the accounting), resets the statistics, waits, and prints the app's share:
# its estimated drain, CPU time, wake lock time and network traffic, and
# what that comes to per hour and per day. Charging is put back as it was
# afterwards, even if the script is interrupted.
#
# The emulator's power figures come from a generic power profile, so only
# its CPU time, wake lock and traffic numbers mean much there. For a real
# figure, run it on a phone; the cellular or Wi-Fi radio, which a constant
# packet stream never lets go idle, is most of the cost.
set -euo pipefail

APP_ID="${APP_ID:-nz.ac.waikato.compx374.e2e_messenger.debug}"
ADB="${ADB:-$(command -v adb || echo "${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb")}"

minutes=30
label="logged in, link up"
adb_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -s) adb_args=(-s "$2"); shift 2 ;;
    --baseline) label="baseline, nobody logged in"; shift ;;
    [0-9]*) minutes="$1"; shift ;;
    *) sed -n '8,10p' "$0" | sed 's/^# *//' >&2; exit 1 ;;
  esac
done
adb_() { "$ADB" "${adb_args[@]}" "$@"; }

if [ "$(adb_ get-state 2>/dev/null)" != device ]; then
  echo "error: no device found over adb (start ./run-emulator.sh, or plug in a phone)." >&2
  exit 1
fi
# (Read whole outputs before searching them: with pipefail, a grep that
# stops early would kill adb with SIGPIPE, and the script with it.)
package="$(adb_ shell dumpsys package "$APP_ID" | tr -d '\r')"
# `appId=` on recent Android, `userId=` on older versions.
uid="$(grep -m1 -oE '(appId|userId)=[0-9]+' <<<"$package" | cut -d= -f2 || true)"
if [ -z "$uid" ]; then
  echo "error: $APP_ID isn't installed (APP_ID=... for a release build)." >&2
  exit 1
fi
# How batterystats names the app: u0a<uid - 10000>.
app="u0a$((uid - 10000))"

adb_ shell dumpsys battery unplug
trap 'adb_ shell dumpsys battery reset >/dev/null 2>&1 || true' EXIT
adb_ shell dumpsys batterystats --reset >/dev/null
echo "Measuring for $minutes minutes ($label), from $(date '+%H:%M')..."
sleep "$((minutes * 60))"

stats="$(adb_ shell dumpsys batterystats | tr -d '\r')"
capacity="$(grep -m1 -o 'Capacity: [0-9.]*' <<<"$stats" | awk '{print $2}' || true)"
drain="$(grep -m1 -E "^ +UID $app: " <<<"$stats" | awk '{print $3}' || true)"

echo
echo "== $APP_ID ($app), $label, $minutes minutes"
grep -m1 -E "^ +UID $app: " <<<"$stats" || echo "  (no power estimate for the app)"
# The app's own section: CPU time, wake locks, network traffic.
awk -v app="$app" '
  $0 ~ "^  "app":$" { inside = 1; print; next }
  inside && /^  [^ ]/ { exit }
  inside && /(Wake lock|Total cpu time|Wi-Fi network|Mobile network|Foreground service)/ { print }
' <<<"$stats"
if [ -n "$drain" ] && [ -n "$capacity" ]; then
  awk -v d="$drain" -v m="$minutes" -v c="$capacity" 'BEGIN {
    per_hour = d * 60 / m
    printf "\n%.2f mAh in %d min = %.1f mAh/hour = %.0f mAh/day (%.1f%% of a %d mAh battery per day)\n",
      d, m, per_hour, per_hour * 24, 100 * per_hour * 24 / c, c
  }'
fi
