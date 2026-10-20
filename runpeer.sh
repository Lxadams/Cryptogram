#!/usr/bin/env bash
# Launches one E2E-Messenger desktop peer (code/frontend). Run this once per
# peer, in its own terminal, instead of hand-rolling the steps in
# code/frontend/README.md — works for any number of peers, not just two.
# Run it with no arguments every time:
#
#   ./runpeer.sh
#   ./runpeer.sh
#   ./runpeer.sh
#   ...
#
# or point it at a relay elsewhere (the deployed one, say), the same way
# ./build-apk.sh does for the phone app:
#
#   ./runpeer.sh -ip 3.24.135.209 -p 443 -pk <hex>
#
#   -ip <ip>    the relay's IP or hostname (default: 127.0.0.1)
#   -p <port>   the relay's UDP port (default: 4430)
#   -pk <hex>   the relay's "Server Static Pubkey" (default: the local
#               relay's; required with -ip, as the app refuses any relay
#               but the one it was given)
#
# Each peer takes its own: one can use the deployed relay while another
# uses the local one.
#
# Each window opens on its own login screen — choose a username + passcode
# there (or pick one you've already used) to select which saved identity
# this window uses; that's what used to be a `<name>` argument here. See
# `login`/`identity_paths` in code/frontend/src-tauri/src/commands.rs.
#
# The first peer started pays the one-time cost of building the app and
# hosting the Trunk dev server (a minute or two); every peer after that
# reuses it and starts almost instantly. Without -ip, requires the relay
# server to already be running (./runserver.sh in another terminal).
#
# The app checks the relay against the public key it's given in
# SERVER_PUBKEY, rather than asking the relay for one (see
# relay_pubkey_hex() in code/frontend/src-tauri/src/commands.rs). For the
# local relay this script reads it from the relay's identity file; for any
# other, pass -pk (or set SERVER_PUBKEY along with SERVER_ADDR, as
# runpeer-lan.sh does) with the "Server Static Pubkey" that relay prints at
# startup.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$REPO_ROOT/code/frontend"
BINARY="$FRONTEND_DIR/src-tauri/target/debug/e2e-messenger"
DEV_PORT=1420

usage() {
  echo "usage: $0 [-ip <ip> -pk <pubkey-hex>] [-p <port>]" >&2
  exit 1
}

ip=""
port=""
pubkey=""
while [ $# -gt 0 ]; do
  case "$1" in
    -ip) [ $# -ge 2 ] || usage; ip="$2"; shift 2 ;;
    -p) [ $# -ge 2 ] || usage; port="$2"; shift 2 ;;
    -pk) [ $# -ge 2 ] || usage; pubkey="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$port" in *[!0-9]*) echo "error: -p needs a port number, not '$port'." >&2; exit 1 ;; esac
if [ -n "$pubkey" ] && ! [[ "$pubkey" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: -pk needs the relay's 64-character hex public key." >&2
  exit 1
fi
if [ -n "$ip" ] && [ -z "$pubkey" ]; then
  echo "error: -ip needs -pk too: the \"Server Static Pubkey\" that relay prints." >&2
  exit 1
fi
# The flags win over SERVER_ADDR/SERVER_PUBKEY from the environment (which
# runpeer-lan.sh sets); the app reads both when it starts.
if [ -n "$ip" ] || [ -n "$port" ]; then
  export SERVER_ADDR="${ip:-127.0.0.1}:${port:-4430}"
fi
if [ -n "$pubkey" ]; then
  export SERVER_PUBKEY="$pubkey"
fi

# Needed so `cargo tauri dev`/the built binary can find tauri.conf.json and
# the Trunk-built frontend assets. Identity storage does NOT depend on this:
# `identities_root()` in commands.rs resolves to the OS's per-app data
# directory (via Tauri's `app_local_data_dir()`), not a path relative to
# cwd — cwd-relative storage used to break here, because `cargo tauri dev`
# runs its DevCommand with cwd set to `src-tauri/` (a `cargo run` detail),
# while a peer attaching directly to an already-running dev server execs
# the binary with cwd left at `$FRONTEND_DIR` — two different processes,
# two different `identities/` directories, confirmed by testing two peers.
cd "$FRONTEND_DIR"

if [ -z "${SERVER_PUBKEY:-}" ]; then
  if [ -n "${SERVER_ADDR:-}" ]; then
    echo "error: set SERVER_PUBKEY to the \"Server Static Pubkey\" the relay at $SERVER_ADDR prints." >&2
    exit 1
  fi
  SERVER_PUBKEY="$(cd "$REPO_ROOT/code/server" && cargo run -q -- --print-pubkey)"
  export SERVER_PUBKEY
fi
echo "Relay: ${SERVER_ADDR:-127.0.0.1:4430}"

# VS Code installed as a snap leaks its sandbox environment into its
# integrated terminal: GTK_PATH, GIO_MODULE_DIR etc. point at libraries under
# /snap built against the snap's own glibc, so the WebKitGTK window dies with
#   symbol lookup error: /snap/core20/current/lib/x86_64-linux-gnu/libpthread.so.0:
#   undefined symbol: __libc_pthread_init, version GLIBC_PRIVATE
# It also points XDG_DATA_HOME at ~/snap/code/<rev>/.local/share, which would
# silently move `app_local_data_dir()` (identity storage) away from the
# identities saved by peers started from a normal terminal. Undo all of it.
if [ "${SNAP_NAME:-}" = "code" ] || [[ "${GTK_PATH:-}" == /snap/* ]]; then
  for var in XDG_DATA_DIRS XDG_CONFIG_DIRS; do
    orig="${var}_VSCODE_SNAP_ORIG"
    if [ -n "${!orig:-}" ]; then export "$var=${!orig}"; else unset "$var"; fi
  done
  unset GTK_PATH GTK_EXE_PREFIX GTK_IM_MODULE_FILE GIO_MODULE_DIR \
    GDK_PIXBUF_MODULE_FILE GDK_PIXBUF_MODULEDIR GSETTINGS_SCHEMA_DIR \
    LOCPATH XDG_DATA_HOME
fi

# Bash-native "is something listening on this TCP port" check — avoids
# depending on nc/lsof/curl being installed.
port_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

if port_open "$DEV_PORT"; then
  if [ ! -x "$BINARY" ]; then
    echo "error: $BINARY not built yet." >&2
    echo "Start your first peer (./runpeer.sh) and wait for its window to open before starting additional ones." >&2
    exit 1
  fi
  echo "Attaching to the running dev server."
  exec "$BINARY"
else
  echo "No dev server detected on port $DEV_PORT — building and hosting it now."
  echo "This peer's terminal must stay open; run ./runpeer.sh again in new terminals for more peers."
  exec cargo tauri dev
fi
