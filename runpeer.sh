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
# Each window opens on its own login screen — choose a username + passcode
# there (or pick one you've already used) to select which saved identity
# this window uses; that's what used to be a `<name>` argument here. See
# `login`/`identity_paths` in code/frontend/src-tauri/src/commands.rs.
#
# The first peer started pays the one-time cost of building the app and
# hosting the Trunk dev server (a minute or two); every peer after that
# reuses it and starts almost instantly. Requires the relay server to
# already be running (./runserver.sh in another terminal).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$REPO_ROOT/code/frontend"
BINARY="$FRONTEND_DIR/src-tauri/target/debug/e2e-messenger"
DEV_PORT=1420

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
