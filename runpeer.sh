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
