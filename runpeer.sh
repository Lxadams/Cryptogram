#!/usr/bin/env bash
# Launches one E2E-Messenger desktop peer (code/frontend). Run this once per
# peer, in its own terminal, instead of hand-rolling the steps in
# code/frontend/README.md — works for any number of peers, not just two:
#
#   ./runpeer.sh alice
#   ./runpeer.sh bob
#   ./runpeer.sh charlie
#   ...
#
# The name is just a label for this peer's own identity/session storage
# (under .peers/<name>/); omit it to auto-pick the next free number.
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

if [ $# -ge 1 ]; then
  PEER_NAME="$1"
else
  n=1
  while [ -d "$REPO_ROOT/.peers/$n" ]; do
    n=$((n + 1))
  done
  PEER_NAME="$n"
fi

PEER_DIR="$REPO_ROOT/.peers/$PEER_NAME"
mkdir -p "$PEER_DIR"
# Every peer's Client::save()/load() goes through this path (see
# code/client/src/lib.rs's state_file_path()), so each peer keeps its own
# identity/sessions no matter where cargo/tauri actually sets the running
# process's working directory.
export E2E_STATE_FILE="$PEER_DIR/client_state.json"

# Read by commands.rs to label this peer's own identity card with a name
# instead of just hex, so contacts can enter it when adding you and see
# "alice" rather than a routing token in their contact list.
export E2E_PEER_NAME="$PEER_NAME"

# Bash-native "is something listening on this TCP port" check — avoids
# depending on nc/lsof/curl being installed.
port_open() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

if port_open "$DEV_PORT"; then
  if [ ! -x "$BINARY" ]; then
    echo "error: $BINARY not built yet." >&2
    echo "Start your first peer (e.g. ./runpeer.sh) and wait for its window to open before starting additional ones." >&2
    exit 1
  fi
  echo "Peer '$PEER_NAME': attaching to the running dev server (state in $PEER_DIR)"
  exec "$BINARY"
else
  echo "Peer '$PEER_NAME': no dev server detected on port $DEV_PORT — building and hosting it now (state in $PEER_DIR)"
  echo "This peer's terminal must stay open; run ./runpeer.sh again in new terminals for more peers."
  cd "$FRONTEND_DIR"
  exec cargo tauri dev
fi
