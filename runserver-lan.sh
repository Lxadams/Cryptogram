#!/usr/bin/env bash
# Runs the relay server so other devices on your network (phones, other
# PCs) can reach it; runserver.sh only listens on 127.0.0.1. Run it with no
# arguments:
#
#   ./runserver-lan.sh
#
# It prints the ./runpeer-lan.sh commands that point clients at it, from
# this machine and from others. On WSL2 other devices can only reach it with
# mirrored networking; the script warns and says how to switch if WSL is
# still in its default NAT mode.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=4430

# This machine's address on the network: the source IP of its default route.
lan_ip() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

reachable=true
if command -v wslinfo >/dev/null && [ "$(wslinfo --networking-mode)" != mirrored ]; then
  reachable=false
  cat >&2 <<EOF
warning: WSL is in NAT mode, so only peers on this PC can reach the relay.
To let other devices in (one-time setup):
  1. Put this in C:\\Users\\<you>\\.wslconfig:
       [wsl2]
       networkingMode=mirrored
  2. Run 'wsl --shutdown' in PowerShell, then reopen WSL.
  3. In PowerShell as administrator, allow inbound UDP $PORT:
       New-NetFirewallHyperVRule -Name E2E-Relay -DisplayName "E2E relay (UDP $PORT)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol UDP -LocalPorts $PORT

EOF
elif command -v ufw >/dev/null && grep -qs "^ENABLED=yes" /etc/ufw/ufw.conf; then
  # (Not "systemctl is-active ufw": that says active even with ufw turned off.)
  echo "note: ufw is running; if devices can't connect, run: sudo ufw allow $PORT/udp" >&2
fi

cd "$REPO_ROOT/code/server"
cargo build

ip="$(lan_ip)"
if $reachable && [ -n "$ip" ]; then
  # Clients are built with the relay's key rather than asking for it. On
  # this machine runpeer-lan.sh reads it itself, as long as it isn't given
  # the relay's address; anywhere else it needs the key. A relay that has
  # never run here has no key yet: it makes one as it starts, below.
  if pubkey="$(./target/debug/server --print-pubkey 2>/dev/null)"; then
    key="SERVER_PUBKEY=$pubkey"
  else
    key='SERVER_PUBKEY=<the "Server Static Pubkey" the relay prints below>'
  fi
  echo
  echo "Relay reachable on your network at $ip:$PORT"
  echo "  On this machine:"
  echo "    Desktop peer:  ./runpeer-lan.sh --pc"
  echo "    Android app:   ./runpeer-lan.sh --mobile"
  echo "  On another machine:"
  echo "    Desktop peer:  $key ./runpeer-lan.sh --pc $ip"
  echo "    Android app:   $key ./runpeer-lan.sh --mobile $ip"
  echo
fi

BIND_ADDR="0.0.0.0:$PORT" exec ./target/debug/server
