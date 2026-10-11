#!/usr/bin/env bash
# Like ./runserver-lan.sh, but over a bad network: each packet between the
# relay and its clients, either way, is dropped with probability LOSS, as
# on a jammed or failing link. Run it with no arguments for 70% loss, or
# give the loss as a fraction:
#
#   ./runserver-lan-lossy.sh        # 70% each way
#   ./runserver-lan-lossy.sh 0.5    # 50% each way
#   ./runserver-lan-lossy.sh 0.7 10 # a summary every 10 s, not every second
#
# Every second that packets flow, it prints how many got through and how
# many were dropped, each way, and the loss so far.
#
# While it runs, type a new loss and press Enter to change it. Adding a
# contact takes several single packets, resent only after 30 s, then 60 s
# and so on, so at 70% it can take many minutes. To test messages, type 0,
# add contacts, then type 0.7.
#
# Clients connect exactly as to runserver-lan.sh's relay (UDP 4430, the
# same key), so the ./runpeer-lan.sh commands it prints, and APKs from
# ./build-apk.sh, work unchanged. Behind that port, a proxy
# (code/server/examples/lossy_proxy.rs) does the dropping, and the relay
# itself listens on 4431. A client pointed at 4431 skips the loss, so you
# can jam just one side of a conversation.
#
# Every client reaches the relay through the proxy, from this machine, so
# they share the relay's handshake limit for one address (a burst of 20,
# then one a second). That's plenty for a few devices.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=4430       # through the loss
CLEAN_PORT=4431 # the relay itself
LOSS="${1:-0.7}"
REPORT_SECS="${2:-1}" # how often the proxy prints a summary

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
  3. In PowerShell as administrator, allow inbound UDP $PORT and $CLEAN_PORT:
       New-NetFirewallHyperVRule -Name E2E-Relay-Lossy -DisplayName "E2E relay (UDP $PORT, $CLEAN_PORT)" -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol UDP -LocalPorts $PORT,$CLEAN_PORT

EOF
elif command -v ufw >/dev/null && grep -qs "^ENABLED=yes" /etc/ufw/ufw.conf; then
  # (Not "systemctl is-active ufw": that says active even with ufw turned off.)
  echo "note: ufw is running; if devices can't connect, run: sudo ufw allow $PORT/udp && sudo ufw allow $CLEAN_PORT/udp" >&2
fi

cd "$REPO_ROOT/code/server"
cargo build
cargo build --example lossy_proxy

ip="$(lan_ip)"
if $reachable && [ -n "$ip" ]; then
  # As in runserver-lan.sh: on this machine runpeer-lan.sh reads the key
  # itself, as long as it isn't given the relay's address.
  if pubkey="$(./target/debug/server --print-pubkey 2>/dev/null)"; then
    key="SERVER_PUBKEY=$pubkey"
  else
    key='SERVER_PUBKEY=<the "Server Static Pubkey" the relay prints below>'
  fi
  echo
  echo "Relay reachable on your network at $ip:$PORT, through the loss"
  echo "  On this machine:"
  echo "    Desktop peer:  ./runpeer-lan.sh --pc"
  echo "    Android app:   ./runpeer-lan.sh --mobile"
  echo "  On another machine:"
  echo "    Desktop peer:  $key ./runpeer-lan.sh --pc $ip"
  echo "    Android app:   $key ./runpeer-lan.sh --mobile $ip"
  echo "  With no loss, to jam only the other side (from anywhere):"
  echo "    Desktop peer:  $key ./runpeer-lan.sh --pc $ip:$CLEAN_PORT"
  echo "    Android app:   $key ./runpeer-lan.sh --mobile $ip:$CLEAN_PORT"
  echo
fi

# Run both, and stop both when either stops (or on Ctrl-C). The proxy
# reads new losses from this terminal: a job in the background would
# otherwise get /dev/null as its input.
exec 3<&0
BIND_ADDR="0.0.0.0:$CLEAN_PORT" ./target/debug/server &
relay=$!
./target/debug/examples/lossy_proxy "0.0.0.0:$PORT" "127.0.0.1:$CLEAN_PORT" "$LOSS" "$REPORT_SECS" <&3 &
proxy=$!
trap 'kill "$relay" "$proxy" 2>/dev/null' EXIT
trap 'exit 130' INT TERM
wait -n "$relay" "$proxy"
