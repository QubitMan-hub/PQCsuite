#!/bin/sh
# The gateway image runs acxelin-vpn. For `up` (site-to-site IPsec) it starts strongSwan's charon first and waits for its control socket.
set -e
if [ "${1:-}" = up ]; then
  /opt/strongswan/libexec/ipsec/charon &
  for i in $(seq 20); do [ -S /var/run/charon.vici ] && break; sleep 0.5; done
  [ -S /var/run/charon.vici ] || { echo "strongSwan's charon did not start; run the container with --network host --cap-add NET_ADMIN" >&2; exit 1; }
fi
exec acxelin-vpn "$@"
