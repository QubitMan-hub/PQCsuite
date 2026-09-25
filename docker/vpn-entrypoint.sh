#!/bin/sh
set -e
/opt/strongswan/libexec/ipsec/charon &
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /var/run/charon.vici ] && break; sleep 0.5; done
exec pqcsuite vpn up --config "$1"
