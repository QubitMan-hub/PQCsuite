#!/bin/sh
# Debian 13: OpenSSL 3.5 and Python 3.13 from the distribution, strongSwan 6.1.0 from source, WireGuard from the kernel.
set -eu
STRONGSWAN=6.1.0
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y --no-install-recommends python3 python3-venv iproute2 wireguard-tools nftables \
  build-essential libssl-dev libgmp-dev pkg-config curl bzip2 ca-certificates
curl -fsSL "https://github.com/strongswan/strongswan/releases/download/${STRONGSWAN}/strongswan-${STRONGSWAN}.tar.bz2" | tar xj -C /tmp
(cd "/tmp/strongswan-${STRONGSWAN}" && ./configure --prefix=/opt/strongswan --sysconfdir=/etc --disable-defaults --enable-openssl --enable-ml \
  --enable-vici --enable-swanctl --enable-charon --enable-ikev2 --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-pubkey \
  --enable-random --enable-nonce --enable-hmac --enable-kdf --enable-kernel-netlink --enable-socket-default --enable-updown --enable-resolve \
  --enable-attr --enable-constraints --enable-revocation && make -j"$(nproc)" && sudo make install)
sudo rm -rf "/tmp/strongswan-${STRONGSWAN}"
sudo apt-get purge -y build-essential libssl-dev libgmp-dev pkg-config && sudo apt-get autoremove -y
sudo useradd --system --home /var/lib/pqcsuite --create-home pqc
sudo python3 -m venv /opt/pqcsuite
sudo /opt/pqcsuite/bin/pip install --no-cache-dir "/tmp/pqcsuite[vpn]"
sudo ln -sf /opt/pqcsuite/bin/pqcsuite /usr/local/bin/pqcsuite
sudo install -d -m 0750 -o pqc /etc/pqcsuite
sudo install -m 0644 /tmp/pqcsuite/deploy/systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
for unit in pqcsuite-edge strongswan-pqc pqcsuite-ipsec pqcsuite-wireguard pqcsuite-maintain.timer; do sudo systemctl enable "$unit"; done
pqcsuite doctor
sudo rm -rf /tmp/pqcsuite
