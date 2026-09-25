# VPN gateway: strongSwan 6.1.0 (the release that fixes CVE-2026-78133 and CVE-2026-78135) built against Debian 13's OpenSSL 3.5,
# plus the pqcsuite controller. Run with --network host --cap-add NET_ADMIN (IPsec lives in the host kernel).
ARG BASE=python:3.13-slim-trixie
FROM ${BASE} AS build
ARG STRONGSWAN=6.1.0
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev libgmp-dev pkg-config curl bzip2 ca-certificates \
 && curl -fsSL https://github.com/strongswan/strongswan/releases/download/${STRONGSWAN}/strongswan-${STRONGSWAN}.tar.bz2 | tar xj -C /tmp \
 && cd /tmp/strongswan-${STRONGSWAN} \
 && ./configure --prefix=/opt/strongswan --sysconfdir=/etc --disable-defaults --enable-openssl --enable-ml --enable-vici --enable-swanctl \
      --enable-charon --enable-ikev2 --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-pubkey --enable-random --enable-nonce \
      --enable-hmac --enable-kdf --enable-kernel-netlink --enable-socket-default --enable-updown --enable-resolve --enable-attr \
      --enable-constraints --enable-revocation \
 && make -j"$(nproc)" && make install

FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 libgmp10 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/strongswan /opt/strongswan
COPY --from=build /etc/strongswan.conf /etc/strongswan.conf
COPY pyproject.toml README.md /app/
COPY pqcsuite /app/pqcsuite
RUN pip install --no-cache-dir "/app[vpn]"
COPY docker/vpn-entrypoint.sh /usr/local/bin/vpn-entrypoint
ENTRYPOINT ["vpn-entrypoint"]
CMD ["/etc/pqcsuite/site.toml"]
