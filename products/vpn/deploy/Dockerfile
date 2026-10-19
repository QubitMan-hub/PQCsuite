# The Acxelin VPN gateway: strongSwan 6.1.0 (the release that fixes CVE-2026-78133 and CVE-2026-78135) built against Debian 13's
# OpenSSL 3.5, WireGuard's tools, and acxelin-vpn. IPsec and WireGuard live in the host kernel, so run it with
# --network host --cap-add NET_ADMIN and mount /etc/acxelin-vpn. Build from the repository root:
#   docker build -f products/vpn/deploy/Dockerfile -t acxelin-vpn .
ARG BASE=python:3.13-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
FROM ${BASE} AS strongswan
ARG STRONGSWAN=6.1.0
# the tarball's SHA-256; change it together with STRONGSWAN
ARG STRONGSWAN_SHA256=fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev libgmp-dev pkg-config curl bzip2 ca-certificates \
 && curl -fsSL -o /tmp/ss.tbz https://github.com/strongswan/strongswan/releases/download/${STRONGSWAN}/strongswan-${STRONGSWAN}.tar.bz2 \
 && echo "${STRONGSWAN_SHA256}  /tmp/ss.tbz" | sha256sum -c - && tar xjf /tmp/ss.tbz -C /tmp \
 && cd /tmp/strongswan-${STRONGSWAN} \
 && ./configure --prefix=/opt/strongswan --sysconfdir=/etc --disable-defaults --enable-openssl --enable-ml --enable-vici --enable-swanctl \
      --enable-charon --enable-ikev2 --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-pubkey --enable-random --enable-nonce \
      --enable-hmac --enable-kdf --enable-kernel-netlink --enable-socket-default --enable-updown --enable-resolve --enable-attr \
      --enable-constraints --enable-revocation \
 && make -j"$(nproc)" && make install

FROM ${BASE}
# Apply distribution security updates even when the pinned base predates their publication.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends iproute2 iptables libgmp10 wireguard-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=strongswan /opt/strongswan /opt/strongswan
# charon loads its plugins from strongswan.d (load_modular), so the configuration comes with it
COPY --from=strongswan /etc/strongswan.conf /etc/strongswan.conf
COPY --from=strongswan /etc/strongswan.d /etc/strongswan.d
ENV PATH=/opt/strongswan/sbin:$PATH
COPY core /src/core
COPY products/vpn /src/vpn
# pip is not needed at run time and carries its own vendored packages, so it leaves the image.
RUN pip install --no-cache-dir /src/core "/src/vpn[vpn]" && cp /src/vpn/deploy/entrypoint.sh /usr/local/bin/acxelin-vpn-entrypoint \
 && rm -rf /src && pip uninstall -y pip && acxelin-vpn doctor
VOLUME /etc/acxelin-vpn
ENTRYPOINT ["acxelin-vpn-entrypoint"]
# Site-to-site by default; the WireGuard gateway is: gateway --config /etc/acxelin-vpn/gateway.toml
CMD ["up", "--config", "/etc/acxelin-vpn/site.toml"]
