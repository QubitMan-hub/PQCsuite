# Acxelin PQC Suite

Post-quantum security for the traffic, tunnels and data you run today, in Python. Four products share one ML-DSA certificate authority:

| Product | What it does | Command |
|---|---|---|
| **TLS 1.3 + mTLS** | Post-quantum TLS in front of any TCP service, mutual TLS between services, and a CA with EST and ACME enrollment | `pqcsuite tls`, `pqcsuite ca` |
| **IPsec VPN** | Site-to-site IPsec with hybrid ML-KEM and ML-DSA authentication, plus WireGuard remote access | `pqcsuite vpn` |
| **Vault** | Quantum-safe encryption for files, folders and backups | `pqcsuite vault` |
| **Readiness assessment** | TLS and SSH endpoint grades, and compliance evidence for NIST IR 8547 and CNSA 2.0 | `pqcsuite readiness` |

`pqcsuite console` shows all four on one page. The website is in `site/`; `python site/publish.py https://YOUR-ADDRESS/ dist` copies it into `dist` with the absolute addresses that link previews and search engines need (canonical links, preview images, `sitemap.xml`, `robots.txt`). Wolf Pack CBOM, the separate cryptography inventory scanner, is in [`wolf-pack/`](wolf-pack/README.md). `pqcsuite` is a working name (`NAME` in `pqcsuite/__init__.py`).

## Install

Python 3.11+.

```
pip install -e .            # add [vpn] on IPsec gateways
pqcsuite doctor
```

The CA and Vault work everywhere. TLS and the VPN key agreement need **OpenSSL 3.5 or newer**:

| Platform | How to get it |
|---|---|
| Debian 13, Ubuntu 25.04+ | Already the system OpenSSL |
| Docker | `docker build -t pqcsuite .` (Debian 13 base) |
| Windows | Install OpenSSL 3.5+ and put its `bin` on `PATH`, or set `PQCSUITE_OPENSSL` to that folder |
| Older Linux | Build OpenSSL 3.5 and run with `LD_LIBRARY_PATH=/path/to/openssl/lib` |

Config and target files can be written with any editor, Notepad and PowerShell included: UTF-8 with or without a byte-order mark, or UTF-16.

## TLS 1.3 + mTLS

```
pqcsuite ca init --name "Acme PQC Root" --encrypt              # ML-DSA-87 root; scripts set PQCSUITE_CA_PASSPHRASE
pqcsuite ca issue server app.acme.example --out certs/edge
pqcsuite tls edge --target 127.0.0.1:8080 --cert certs/edge/chain.pem --key certs/edge/key.pem --metrics 127.0.0.1:9100
```

Clients now reach the app on port 8443 over TLS 1.3 with X25519MLKEM768 and an ML-DSA certificate. `examples/edge.toml` documents routes, mutual TLS, CRLs and tunnels (`pqcsuite tls edge --config examples/edge.toml`).

- **Edge modes:** `terminate` puts PQC TLS in front of a service. `originate` lets a plain local client reach a remote edge, so two edges make a post-quantum tunnel for any TCP protocol.
- **Mutual TLS:** `require_client_cert` plus a CRL. Revoked clients are refused at the next handshake. A forged or expired CRL refuses everyone (fail closed).
- **Policies:** `strict` (post-quantum only, the default), `transition` (also serves classical clients) and `cnsa2` (ML-KEM-1024, ML-DSA-87, AES-256 only).
- **Browsers:** they negotiate X25519MLKEM768 but cannot verify ML-DSA yet. Under `transition`, `fallback_cert`/`fallback_key` (or `--fallback-cert`/`--fallback-key`) give them an ECDSA or RSA certificate, while post-quantum clients get ML-DSA on the same port.
- **Operations:** certificates reload without a restart, `/metrics` for Prometheus, JSON logs, graceful shutdown, connection limits and deadlines on every socket.
- **Bundles:** `pqcsuite tls bundle nginx|postgres|pgvector|mqtt --host NAME` writes a Compose project with the service behind the edge.

Which clients connect (tested against the edge):

| Client | `strict` | `transition` with an ECDSA fallback |
|---|---|---|
| OpenSSL 3.5 command line, Node 22 | X25519MLKEM768, ML-DSA verified | X25519MLKEM768, ML-DSA |
| Chrome/Chromium, Go 1.24 | refused (cannot verify ML-DSA) | X25519MLKEM768, ECDSA certificate |
| Java 21, Python and curl on OpenSSL 3.0 | refused | X25519 (classical), ECDSA certificate |

`cnsa2` needs ML-KEM-1024, which no client offers by default: OpenSSL 3.5 clients add `-groups SecP384r1MLKEM1024` (or `MLKEM1024`); `pqcsuite tls connect --policy cnsa2` does it for you. Browsers need a fallback certificate only because they cannot verify ML-DSA yet; the fallback also needs a DNS name in its SAN, which browsers and Go require.

Check a connection:

```
pqcsuite tls connect app.acme.example:8443 --ca pki/ca.crt --send hello
       version  TLSv1.3
        cipher  TLS_AES_256_GCM_SHA384
         group  X25519MLKEM768
      peer_key  ML-DSA-65
```

### Certificate authority

- **Hierarchy:** ML-DSA or SLH-DSA (FIPS 205) roots, and issuing CAs under them (`ca init --parent`). SLH-DSA needs OpenSSL 3.5+.
- **Keys:** encrypted PKCS#8 files, AWS KMS ML-DSA keys (`--kms`, signing the 64-byte external mu), or any HSM with a command-line signer (`--signer-command`). KMS is tested against a stand-in for its API, not AWS itself.
- **Lifecycle:** issue, sign CSRs, revoke, CRLs. `pqcsuite ca maintain` (daily) renews what expires within 30 days in place, with the same algorithm, and re-signs the CRL. Listing and reports read the CA without its passphrase; only signing needs it.
- **External signers are checked:** a signature from KMS or an HSM command is verified against the CA's public key before anything is issued.
- **EST (RFC 7030):** `ca serve` on post-quantum TLS; `ca token` makes one-time tokens bound to a name. Machines run `ca enroll` (the key never leaves them) and renew from cron over mutual TLS.
- **ACME (RFC 8555):** `ca acme` with http-01, external account binding and an allow-list. The CSR must carry an ML-DSA key (`ca csr`, then `certbot --csr`). Clients that generate RSA or ECDSA keys, such as cert-manager, are refused with a clear error.

## IPsec VPN

```
pqcsuite ca issue site hq.acme.example --san 203.0.113.10 --out hq
pqcsuite vpn check                                # strongSwan version and ML-KEM support
pqcsuite vpn up --config examples/vpn-hq.toml
pqcsuite vpn status
hq.acme.example  ESTABLISHED  CURVE_25519 + ML_KEM_768         PPK yes  up 42s
```

- **Key exchange:** IKEv2 with X25519 + ML-KEM-768 (RFC 9370) on the first exchange and every rekey; the `high` profile uses P-384 + ML-KEM-1024.
- **Authentication:** strongSwan cannot authenticate with ML-DSA yet, so each pair of gateways agrees keys over ML-DSA mutual TLS and derives the IKE PSK and an RFC 8784 post-quantum PPK from the TLS exporter. The keys never cross the network.
- **Rotation and revocation:** keys rotate make-before-break. A revoked gateway's tunnel closes within 15 seconds.
- **Gateway image:** `docker/vpn-gateway.Dockerfile` builds strongSwan 6.1.0 (it fixes CVE-2026-78133 and CVE-2026-78135).

### Remote access

Laptops use WireGuard with a pre-shared key from the same ML-DSA mutual TLS key agreement, replaced every 2 minutes and bound to both WireGuard keys:

```
pqcsuite vpn gateway --config examples/wireguard-gateway.toml
sudo pqcsuite vpn connect vpn.acme.example:7443 --cert-dir ~/.pqcsuite/alice
```

Each user keeps one address from the pool. Revoking a user removes them within 15 seconds. Why not IKEv2 for laptops: the IKEv2 clients built into Windows, macOS and phones support neither ML-KEM nor PPKs. `vpn connect` configures the interface on Linux only; full-tunnel routing is not supported yet.

## Vault

```
pqcsuite vault keygen ops                        # ops.key (secret) + ops.pub; scripts add --passphrase-env VAR
pqcsuite vault backup /var/lib/app --to /backups -r ops.pub --sign-cert bot/cert.pem --sign-key bot/key.pem --keep 14
pqcsuite vault decrypt /backups/app-20260925T161150Z.pqv --key ops.key -o /restore --ca pki/ca.crt --signer backup-bot
pqcsuite vault share file.pqv --key ops.key -r new-admin.pub
```

- **Encryption:** the file key is wrapped per recipient with X25519 + ML-KEM-768 (`keygen --cnsa2`: P-384 + ML-KEM-1024); the data is AES-256-GCM in 1 MiB chunks.
- **Integrity:** modifying, reordering or truncating anything is detected before anything is written. Folders restore with Python's safe `data` filter.
- **Signatures:** ML-DSA certificates from the CA. Restore can require the signer to chain to the CA, not be revoked, and have a given name.
- **Sharing:** `share` adds recipients without re-encrypting the data.

## Readiness assessment

```
pqcsuite readiness scan hosts.txt ssh://bastion.acme.example:22 --html readiness.html
pqcsuite readiness report --ca pki --targets hosts.txt --vici unix:///var/run/charon.vici --backups /backups --html evidence.html
```

Targets are `host` (port 443), `host:port`, a pasted `https://` address, or `ssh://host` (port 22); a `.txt` file holds one per line, `#` starts a comment. Scan from a network without TLS inspection: behind an inspecting proxy every certificate is the proxy's (the report shows each issuer), and the grades describe the proxy, not the server.

| Grade | Meaning |
|---|---|
| A | Post-quantum key exchange only |
| B | Post-quantum preferred, classical still accepted |
| C | Classical only (harvest-now risk) |
| F | Unreachable or no TLS 1.3 |

SSH servers are graded from their key-exchange offer (`mlkem768x25519-sha256` and `sntrup761x25519-sha512` count as post-quantum). The report maps every certificate, endpoint, tunnel and backup to NIST IR 8547 (quantum-vulnerable algorithms deprecated after 2030, disallowed after 2035) and to CNSA 2.0 with its deadline. Both commands exit non-zero while anything needs action, so they can gate CI.

## Console

```
pqcsuite console --ca pki --edge http://127.0.0.1:9100 --vici unix:///var/run/charon.vici --wireguard http://127.0.0.1:9101 --backups /backups
```

Pages: overview, TLS 1.3 edges, mTLS certificates (issue, revoke, renew), IPsec VPN tunnels and remote users, Vault backups, and readiness scans. It binds to localhost, needs the printed token on every API call and audits every change. Browsers cannot verify ML-DSA yet, so publish it with `pqcsuite tls edge --policy transition` and a classical certificate.

## Deploy

- **Docker:** `Dockerfile` (edge and tools) and `docker/vpn-gateway.Dockerfile`.
- **Kubernetes:** `deploy/helm/pqcsuite` runs the CA (EST, ACME, daily maintenance, optional console) and edge gateways; `deploy/k8s/sidecar.yaml` shows the edge as a sidecar. Edge certificates come from a Secret you create.
- **Cloud images:** `deploy/packer` builds a Debian 13 image for AWS, Azure and GCP with OpenSSL 3.5, strongSwan 6.1.0, WireGuard and systemd units that start when their configuration exists. Not yet built in a real cloud account.

## Demo

```
python examples/clinic_demo.py          # pauses before each step
python examples/clinic_demo.py --auto   # runs straight through and checks every result
python examples/bank_demo.py            # the same for a bank; ends with the console open
sudo python examples/vpn_demo.py        # a branch over IPsec and a laptop over WireGuard, on one Linux machine
```

A clinic's patient portal, old records server, a doctor's laptop and nightly backups, in about a minute: readiness grades, Wolf Pack on the clinic's code (when `wolfpack` is installed: `pip install ./wolf-pack`), the portal behind post-quantum mutual TLS, a stolen laptop cut off, a signed Vault backup, a tampered backup refused, and the evidence report. `bank_demo.py` tells the story for a bank: a partner payment API behind post-quantum mutual TLS, a card switch's line protocol tunnelled unchanged, 3DES and RSA-1024 found in legacy code, a compromised branch cut off, a statement archive shared with an auditor and protected against edits. `vpn_demo.py` builds headquarters, a branch and a laptop in network namespaces: the branch joins over IPsec with X25519 + ML-KEM-768 and a post-quantum PPK, the laptop over WireGuard with a key agreed over ML-DSA mutual TLS, and revoking either certificate cuts it off (it needs root, and strongSwan 6.0.2+ or WireGuard). CI runs all three on every change.

## Tests

```
python -m unittest discover -s tests -v
```

With pytest installed, `python -m pytest` at the repository root runs these and Wolf Pack's tests together. The suite needs `cryptography` 49 or newer (for ML-KEM and ML-DSA); an older one stops every test at import with a message saying so.

The TLS tests run when OpenSSL 3.5+ is available. `tests/test_scenarios.py` puts real applications behind the products and checks them with independent clients: nginx (OpenSSL 3.5 command line and curl), PostgreSQL, Redis and MQTT through edge tunnels, EST enrollment, a vault backup with tampering, and readiness grades; each is skipped when the application is missing. CI also runs two IPsec sites and a WireGuard gateway in network namespaces with real traffic, installs the Helm chart in a kind cluster, and runs the image's provisioning script on Debian 13.

## Limits

- The edge uses one thread per connection (512 by default) and forwards TCP bytes; it does not parse HTTP. One process handles about 500 new TLS connections a second; on Linux, `--workers N` runs N processes on the same port (4 workers on 4 cores: about 1,500 a second, half of nginx with OpenSSL 3.5 on the same machine). Long-lived connections cost little once the handshake is done.
- One address cannot fill the connection limit with silent sockets: once half the slots are taken, a host with 32 handshakes still unfinished waits. A flood from many addresses can still fill it; put the edge behind a load balancer or firewall that limits connections per source.
- Revocation uses CRL files; there is no OCSP responder. The CA keeps its index in one JSON file: issuing takes about 6 ms per certificate at 1,000 certificates and 34 ms at 5,000, growing with the index. Fine for thousands of devices; a CA for hundreds of thousands needs a database.
- Algorithms come from OpenSSL and pyca/cryptography. Nothing here is FIPS 140-3 validated.

## Roadmap

1. VPN: Windows and macOS clients, and full-tunnel routing, for remote access.
2. mTLS: a cert-manager issuer and in-cluster renewal of edge Secrets; dns-01 for ACME.
