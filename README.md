# pqcsuite

Post-quantum secure communication, in Python. `pqcsuite` is a working name; the product name lives in `pqcsuite/__init__.py`.

- **Certificate authority:** ML-DSA (FIPS 204) root and leaf certificates, CSR signing, revocation and CRLs, renewal. Pure Python, with no OpenSSL install needed.
- **TLS 1.3 and mutual TLS:** X25519MLKEM768 and other ML-KEM (FIPS 203) hybrid key exchanges, ML-DSA certificates, and a PQC-only or transition policy. It runs on OpenSSL 3.5+ through a small ctypes bridge.
- **Edge:** puts post-quantum TLS in front of any TCP service (web app, database, MQTT broker) without touching it. A tunnel mode lets legacy clients reach one. It exposes Prometheus metrics.
- **VPN:** site-to-site IPsec on strongSwan 6.1. Key exchange is hybrid ML-KEM on every exchange, and authentication is rooted in ML-DSA certificates. Keys rotate, and a revoked site is cut off within seconds.

- **Vault:** quantum-safe encryption for files, folders and backups. It handles several recipients, has optional ML-DSA signatures from CA certificates, and can share a file without re-encrypting it.

- **Console:** one web page for certificates, edges, VPN tunnels, backups and readiness scans.

## Why

A quantum computer large enough to run Shor's algorithm breaks RSA and elliptic-curve cryptography. Traffic recorded today can be decrypted then ("harvest now, decrypt later"), so anything that must stay secret for years needs post-quantum key exchange now. NIST standardised ML-KEM and ML-DSA in 2024 and deprecates RSA and ECC after 2030.

## Install

Python 3.11+.

```
pip install -e .
pqcsuite doctor
```

The certificate authority works everywhere. TLS needs **OpenSSL 3.5 or newer**:

| Platform | How to get it |
|---|---|
| Debian 13, Ubuntu 25.04+ | Already the system OpenSSL |
| Docker | `docker build -t pqcsuite .` (Debian 13 base) |
| Windows | Install OpenSSL 3.5+ (for example the Shining Light build) and put its `bin` on `PATH`, or set `PQCSUITE_OPENSSL` to that folder |
| Older Linux | Build OpenSSL 3.5 and run with `LD_LIBRARY_PATH=/path/to/openssl/lib` (Linux loads one OpenSSL per process, and Python's own comes first otherwise) |

`pqcsuite doctor` tells you which OpenSSL was found and whether it can do post-quantum TLS.

## Quick start

```
# 1. A certificate authority (ML-DSA-87 root; --encrypt protects its key with a passphrase)
pqcsuite ca init --name "Acme PQC Root" --encrypt
pqcsuite ca issue server localhost --san 127.0.0.1 --out certs/server
pqcsuite ca issue client alice --out certs/alice

# 2. TLS 1.3 with X25519MLKEM768 (terminal 1, then terminal 2)
pqcsuite tls serve --cert certs/server/chain.pem --key certs/server/key.pem
pqcsuite tls connect localhost:8443 --ca pki/ca.crt --send "hello"

# 3. Mutual TLS: the server checks the client too, and refuses revoked certificates
pqcsuite tls serve --cert certs/server/chain.pem --key certs/server/key.pem --ca pki/ca.crt --require-client-cert --crl pki/crl.pem
pqcsuite tls connect localhost:8443 --ca pki/ca.crt --cert certs/alice/chain.pem --key certs/alice/key.pem --send "hello"

# 4. Is a server quantum-safe?
pqcsuite tls probe example.com:443
```

`tls connect` prints what was negotiated:

```
       version  TLSv1.3
        cipher  TLS_AES_256_GCM_SHA384
         group  X25519MLKEM768
          peer  CN=localhost
      peer_key  ML-DSA-65
         reply  hello
```

## Edge: protect an existing service

```
pqcsuite ca issue server edge.example.com --out certs/edge
pqcsuite edge --target 127.0.0.1:8080 --cert certs/edge/chain.pem --key certs/edge/key.pem --metrics 127.0.0.1:9100
```

Clients now reach the app on port 8443 over post-quantum TLS. For several routes, mutual TLS, CRLs and tunnels, use a config file. `examples/edge.toml` documents every setting.

```
pqcsuite edge --config examples/edge.toml
```

- **terminate:** PQC TLS clients reach the edge, which forwards plain TCP to your upstream.
- **originate:** a plain local client reaches the edge, which opens PQC TLS to a remote edge. Two edges give a post-quantum tunnel between two sites, for any TCP protocol.

Renewed certificates are picked up within five seconds without a restart. `/metrics` reports connections, handshake failures and the negotiated groups for Prometheus.

## VPN: post-quantum site-to-site IPsec

Most "quantum-safe VPNs" add ML-KEM to the key exchange and stop there: authentication is still RSA or ECDSA, or a static password. strongSwan, the IPsec engine this builds on, cannot authenticate with ML-DSA yet. pqcsuite closes that gap without waiting for it:

1. **Key agreement:** each pair of gateways agrees keys over post-quantum mutual TLS: ML-DSA certificates from the pqcsuite CA, X25519MLKEM768, and the CRL checked.
2. **Two keys from one session:** both sides derive the IKE pre-shared key and an RFC 8784 post-quantum pre-shared key (PPK) from that session's exporter (RFC 8446, section 7.5). The keys never cross the network.
3. **Hybrid IKEv2:** X25519 + ML-KEM-768 (RFC 9370), with the PPK mixed into every key. ESP is AES-256-GCM with a hybrid ML-KEM exchange on every rekey. The `high` profile uses P-384 + ML-KEM-1024.
4. **Rotation:** keys rotate on a schedule (`rotate_minutes`). A new tunnel comes up with the new keys before the old one goes away.
5. **Revocation:** revoke a gateway's certificate in the CA and its tunnel is closed and its keys discarded within 15 seconds. It cannot get new ones.
6. **PPK isolation:** each peer pair has its own PPK namespace, so one branch cannot present another branch's key.

```
# once, on the CA machine
pqcsuite ca issue site hq.acme.example --san 203.0.113.10 --out hq
pqcsuite ca issue site branch1.acme.example --san 198.51.100.7 --out branch1

# on each gateway (strongSwan 6.0.2+ with ML-KEM, or the gateway image below)
pip install -e ".[vpn]"
pqcsuite vpn check                                # strongSwan version and ML-KEM support
pqcsuite vpn up --config examples/vpn-hq.toml     # at HQ
pqcsuite vpn up --config examples/vpn-branch.toml # at the branch
pqcsuite vpn status
```

```
hq.acme.example  ESTABLISHED  CURVE_25519 + ML_KEM_768         PPK yes  up 42s
  net            INSTALLED    AES_GCM_16     in 5218 B / out 5218 B
```

Gateway image: `docker build -f docker/vpn-gateway.Dockerfile -t pqcsuite-vpn .`, then run it with `--network host --cap-add NET_ADMIN -v /etc/pqcsuite:/etc/pqcsuite`. It builds strongSwan 6.1.0 from source. 6.1.0 fixes CVE-2026-78133, a use-after-free in IKEv2 rekeying that can allow remote code execution, and CVE-2026-78135, a CHILD_SA usable before authentication. Older 6.0.x builds have both.

What the tests prove: `tests/test_vpn.py` builds two sites in Linux network namespaces, with real charon daemons and real `pqcsuite vpn up` controllers. It checks:

- the tunnel negotiates CURVE_25519 + ML_KEM_768 and uses a PPK
- traffic flows through ESP (CI)
- a second key agreement produces a new PPK-protected SA
- revoking the branch closes its tunnel at HQ

## VPN: remote access over WireGuard

Laptops and small sites connect to a WireGuard gateway. WireGuard's own handshake is X25519. pqcsuite adds a 32-byte pre-shared key to every peer, and WireGuard mixes it into each handshake. The key comes from post-quantum mutual TLS: both sides prove who they are with ML-DSA certificates from your CA, agree keys over X25519MLKEM768, and derive the PSK from the TLS exporter, bound to both WireGuard public keys. An attacker who later breaks X25519 still lacks the PSK. Rosenpass uses the same approach.

```
# gateway (Linux; uses the kernel module, or wireguard-go when the module is missing)
pqcsuite vpn gateway --config examples/wireguard-gateway.toml

# each laptop: enroll once (EST) or copy cert.pem, chain.pem, key.pem and ca.crt into a folder, then
sudo pqcsuite vpn connect vpn.acme.example:7443 --cert-dir ~/.pqcsuite/alice
```

- **Addresses:** each user (certificate name) keeps one address from the pool. A second device with the same certificate replaces the first.
- **Rotation:** the PSK is replaced every `rotate_minutes` (2 by default). A client that stops renewing is removed after three periods.
- **Revocation:** revoking a user's certificate removes their peer within 15 seconds and refuses their next key agreement.
- **Access control:** `users` is an allow-list. Clients listed under `sites` also route the subnets behind them, which makes the gateway a site-to-site hub.
- **Monitoring:** `/metrics` and `/status` show users, handshakes and traffic. The console's VPN page shows them with `--wireguard http://gateway:9101`.

Limits: `vpn connect` configures the interface itself on Linux only. On Windows and macOS, `--no-apply --config-out wg.conf` writes a WireGuard app configuration, but its PSK expires at the next rotation, so it is only for trials. Full-tunnel (0.0.0.0/0) routing is not supported yet. Why not IKEv2 for laptops: the IKEv2 clients built into Windows, macOS and phones support neither ML-KEM nor PPKs.

`tests/test_wireguard.py` runs a gateway and a laptop in network namespaces with real WireGuard. It checks that traffic flows, that the PSK rotates on both sides and traffic survives, and that revoking the user removes them and stops their traffic.

## Vault: quantum-safe backups

```
pqcsuite vault keygen ops                        # ops.key (secret) + ops.pub
pqcsuite vault backup /var/lib/app --to /backups -r ops.pub -r dr-site.pub \
    --sign-cert bot/cert.pem --sign-key bot/key.pem --keep 14
pqcsuite vault decrypt /backups/app-20260925T161150Z.pqv --key ops.key -o /restore --ca pki/ca.crt --signer backup-bot
pqcsuite vault share file.pqv --key ops.key -r new-admin.pub   # grant access, data untouched
pqcsuite vault inspect file.pqv
```

How it's built:

- **Per recipient:** the file key is wrapped with X25519 + ML-KEM-768, combined as X-Wing combines them. An attacker must break both.
- **Data:** AES-256-GCM in 1 MiB chunks. Each nonce carries the chunk number and a last-chunk flag. Modifying, reordering or truncating anything, including dropping the final chunk, is detected before anything is written.
- **Folders:** stored as a tar stream and extracted with Python's safe `data` filter, so an archive cannot write outside the restore folder.
- **Signatures:** optional, using any ML-DSA certificate from the pqcsuite CA. Restore can require the signer's certificate to chain to the CA, not be revoked, and carry a given name. The signer is bound into every chunk, so a signature cannot be stripped.
- **Sharing:** `share` re-wraps the file key for new recipients. The encrypted data is copied unchanged, so granting access to a large archive is cheap.
- **Speed:** about 100 MB/s on the build machine. The `.pqv` files can be synced to any storage (S3, Azure, a NAS, tape) with the tools you already use.

## PQCready bundles

One command gives a Docker Compose project with a common service behind the post-quantum edge. It includes a certificate from your CA, and only the edge is published:

```
pqcsuite bundle nginx    --host www.acme.example
pqcsuite bundle postgres --host db.acme.example --ca pki --mtls
pqcsuite bundle pgvector --host vectors.acme.example
pqcsuite bundle mqtt     --host broker.acme.example
```

Each bundle has a README with the exact client command. Postgres needs libpq 17+ (`sslnegotiation=direct`). Clients negotiate ML-KEM only if their TLS library supports it (OpenSSL 3.5+, BoringSSL, Go 1.24+). Otherwise, put `pqcsuite edge --mode originate` next to them.

## Readiness scan

```
pqcsuite scan hosts.txt api.acme.example:443 --html readiness.html --json readiness.json
```

Every endpoint gets a grade:

| Grade | Meaning |
|---|---|
| A | Post-quantum key exchange only |
| B | Post-quantum preferred, classical still accepted |
| C | Classical only (harvest-now risk) |
| F | Unreachable or no TLS 1.3 |

The report also covers the negotiated group, the certificate's key (RSA, ECDSA or ML-DSA) and certificate expiry. The HTML report is one self-contained file, and the exit code is non-zero until every endpoint offers post-quantum key exchange, so it can gate CI.

## CA hierarchy, SLH-DSA roots and keys in KMS or an HSM

```
# a hash-based SLH-DSA root (FIPS 205) that stays offline, and an ML-DSA issuing CA under it
pqcsuite ca init --dir root --name "Acme Root" --algorithm SLH-DSA-SHA2-256s --encrypt
pqcsuite ca init --dir issuing --name "Acme Issuing CA" --parent root
pqcsuite ca issue --dir issuing server api.example.com     # chain.pem = leaf + issuing CA + root; clients trust issuing/root.crt

# an issuing CA whose key never leaves AWS KMS (an ML_DSA_65 or ML_DSA_87 key; needs boto3)
pqcsuite ca init --dir kms-ca --name "Acme KMS CA" --parent root --kms alias/acme-issuing --kms-region eu-central-1

# any HSM with a command-line signer: it reads the bytes on stdin and writes the signature to stdout
pqcsuite ca init --dir hsm-ca --name "Acme HSM CA" --parent root --signer-public-key hsm.pub.pem --signer-command hsm-sign --label acme-issuing
```

- An SLH-DSA root rests on hash functions only, a different assumption from ML-DSA's lattices, so one broken scheme does not break the hierarchy. It signs slowly and its signatures are large (8 to 50 KB), which is fine for a root that signs a few CA certificates. SLH-DSA keys need OpenSSL 3.5+ (pyca/cryptography does not support them yet).
- Intermediate CAs are recorded in their parent's index as kind `ca`; revoking one lists it in the parent's CRL. Servers check a client's certificate against the CRL of the CA that issued it, taking that CA's certificate from the chain OpenSSL verified.
- KMS signing sends only the 64-byte ML-DSA "external mu" (FIPS 204), so certificates and CRLs of any size fit in one call and never leave the machine. It is tested against a stand-in for the KMS API, not against AWS itself.

## Enrollment: certificates for many machines (EST, RFC 7030)

```
# on the CA
pqcsuite ca issue server ca.acme.example --out est
pqcsuite ca serve --cert est/chain.pem --key est/key.pem       # prints the CA fingerprint
pqcsuite ca token server web1.acme.example --san 10.0.0.7     # one-time token, shown once

# on the new machine: the ML-DSA key is generated here and never leaves it
pqcsuite enroll https://ca.acme.example:9443 --token <token> --cn web1.acme.example --san 10.0.0.7 --ca-fingerprint <sha256> --out /etc/pqc
# daily from cron: renews in place 30 days before expiry, over mutual TLS with the current certificate
pqcsuite enroll https://ca.acme.example:9443 --renew /etc/pqc --within-days 30
```

How it's secured:

- **Tokens:** a token works once and only before it expires. It is only good for the name and addresses it was created for, and only its hash is stored.
- **Renewal:** it keeps the machine's identity. A certificate cannot renew itself into another name, and a revoked one cannot renew.
- **Trust:** the client pins the CA by its fingerprint before trusting anything.
- **Audit:** every enrollment and every refusal goes to `est-audit.jsonl`.

## ACME (RFC 8555)

```
pqcsuite acme serve --dir pki --listen 0.0.0.0:14000 --base-url https://acme.corp.example:14000 \
    --tls-cert acme-classical.pem --tls-key acme-classical.key --allow '*.corp.example' --require-eab
pqcsuite acme eab --dir pki --note "web team"            # one key id + HMAC key per client

# on the web server: an ML-DSA key and CSR, then plain certbot
pqcsuite acme csr www.corp.example --out /etc/pqcsuite/www
certbot certonly --csr /etc/pqcsuite/www/csr.der --server https://acme.corp.example:14000/directory \
    --standalone --eab-kid KID --eab-hmac-key KEY --agree-tos -m ops@corp.example
```

- Identifiers are proved with http-01, for DNS names and IP addresses (RFC 8738). Wildcards need dns-01, which is not implemented.
- `--allow` limits which names the CA issues for. `--require-eab` stops strangers from registering. Each EAB key binds one account.
- Accounts can revoke only certificates they ordered. Revocation reaches the CA's CRL immediately.
- Certificates are ML-DSA. The CSR must carry an ML-DSA key, so the ACME client must accept a CSR file. Clients that generate their own RSA or ECDSA keys, such as cert-manager or default certbot, get a `badCSR` error that says so.
- The ACME endpoint is ordinary HTTPS with a classical certificate, because ACME clients cannot verify ML-DSA server certificates yet. ACME account keys are classical too (RS256, ES256/384/512, EdDSA), as in every ACME client.

`tests/test_acme.py` drives the server with certbot's `acme` library and with the certbot command line. It covers issuance, a failed http-01, refused classical keys, EAB, cross-account revocation, and forged, replayed and misdirected requests.

## Fleet management

```
# central: the fleet service (post-quantum mutual TLS; agents are identified by their CA certificate)
pqcsuite fleet serve --dir fleet --cert fleet-srv/chain.pem --key fleet-srv/key.pem --ca pki/ca.crt --crl pki/crl.pem
# each machine: enroll once, then run the agent
pqcsuite agent https://fleet.acme.example:9444 --cert-dir /etc/pqc
# assign routes from the console's Fleet page, or by writing fleet/desired/<agent>.toml (default.toml for everyone)
pqcsuite console --ca pki --fleet fleet
```

How it works:

- **Reporting:** every 30 seconds each agent reports its host, version, certificate expiry and the live stats of its edge routes, and receives its assigned configuration.
- **Applying config:** the agent applies changes route by route. Unchanged routes keep their connections.
- **Bad config:** it is refused twice, first by the console and then by the agent, which keeps running the last good one and reports the error.
- **Revoked agents:** revoking an agent's certificate shuts it out of the fleet.

## Compliance evidence

```
pqcsuite report --ca pki --targets hosts.txt ssh://bastion.acme.example:22 --vici unix:///var/run/charon.vici --backups /backups \
    --html evidence.html --json evidence.json
```

Every certificate, TLS and SSH endpoint, VPN tunnel and backup gets:

- **Status:** quantum-safe, quantum-safe with a classical fallback still allowed, or action needed.
- **NIST IR 8547:** what the draft says about it (quantum-vulnerable algorithms deprecated after 2030 at 112-bit, disallowed after 2035).
- **CNSA 2.0:** whether it meets NSA CNSA 2.0, and the deadline for its category (2030 for VPNs, 2033 for servers and services).
- **Exit code:** non-zero while anything needs action, so it can gate a pipeline.

For CNSA 2.0 backups, make recipient keys with `pqcsuite vault keygen --cnsa2` (ML-KEM-1024 + P-384, SHA-384 combiner).

`scan` also takes SSH servers (`ssh://host:22`). It reads the server's key-exchange offer and grades it the same way: `mlkem768x25519-sha256` and `sntrup761x25519-sha512` count as post-quantum.

## Keeping it running

```
pqcsuite ca maintain --dir pki     # daily, from cron or a scheduled task
```

It renews certificates that expire within 30 days, in the folder they were issued to (edges and VPN gateways reload them within seconds), and re-signs the CRL. Mutual TLS refuses everyone once the CRL expires, so this matters. Encrypted keys are reported for manual renewal.

## Console

```
pqcsuite console --ca pki --edge http://127.0.0.1:9100 --vici unix:///var/run/charon.vici --backups /backups
```

It prints a URL and an access token. The pages are:

- **Overview:** one tile each for certificates, edges, VPN, backups and readiness.
- **Certificates:** issue, revoke (with a confirm step), and renew-and-refresh-CRL.
- **Edges:** live connections, refused handshakes and negotiated groups.
- **VPN:** tunnel state, key exchange, PPK and traffic.
- **Backups:** creation time, recipients and signer.
- **Readiness:** run a scan and read the graded results.

How it's secured:

- **Access:** it binds to localhost by default, every API call needs the token (compared in constant time), and every change goes to an audit log (`console-audit.jsonl`).
- **Offline:** the page is one self-contained file, with no external scripts or fonts, so it works on an isolated network.
- **Remote access:** browsers already negotiate X25519MLKEM768 but cannot verify ML-DSA certificates yet. So publish the console through the edge with the `transition` policy and a certificate browsers accept: `pqcsuite edge --policy transition --target 127.0.0.1:8900 --cert <ECDSA or RSA chain> --key <key>`.

## Policies

| Policy | Key exchange | Certificates | Use |
|---|---|---|---|
| `strict` (default) | X25519MLKEM768, SecP384r1MLKEM1024, SecP256r1MLKEM768 | ML-DSA only | Post-quantum end to end |
| `transition` | The same, plus X25519, P-256 and P-384 | Any | Prefers PQC but still serves classical clients while they migrate |
| `cnsa2` | SecP384r1MLKEM1024, ML-KEM-1024 | ML-DSA-87 only, AES-256-GCM only | NSA CNSA 2.0 (national security systems, defense suppliers) |

Every connection uses TLS 1.3 only, with AES-256-GCM, ChaCha20-Poly1305 or AES-128-GCM.

## Production-ready: what the demos did not have

| Area | What it does |
|---|---|
| Keys | Created owner-only. The CA key and any leaf key can be passphrase-encrypted (PKCS#8). Encrypted keys are passed straight to OpenSSL. |
| Certificates | Proper extensions: basic constraints, key usage, server or client EKU, SKI/AKI and SANs. A leaf never outlives its root. |
| Revocation | Signed CRLs. Servers re-read the CRL when it changes and refuse a forged or expired CRL (fail closed). |
| Verification | Hostname or IP checked against the certificate. The CA chain is verified in both directions for mTLS. |
| Robustness | Every socket operation has a deadline, and silent clients are dropped after the handshake timeout. A connection limit refuses excess clients instead of exhausting the process. |
| Errors | OpenSSL's own error queue is turned into readable messages: "hostname mismatch", "peer did not return a certificate", "wrong passphrase?". |
| Resources | No global state. Contexts and connections are freed deterministically. |
| Operations | Certificate hot-reload, graceful shutdown on SIGTERM, JSON logs (`--log-json`), Prometheus metrics, a non-root Docker image. |
| Tests | A real X25519MLKEM768 + ML-DSA handshake in CI, plus tests for each attack the server must refuse: classical-only client, wrong CA, wrong name, no client certificate, revoked certificate, silent client. |

## From the demos to the product

| Demo | Now |
|---|---|
| `TLS 1.3/gen_certs.py` (openssl CLI) | `pqcsuite ca init` and `ca issue server` (pure Python) |
| `TLS 1.3/server_app.py` and `client_app.py` | `pqcsuite tls serve` and `tls connect`, or the `pqcsuite.tls` API |
| `mTLS/*` | `--require-client-cert`, with a CRL, on the same commands |
| `mTLS` step 5 (unauthorised client) | Tested in `tests/test_tls.py`: no certificate, a foreign CA, a revoked certificate |
| `openssl_bridge.py` | `pqcsuite/tls/openssl.py`: version check, error messages, deadlines, SNI and hostname checks, encrypted keys, cleanup |
| `pqc-ipsec` (PSK `demo-psk-12345`, strongSwan 6.0.7, swanctl output parsing) | `pqcsuite vpn`: keys from ML-DSA mutual TLS plus a PPK, strongSwan 6.1.0 driven through VICI, rotation and revocation |

## Using it from Python

```python
from pqcsuite import tls

ctx = tls.client_context(ca="pki/ca.crt", cert="alice/chain.pem", key="alice/key.pem")
with tls.connect("api.example.com", 8443, ctx) as conn:
    conn.sendall(b"hello")
    print(conn.info(), conn.recv())
```

## Limits, stated plainly

- **Throughput:** the edge uses one thread per connection (512 by default). That suits branch links, APIs and internal services, not tens of thousands of concurrent clients. Put it behind a load balancer and run several instances if you need more.
- **Protocol:** the edge forwards TCP bytes. It does not parse HTTP, so it cannot add `X-Forwarded-For`. Use `proxy_protocol = true` with an upstream that understands the PROXY protocol.
- **Revocation:** revocation uses CRL files that you distribute. There is no OCSP responder yet.
- **Assurance:** algorithm implementations come from OpenSSL and pyca/cryptography. Nothing here is FIPS 140-3 validated.

## Roadmap

1. **VPN, next:** full-tunnel routing and a Windows/macOS client for WireGuard remote access.
2. **Discovery.** Integrate Wolf Pack CBOM into the console: find where classical cryptography lives in code, configs and binaries, and feed it into the readiness view.

The readiness scan marks each endpoint that meets CNSA 2.0: it accepts only ML-KEM-1024 key exchanges and presents an ML-DSA-87 certificate. For a CNSA 2.0 VPN, use `profile = "high"` (P-384 + ML-KEM-1024).

What to build next, and how pqcsuite compares with QuSecure, SandboxAQ, Keyfactor, pqcrypto and others: [docs/ROADMAP.md](docs/ROADMAP.md).

## Tests

```
python -m unittest discover -s tests -v
```

The TLS tests run when OpenSSL 3.5+ is available and are skipped otherwise. CI runs them in a Debian 13 container.
