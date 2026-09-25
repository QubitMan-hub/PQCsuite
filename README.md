# pqcsuite

Post-quantum secure communication, in Python. `pqcsuite` is a working name; the product name lives in `pqcsuite/__init__.py`.

- **Certificate authority:** ML-DSA (FIPS 204) root and leaf certificates, CSR signing, revocation and CRLs, renewal. Pure Python, with no OpenSSL install needed.
- **TLS 1.3 and mutual TLS:** X25519MLKEM768 and other ML-KEM (FIPS 203) hybrid key exchanges, ML-DSA certificates, and a PQC-only or transition policy. It runs on OpenSSL 3.5+ through a small ctypes bridge.
- **Edge:** puts post-quantum TLS in front of any TCP service (web app, database, MQTT broker) without touching it. A tunnel mode lets legacy clients reach one. It exposes Prometheus metrics.
- **VPN:** site-to-site IPsec on strongSwan 6.1. Key exchange is hybrid ML-KEM on every exchange, and authentication is rooted in ML-DSA certificates. Keys rotate, and a revoked site is cut off within seconds.

The data vault and the web console come next (see the roadmap).

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

## Policies

| Policy | Key exchange | Certificates | Use |
|---|---|---|---|
| `strict` (default) | X25519MLKEM768, SecP384r1MLKEM1024, SecP256r1MLKEM768 | ML-DSA only | Post-quantum end to end |
| `transition` | The same, plus X25519, P-256 and P-384 | Any | Prefers PQC but still serves classical clients while they migrate |

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

1. **VPN, next:** remote access for laptops (virtual IP pools), and WireGuard as a second data plane fed by the same ML-DSA key agreement.
2. **Vault.** Encrypt and sign files and backups for one or more recipients with X25519 + ML-KEM-768 and ML-DSA.
3. **Console.** One web dashboard: certificates and expiry, edges and their live metrics, tunnels, probes, plus crypto discovery from Wolf Pack CBOM.

## Tests

```
python -m unittest discover -s tests -v
```

The TLS tests run when OpenSSL 3.5+ is available and are skipped otherwise. CI runs them in a Debian 13 container.
