# pqcsuite

Post-quantum secure communication, in Python. `pqcsuite` is a working name; the product name lives in `pqcsuite/__init__.py`.

- **Certificate authority:** ML-DSA (FIPS 204) root and leaf certificates, CSR signing, revocation and CRLs, renewal. Pure Python, with no OpenSSL install needed.
- **TLS 1.3 and mutual TLS:** X25519MLKEM768 and other ML-KEM (FIPS 203) hybrid key exchanges, ML-DSA certificates, and a PQC-only or transition policy. It runs on OpenSSL 3.5+ through a small ctypes bridge.
- **Edge:** puts post-quantum TLS in front of any TCP service (web app, database, MQTT broker) without touching it. A tunnel mode lets legacy clients reach one. It exposes Prometheus metrics.

The IPsec VPN, the data vault and the web console come next (see the roadmap).

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
| `pqc-ipsec` | Roadmap stage 3 |

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

1. **IPsec VPN.** Drive strongSwan 6 from Python through its VICI API. Authenticate peers with ML-DSA certificates from this CA instead of a PSK, generate tunnel configs, monitor and rekey, and ship a gateway Docker image.
2. **Vault.** Encrypt and sign files and backups for one or more recipients with X25519 + ML-KEM-768 and ML-DSA.
3. **Console.** One web dashboard: certificates and expiry, edges and their live metrics, tunnels, probes, plus crypto discovery from Wolf Pack CBOM.

## Tests

```
python -m unittest discover -s tests -v
```

The TLS tests run when OpenSSL 3.5+ is available and are skipped otherwise. CI runs them in a Debian 13 container.
