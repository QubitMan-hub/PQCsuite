# Acxelin TLS

Put post-quantum TLS 1.3 and mutual TLS in front of the services you already run, and issue the ML-DSA certificates they need from your own certificate authority.

Acxelin TLS has three parts:
- **The edge:** a proxy that accepts only post-quantum clients (X25519MLKEM768, SecP384r1MLKEM1024 or SecP256r1MLKEM768 key exchange, ML-DSA certificates) in front of any TCP service, or a tunnel from a plain local client to a remote edge. The service behind it doesn't change.
- **The certificate authority:** issues, renews and revokes ML-DSA certificates, keeps the CRL fresh, and offers enrollment over EST (RFC 7030) and ACME (RFC 8555).
- **The console:** a local web page for the routine work (create the CA; issue, download, renew and revoke certificates; check edges; test a connection, with a client certificate for mutual TLS), so none of it needs the command line. A private key reaches the browser only when you choose Download with key, never for a revoked certificate or an encrypted key, and every action is recorded in an owner-only audit log.

## Install

Python 3.11 to 3.14, and **OpenSSL 3.5 or newer** (Debian 13 ships it, and the container image has it):

```
pip install ./core ./products/tls
acxelin-tls doctor
```

From a release, unpack its wheelhouse and run `pip install --no-index --find-links wheelhouse acxelin-tls`. `doctor` says whether this machine can do post-quantum TLS. If OpenSSL 3.5 is installed somewhere other than the system default, point `ACXELIN_OPENSSL` at its folder.

## See it work

```
acxelin-tls try
```

A one-minute tour with nothing to set up: a CA, an ordinary web server, the edge in front of it, a post-quantum client that gets through and a classical client that is refused.

## Use

| Task | Command |
|---|---|
| Open the console | `acxelin-tls console` |
| Create a CA | `acxelin-tls ca init --name "Example Root CA" --dir pki` |
| Issue a server certificate | `acxelin-tls ca issue server web.example.com --dir pki --out web` |
| Put the edge in front of a service | `acxelin-tls edge --listen 0.0.0.0:8443 --target 127.0.0.1:8080 --cert web/chain.pem --key web/key.pem` |
| Require client certificates (mutual TLS) | add `--require-client-cert --ca pki/ca.crt --crl pki/crl.pem` |
| Configure several routes | `acxelin-tls edge --config edge.toml` (see `config/example.toml`) |
| nginx, PostgreSQL, pgvector or MQTT behind an edge, ready to run | `acxelin-tls bundle nginx --host web.example.com` |
| Revoke a certificate | `acxelin-tls ca revoke SERIAL --dir pki` |
| Keep the CA fresh | `acxelin-tls ca maintain --dir pki` (daily) |
| Check an edge or a CA folder | `acxelin-tls doctor --config edge.toml --ca pki` |
| See what a running edge reports | `acxelin-tls status --url http://127.0.0.1:9100` |
| Test a connection | `acxelin-tls connect host:8443 --ca pki/ca.crt` |

Enrollment services: `ca serve` (EST), `ca acme` (ACME), `ca publish` (the CA certificate and CRL over HTTP).

### Policies

| Policy | Allows |
|---|---|
| `strict` (default) | post-quantum key exchange and ML-DSA certificates only |
| `transition` | also classical clients while you migrate; use it with `fallback_cert` for browsers, which cannot verify ML-DSA yet |
| `cnsa2` | NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87 and AES-256 only |

## The console

`acxelin-tls console` opens your browser already signed in. The first time, create the certificate authority (give its key a passphrase; the console keeps it in memory only, so it asks again after a restart). Then issue, download, renew and revoke certificates, add running edges to see their policy and negotiated key exchanges, test a connection, and read the health checks.

The console listens only on the machine it runs on. For a remote server:

```
ssh -L 8900:127.0.0.1:8900 server
acxelin-tls console link --port 8900    # run in that SSH session; open the address it prints
```

In Docker, start the console with `--container` and publish its port to loopback only: `docker run -v acxelin-tls:/data -p 127.0.0.1:8900:8900 acxelin-tls console --container`, then run `docker exec -it NAME acxelin-tls console link`. In Kubernetes, use `kubectl port-forward` and the same `console link` through `kubectl exec`.

## Deploy

- **Docker:** `docker build -f products/tls/deploy/Dockerfile -t acxelin-tls .`
- **Kubernetes:** a Helm chart at `deploy/helm/acxelin-tls` (CA, EST, ACME, CRL publishing and edges) and a sidecar example at `deploy/k8s/sidecar.yaml`.
- **systemd:** `deploy/systemd/acxelin-tls-edge.service`, and `acxelin-tls-maintain.service` with its timer for the CA.

The Helm templates have not been rendered or linted here, only the plain YAML files parsed. Run `helm lint` before installing.

## Limits

- Browsers cannot verify ML-DSA certificates yet. For them, use the `transition` policy with a classical fallback certificate.
- Revocation reaches an edge through its CRL, within `crl_every` seconds of the CA publishing one. A revoked client keeps access until then.
- Hardware and cloud signing (`--kms`, `--signer-command`) are implemented, but they have not been run against real HSMs or cloud accounts here.

More: `docs/manual.md`, `docs/upgrade.md` (coming from the PQC Suite) and `docs/threat-model.md`.
