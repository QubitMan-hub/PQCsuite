# Acxelin TLS manual

## How a connection is decided

A client connects to the edge. The edge's policy decides what it accepts:
1. **Key exchange.** Under `strict`, the client must offer a post-quantum group. A client that offers only classical groups is refused, and the log says why ("the client offers no post-quantum key exchange").
2. **Certificates.** Under `strict`, certificates must use ML-DSA. A client that cannot verify ML-DSA is refused.
3. **Client certificate.** With `require_client_cert`, the client must present a certificate that chains to the CA and is not on the CRL.

Nothing falls back silently: a connection that cannot meet the policy ends.

## The certificate authority

`acxelin-tls ca init` creates a root (ML-DSA-87 by default) in a folder: `ca.crt`, `ca.key` (encrypted unless you pass `--no-encrypt`), an index of what it issued, and `crl.pem`.

Certificates are ML-DSA-65 by default. `ca issue server NAME` makes a key and certificate in `--out`; `ca renew SERIAL` reissues; `ca sign-csr` certifies a key made elsewhere; `ca list` shows everything; `ca revoke SERIAL` revokes and re-signs the CRL. `ca maintain` renews what expires soon and re-signs the CRL, so run it daily. The CRL is valid for 7 days by default; an edge whose CRL has expired refuses every client.

Passphrases come from `ACXELIN_TLS_CA_PASSPHRASE` or a prompt, never from the command line.

### Intermediate CAs and signers

`ca init --parent DIR` makes an issuing CA under a root you keep offline. The CA key can live in AWS KMS (`--kms`, with the `kms` extra) or behind your own command (`--signer-command`), and SLH-DSA roots are supported. These paths have not been run against real HSMs or cloud accounts here.

## Enrollment

- **EST** (`ca serve`): clients enroll with a one-time token from `ca token`, over post-quantum TLS. Every enrollment attempt is written to an owner-only audit log that never contains the token's secret.
- **ACME** (`ca acme`): standard ACME clients, such as certbot with `--csr`, obtain ML-DSA certificates. Use `ca eab` for an external account binding key and `ca csr` to make a key and CSR.
- **Publishing** (`ca publish`): serves `ca.crt` and `crl.pem` over HTTP so edges can follow the CRL.

## The edge

An edge is one or more routes. A route listens on a port and sends traffic on:
- `mode = "terminate"`: post-quantum TLS in front of a plain service at `target`.
- `mode = "originate"`: a plain local client reaches a remote edge at `target` over post-quantum TLS.

`config/example.toml` lists every setting. Changing the configuration file reloads it without a restart, and certificates are re-read when their files change. `--workers N` shares the listen ports across processes (Linux).

With `--metrics HOST:PORT` an edge serves `/healthz`, `/metrics` (Prometheus) and `/status` (JSON).

### Metrics

| Metric | Meaning |
|---|---|
| `acxelin_tls_connections_active{edge}` | open connections |
| `acxelin_tls_events_total{edge,event}` | handshakes accepted and refused, by reason |
| `acxelin_tls_group_total{edge,group}` | connections by negotiated key-exchange group |

## Exit codes

`doctor` exits 0 when everything passes, 1 on warnings with `--strict`, 2 when a check fails, and 3 when this machine cannot run Acxelin TLS. Other commands exit 1 with one line on stderr when they fail.
