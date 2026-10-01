# Acxelin PQC Suite

Post-quantum security for the traffic, tunnels and data you run today, in Python. Four products share one ML-DSA certificate authority:

| Product | What it does | Command |
|---|---|---|
| **TLS 1.3 + mTLS** | Post-quantum TLS in front of any TCP service, mutual TLS between services, and a CA with EST and ACME enrollment | `pqcsuite tls`, `pqcsuite ca` |
| **IPsec VPN** | Site-to-site IPsec with hybrid ML-KEM and ML-DSA authentication, plus WireGuard remote access | `pqcsuite vpn` |
| **Vault** | Quantum-safe encryption for files, folders and backups | `pqcsuite vault` |
| **Readiness assessment** | TLS and SSH endpoint grades, and compliance evidence for NIST IR 8547 and CNSA 2.0 | `pqcsuite readiness` |

`pqcsuite console` shows all four on one page. Wolf Pack CBOM, the separate cryptography inventory scanner, is in [`wolf-pack/`](wolf-pack/README.md). The website is https://qubitman-hub.github.io/PQCsuite/; working on the suite itself (tests, website, releases) is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Scan one project

From a source checkout, install the scanner alongside the suite:

```sh
pip install './wolf-pack[crawler]' '.[scan-web]'
pqcsuite scan ./payments-api --out pqcsuite-out --open
pqcsuite console --sample-project
# Or select your own local repositories:
pqcsuite console --repositories ./repositories --project-history project-history.json
```

The Readiness page provides **Add repository → Scan → Assign remediation → Rescan → Review progress**. Repository selection stays inside the administrator-approved local parent folder. Priorities, affected modules/functions/callers and scan history appear together; parser coverage, test-only findings and exports are in advanced views. The CLI writes an offline report, CBOM, SARIF, audit findings, code relationships and assessment JSON. Unified scans omit source snippets and raw source literals. Optional history keeps the last 100 summaries locally. Console registrations, latest full assessments, owner labels, deadlines and expiring exceptions persist in `.pqcsuite/projects.json` (override with `--project-state`). Switch projects to reopen saved results. Exceptions require a rationale and expiry and never hide risk. Rescans distinguish new, persisting and previously observed findings; “not observed” is static evidence, not proof of a deployed fix. This is a single-administrator workspace, not team RBAC.

Unified scans stop at 50,000 discovered files or 512 MB of discovered files, with a five-minute cooperative time budget. Cancel in the console to preserve the preceding assessment. Checks occur between analysis operations; parsing a file or resolving relationships is not forcibly interrupted. Persistent state is bounded to 16 MB and 5,000 current/historical findings per project. Storage failures leave completed results available in the session with a visible warning.

Python relationships reuse Wolf Pack's existing AST. Optional JavaScript/TypeScript syntax trees feed the same graph and impact engine; other languages retain their crypto detectors with explicit relationship gaps. Dynamic dispatch and business ownership require review. Source stays on your machine and is never executed by the scan. See [Code Crawler](docs/CODE-CRAWLER.md) for evidence limits and measured validation. Wolf Pack 1.3.0 here is checkout code; install from the checkout until that release is published.

## Try it in one minute

With [Docker Desktop](https://www.docker.com/products/docker-desktop/) running, in any terminal (PowerShell, Command Prompt, macOS or Linux):

```
docker run --rm ghcr.io/qubitman-hub/pqcsuite
```

It creates a certificate authority, puts the post-quantum edge in front of an ordinary web server, fetches a page through it with X25519MLKEM768 and an ML-DSA certificate, and shows a classical-only client being refused. Nothing is left behind.

Then check your own sites, with each grade explained and the next step:

```
docker run --rm ghcr.io/qubitman-hub/pqcsuite readiness scan www.your-company.com api.your-company.com
```

Scan from outside your company network: a TLS-inspecting proxy answers in the site's place, and the scanner says so when the certificate it sees is not trusted. The image is the one each release publishes (`ghcr.io/qubitman-hub/pqcsuite:X.Y.Z`, with signed build provenance); to try the latest code instead, `docker build -t pqcsuite https://github.com/QubitMan-hub/PQCsuite.git#main` and `docker run --rm pqcsuite`.

## Install

Python 3.11+, on Windows, macOS or Linux. In a clone of this repository, or with the wheel from a [release](https://github.com/QubitMan-hub/PQCsuite/releases) (`pip install pqcsuite-X.Y.Z-py3-none-any.whl`):

```
pip install .                  # on IPsec gateways: pip install ".[vpn]"; AWS KMS keys: ".[kms]"
pqcsuite                       # every command, and where to start
pqcsuite doctor                # what works on this machine
pqcsuite doctor --ca pki --config edge.toml   # preflight: CA key protection, CRL freshness, expiring certificates, risky settings
```

Every command explains itself with `--help`, and most show an example (`pqcsuite ca issue --help`).

The CA and Vault work everywhere. TLS and the VPN key agreement need **OpenSSL 3.5 or newer**:

| Platform | How to get it |
|---|---|
| Debian 13, Ubuntu 25.04+ | Already the system OpenSSL |
| Docker | `docker run --rm ghcr.io/qubitman-hub/pqcsuite` (Debian 13 base; `docker build -t pqcsuite .` for the latest code) |
| Windows | Install OpenSSL 3.5+ and put its `bin` on `PATH`, or set `PQCSUITE_OPENSSL` to that folder |
| Older Linux | Build OpenSSL 3.5 and run with `LD_LIBRARY_PATH=/path/to/openssl/lib` |

Config and target files can be written with any editor, Notepad and PowerShell included: UTF-8 with or without a byte-order mark, or UTF-16.

### What listens where

| Command | Listens on by default | Serves |
|---|---|---|
| `tls edge`, `tls serve` | every interface, port 8443 | post-quantum TLS; mutual TLS where configured |
| `ca serve` (EST) | every interface, port 9443 | enrollment over post-quantum TLS: a one-time token, or the current certificate to renew; the CA certificate itself is public |
| `ca publish` | every interface, port 8080 | the CRL and the CA certificate over plain HTTP: both are public by design |
| `ca acme` | this machine only, 127.0.0.1:14000 | ACME; put it behind the edge or set `--listen` |
| `console` | this machine only, 127.0.0.1:8900 | the dashboard, with a bearer token |

The edge, EST and the CRL publisher are there for other machines to reach, so they listen on every interface (`0.0.0.0`): anything that can route to the machine can connect to them. To narrow that, give `--listen` one address (`--listen 10.0.0.5:8443`, or `127.0.0.1:8443` for this machine only) or `listen` in the configuration file, and firewall the ports. The console and ACME stay on this machine unless you say otherwise, and `pqcsuite doctor --config console.toml` warns when the console listens beyond it.

## TLS 1.3 + mTLS

```
pqcsuite ca init --name "Acme PQC Root"                        # ML-DSA-87 root, key encrypted; scripts set PQCSUITE_CA_PASSPHRASE
pqcsuite ca issue server app.acme.example --out certs/edge
pqcsuite tls edge --target 127.0.0.1:8080 --cert certs/edge/chain.pem --key certs/edge/key.pem --metrics 127.0.0.1:9100
```

Clients now reach the app on port 8443 over TLS 1.3 with X25519MLKEM768 and an ML-DSA certificate. `examples/edge.toml` documents routes, mutual TLS, CRLs and tunnels (`pqcsuite tls edge --config examples/edge.toml`).

- **Edge modes:** `terminate` puts PQC TLS in front of a service. `originate` lets a plain local client reach a remote edge, so two edges make a post-quantum tunnel for any TCP protocol.
- **Mutual TLS:** `require_client_cert` plus a CRL. Revoked clients are refused at the next handshake. A forged or expired CRL refuses everyone (fail closed). When the CA runs on another machine, `pqcsuite ca publish` serves its CRL and `crl_url` makes edges and VPN gateways fetch it every minute (`crl_every`), so a revocation reaches them without copying files; a download that is forged, expired or older than the kept copy is ignored.
- **Policies:** `strict` (post-quantum only, the default), `transition` (also serves classical clients) and `cnsa2` (ML-KEM-1024, ML-DSA-87, AES-256 only).
- **Browsers:** they negotiate X25519MLKEM768 but cannot verify ML-DSA yet. Under `transition`, `fallback_cert`/`fallback_key` (or `--fallback-cert`/`--fallback-key`) give them an ECDSA or RSA certificate, while post-quantum clients get ML-DSA on the same port.
- **Operations:** certificates reload without a restart, and so does `edge.toml`: a changed route restarts on its own while the others keep their connections, and a file that does not load is logged and ignored (`systemctl reload` works too). `/metrics` for Prometheus, JSON logs, graceful shutdown, connection limits and deadlines on every socket.
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
- **EST (RFC 7030):** `ca serve` on post-quantum TLS; `ca token` makes one-time tokens bound to a name. Machines run `ca enroll` with the token in `PQCSUITE_ENROLL_TOKEN` (the key never leaves them) and renew from cron over mutual TLS.
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
- **Rotation and revocation:** keys rotate make-before-break. A revoked gateway's tunnel closes within 15 seconds of the CRL reaching it (`crl_url` fetches it from the CA every minute).
- **Configuration changes:** the controller and the WireGuard gateway follow their TOML files. The controller restarts in place and its tunnels stay up; the gateway applies changed users, routes, DNS and sites while running (a user taken off the list is removed at once) and restarts in place for anything else. A file that does not load is logged and ignored.
- **Gateway image:** `docker/vpn-gateway.Dockerfile` builds strongSwan 6.1.0 (it fixes CVE-2026-78133 and CVE-2026-78135).

### Remote access

Laptops on Linux, Windows and macOS use WireGuard with a pre-shared key from the same ML-DSA mutual TLS key agreement, replaced every 2 minutes and bound to both WireGuard keys:

```
pqcsuite vpn gateway --config examples/wireguard-gateway.toml
sudo pqcsuite vpn connect vpn.acme.example:7443 --cert-dir ~/.pqcsuite/alice     # connect now (Windows: an administrator prompt, no sudo)
sudo pqcsuite vpn install vpn.acme.example:7443 --cert-dir ~/.pqcsuite/alice     # always on: at every start, restarted if it stops
sudo pqcsuite vpn disconnect                                                      # take it down and lift the kill switch
```

The client drives each platform's own WireGuard: `wg-quick` on Linux, `wg-quick` from Homebrew on macOS (`brew install wireguard-tools`), and WireGuard for Windows as a tunnel service. Keys are renewed in place, without dropping the tunnel, and right after the laptop wakes from sleep; if the gateway has forgotten the laptop meanwhile, the tunnel is taken down, new keys are agreed directly and it comes back.

- **Full tunnel:** with `full_tunnel = true` on the gateway, all of a laptop's traffic goes through the gateway, which forwards it with NAT. IPv6 goes into the tunnel too and is dropped there, so it cannot leak.
- **Kill switch:** in full-tunnel mode nothing leaves the laptop outside the tunnel except WireGuard's own packets and the key agreement with the gateway: an iptables chain on Linux, a pf anchor on macOS, and WireGuard for Windows' own block on Windows. The Linux and macOS rules stay if the client crashes (it fails closed) and while new keys are agreed after a sleep; `vpn disconnect` lifts them. On Windows the block goes with the tunnel for those few seconds.
- **DNS:** the gateway's `dns` servers are set on the laptop; with the kill switch, queries to any other server cannot leave.

Each user keeps one address from the pool. Revoking a user removes them within 15 seconds of the CRL reaching the gateway (`crl_url`: at most a minute later). Why not IKEv2 for laptops: the IKEv2 clients built into Windows, macOS and phones support neither ML-KEM nor PPKs. Phones are not supported yet: their WireGuard apps cannot take a new pre-shared key every 2 minutes.

## Vault

```
pqcsuite vault keygen ops                        # ops.key (secret) + ops.pub; scripts add --passphrase-env VAR
pqcsuite vault keygen recovery                   # a second key, kept offline
pqcsuite vault backup /var/lib/app --to /backups -r ops.pub -r recovery.pub --sign-cert bot/cert.pem --sign-key bot/key.pem --keep 14
pqcsuite vault verify /backups/app-20260925T161150Z.pqv --key recovery.key      # restore drill: checks everything, writes nothing
pqcsuite vault decrypt /backups/app-20260925T161150Z.pqv --key ops.key -o /restore --ca pki/ca.crt --signer backup-bot
pqcsuite vault share file.pqv --key ops.key -r new-admin.pub
pqcsuite doctor --backups /backups               # every archive readable and opened by two keys, the newest recent
```

- **No single point of loss:** a key that is lost, or whose passphrase is forgotten, cannot be recovered, and neither can what only it opens. So `vault backup` refuses an archive that one key opens, unless `--no-recovery-key`; `vault encrypt` warns. Keep the recovery key offline, and rehearse a restore with `vault verify`.

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

Pages: overview, TLS 1.3 edges, mTLS certificates (issue, revoke, renew), IPsec VPN tunnels and remote users, Vault backups, and readiness scans. `--scan HOST:PORT --scan-every 24` re-scans your endpoints on a schedule and lists every endpoint whose grade changed since the scan before. `--check-updates` shows when a newer release is out (it asks GitHub once a day; nothing is sent otherwise, and `pqcsuite doctor --check-updates` does the same once). It binds to localhost, needs the printed token on every API call and audits every change. Browsers cannot verify ML-DSA yet, so publish it with `pqcsuite tls edge --policy transition` and a classical certificate.

## Deploy

- **Docker:** `Dockerfile` (edge and tools) and `docker/vpn-gateway.Dockerfile`.
- **Kubernetes:** `deploy/helm/pqcsuite` runs the CA (EST, ACME, daily maintenance, optional console) and edge gateways. EST, ACME and the console sign with an issuing CA whose key is always encrypted; they never see a root key. By default the chart makes the root and the issuing CA on first start and mounts the root into no service; for production, make the issuing CA offline under your own root and give it to the chart (`ca.issuingSecret`), so no root key is in the cluster at all; `deploy/k8s/sidecar.yaml` shows the edge as a sidecar. Edge certificates come from a Secret you create.
- **Cloud images:** `deploy/packer` builds a Debian 13 image for AWS, Azure and GCP with OpenSSL 3.5, strongSwan 6.1.0, WireGuard and systemd units that start when their configuration exists. Not yet built in a real cloud account.

## Demo

```
python examples/clinic_demo.py          # pauses before each step
python examples/clinic_demo.py --auto   # runs straight through and checks every result
python examples/bank_demo.py            # the same for a bank; ends with the console open
sudo python examples/vpn_demo.py        # a branch over IPsec and a laptop over WireGuard, on one Linux machine
```

A clinic's patient portal, old records server, a doctor's laptop and nightly backups, in about a minute: readiness grades, Wolf Pack on the clinic's code (when `wolfpack` is installed: `pip install ./wolf-pack`), the portal behind post-quantum mutual TLS, a stolen laptop cut off, a signed Vault backup, a tampered backup refused, and the evidence report. `bank_demo.py` tells the story for a bank: a partner payment API behind post-quantum mutual TLS, a card switch's line protocol tunnelled unchanged, 3DES and RSA-1024 found in legacy code, a compromised branch cut off, a statement archive shared with an auditor and protected against edits. `vpn_demo.py` builds headquarters, a branch and a laptop in network namespaces: the branch joins over IPsec with X25519 + ML-KEM-768 and a post-quantum PPK, the laptop over WireGuard with a key agreed over ML-DSA mutual TLS, and revoking either certificate cuts it off (it needs root, and strongSwan 6.0.2+ or WireGuard). CI runs all three on every change.

## Documentation

| Where | What it covers |
|---|---|
| This README | Installing the suite and using each product |
| `pqcsuite COMMAND --help` | Every option of every command, most with an example |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release, and what is on `main` but not released yet |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Which attackers the suite stops and which it does not, revocation when things fail, the key lifecycle, and runbooks for a compromised or lost key |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, and every classical algorithm in the code and why it is there |
| [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) | The brief for an independent security review: assets, trust boundaries, what to test |
| [docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md) | What every release must pass, and what has not been validated yet |
| [docs/PRODUCT-REVIEW.md](docs/PRODUCT-REVIEW.md) | Market map, implemented customer workflows, evidence boundaries and remaining product gaps |
| [docs/PILOT.md](docs/PILOT.md) | Step-by-step checks that need your own cloud accounts or hardware |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Working on the suite: tests, the website and releases |
| [wolf-pack/README.md](wolf-pack/README.md) | Wolf Pack CBOM, the cryptography inventory scanner |

`tests/test_docs.py` checks, on every change, that every command and option quoted here, in `docs/`, in the examples and on the website exists, and that every link between them leads somewhere.

## Limits

- The edge uses one thread per connection (512 by default) and forwards TCP bytes; it does not parse HTTP. One process handles about 500 new TLS connections a second; on Linux, `--workers N` runs N processes on the same port (4 workers on 4 cores: about 1,500 a second, half of nginx with OpenSSL 3.5 on the same machine). Long-lived connections cost little once the handshake is done.
- One address cannot fill the connection limit with silent sockets: once half the slots are taken, a host with 32 handshakes still unfinished waits. A flood from many addresses can still fill it; put the edge behind a load balancer or firewall that limits connections per source.
- Revocation uses CRL files; there is no OCSP responder. The CA keeps its index in one JSON file: issuing takes about 6 ms per certificate at 1,000 certificates and 34 ms at 5,000, growing with the index. Fine for thousands of devices; a CA for hundreds of thousands needs a database.
- Algorithms come from OpenSSL and pyca/cryptography. Nothing here is FIPS 140-3 validated, and no independent security review has been done yet.
- The console has one administrator token and no roles: whoever holds it can issue and revoke certificates.

Which attackers the suite stops and which it does not, how revocation behaves when the CA or its address is down, and runbooks for a compromised key: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). What each release must pass, and what has not been validated yet: [docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md).

## Roadmap

First, proving what exists rather than adding to it: an independent security review, deployments in real cloud accounts and on EKS, AKS and GKE, days-long soak tests, and benchmarks on production hardware (the open list is in [docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md), and [docs/PILOT.md](docs/PILOT.md) is the script for each). After that:

1. VPN: sign-in with the company's identity provider, per-group access rules and a users page in the console; two gateways with failover; phones.
2. mTLS: a cert-manager issuer and in-cluster renewal of edge certificates (CRLs already reach edges through `crl_url`); dns-01 for ACME.
