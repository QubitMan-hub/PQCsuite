# Four standalone products: design

Revision 2, 16 October 2026. Base commit `5f8c349a102e566560708ee12b9b1574e4a6e6cc`. Status: for owner review. Revision 1 was reviewed by the owner; this revision answers that review.

## Goal

Turn the PQC Suite monolith and the separate Wolf Pack scanner into four products that a customer can install, configure, operate, test, deploy and understand on their own:

- Acxelin TLS
- Acxelin VPN
- Acxelin Readiness
- Acxelin Q-Vault

Success means all of the following hold, each proven by an executed test:

1. **Independent install.** Each product installs from built wheels into a fresh environment outside the repository and pulls in no other product.
2. **No cross-product imports.** No product imports another product.
3. **Own interface.** Each product has a simple interface for routine tasks: configure, run common operations, view status and troubleshoot. It exposes only that product. CLI commands stay for automation and advanced use.
4. **Old data still works.** Legitimate data written by the current release still works: archives, invitations, CA folders, configs and CBOM baselines. Tampered, revoked or malformed data is refused.
5. **No Wolf Pack names.** The Wolf Pack name and vocabulary are absent from code and output, except where "Branding exemptions" lists them.
6. **Own pages.** Each product has its own README, example config, docs, deploy path and website section.

## Decision record

"Confirmed" means the owner chose it in this design conversation. "Proposed" means it awaits the owner's review of this document.

| # | Decision | Status |
|---|---|---|
| D1 | One shared library, `acxelin-core`, holding mechanisms only (see "Shared core") | Confirmed |
| D2 | Acxelin VPN keeps IPsec site-to-site, WireGuard remote access and the desktop app | Confirmed |
| D3 | The Wolf Pack concept goes. The role switchboard, the per-heuristic ablation benchmark and the evaluation kits move to git tag `research-archive-2026-10`. The dev corpus and `bench/truth.json` stay as a CI quality gate. | Confirmed |
| D4 | One website: a shared home page, and each product's own section reached from it | Confirmed |
| D5 | Legitimate old data stays readable through versioned readers. Insecure behaviour is not preserved. Old names are read through each product's compatibility window. | Confirmed in principle; the details below are proposed |
| D6 | Commands `acxelin-tls`, `acxelin-vpn`, `acxelin-readiness` and `acxelin-vault` | Confirmed |
| D6a | Packages named like the commands, core `acxelin-core`, display names Acxelin TLS, Acxelin VPN, Acxelin Readiness and Acxelin Q-Vault | Proposed |
| D7 | All six architecture candidates are in scope. The HTTP and keyring candidates must pass "Spike criteria" or are deferred. | Confirmed (criteria proposed) |
| D8 | Each product keeps a web interface for routine work, adapted from today's console, VPN app and desktop app (see "Product interfaces") | Confirmed by owner instruction |
| D9 | Readiness reads other products' assets through CycloneDX CBOM files (see "CBOM contract") | Proposed |
| D10 | The GitHub release check (`latest_release`) is removed; products do not phone home | Proposed |
| D11 | Product consoles listen on localhost only. Remote use goes through an SSH port-forward, not another product. | Proposed |
| D12 | Hosting: GitHub Pages from this repository, with product sections as sub-paths | Proposed |
| D13 | Out of scope: team access (SSO, RBAC), installer code signing, independent security review | Inherited from the repository's 1 October 2026 note; not yet reconfirmed by the owner |

## Target layout

```
core/                      acxelin-core
products/
  tls/                     acxelin-tls
  vpn/                     acxelin-vpn
  readiness/               acxelin-readiness
  vault/                   acxelin-vault
site/                      shared home + one section per product
tools/                     wheelhouse build, fixtures, release gate, manual renderer (not shipped)
.github/workflows/         one workflow per product, plus core, pages, codeql, upstream, downloads
```

Every product folder:

```
products/<name>/
  pyproject.toml           own version; depends on acxelin-core
  README.md                install, quickstart, open the console, config reference
  src/acxelin_<name>/      code, plus console page and assets as package data
  config/example.toml
  tests/                   behaviour, rejection, interface-journey and install tests
  docs/                    manual.md, threat-model.md, upgrade.md
  deploy/                  that product's own deploy path
  CHANGELOG.md
```

## Shared core

### Mechanism, not policy

The core holds mechanisms that two or more products use. Each product owns the policy: what to allow, which defaults, which commands and which pages. The core has no command, no config file, no page content and no product name in its code. A test greps `core/` for product names and fails if it finds one.

| Core module (mechanism) | Products own (policy) | Used by |
|---|---|---|
| `config`: TOML parsing, typed validation with clear errors, passphrase from environment | each product's settings schema and defaults | all four |
| `files`: atomic private writes, locks | where each product keeps its state | all four |
| `http`: threaded localhost server, idle timeout, body-size limit, JSON replies | routes | all four |
| `console`: localhost bind, bearer token compared in constant time, lockout after 10 wrong tokens per address per minute, page shell | the page, its API routes and its actions | all four |
| `openssl`: ctypes binding to OpenSSL 3.5+, context building from explicit group and signature lists, `Server` with reload and CRL | TLS's named policies (strict, transition); VPN's fixed strict list | TLS, VPN, Readiness (full-handshake capability only) |
| `pki`: CA issue, renew, revoke and CRL signing, chain and CRL verification, signers, EST protocol client and service | certificate profiles, lifetimes, who may enroll, and the `ca`/`est` commands | TLS and VPN issue; Vault verifies signers only |

Revision 1 put CLI argument definitions in the core. They now stay in each product, because which CA operations a product offers is policy. Acxelin VPN offers a smaller CA command set than Acxelin TLS.

Importing `acxelin_core` does not load OpenSSL; only `acxelin_core.openssl` does. Acxelin Readiness now depends on the core for `console`, `http`, `files` and `config` (all pure Python). It uses `openssl` only for its full-handshake capability, which is active when OpenSSL 3.5+ is found and reported by `acxelin-readiness doctor` (see "Readiness behaviour contract").

### Installing before packages are published

Nothing is on PyPI yet, so a product's dependency on `acxelin-core` can't be resolved from an index. Two supported ways cover this:

1. **From a checkout**, one command that names both folders:
   ```
   pip install ./core ./products/vault
   ```
   pip satisfies the product's `acxelin-core` requirement with the local core in the same command.
2. **From a release**, each product's release attaches a wheelhouse: the product wheel, the matching core wheel and pinned third-party wheels. Customers run:
   ```
   pip install --no-index --find-links wheelhouse acxelin-vault
   ```
   `tools/wheelhouse.py <product>` builds it.

### Built-wheel install test

For each product, the test:

1. Builds wheels with `tools/wheelhouse.py`.
2. Creates a fresh virtual environment in a temporary folder outside the repository.
3. Installs with `--no-index --find-links`, from a working directory outside the repository, with `PYTHONPATH` empty.
4. Asserts:
   - no installed distribution is editable
   - every imported product and core module resolves inside the environment's `site-packages`
   - no other product's distribution is installed
   - the wheel contains every runtime asset the product loads: console page, VPN app page, tour script, report fonts and logo, example config, and the templates the product writes (systemd units, compose files)
5. Runs the product's smoke journey: its main CLI commands, then starting its console and loading the page.

### Supported platforms

A platform is "supported" only when a CI job runs that product's tests on it. Anything else is listed as unverified, never claimed.

| Product | Python | Operating systems |
|---|---|---|
| Acxelin Readiness | 3.11 to 3.14 | Linux, Windows, macOS |
| Acxelin Q-Vault | 3.11 to 3.14 | Linux, Windows, macOS |
| Acxelin TLS | 3.11 to 3.14 | Linux (OpenSSL 3.5.9 built in CI); Windows and macOS only if Stage 0 shows their jobs run the TLS tests rather than skip them |
| Acxelin VPN | 3.11 to 3.14 | Gateway: Linux. Client and desktop app: Linux, Windows, macOS (Apple silicon) |

CI runs each product on the lowest and highest Python version, and on every operating system in the table.

### Vault without an external OpenSSL

Acxelin Q-Vault must work with only the `cryptography` wheel, which bundles its own OpenSSL. Its test runs in a container whose system OpenSSL is older than 3.5, with `ACXELIN_OPENSSL` unset. It runs every routine Vault operation and the console journey, not just an import:

- `keygen` (default and `--cnsa2`), `encrypt`, `decrypt`, `verify`, `backup`, `share` and `inspect`
- signed archives

Whether `cryptography>=49`'s bundled OpenSSL provides ML-KEM and ML-DSA is a Stage 0 finding. If it doesn't, this test fails and the gap is reported, not hidden.

## Products

### Acxelin TLS

For platform and security teams putting post-quantum TLS 1.3 and mTLS in front of existing services.

- **Code:** edge (`tls/edge.py`, `bundles.py`, `http.py`), ACME (`pki/acme.py`), the one-minute tour, and TLS checks from `checks.py`.
- **Console:** see "Product interfaces".
- **Commands:**
  - `acxelin-tls console`, `try`, `doctor`, `status`
  - `edge`, `bundle`, `serve`, `connect`
  - `ca init|issue|renew|sign-csr|revoke|crl|maintain|list|token|publish|serve|enroll|acme|eab|csr`
- **Deploy:** Docker, Helm (CA + edge), the Kubernetes sidecar, and systemd units `acxelin-tls-edge.service` and `acxelin-tls-maintain.timer`. The soak and benchmark scripts move here.
- **Inventory contribution:** see "CBOM contract".

### Acxelin VPN

For network teams connecting sites over IPsec and staff over WireGuard.

- **Code:** `vpn/*` (charon, controller, wireguard, platforms, desktop, app, join).
- **Interfaces:** the end-user app and desktop app, plus an administrator console.
- **Commands:**
  - `acxelin-vpn console`, `doctor`, `status`, `check`
  - `up`, `gateway`, `invite`, `join`, `app`, `desktop`, `connect`, `install`, `disconnect`, `uninstall`
  - `ca init|issue|revoke|crl|maintain|list|serve`
  - `inventory --cbom`

  `ca serve` is the EST service that invitations enroll against, so `invite` and `join` need nothing from Acxelin TLS.
- **Deploy:**
  - systemd units `acxelin-vpn-ipsec`, `acxelin-vpn-wireguard`, `strongswan-pqc` and `acxelin-vpn-ca-maintain.timer`
  - the gateway Docker image
  - the Packer gateway image
  - desktop installers (`packaging/`, `.github/actions/installer`)

### Acxelin Readiness

For security and compliance teams finding quantum-vulnerable cryptography and deciding what to migrate first. It merges the Wolf Pack engine with the suite's readiness assessment.

- **Commands:**
  - `acxelin-readiness console`, `setup`, `doctor`
  - `scan PATH [--tls HOST:PORT] [--ssh HOST] [--open] [--history FILE]`
  - `probe`
  - `report [--certs DIR] [--targets ...] [--cbom FILE]...`
  - `merge`
- **Full-handshake capability:** used automatically when OpenSSL 3.5+ is found (`ACXELIN_OPENSSL` or the system library); no extra package. `doctor` reports whether it is active.
- **Deploy:** pip, Docker, and the GitHub Action at `products/readiness/action.yml`.

Engine renames:

| Old | New |
|---|---|
| `wolfpack` | `acxelin_readiness` |
| `pack.py` (`run`, `hunt`) | `pipeline.py` (`run`, `detect`) |
| `scouts/` | `detectors/` |
| `den.py` | `verify.py` |
| `alpha.py` | `rank.py` |
| `elders.py` | `catalog.py` |
| `Sighting` | `Detection` |

`pack.Roles`, the ablation configurations and `hunt --without` are removed. Verdict and evidence names stay, because they are domain terms.

### Acxelin Q-Vault

For data owners whose archives and backups must stay secret past the arrival of quantum computers.

- **Recipients:** ML-KEM-768 + X25519 key pairs (ML-KEM-1024 + P-384 with `--cnsa2`). An optional signer certificate and CRL from any CA are checked with core `pki`.
- **Commands:** `acxelin-vault console`, `doctor`, `keygen`, `encrypt`, `decrypt`, `verify`, `backup`, `share`, `inspect`, and `inventory --cbom`.
- **Deploy:** pip, plus a Docker image for scheduled backups.

## Product interfaces

Every existing console page keeps a home in its own product. Each product console runs on the core `console` mechanism. It listens on 127.0.0.1, requires its bearer token on every API call, and locks out an address after 10 wrong tokens in a minute. It shows only its own product's pages, and its API serves only its own routes.

### Where each console feature goes

| Today (console route or page) | Product interface | Customer journey (acceptance test) |
|---|---|---|
| `/api/certificates`, issue, revoke, maintain; "Issue a certificate"; "Issued certificates" | TLS console: Certificates | Create the CA, issue an edge certificate, revoke it, and see the CRL refreshed, all without the CLI |
| `/api/edges` | TLS console: Edges | See what each edge's status endpoint reports, plus its certificate expiry; run a connection test showing the negotiated group |
| `doctor` output | TLS console: Health | See each failed check with its fix |
| `/api/tunnels` | VPN admin console: Sites | See each IPsec tunnel's state, algorithms and last rotation |
| `/api/remote`; "Remote access · gateway observations" | VPN admin console: People | Invite a person and download their invitation file; see who is connected; revoke a person and watch their session end |
| VPN `app` (`/api/state`, invitation, connect, disconnect, ticket) | VPN app and desktop app (unchanged) | Join from an invitation, connect, see "Protected", disconnect, create a support ticket |
| `/api/backups`; "Protect your first backup" | Vault console | Create keys with a recovery key, protect a folder with retention, run a restore drill, see the warning when an archive has no recovery recipient, share a file with one more recipient |
| Projects (register, select, scan, cancel, track, verify); "Repository readiness"; "Code inventory → migration priorities"; `setup` | Readiness console: Projects | Add a project, scan it, cancel a scan and keep the previous result, see priorities, open the full report |
| `/api/scan`; "Scan endpoints"; "Changed since the scan before"; "Endpoint migration queue" | Readiness console: Endpoints | Scan endpoints, see the change since the previous scan, export the CBOM |
| `/api/overview` | each console's home page, showing only its product | Open the console and see that product's status at a glance |

Vault's create, restore-drill and share actions, and the TLS connection test, are new console actions over existing CLI functions. They're added because routine work must not need the CLI.

### Rules for removing a console feature

1. A console feature is removed only after its replacement row above passes its journey test.
2. Each journey has a Playwright test against that product's console, served by a test harness like today's `tests/browser/console_server.py`.
3. Each journey also has an API-level pytest.
4. Each console has a test proving it loads no other product's code, routes or names.
5. Each console keeps the existing security tests: missing token, wrong token, lockout and non-local bind.

## Old command migration

| Old | New |
|---|---|
| `pqcsuite tls edge\|bundle\|serve\|connect` | `acxelin-tls edge\|bundle\|serve\|connect` |
| `pqcsuite ca ...` | `acxelin-tls ca ...` (VPN administrators: `acxelin-vpn ca ...`) |
| `pqcsuite try` | `acxelin-tls try` |
| `pqcsuite doctor` | `acxelin-<product> doctor` |
| `pqcsuite console` | `acxelin-<product> console` |
| `pqcsuite setup` | `acxelin-readiness setup` |
| `pqcsuite vpn <cmd>` | `acxelin-vpn <cmd>` |
| `pqcsuite vault <cmd>` | `acxelin-vault <cmd>` |
| `pqcsuite readiness scan` (endpoints) | `acxelin-readiness scan --tls ...` |
| `pqcsuite readiness probe` | `acxelin-readiness probe` |
| `pqcsuite readiness report --ca/--targets` | `acxelin-readiness report --certs/--targets` |
| `pqcsuite readiness report --vici` | `acxelin-vpn inventory --cbom`, then `acxelin-readiness report --cbom` |
| `pqcsuite readiness report --backups` | `acxelin-vault inventory --cbom`, then `acxelin-readiness report --cbom` |
| `pqcsuite readiness report --wolfpack` | not needed: one product |
| `pqcsuite scan PATH` (project scan) | `acxelin-readiness scan PATH` |
| `wolfpack scan\|merge` | `acxelin-readiness scan\|merge` |
| `wolfpack bench` | removed (D3); the CI gate is `tools/quality_gate.py` |

Each product ships `docs/upgrade.md` with its rows of this table, and the old-to-new path, setting and environment-variable changes.

## Compatibility and migration

### Compatibility, not bug preservation

1. Legitimate old data stays readable through explicit, versioned readers. The Vault archive format is version 1 (magic `PQV1`, signature block `SIG1`, key-derivation label `pqcsuite-vault-v1`). Version 1 stays readable for as long as such archives can exist. The label is part of the format and is never renamed.
2. A security fix may change a format. It then gets a new version (for example `PQV2`), new data is written in it, version 1 stays readable, and `docs/upgrade.md` explains the change.
3. Old readers apply today's checks. Reading old data never skips signature, MAC, revocation or policy checks.
4. Golden fixtures prove legitimate old data is readable. A behaviour found insecure is fixed, its golden test is replaced by a rejection test, and the change is logged in the stage report.

### Rejection cases

Each of these must be refused, with a clear message:

- **Vault archives:**
  - one flipped bit in each section (header, recipient entry, chunk, final chunk, signature)
  - a truncated archive
  - reordered or duplicated chunks
  - a header with a recipient added or removed after writing
  - a valid archive with a signature by a key other than its certificate's
  - a signer certificate from an untrusted CA
  - a signer certificate on the CRL
  - an expected signer that doesn't match
- **Credentials:**
  - an edge, VPN keyring or EST client presenting a revoked certificate
  - an expired certificate
  - a certificate for the wrong name
  - a CRL with a bad signature
  - a stale CRL past its next-update time
- **Invitations:**
  - invalid JSON or the wrong version
  - a missing field
  - a non-HTTPS enrollment URL
  - a fingerprint that isn't 64 hex characters
  - an expired invitation
  - an invitation whose token was already used
  - a CA whose fingerprint doesn't match the invitation
- **Configs and CBOMs:**
  - unknown or mistyped settings
  - a malformed CBOM or baseline
  - a CBOM that fails the CycloneDX 1.6 schema

### Compatibility window

The window is the 1.x line of the affected product. Old names are read, with a one-line deprecation warning naming the new one, in every 1.x release. They are removed no earlier than that product's 2.0.0, whose release notes must list them.

| Product | Old name read through 1.x | New name |
|---|---|---|
| Readiness | `wolfpack:ignore` | `acxelin:ignore` |
| Readiness | `wolfpack:*` CBOM properties in baselines and `merge` inputs | `acxelin:*` |
| Readiness | `.wolfpack.toml` | `.acxelin-readiness.toml` |
| Readiness | `wolf-pack/action.yml` (a shim that warns) | `products/readiness/action.yml` |
| VPN | `pqcsuite_invite` key, `.pqcinvite` files | `acxelin_invite`, `.acxinvite` |
| VPN | `PQCSUITE_WIREGUARD_GO`, `PQCSUITE_STRONGSWAN`, `PQCSUITE_VPN_DATAPLANE` | `ACXELIN_*` equivalents |
| VPN | `PQCSUITE-KILLSWITCH` chain, `com.apple/pqcsuite` anchor, and the Windows rule names | `ACXELIN-KILLSWITCH`, `com.apple/acxelin-vpn`, new Windows names |
| VPN | `~/.pqcsuite` | `~/.acxelin-vpn` |
| TLS and VPN | `PQCSUITE_OPENSSL` | `ACXELIN_OPENSSL` |
| TLS, VPN and Readiness | `PQCSUITE_CONSOLE_TOKEN` | `ACXELIN_<PRODUCT>_CONSOLE_TOKEN` |

### Precedence when both exist

- **Settings, environment variables and config files:** the new name wins. The old one is ignored with a warning naming both. They are never merged.
- **Suppression comments:** both are honoured, because each applies to its own line.
- **Folders:** the old folder is read only when the new one is absent. Nothing is copied or moved automatically.
- **Key material and CA folders:** never moved automatically. `docs/upgrade.md` gives the commands.

### Kill-switch migration

The upgrade installs the new rules first and removes the old ones only after the new ones are active. If it fails in between, both rule sets block traffic, and it never leaves a moment with neither.

**Acceptance test (Linux, network namespaces in CI):**

1. Start a client namespace with the old `PQCSUITE-KILLSWITCH` chain active and the tunnel up.
2. Send traffic continuously to an address outside the tunnel.
3. Run the upgrade.
4. Repeat the run while killing the upgrade after the new chain is installed but before the old one is removed.
5. Repeat the run while making the new chain's installation fail.

It passes when:
- the counter of packets leaving any non-tunnel interface stays at zero throughout every run
- after a normal upgrade, only the new chain exists
- after the killed run, both chains block
- after the failed installation, the old chain is still active

**macOS and Windows:** recorded-command tests check that rule commands run in that order, including both failure points. A run on CI's macOS and Windows runners with administrator rights is required. If those runners cannot apply firewall rules, the stage stays pending until a pilot machine run is recorded.

### Branding exemptions

"Wolf", "wolfpack" and "pqcsuite" may appear only in:
- the compatibility readers and their deprecation messages
- golden fixtures
- `docs/upgrade.md` and frozen changelog history
- the archived tag
- the shim action

A test greps the tree and fails on any occurrence outside an allowlist of exactly those paths.

## Readiness behaviour contract

The engine's pure-Python probe replaces the suite's OpenSSL prober only for the capabilities where both produce the same results in the contract tests below. Everything else keeps today's prober, as the full-handshake capability, until a replacement passes. Without OpenSSL 3.5+, a report says what was not observed and how to observe it. It never marks it as passing.

| Capability | Suite prober today | Engine probe today | Contract |
|---|---|---|---|
| Protocols | TLS 1.3/1.2, legacy TLS 1.0/1.1 detection, SSH | same | all kept |
| Group acceptance | full handshake per group: 5 post-quantum, 7 classical | ServerHello or HelloRetryRequest selection per group: 14 groups | each group is reported accepted or refused, identically, against test servers configured for post-quantum only, hybrid and classical |
| Negotiated group on a default offer | yes | yes | identical |
| Endpoint certificate | yes, including post-quantum-only servers and ML-DSA certificates | only through a classical handshake with the system OpenSSL | key algorithm, size, signature algorithm, issuer, expiry and names are reported for all three test servers; **gap today; keep the prober** |
| Trust check (system roots, hostname) | yes | no | trusted, untrusted and wrong-name outcomes are reported; **gap; keep** |
| Grade A/B/C/F | yes | no | same grade for the same server; **port the rules** |
| SSH | banner, key exchanges, host keys; refuses oversized and truncated packets | banner, key exchanges, host keys | identical fields; oversized, truncated and non-SSH responses produce an error row, not a crash |
| Timeouts | 8 s per connection | 5–6 s | 8 s default, configurable; slow-server test endpoints finish within (handshakes per target) × timeout |
| Concurrency | 16 workers | sequential | 16 workers default |
| Target input | host, host:port, ssh://host, .txt files; first 10 bad targets listed | similar | identical parsing and error message |
| Errors | unreachable → F with reason; one target's failure never stops the others | similar | kept |
| Project scan limits | 50,000 files, 512 MB, 300 s (from `project.py`) | none | kept, with a clear message when reached |
| Cancellation | stops, keeps the previous completed result | none | stops within one file or one handshake; previous result kept; no partial output overwrites it |
| History | last 100 scan summaries in a JSON file | none | kept |

Contract tests run against local test servers built in the test suite, on the edge from core `openssl` and a classical Python `ssl` server, plus an SSH stand-in. They never touch the internet.

## CBOM contract

The format is CycloneDX 1.6 JSON. Every export and every Readiness output must validate against the official 1.6 schema with 0 errors.

**Required fields**
- **BOM:** `bomFormat`, `specVersion` "1.6", `serialNumber` (`urn:uuid`), `version`.
- **Metadata:** `metadata.timestamp`, `metadata.tools` (product name and version), and `metadata.component` (the system inventoried: name and type).
- **Each cryptographic asset:** `type` "cryptographic-asset", `bom-ref`, `name`, and `cryptoProperties.assetType` (algorithm, certificate, protocol or related-crypto-material). Then by type:
  - algorithm: `algorithmProperties.primitive`, and `parameterSetIdentifier` and `nistQuantumSecurityLevel` when known
  - certificate: `signatureAlgorithmRef`, `subjectPublicKeyRef`, `notValidAfter`
  - protocol: `protocolProperties.type` (tls, ipsec, ssh, wireguard) and its cipher-suite references
  - related material: type and size only, never a value

**Algorithm identifiers.** Names come from the Readiness catalog's canonical list (for example ML-KEM-768, X25519MLKEM768, ML-DSA-65, AES-256-GCM, RSA-2048), plus the OID when the catalog has one. A cross-product test, not a runtime dependency, checks that every name VPN and Vault can export is known to the catalog. Readiness imports an unknown name as unknown, keeps the raw name, and lists it in the report.

**Relationships**
- `dependencies`: the system depends on each asset it uses.
- Certificates reference their signature and key algorithms.
- Protocols reference their algorithms.

**Provenance.** Every asset carries:
- `acxelin:source`: product and version
- `acxelin:system`: the system name
- `acxelin:observed`: one of observed, configured or declared
- `evidence.occurrences` with a location: host:port, tunnel name, archive path or file:line

**Unknown values.** A field that isn't known is omitted, never guessed, and named in `acxelin:unknown`. The compliance rules treat unknown parameters as unverified. That includes AES of unknown key size, which the engine counts as CNSA 2.0-compliant today; that is the correctness fix.

**Merge and deduplication.**
- Assets are identical only when assetType, name, parameterSetIdentifier, primitive, mode, padding and curve all match. Today's `inventory.build` matches on name alone and keeps the first system's properties.
- Occurrences are unioned and prefixed with their system.
- The asset's tier is the worst across systems.
- If two inputs disagree on a non-identity field, the catalog's value is used and the disagreement is recorded in `acxelin:conflict`.
- Output is sorted by `bom-ref`, so the same inputs always give the same file.

**Secrets.** Exports never include private keys, PSKs, PPKs, session keys, enrollment tokens, console tokens or passphrases, in any encoding. A test exports from fixtures whose secrets are known, then searches the output for each secret as raw bytes, hex, base64 and PEM, and fails on any match.

**Acxelin TLS.** It contributes through standard interfaces, with no export command:
- its issued certificates, read as PEM with `report --certs`
- its live edges, probed with `report --targets`

That covers what a customer's auditors see. Configured but unexposed policies (internal mTLS upstreams, the CA's signer algorithm) are not inventoried. That limit is stated in the Readiness docs.

**Pipeline test.** VPN and Vault each run export → schema validation → Readiness import → report, and check every exported asset appears with its provenance.

## Architecture changes

1. **Dissolve the suite hub.** `cli/`, `console/`, `checks.py` and `cli/common.py` go. The `pqcsuite/__init__.py` helpers move to core mechanisms, and each product owns its command, doctor and console.
2. **One assessment pipeline for Readiness**, with the behaviour contract and the CNSA 2.0 fix.
3. **Delete the role switchboard** (D3).
4. **One keyring module for both VPN tunnels.** This is not needed for independence, because both tunnels stay in Acxelin VPN. It's a spike after Stage 4 is green.
5. **One HTTP mechanism.** It's needed for the consoles, which all use core `http` and `console`. Folding ACME's own handler into it is not needed, so that part is a spike.
6. **One brand module**, owned by Readiness, the only product that writes branded reports. The consoles use the core page shell. The site keeps its own copy of the fonts and tokens.

### Spike criteria

The keyring spike and the ACME-handler spike go ahead only if all of these hold. Otherwise they are deferred, and the reason is recorded.

**Security preserved.** Before the change, rejection tests cover every limit and check in the code being merged, and those tests pass both before and after:
- idle timeout (30 s) and body-size limit
- token lockout
- CRL refresh interval and stale-CRL cut-off
- certificate reload
- revoked-peer disconnect

**Simpler.**
- fewer total lines and fewer classes across the affected files
- no new setting
- no product name or product-specific branch in the shared code

**No behaviour change** in the existing tests for both adapters.

## Testing strategy

1. **Baseline record (Stage 0).** Commit `tools/baseline.md` with:
   - the full base commit
   - `pip freeze`
   - Python, OpenSSL, `cryptography` and operating system versions
   - every command run
   - pass, fail and skip counts with each failure and skip reason
   - coverage per mapped product
   - precision and recall
2. **Golden fixtures.** `tools/make_fixtures.py` writes them with today's code, from a fixed seed where the format allows. The procedure is committed with the fixtures. All keys, certificates and tokens are synthetic, generated for the test, and named `*.invalid`. No real credential is ever committed.
3. **Tests first.** Each stage writes its behaviour, rejection and journey tests first. It shows them failing, or passing on the old code for golden fixtures, before changing code. Intended behaviour comes from the manual, threat model, security review and CLI help. Existing tests are triaged as keep, rewrite or delete, with reasons in the stage report.
4. **Independence tests:** the built-wheel install test, the import-boundary test, the core product-name test, the branding test, and the Vault-without-external-OpenSSL test.
5. **Interface journeys:** a Playwright test and an API pytest for each row of "Where each console feature goes", plus each console's isolation and security tests.
6. **Coverage on mapped code.** Stage 0 maps every current file to the product or core module it becomes, or to "deleted" with a reason. The baseline line coverage is computed per product over the old files that map to it, and later stages are compared like-for-like. Deleted code is excluded from both sides. Each product's floor is its baseline.
7. **Readiness quality gate.**
   - Unit: (file, algorithm family) pairs, as `bench.py` scores today.
   - Precision = true positives ÷ predicted pairs. Recall = true positives ÷ pairs in `bench/truth.json`.
   - CI fails if either drops below its Stage 0 value at three decimals.
   - Changes to `truth.json` go only in separate commits titled `truth:`. Each changed label carries a reason quoting the file evidence, and each commit needs owner approval.
   - The gate reports scores against both the old and the corrected truth.

## Website

- `/` is a shared home in Acxelin's format: one entry per product, with the customer challenge as headline, the product name, one line, and a link. There are no feature lists.
- `/tls/`, `/vpn/`, `/readiness/` and `/vault/` each have up to five pages: overview, how it works, set up, sample or demo, and security. Each section's navigation shows only its own pages.
- Each "set up" page ends at opening that product's console.
- Manuals render from `products/<name>/docs/manual.md`.
- Old public URLs get redirect pages, kept until every product has reached 2.0.0.
- Fonts are self-hosted; the existing Acxelin tokens are used. Design work uses frontend-design and Impeccable.
- Playwright journeys, one per product:
  - home, then the product, set up, and the install command copied
  - the sample opens
  - a product page shows no other product's description
  - axe accessibility checks
  - a mobile viewport

## Repository cleanup

Each removal first shows no reference outside the removal set. `pqcsuite/console/` is no longer removed outright: its pages move into the product consoles, and the shell moves into core `console`.

| Item | Action |
|---|---|
| eval kits, ablation bench, `pack.Roles` | archive at tag |
| `.claude/skills/archify`, `docs/architecture/`, `docs/how-it-works/`, `site/architecture/` | remove |
| `.claude/skills/wolf-pack-tidy`, `.agents/skills/pqcsuite-project-scan` | remove |
| `docs/AGENT-HANDOFF.md`, `docs/PRODUCT-REVIEW.md`, `wolf-pack/docs/HANDOFF.md` | remove (git history keeps them) |
| manual, threat model, security-review brief, pilot protocol | split per product |
| `docs/CODE-CRAWLER.md` | Readiness docs |
| release gate, release notes, manual renderer | `tools/` |
| `scripts/console_demo.py`, `site/console-demo.html` | replaced by a per-product console demo on each product's "sample or demo" page |
| `examples/` | one quickstart per product; the whole-suite demos go |
| root and `wolf-pack` `CLAUDE.md` and `CONTRIBUTING.md` | one short root version of each |
| changelogs | frozen as history; each product starts its own |

## CI and releases

**Triggers**
- **Product workflow:** `products/<name>/**`, its own workflow file, and `.github/actions/**` it uses.
- **Core changes** (`core/**`): the core workflow and every product workflow.
- **Shared tooling** (`tools/**`): every product workflow.
- **Dependency files** (any `pyproject.toml`, lock or constraints file, Dockerfile base pins, Dependabot updates): the owning workflow plus every dependent of core when core's dependencies change.
- **Workflow changes:** that workflow runs on its own change.
- `pages.yml` runs on `site/**`, on product `docs/**`, and on its own change.

**Release ordering**
1. The core is released first.
2. A product release gate fails unless the product's declared core range includes a released core version.
3. Product CI runs against core from the same commit and against the lowest core version in its declared range.
4. A breaking core change is a core major release, and its dependents update their range in the same change.
5. Tags are per product: `core-v1.0.0`, `tls-v1.0.0`, `vpn-v1.0.0`, `readiness-v1.0.0`, `vault-v1.0.0`.

**Upgrade and rollback checks (per product, in the release gate)**
1. Install the previous release from its wheelhouse. For the first release, that's suite v0.3.1 and Wolf Pack 1.3.0.
2. Create state: a CA, certificates, archives, invitations, configs and a scan history.
3. Upgrade and run the journeys. All state must be readable.
4. Roll back to the previous release and confirm the state is still readable by it.
5. Where a new version writes something the old one can't read (for example a new format version), the check confirms that `docs/upgrade.md` documents the backup step. No new version rewrites old data in place.

## Stages

A stage is approved only on executed evidence. When the right environment isn't available locally, the stage is marked **pending** until CI run links are recorded in its report. A stage is never approved on tests that were only written. Each stage report lists changes, test results (failing first, then passing), evidence links and remaining gaps, and waits for the owner.

| Stage | Work | Evidence required |
|---|---|---|
| 0 | Environment findings, baseline record, golden fixtures, coverage map | `tools/baseline.md` committed; fixtures pass on old code |
| 1 | Core pure-Python mechanisms (`config`, `files`, `http`, `console`), then Acxelin Readiness: renames, pipeline, contract, CBOM import, console | core tests, contract, rejection, quality-gate, install and journey tests executed |
| 2 | Core `pki` verification, then Acxelin Q-Vault, with its console and export | install test, Vault-without-external-OpenSSL test, golden archives, rejection and journey tests executed |
| 3 | Core `openssl` and `pki` issuance and EST, then Acxelin TLS, with its console | TLS tests on OpenSSL 3.5, install and journey tests executed |
| 4 | Acxelin VPN, with its console, app, desktop app and export | unit tests; network-namespace, kill-switch migration and desktop tests executed in CI |
| 5 | Website and all Playwright journeys | Playwright and axe runs executed, locally or in CI |
| 6 | Spikes, cleanup, CI and final report | full boundary, branding and upgrade/rollback checks executed |

## Environment findings (to be established in Stage 0)

Revision 1 stated in advance what this environment can and can't verify. Stage 0 establishes each of these by running it, and records the result in `tools/baseline.md`. Stage evidence plans adapt to the findings.

1. Can OpenSSL 3.5.9 be built here, and do the TLS tests pass against it?
2. Is `cryptography>=49` installable, and does its bundled OpenSSL provide ML-KEM and ML-DSA?
3. Can strongSwan 6.1 be built, and can network namespaces be created here?
4. Can a Playwright browser be obtained here? (The first check showed its download host blocked.)
5. Can the result be pushed to GitHub to get CI evidence? (No credentials are expected; otherwise the owner pushes a branch.)
6. Do the existing Windows and macOS jobs run the TLS tests, or skip them?

## Owner decisions still needed

1. **License.** The repository has none, so no one is granted any rights to use the code. This is a legal choice. If it isn't decided, each package states "All rights reserved, Acxelin Quantum", and the gap stays on the production-readiness list.
2. **The proposed decisions** in the decision record: D5 details, D6a, D7 criteria, D9 to D13.
