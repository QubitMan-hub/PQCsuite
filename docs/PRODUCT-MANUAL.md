# PQCSuite product manual

**Acxelin Quantum · Customer guide · 2 October 2026**

This guide explains what to use, how to start, what a successful result looks like, and what to do when something goes wrong. You do not need to understand cryptographic algorithms to follow the first steps. Running a production certificate authority or VPN does require a system administrator.

The release family covered here is **PQC Suite 0.4.1 and Wolf Pack 1.4.0**. Check the release links in [Installation and versions](#installation-and-versions) before downloading: a release is available only after its publication workflow succeeds. Old releases remain old snapshots.

## Contents

- [Choose the right product](#choose-the-right-product)
- [Use the website and console](#use-the-website-and-console)
- [Installation and versions](#installation-and-versions)
- [Your first useful result](#your-first-useful-result)
- [Wolf Pack: find cryptography in code](#wolf-pack-find-cryptography-in-code)
- [Readiness: understand exposure and next actions](#readiness-understand-exposure-and-next-actions)
- [TLS and mTLS: protect one service connection](#tls-and-mtls-protect-one-service-connection)
- [VPN: connect sites and remote computers](#vpn-connect-sites-and-remote-computers)
- [Vault: protect files and backups](#vault-protect-files-and-backups)
- [Verify a migration](#verify-a-migration)
- [Daily operation and recovery](#daily-operation-and-recovery)
- [Troubleshooting](#troubleshooting)
- [What the evidence does and does not prove](#what-the-evidence-does-and-does-not-prove)
- [Glossary and further help](#glossary-and-further-help)

## Choose the right product

There are five products to consider: four in PQC Suite, plus the separate Wolf Pack CBOM product. Code Crawler is the shared analysis engine, not a sixth tool customers must operate.

| Your question | Start here | What you get |
|---|---|---|
| Where does our code use cryptography? | Wolf Pack / WolfBOM | An inventory, supporting locations, supported callers and recommended changes |
| What is exposed, and what should we fix first? | Readiness | Repository priorities or live endpoint grades, with evidence and next steps |
| How do we protect a connection to an application or database? | TLS 1.3 + mTLS | An encrypted connection; mTLS also identifies the connecting client |
| How do we connect offices or staff laptops? | VPN | Protected network traffic between configured gateways or devices |
| How do we protect files and recover backups? | Vault | Encrypted archives, authorized recipients and integrity verification |

A sensible order is **scan → review → choose a change → deploy it → test it again**. You do not need to install every product to scan a repository. Scanning does not automatically rewrite code, upgrade a server, configure a VPN or encrypt files.

**Example: a small online shop.** Use Wolf Pack to find signing keys and encryption calls in its application; Readiness to assess its public API; TLS to protect service connections; VPN for approved staff access; Vault for database exports and backup files. Each protects a different part of the system.

## Use the website and console

The [public website](https://qubitman-hub.github.io/PQCsuite/) explains the products and offers examples. It is not a hosted control panel and does not scan or upload your repository. Use the product descriptions to choose a starting point, then follow the installation instructions below.

The [Wolf Pack page](https://qubitman-hub.github.io/PQCsuite/wolf-pack.html) is the separate scanner's product page. Its sample report shows one invented application; its sample dashboard combines three invented systems. They are generated scanner output, not your results and not a claim that those applications are deployed. The older animated page inside `wolf-pack/site/` is explicitly a historical demo.

The **local console** is the browser interface running on your own computer, normally at `http://127.0.0.1:8900`. Keep its terminal running. Open the address printed there and use the startup token to sign in. Treat that token like an administrator password; do not put it in a screenshot or support request. Stop the foreground process with Ctrl+C when finished.

The overview summarizes configured services. The TLS and certificate views show connected edges and certificate records. VPN shows configured gateway/tunnel information; it is not proof that this laptop's traffic is protected. Vault shows configured backup folders. Readiness combines repository results and separate endpoint scans. Wolf Pack has its own navigation group. A page with no configured service is not a product failure: connect that service's CA, metrics or folder first.

Use **Readiness → repository → Scan** for the simplest workflow. Keep advanced views closed until you need parser coverage, test-code findings, exported evidence or deployment verification. Owner labels and deadlines organize work; they do not create user accounts or restrict permissions. The console has one administrator token, with no team SSO or roles.

## Installation and versions

### Choose an installation

| Option | Use it for | Important distinction |
|---|---|---|
| PQC Suite release wheel | A fixed version of TLS, VPN, Vault, Readiness and console | Repository scanning also needs a compatible Wolf Pack installation |
| Wolf Pack release wheel | A fixed scanner version | JavaScript/TypeScript, Java and Go relationships need its `crawler` extra |
| Acxelin VPN installer | Laptops that only join the VPN (from 0.4.0) | See [Enroll and connect a laptop](#enroll-and-connect-a-laptop) |
| Current source checkout | Unreleased changes, development and testing | Record the Git commit; `main` can change |
| Published suite container | TLS/readiness demonstrations and configured services | The base image does not include repository scanning; persistent data needs mounted storage |
| Wolf Pack base container or base Action | Minimal scanner automation | Python relationships are included; JavaScript/TypeScript AST relationships need the optional parser installation |

[Suite releases](https://github.com/QubitMan-hub/PQCsuite/releases) and [Wolf Pack 1.4.0](https://github.com/QubitMan-hub/PQCsuite/releases/tag/wolf-pack-v1.4.0) are separate downloads. Suite 0.4.1 and Wolf Pack 1.4.0 are the aligned targets for this manual. Earlier releases predate the desktop app and installers; Wolf Pack 1.3.0 skipped files a project's `.gitignore` leaves out. A Git push does not modify an existing wheel or image. Use a specific container version for repeatable deployments rather than assuming `latest` is unchanged.

### Install a release

You need Python 3.11 or newer. Download both wheels, [pqcsuite-0.4.1-py3-none-any.whl](https://github.com/QubitMan-hub/PQCsuite/releases/download/v0.4.1/pqcsuite-0.4.1-py3-none-any.whl) and [wolfpack_cbom-1.4.0-py3-none-any.whl](https://github.com/QubitMan-hub/PQCsuite/releases/download/wolf-pack-v1.4.0/wolfpack_cbom-1.4.0-py3-none-any.whl), into a new folder. Open a terminal there and create a separate Python environment so the install does not touch your computer's other applications:

```sh
python -m venv .venv
```

Activate it in PowerShell with `.\.venv\Scripts\Activate.ps1`, or on macOS/Linux with `source .venv/bin/activate`. If your organization blocks PowerShell activation scripts, run `.\.venv\Scripts\python.exe` and `.\.venv\Scripts\pqcsuite.exe` directly instead. Then install and check:

```sh
python -m pip install 'wolfpack_cbom-1.4.0-py3-none-any.whl[crawler]' 'pqcsuite-0.4.1-py3-none-any.whl[scan-web]'
pqcsuite --version
pqcsuite doctor
```

Release assets include build provenance, which is not the same as a code signature; the Acxelin VPN installers are not code-signed yet. The base suite wheel does not bundle Wolf Pack.

### Install the current checkout

For unreleased changes. You need Git and Python 3.11 or newer. These commands install both packages in a separate Python environment so they do not replace your computer's other applications.

```sh
git clone https://github.com/QubitMan-hub/PQCsuite.git
cd PQCsuite
python -m venv .venv
```

On Windows, `py -3 -m venv .venv` is another way to select Python. Activate the environment in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```sh
source .venv/bin/activate
```

If your organization blocks PowerShell activation scripts, do not change its security policy just for this guide. Run `.\.venv\Scripts\python.exe` and `.\.venv\Scripts\pqcsuite.exe` directly instead. After activation, install and check:

```sh
python -m pip install './wolf-pack[crawler]' '.[scan-web]'
pqcsuite --version
wolfpack --version
pqcsuite doctor --json --product all
git rev-parse HEAD
```

Save the versions and commit with your assessment. `doctor` reports available capabilities and actions for missing prerequisites. A VPN warning on a laptop used only for code scanning is not a reason to abandon the repository scan. Use `pqcsuite doctor --json --product repository` to check just that workflow.

### Additional product prerequisites

Repository scanning and Vault do not require a running VPN. TLS and the VPN key-agreement service need **OpenSSL 3.5 or newer**. Use `doctor` to verify the actual loaded library, not only an unrelated command-line executable's version. Debian 13 containers provide a suitable library. On macOS, install Homebrew `openssl@3` and point `PQCSUITE_OPENSSL` at its `lib` folder if discovery fails. On Windows, install a compatible OpenSSL build and point `PQCSUITE_OPENSSL` at its DLL folder. The Python and library architectures must match.

Site-to-site VPN gateways require Linux, strongSwan with ML-KEM support, VICI, networking permissions and suitable kernel support. Install the suite's VPN extra with `python -m pip install 'pqcsuite-0.4.1-py3-none-any.whl[vpn]'` (or `'.[vpn]'` from a checkout). Remote laptops use the official WireGuard tools for their OS; installing Python alone does not install a tunnel driver. Real gateway addresses, certificates and routes must be supplied by the administrator.

### Update without losing work

Back up your private project workspace and security configuration first. In a source checkout, inspect `git status`; preserve local changes, then use `git pull --ff-only` and repeat the package installation. If Git reports divergence, resolve it rather than resetting away someone's work. Stop and restart your console after installing an update.

Workspace format 2 reads older format-1 project state. Older software cannot read format 2. Keep a pre-upgrade backup if rollback matters. Do not overwrite old security keys with new demo keys. Release upgrades do not automatically migrate a deployed gateway, replace certificates or restart every service.

## Your first useful result

Start with an example if you do not have a repository ready:

```sh
pqcsuite console --sample-project
```

Open the printed local address, sign in with the token, choose the example and scan. You should see cryptographic findings and recommended actions. This is an intentionally classical example, so warnings are expected. It is not a production deployment.

To use your own repository, replace `PATH_TO_REPOSITORY` with an existing folder on your computer. Keep quotation marks when a path contains spaces:

```sh
pqcsuite setup --project "PATH_TO_REPOSITORY" --out .pqcsuite/console.toml
pqcsuite console --config .pqcsuite/console.toml
```

Setup checks scanner prerequisites and creates a private local configuration. It refuses to overwrite an existing configuration. Reuse that file or choose a different output path. This command does not clone a remote URL or deploy a server.

For several repositories, put them under a parent folder approved by the administrator and run:

```sh
pqcsuite console --repositories "PATH_TO_PARENT_FOLDER"
```

Use Add repository to select an eligible folder. The console rejects paths outside the approved parent and symlink escapes. Add repository registers local code; it is not a GitHub OAuth integration.

A successful first run means the scan finishes, results appear, the folder name is correct, and saved results reopen when you restart the console. Review any storage warning before assuming the scan was saved. No findings is not the same as complete coverage: check language and parser gaps.

## Wolf Pack: find cryptography in code

**Purpose:** answer “where is cryptography used, what depends on it, and what should we review?” Wolf Pack inventories source, configurations, dependencies, keys/certificates and supported binary evidence. WolfBOM refers to the resulting cryptographic inventory/CBOM workflow.

**Use cases:** preparing a migration backlog, checking a new application before adoption, locating old signing/encryption code, reviewing a change in CI, and giving an auditor a supported inventory. Static scanning reads the target; it does not execute the project's code or install its dependencies.

### Scan and understand a result

Use the console workflow above, or generate offline output:

```sh
pqcsuite scan "PATH_TO_REPOSITORY" --out pqcsuite-out --open
```

For standalone inventory and CI use:

```sh
wolfpack scan "PATH_TO_REPOSITORY" -o wolfpack-out
```

Start with the migration queue, select a finding, inspect its source locations and supported callers, and check the suggested action. A useful relationship is “RSA → key creation function → callers → affected module → migration recommendation.” A supported caller relationship is static evidence; it is not proof the function runs in production.

| Result | How to interpret it |
|---|---|
| Critical/high/medium/low/ok | Review priority based on detected algorithms and context, not a universal business-risk score |
| Declared non-security MD5 | The code explicitly labels a cache/checksum use as non-security; verify that it truly is |
| Password hashing recommendation | Use a password-specific design such as Argon2id/scrypt; plain SHA-256 is not a password-storage fix |
| Candidate hybrid composition | Classical and PQ components appear together; this does not establish a secure combiner or deployed protection |
| Name/literal uncertainty | The algorithm was inferred; inspect the actual implementation and dynamic behavior |
| Test-only or declared support | Evidence exists, but may not represent production usage; advanced views retain it |
| Held: code that can never run | A Python line under `if False:` or after `return` is kept in `findings.json` but left out of the inventory |
| Security pattern (WPC001–WPC005) | Certificate checks switched off, a secret in code (its value is redacted), weak randomness for keys, an unsigned token, a fixed IV. Matched line by line; review each one |

Read the explanation, not only the color. SHA-1 inside HMAC/PBKDF2, cache fingerprints, compatibility tests and library registries need context. Do not delete supported behavior or replace a working protocol solely because an algorithm name appears.

### What gets saved

| File | What it is for |
|---|---|
| `report.html` | Offline human-readable findings and recommendations |
| `cbom.json` | CycloneDX cryptographic inventory for compatible tools |
| `wolfpack.sarif` | Findings for code-scanning tools |
| `findings.json` | Detector evidence and verdicts |
| `relationships.json` | Supported symbols/callers and incomplete coverage |
| `assessment.json` | Unified repository/readiness result from the suite scan |

The unified suite scan removes source snippets and raw source literals from exported evidence. Standalone Wolf Pack evidence can contain snippets; inspect exports before sharing them. Paths, system names and cryptographic inventory can still be sensitive in either workflow.

For Python, Wolf Pack also follows values through the code: a constant imported from a settings module, a class attribute, a `CONFIG["hash"]` entry, a default argument, or a value a caller passes into a function. A key size or hash chosen in one file and used in another is therefore reported where it is used, for example RSA-1024 rather than just RSA. A value that cannot be worked out from the code is left unresolved, never guessed. A local helper that merely borrows an algorithm's name (`def md5(text)` that formats text) is not counted.

Python, and with the optional parsers JavaScript/TypeScript, Java and Go, build relationships. In Java and Go a call counts only when the source states the type: the same class or package, an import, a typed field, parameter or local variable, or a Go receiver. Other supported languages retain crypto detectors without equivalent function graphs. Dynamic callbacks and aliases can remain unresolved. Production files consume graph budgets before tests. Console repeat scans reuse unchanged syntax, but still read files and recompute findings and cross-file relationships; not every repository scans faster.

If a limit is reached, open advanced coverage and inspect the named omissions. Narrow the scope or use standalone exclusions. Unified discovery is limited to 50,000 files/512 MB and a cooperative five-minute deadline; a parsing operation is not forcibly interrupted. The workspace is limited to 16 MB with a maximum 64 MB decompressed graph. Smaller scan scopes may be necessary even when disk space is available.

### Act and rescan

Assign an owner label and due date. If accepting a temporary exception, record a reason and expiry. Exceptions remain visible and do not change the underlying cryptographic risk. Make the change in your normal development workflow, run the application's own tests, then rescan.

“New” means newly observed relative to the prior assessment. “Persisting” means still observed. “Not observed” can mean fixed, removed, renamed, excluded or missed; it is not automatically a verified migration. Use [Verify a migration](#verify-a-migration) when a deployed endpoint also matters.

## Readiness: understand exposure and next actions

**Purpose:** bring evidence into a practical priority list. Repository readiness uses the shared Wolf Pack/Code Crawler scan. Live endpoint assessment asks what a network service offers from the scanner's location. They are different evidence sources, not interchangeable percentages.

**Use cases:** deciding which services to investigate first, comparing before/after endpoint posture, tracking repository remediation and preparing evidence for a security review.

### Scan a service you are authorized to test

Replace `api.example.com` with your service. The sample name is not a supplied demo endpoint.

```sh
pqcsuite readiness scan api.example.com:443 --html readiness.html --json readiness.json
```

For several targets, create `hosts.txt` with one hostname or `host:port` per line. Use `ssh://bastion.example.com:22` for SSH. A `#` begins a comment.

```sh
pqcsuite readiness scan hosts.txt --html readiness.html
```

| Grade | Plain-language meaning |
|---|---|
| A | PQ key exchange only was observed by the scanner |
| B | PQ is preferred, but classical fallback is still accepted |
| C | Classical key exchange only; investigate long-lived confidentiality needs |
| F | Unreachable or no TLS 1.3; read the reason before deciding which problem applies |

A report may be produced successfully while the command exits nonzero because action is needed. This is intentional for automation. An F grade is not necessarily a scanner crash. Behind a TLS-inspecting proxy, observations may describe the proxy rather than the destination; inspect issuer and trust warnings.

For broader configured evidence:

```sh
pqcsuite readiness report --ca pki --targets hosts.txt --backups backups --html evidence.html
```

To include cryptography found in your own code, add one or more Wolf Pack output folders. Each algorithm becomes a row that names the files and lines where it is used and, for Python and JavaScript/TypeScript, the functions that reach it; high-severity security patterns such as switched-off certificate checks become rows that need action:

```sh
wolfpack scan "PATH_TO_REPOSITORY" -o wolfpack-out
pqcsuite readiness report --targets hosts.txt --wolfpack wolfpack-out --html evidence.html
```

Use only paths that actually exist on this installation. NIST IR 8547/CNSA 2.0 mappings help organize evidence; they are not an independent certification or a legal compliance opinion. A backup header alone does not prove a successful restore.

## TLS and mTLS: protect one service connection

**Purpose:** put a protected connection in front of an application without rewriting that application's protocol. The “edge” accepts TLS and forwards traffic to the configured application. The edge-to-application hop must be protected separately when it crosses an untrusted network.

**TLS** proves the server's identity to a client. **Mutual TLS (mTLS)** also requires the client to prove its identity with a certificate. A **certificate authority (CA)** issues those identity documents. A **CRL** lists revoked certificates.

**Use cases:** service-to-service APIs, databases, MQTT, partner connections and private applications. Ordinary browsers may not accept ML-DSA certificates. Do not assume a strict PQ edge is a drop-in public browser website.

### A local learning exercise

Use an empty working directory and OpenSSL 3.5+. These are local test certificates, not a production CA design. The CA asks for a passphrase. The issued demonstration server key is stored locally without its own passphrase; keep the directory private and use encrypted service keys/managed secrets for deployment.

```sh
pqcsuite ca init --name "Manual Test Root" --dir manual-pki
pqcsuite ca issue server localhost --san 127.0.0.1 --dir manual-pki --out manual-server
pqcsuite tls serve --listen 127.0.0.1:8443 --cert manual-server/chain.pem --key manual-server/key.pem
```

Keep that terminal running. In another terminal with the same environment activated and working directory:

```sh
pqcsuite tls connect localhost:8443 --ca manual-pki/ca.crt --send hello
```

Success means the handshake reports its negotiated protection and the echo server returns `hello`. Ctrl+C stops the test server. This exercise protects one local connection; it is not a VPN or a deployed application.

### Put an actual application behind the edge

First start your application on local port 8080. Stop the test echo server if it still uses 8443. Then:

```sh
pqcsuite tls edge --listen 127.0.0.1:8443 --target 127.0.0.1:8080 --cert manual-server/chain.pem --key manual-server/key.pem
```

Use application-aware clients that trust your CA and support the selected certificate/key-exchange policy. A TLS handshake alone does not verify the application's database query or HTTP behavior. For nginx, PostgreSQL, pgvector and MQTT starting configurations, see `pqcsuite tls bundle --help` and [the edge configuration example](../examples/edge.toml).

For mTLS, issue client certificates, configure `require_client_cert`, a trusted CA and a current CRL, and supply the client's certificate/key. The edge can use `crl_url` to refresh revocations. Revocation normally affects new handshakes; do not assume every existing application session ends immediately. Use the documented service controls and verify traffic behavior.

| Policy | Customer decision |
|---|---|
| `strict` | Require the supported PQ policy; incompatible clients are refused |
| `transition` | Allow supported classical compatibility; record the fallback instead of calling it PQ-only |
| `cnsa2` | Use the stronger supported algorithm profile; still not a certification |

Do not switch off trust/hostname verification to “fix” a failed connection. Correct the trust anchor, name, clock, certificate or policy. Production use should separate offline root keys from issuing services and provide key backup, restricted file access and renewal monitoring.

## VPN: connect sites and remote computers

**Purpose:** protect traffic at the network level rather than just one application connection. There are two modes: site-to-site IPsec for Linux gateways, and WireGuard remote access for supported laptops. The remote-access pre-shared key comes from PQ-authenticated key agreement; it is not a claim that WireGuard itself uses ML-KEM natively.

**Use cases:** connecting a branch office to headquarters, or giving an approved laptop access to private applications. Phones and built-in operating-system IKEv2 clients are not supported as equivalent PQ clients.

### What the administrator must prepare

Before a customer connects, the administrator supplies a reachable gateway, routing/DNS plan, device certificate enrollment service and trusted CA fingerprint. Gateways need appropriate firewall rules, privileges and kernel capabilities. A copied example TOML with placeholder addresses is not a working network.

For site-to-site deployment, adapt [HQ](../examples/vpn-hq.toml) and [branch](../examples/vpn-branch.toml) configurations to your own networks, certificate paths, VICI address and peer identities. Install the dependencies and test both sides:

```sh
pqcsuite vpn check
pqcsuite vpn up --config examples/vpn-hq.toml
```

The second command is a long-running service. In another terminal:

```sh
pqcsuite vpn status --config examples/vpn-hq.toml --json
```

Success requires an installed encrypted child tunnel and actual application traffic across it, not only an IKE connection or a green control-plane indicator. Test a real request to an authorized private service and confirm encrypted tunnel counters/algorithms. Production service installation and network changes belong to the gateway administrator.

### Enroll and connect a laptop

**Administrator, once per person:** create an invitation. It holds the enrollment address, the CA fingerprint the laptop will trust, the gateway and a one-time token, so the person does not have to copy four values by hand. Add the name to the gateway's `users` list if it has one.

```sh
pqcsuite vpn invite alice --dir pki --enroll https://ca.example.com:9443 --gateway vpn.example.com:7443
```

Send `alice.pqcinvite` through a channel you trust (it is valid for 24 hours by default; `--hours` changes that).

**On the laptop:** install the official WireGuard client and the suite, open an administrator terminal (Windows: *Run as administrator*; Linux/macOS: `sudo`), and run:

```sh
pqcsuite vpn join alice.pqcinvite
```

It checks administrator rights and WireGuard first, asks you to choose a passphrase for the device key, enrolls (the key never leaves the laptop and is stored encrypted), and connects. The window then says where you stand:

| Message | Meaning |
|---|---|
| **Protected.** | The tunnel has completed a handshake using a key from the latest post-quantum key agreement. The next line names the TLS group, the gateway's certificate algorithm and how often the key is renewed. |
| **Connecting.** | Keys are agreed; the tunnel has not completed its first handshake yet. |
| **Not protected.** | The gateway could not be reached or refused this device; the reason follows. It retries on its own; with a full tunnel, internet traffic stays blocked meanwhile. |

**Prefer an app?** Install **Acxelin VPN** from the installer attached to each release. It carries everything it needs, including OpenSSL 3.5, so there is nothing else to install apart from WireGuard:

| System | File | How to install |
|---|---|---|
| Windows 10/11 (x64) | `Acxelin-VPN-VERSION-Setup.exe` | Run it and follow the steps. Leave **Show Acxelin VPN in the tray when I log in** ticked to start it at login. Install [WireGuard for Windows](https://www.wireguard.com/install/) too; the installer reminds you if it is missing. |
| macOS (Apple silicon) | `Acxelin-VPN-VERSION.dmg` | Open it and drag Acxelin VPN to Applications. Install WireGuard's tools with `brew install wireguard-tools`. |
| Ubuntu, Debian (x64) | `acxelin-vpn_VERSION_amd64.deb` | `sudo apt install ./acxelin-vpn_VERSION_amd64.deb` (this also installs WireGuard's tools). |

The installers are not code-signed yet, so the first launch shows a warning. On Windows, SmartScreen says "Windows protected your PC": choose **More info**, then **Run anyway**. On macOS, Gatekeeper refuses to open the app: open **System Settings > Privacy & Security** and choose **Open Anyway**. Check the file's SHA-256 against the release before you do either. Without the installer, `pip install "pqcsuite[desktop]"` and `pqcsuite vpn desktop --launcher` give you the same app.

Open it like any other app, from a normal account rather than an administrator terminal:

1. A shield appears in the system tray (Windows taskbar corner, macOS menu bar, Linux panel). Its colour says where you stand: green with a tick is **Protected**, amber is **Connecting**, red is **Not protected**, grey is disconnected or not set up. Hover over it for the words.
2. The Acxelin VPN window opens. Choose **Open invitation…**, pick the `.pqcinvite` file, choose a passphrase for this computer, and press **Connect**. The first time, your system asks for administrator approval (Windows UAC, the macOS password dialog, or the Linux administrator prompt), because the VPN changes this computer's network.
3. Next time, open Acxelin VPN and enter only the passphrase.

The tray icon's menu shows the current state and offers **Open Acxelin VPN**, **Disconnect**, **Start at login** and **Quit and disconnect**. With **Start at login** ticked (or `pqcsuite vpn desktop --start-at-login on`), the shield appears when you log in; it does not open the window or ask for administrator approval until you open it to connect, and connecting still needs your passphrase. The first time the window opens, a short guided tour points at each part; the **?** button replays it. Closing the window leaves the VPN connected; **Quit and disconnect** takes it down and closes the tray. Only the background VPN service runs with administrator rights; the tray and the window run as you. The window opens as an app window in Microsoft Edge or Google Chrome when one is installed (otherwise in your default browser), uses its own browser profile, and never offers to save your passphrase. On Linux, the tray menu needs a desktop with AppIndicator support (GNOME with its AppIndicator extension, KDE, and most others); without it, clicking the shield opens the window. The Linux package always works this way: its shield opens the window and has no menu, and Disconnect is in the window; a `pip install` on a desktop with AppIndicator gets the full menu. `pqcsuite vpn desktop --remove-launcher` removes the shortcut.

**Prefer a browser?** `pqcsuite vpn app` (in an administrator terminal) serves the same window and prints its address; this needs no extra install. Running it again while it is running opens the same window. Both the app and the browser window are served only on 127.0.0.1. They open only from a one-time address (from the tray, or printed by the command) that cannot be used twice, and they refuse other host names and requests from other websites. Closing the page does not disconnect; Ctrl+C in the terminal does.

From another terminal, `pqcsuite vpn status` gives the same answer (add `--details` for algorithms, handshake and key timing, or `--json`). It exits 0 only when protected. Next time, run `pqcsuite vpn join alice.pqcinvite` again: the laptop is already enrolled, so it only asks for the passphrase and connects. Ctrl+C or `pqcsuite vpn disconnect` (same privileges) takes the tunnel down and lifts the kill switch.

The remote-access pre-shared key comes from post-quantum TLS key agreement and is mixed into WireGuard; WireGuard's own handshake stays classical. `pqcsuite vpn connect GATEWAY --cert-dir FOLDER` and `pqcsuite ca enroll --guide` remain available for administrators who enroll devices themselves. `--no-apply` and `--once` are checks, not an active tunnel. The built-in `pqcsuite vpn install` cannot unlock an encrypted device key; use interactive join or connect, or an administrator-managed service with `--key-passphrase-env` and protected secret injection.

### Split tunnel, full tunnel and recovery

A split tunnel protects configured private routes; unrelated internet traffic may use the normal network. Full tunnel routes internet traffic through the gateway and applies the supported kill-switch behavior. A kill switch attempts to stop traffic from escaping when protection fails. It is not identical on all platforms: the Windows block follows tunnel lifetime and can lift during tunnel recreation, while Linux/macOS rules are designed to remain during recovery.

Before broad rollout, test sleep/wake, Wi-Fi changes, gateway restart, DNS/IPv6, revocation and kill switches on your actual laptop model/OS. CI tunnel tests are not a substitute for those conditions. Keep an administrator recovery route when testing network changes, and use the [pilot protocol](PILOT.md) to record results.

## Vault: protect files and backups

**Purpose:** turn files or directories into encrypted `.pqv` archives that only intended recipients can open. It is not a password manager or a live secret-injection service. A public recipient key can be shared; a private `.key` file and its passphrase must stay private.

**Use cases:** database export files, document archives, backup transfers and giving an auditor access to a copy. For a running database, create a consistent database-native dump first. Encrypting arbitrary changing database files does not make a valid backup.

### First file, with a recovery recipient

Use an empty directory. Create a small `notes.txt` file with harmless test text. Generate two keys and choose strong passphrases when prompted:

```sh
pqcsuite vault keygen owner
pqcsuite vault keygen recovery
pqcsuite vault encrypt notes.txt -o notes.pqv -r owner.pub -r recovery.pub
pqcsuite vault verify notes.pqv --key recovery.key
pqcsuite vault decrypt notes.pqv --key owner.key -o restored
```

Success means verification completes and `restored/notes.txt` matches the original. Verification writes no restored content. Decryption restores the original name inside the destination folder. Use a new destination directory; do not experiment against valuable originals.

Keep the recovery key/passphrase offline and separate from the routine key after this exercise. Anyone who loses every usable private key or passphrase loses access permanently. PQCSuite cannot reset that access for you. A second copy of the same private key is not an independent recovery recipient.

### Backups, retention and sharing

For an existing `documents` directory:

```sh
pqcsuite vault backup documents --to backups -r owner.pub -r recovery.pub
pqcsuite doctor --backups backups
```

The command prints the timestamped archive path. Use that actual path with `vault verify` and the recovery key, then rehearse restoring to a new directory. Header/readability diagnostics are useful but do not replace authenticated verification or a restore drill. `--keep N` deletes older archives according to retention; decide retention only after testing recovery and external storage copies.

To add a recipient to an archive you can already open:

```sh
pqcsuite vault keygen auditor
pqcsuite vault share notes.pqv --key owner.key -r auditor.pub
```

Sharing adds access; it cannot revoke access to copies already distributed. For a compromised recipient, protect future archives with new authorized recipients and assess previously shared copies. Use `vault inspect` for header information, remembering that inspection alone does not authenticate every claimed property.

### Signatures and trusted senders

Encryption protects contents; a signature can identify who produced them. With an appropriately issued ML-DSA signing identity, use `--sign-cert` and `--sign-key` when encrypting/backing up. Recipients can require a signature, CA trust, expected signer and CRL during verify/decrypt. See `pqcsuite vault verify --help` for these options.

Archive/certificate cryptographic signatures remain supported. The decision not to provide native installer code signing does not remove those security features. Store archived signing/trust evidence according to your retention policy so a later restore can be assessed correctly.

## Verify a migration

There are three separate questions:

1. Did the source finding change? Rescan the same approved repository and inspect new/persisting/not-observed findings and coverage.
2. Did the intended release reach the intended service? Record release identity and deployment evidence from your own build/deployment process.
3. Can the service establish the expected protected connection? Use a configured endpoint observation and application tests.

To use the console's advanced verification, the administrator must configure a persistent workspace, CA directory with its current issuer CRL, and approved `scan_targets`. A scan target is a service you are authorized to contact, not an arbitrary URL submitted by a browser user. The deployment verification feature currently handles TLS endpoints.

After a completed repository scan, open advanced deployment verification. Choose the finding and approved endpoint. Enter the release identifier, why that finding is associated with the service, and the expected certificate's SHA-256 fingerprint from trusted deployment records. Do not copy an untrusted observed fingerprint merely to make the check pass. Run verification.

Success means one strict, CA/hostname-verified PQ connection matched the pinned certificate and passed the current issuer CRL check. The source-to-release association is still operator supplied. The check does not prove every route/client is protected, that all fallback is refused, or that the application behaves correctly. A failed observation is retained; it is not relabeled as verified. Observations expire after 24 hours and must be checked again after a source rescan. Certificate rotation may require updating the expected fingerprint using trusted records.

**Example:** a source scan no longer observes RSA after a library migration. That is source progress. The deployed API might still run an older build. Record the deployed release, probe its expected endpoint, and run its real application tests before claiming the migration is complete.

## Daily operation and recovery

| When | What to do | What to retain |
|---|---|---|
| After a code/dependency change | Rescan, compare coverage and review new findings | Commit, configuration, assessment and reviewed exceptions |
| After deployment or certificate rotation | Recheck endpoint evidence and actual application requests | Release ID, expected certificate identity, observation time and test result |
| Regularly | Review overdue findings, expiring exceptions/certificates and CRL freshness | Owner decisions and change history |
| After backups | Verify and periodically restore using the recovery key | Restore result, archive identity and secure recovery instructions |
| After a VPN/client upgrade | Exercise traffic, reconnect, DNS and kill-switch conditions | OS/version, route configuration and observed behavior |
| Before software upgrades | Back up project state and security configuration | Old version/commit and rollback-compatible state |

`pqcsuite ca maintain --dir pki` refreshes CRLs and renews certificates nearing expiry; run it under an appropriate scheduled service with protected credentials. Verify that consumers load refreshed certificates/CRLs. A successful maintenance command on one machine does not establish that every remote gateway has fetched the new CRL.

If a device key is exposed, identify the certificate with `pqcsuite ca list --dir pki`, revoke its serial with `pqcsuite ca revoke SERIAL --dir pki --reason keyCompromise`, distribute the CRL, and verify refusal. Replace the compromised identity. For a CA compromise, stop ordinary issuance and follow the [threat-model recovery runbooks](THREAT-MODEL.md); revoking a single client is not sufficient.

Keep `.pqcsuite/projects.json` (or the configured state path), console audit records and relevant exports in protected storage. Graph compression saves space; it is not encryption. The workspace contains findings, local paths and deployment metadata. Keep private keys, passphrases and enrollment tokens out of Git. Do not delete a CA, device folder or recovery key simply to clear a dashboard error.

## Troubleshooting

| What you see | Likely cause | Next action |
|---|---|---|
| `pqcsuite` is not found | Wrong Python environment or PATH | Activate the environment or use its full executable path; reinstall in that environment |
| Repository scanner unavailable | Suite installed without compatible Wolf Pack | Install both packages and scanning extras from the same checkout/release family |
| JavaScript/TypeScript, Java or Go relationships unavailable | Optional parser extra missing | Install Wolf Pack's `crawler` extra; rerun the scan and inspect coverage |
| Setup refuses an existing file | It is preserving your configuration | Use that config or choose a new output filename |
| Add repository rejects a folder | Outside approved parent, symlink or unavailable path | Ask the local administrator to configure the intended parent; do not weaken containment checks |
| Scan stops or cannot save | Discovery/time/graph/workspace limit, permissions or disk problem | Read the exact warning, narrow scope and export available results; preserve old state |
| Finding remains after editing | Other locations still exist, wrong repository selected, or change not deployed | Inspect locations, commit, scope and selected project; source scan and deployment are separate |
| TLS handshake fails | Incompatible OpenSSL/policy, wrong CA/name, expired certificate or CRL | Run product diagnostics; correct trust/configuration and renew records |
| Endpoint verification fails after renewal | Expected pin changed or CRL is unavailable/stale | Confirm the new certificate through deployment records and update current issuer revocation evidence |
| VPN says connected but application fails | Routes/DNS/firewall, missing encrypted child or unreachable application | Check actual protected traffic and installed child/tunnel state; inspect both gateway and client |
| Console cannot contact a service | Metrics/CA/VICI path missing or inaccessible | Configure the actual service address/path and permissions; do not assume discovery is automatic |
| Console requests authentication again | Restarted process, token change or expired browser session | Use the current startup token locally; do not disable authentication |
| Vault cannot open an archive | Wrong recipient/passphrase, corrupted data or failed trust requirement | Try the authorized recovery identity; retain the original and investigate the exact error |
| Grades look unexpectedly poor behind a proxy | TLS inspection or a network error | Inspect issuer/trust details and scan from an appropriate authorized network |

For support, share the version/commit, OS, relevant redacted command/configuration, exact error and whether it is reproducible on the supplied demo. Remove tokens, passphrases, private keys and customer source. Do not suppress verification or use a trust-all setting just to obtain a green status.

## What the evidence does and does not prove

All products need application-specific validation. Passing automated tests or using PQ algorithms is not a blanket “secure” or “production-ready” certificate. The suite is not independently audited or FIPS 140-3 validated. Real cloud account deployments, managed Kubernetes, long-duration production loads and physical laptop sleep/roaming conditions need their own evidence. The documented three-customer pilot protocol is a plan, not three completed pilots.

Team SSO/roles and native signed installers are outside current scope. Static relationships for C, C#, Rust and Kotlin, general dynamic-dispatch resolution, hard scan-process isolation and independent source-to-deployment provenance remain gaps. The product preserves explicit uncertainty instead of treating unsupported evidence as a clean bill of health.

No single score replaces judgment: use the detected behavior, data lifetime, deployment context, coverage and real tests together. Verify important fixes with your application's tests and an appropriate reviewer.

## Glossary and further help

| Term | Simple meaning |
|---|---|
| PQC / post-quantum | Cryptographic methods designed to resist known quantum attacks |
| Hybrid | Combines classical and PQ components; security depends on the construction |
| CBOM | An inventory of cryptography, like an ingredient list for cryptographic use |
| AST | Parsed code structure that helps identify functions/calls rather than just matching text |
| CA / certificate | Issuer / signed identity document for a server or device |
| Private key / public key | Secret capability / shareable counterpart; never share the private key |
| CRL | Issuer's signed list of revoked certificates |
| Fingerprint | A digest used to compare the exact expected certificate |
| TLS / mTLS | Protected service connection / protected connection with both sides authenticated |
| Endpoint | The hostname/address and port of a service |
| Recovery recipient | A separate key authorized to open an encrypted backup if routine access is lost |
| Static evidence | What can be established by reading files, without running the target application |

Use `pqcsuite --help`, then the relevant command's `--help` for exact options. See the [README](../README.md), [Code Crawler limits](CODE-CRAWLER.md), [release gates](RELEASE-READINESS.md), [pilot instructions](PILOT.md), [security reporting](../SECURITY.md) and [Wolf Pack guide](../wolf-pack/README.md).

For guided stories using temporary data, run `python examples/clinic_demo.py --auto` or `python examples/bank_demo.py --auto` from an installed checkout. The privileged Linux VPN demo needs its documented networking prerequisites. These demos exercise real operations on example data; they do not configure your production organization.
