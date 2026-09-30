# Product and market review

Reviewed 30 September 2026. Public product pages establish advertised capabilities, not verified security guarantees. This review does not represent hands-on access to competitors' authenticated products. No arbitrary rankings, projected Q-Day countdowns, or competitor artwork were adopted.

## Market map → engineering decisions

| Product / public source | Customer problem and advertised functionality | Useful workflow principle | PQCSuite equivalent, gap, and action |
|---|---|---|---|
| [PQCrypto PQCLens](https://pqcrypto.ai/pqclens/) | Cryptographic discovery, severity views, agents, migration recommendations and continuous assessment | Start with exposure and actionable priorities, then inspect evidence | Endpoint assessment and Wolf Pack already produce evidence. Added posture metrics, filters, prioritized endpoint actions, retained rescan targets, and local CBOM review alongside endpoint observations. Continuous endpoint scans exist; fleet agents do not. |
| [PQCrypto PQCvpn](https://pqcrypto.ai/pqcvpn/) | Advertises free Windows/macOS downloads and one-click connection; site-to-site offering is contact-led | Make installation and connection state obvious | PQCSuite provides administrator-managed IPsec and WireGuard, certificate authentication, rotation and native service installation. Added setup/diagnostic guidance and explicit telemetry boundaries. Signed desktop installers and a local connect UI remain absent. Public marketing is not evidence of its tunneling implementation. |
| [PQCrypto Q-Vault](https://pqcrypto.ai/qvault/) | Backup/recovery positioning with many storage destinations | Explain recovery and separate protection from storage | PQCSuite encrypts archives locally and lets customers sync them with their storage tooling. Added protect → verify → restore guidance, key-loss warning and issuer verification explanation. No cloud connector catalog was added. |
| [Tailscale installation documentation](https://tailscale.com/kb/1017/install) | Device installation, supported platforms, quickstart and administrative workflows | Give each platform an obvious entry point; diagnose setup separately | Existing native VPN adapters/services retained. Console now distinguishes gateway status from protection of the viewer's laptop. CLI diagnostics no longer claim a connection when no tunnel was activated. Enrollment still requires administrator-issued credentials. |
| [HashiCorp Vault documentation](https://developer.hashicorp.com/vault/docs) | Secret lifecycle, dynamic credentials, audit, identity, PKI, encryption services | Make permissions, lifecycle and trust boundaries explicit | PQCSuite Vault is an encrypted archive tool, not a dynamic-secrets server. Kept private keys out of browser/API flows; made recovery and unverified header metadata visible. Dynamic secrets/RBAC require a separate service architecture. |
| [AWS KMS](https://aws.amazon.com/kms/) | Key control, encryption, asymmetric signing and service integrations | State what keys control and which service performs each operation | Existing external signer/KMS integration remains. No claim that PQCSuite is a managed KMS or that key storage alone proves archive integrity. |
| [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) | Developer/team secrets and automation workflows | Guide the first useful action; distinguish human and machine access | Added beginner archive lifecycle guidance. Team secret sharing/credential injection is outside the archive model. |
| [Semgrep](https://semgrep.dev/) | SAST/SCA/secrets, prioritized findings, CI and remediation integrations | Let developers search findings, reach evidence, and export actionable results | Wolf Pack already has SARIF, CBOM, policy checks, baselines and remediation. Added offline search, priority filtering, sorting, linked evidence and CSV export. No general SAST feature expansion. |
| [Snyk](https://snyk.io/) | Developer security platform and IDE/CI integrations | Bring findings into existing engineering workflows | Existing SARIF/CI integrations retained; exports and evidence navigation improved. PQCSuite is not a replacement for general dependency vulnerability databases. |
| [SandboxAQ](https://www.sandboxaq.com/) | Broader AI/quantum enterprise solutions with cybersecurity positioning | Tie technical tooling to a concrete business outcome | Position readiness as inventory → observed exposure → migration action. The guessed specialized quantum-safe URL returned 404; no detailed scanner claims inferred from the homepage. |
| [Quantinuum](https://www.quantinuum.com/) | Quantum Origin random-number security alongside quantum computing products | Clearly distinguish randomness, encryption and migration | Adjacent technology; no QRNG dependency introduced. It does not substitute for cryptographic inventory or PQ protocol verification. |
| IBM Quantum Safe, Keyfactor, PQShield, CycloneDX CBOM, Teleport | Relevant candidates for PQ migration, certificate lifecycle, standard inventories and access management | Further specialized research is useful | Requested pages returned proxy 403 in this environment. Their detailed workflows and current pricing were not verified. CycloneDX 1.6 remains the existing machine-readable inventory format. |

The public PQCvpn page describes free downloads. Other pricing and enterprise packaging were not evaluated from authenticated offers. Marketing dashboards may contain examples; their numbers were never imported into PQCSuite.

## Expectations and opportunities

Expected: clear first action, trustworthy connection state, source evidence, prioritized migration actions, filtered findings, accessible exports and explicit recovery/trust boundaries. These guided this implementation.

High-value implemented opportunities: local code-inventory review beside network results; preserve offline reports with interactive investigation; distinguish unknown scan coverage from a protected system; separate PQ key exchange from PQ authentication; flag trust failures, legacy protocols and expiring certificates in endpoint details.

Low-value additions avoided: decorative topology without real relationships, fabricated history or aggregate readiness scores, competitor countdowns, an unrelated dashboard theme, and dozens of storage connectors duplicating existing sync tools. Unknown asset tiers remain labeled unknown instead of being presented as safe.

Opportunities to go further: signed per-platform VPN installers with enrollment; durable authenticated scan history and asset ownership; migration tickets linked to evidence and subsequent verification. These require operational design, signing/release infrastructure, or persistence/access-control decisions beyond changing the dashboard.

## Acxelin visual direction

[Acxelin Quantum](https://acxelinquantum.com/) was retrieved and its public content and style declarations reviewed. It uses Host Grotesk/Roboto, warm pale backgrounds, amber (#FFBF00), dark blue-gray text, restrained borders, clear section headings, and outcome-led language. Existing site, console and report primitives already follow that family; the new controls extend them. No competitor layouts, wording, logos or screenshots were copied. Remote hydrated animation rendering was unreliable locally; live interaction/responsiveness was not independently validated. Product browser checks cover the local implementation.

## Customer journeys and verification boundaries

| Tool | Improved journey | Evidence boundary |
|---|---|---|
| Readiness | Scan → see posture → filter classical/unknown assets → inspect evidence and recommendation → export | Numbers come from completed scans. SSH records advertised algorithms, not a completed authenticated handshake. A PQ exchange does not imply a PQ certificate. |
| Wolf Pack | Scan → search/sort/filter migration queue → open matching evidence/remediation → export filtered actions | HTML remains self-contained and usable without JavaScript. Risk priorities are scanner assessments. SARIF/CBOM/raw audit exports remain available. |
| Integrated investigation | Scan code → load cbom.json in readiness → inspect local priorities beside endpoint results | File is read in the browser, bounded to 10 MB/20,000 components, never uploaded, and cleared on sign out. No automatic mapping between code and endpoints is inferred. |
| Vault | Generate recipient → protect → inspect metadata → verify with key/trusted issuer → restore drill | Console lists headers only; private recipient keys remain on a trusted machine. Verification and restore are existing CLI operations. |
| VPN | Install prerequisites → receive gateway/certificate → connect process → check handshake/routes → optional startup service → disconnect | Gateway observation is not protection of the browser device. ML-KEM + PPK is reported only for established IPsec tunnels carrying those values. --no-apply never claims a tunnel was activated. |

A typical VPN client still has three setup prerequisites (Python/PQCSuite, WireGuard, administrator-issued endpoint/certificate), one connect invocation, a handshake/routes check, and disconnect. Native startup service installation already exists; it is optional. Site-to-site adds strongSwan and an administrator site profile. This pass does not deliver a one-download consumer VPN, a new privileged local API, or validated laptop connections. The separately referenced PQCvpn source was not found in the workspace; its public documentation was used instead.

## Final capability review and remaining gaps

Local investigation now meets common filtering, evidence, action and export expectations while retaining original cryptographic architecture and offline reports. The final comparison still identifies meaningful gaps: desktop packaging/enrollment, organization-wide ownership/RBAC, durable multi-user scan history, and automatic migration verification. Their absence is explicit; UI metrics do not simulate them.

Release limitations remain in [RELEASE-READINESS.md](RELEASE-READINESS.md): independent security review, privileged real VPN/platform validation, real cloud/managed Kubernetes deployments, and long-running production tests. There are no new runtime dependencies or cryptographic primitives in this pass.
