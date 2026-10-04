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

Subsequent milestones added durable local scan history, ownership labels, guided certificate enrollment and endpoint observations. Installer signing and team access are excluded from the current scope; see the current milestone below for remaining gaps.

## Acxelin visual direction

[Acxelin Quantum](https://acxelinquantum.com/) was retrieved and its public content and style declarations reviewed. It uses Host Grotesk/Roboto, warm pale backgrounds, amber (#FFBF00), dark blue-gray text, restrained borders, clear section headings, and outcome-led language. Existing site, console and report primitives already follow that family; the new controls extend them. No competitor layouts, wording, logos or screenshots were copied. Remote hydrated animation rendering was unreliable locally; live interaction/responsiveness was not independently validated. Product browser checks cover the local implementation.

## Customer journeys and verification boundaries

| Tool | Improved journey | Evidence boundary |
|---|---|---|
| Readiness | Scan → see posture → filter classical/unknown assets → inspect evidence and recommendation → export | Numbers come from completed scans. SSH records advertised algorithms, not a completed authenticated handshake. A PQ exchange does not imply a PQ certificate. |
| Wolf Pack | Scan → search/sort/filter migration queue → open matching evidence/remediation → export filtered actions | HTML remains self-contained and usable without JavaScript. Risk priorities are scanner assessments. SARIF/CBOM/raw audit exports remain available. |
| Integrated investigation | Add approved repository → Scan → Readiness priorities → functions/callers → recommended action | Shared Code Crawler/Wolf Pack evidence feeds Readiness automatically. Manual CBOM import remains an advanced, browser-local option (10 MB/20,000 components). Source and endpoint evidence remain distinct; runtime deployment mapping is not inferred. |
| Vault | Generate recipient → protect → inspect metadata → verify with key/trusted issuer → restore drill | Console lists headers only; private recipient keys remain on a trusted machine. Verification and restore are existing CLI operations. |
| VPN | Install prerequisites → receive gateway/certificate → connect process → check handshake/routes → optional startup service → disconnect | Gateway observation is not protection of the browser device. ML-KEM + PPK is reported only for established IPsec tunnels carrying those values. --no-apply never claims a tunnel was activated. |

A typical VPN client still has three setup prerequisites (Python/PQCSuite, WireGuard, administrator-issued endpoint/certificate), one connect invocation, a handshake/routes check, and disconnect. Native startup service installation already exists; it is optional. Site-to-site adds strongSwan and an administrator site profile. This pass does not deliver a one-download consumer VPN, a new privileged local API, or validated laptop connections. The separately referenced PQCvpn source was not found in the workspace; its public documentation was used instead.

## Final capability review and remaining gaps

Local investigation now meets common filtering, evidence, action and export expectations while retaining original cryptographic architecture and offline reports. The final comparison still identifies meaningful gaps: desktop packaging/enrollment, organization-wide ownership/RBAC, durable multi-user scan history, and automatic migration verification. Their absence is explicit; UI metrics do not simulate them.

Release limitations remain in [RELEASE-READINESS.md](RELEASE-READINESS.md): independent security review, privileged real VPN/platform validation, real cloud/managed Kubernetes deployments, and long-running production tests. Base runtime dependencies remain unchanged; optional JavaScript/TypeScript relationships use three Tree-sitter packages. No new cryptographic primitives were introduced.


## Final audit — 30 September 2026

The audit starts from `3366c37` and checks the earlier product changes as well as the final release-gate fixes. Local results do not certify production readiness or replace the required remote CI/platform gates.

| Before | Now |
|---|---|
| Separate code scan, inventory and manual readiness review | One approved-repository scan produces shared relationship, inventory and readiness evidence; advanced manual import remains available |
| Release evidence and some CI jobs use unittest discovery, silently omitting function-style crawler tests | Shared pytest runner in release evidence, Linux integration and macOS jobs; regression tests prove failing function-style tests and empty suites block evidence |
| Green remote jobs can mask failed/missing supplied local evidence | Release report requires a successful local test process as well as every remote gate |
| Wolf Pack-only changes skip suite integration CI; parser extras absent from dependency audit | Runtime scanner changes trigger suite CI, and optional dependencies come directly from the package manifests for auditing |
| Handoff mixes obsolete Python-only/single-writer statements with current behavior | One current handoff, consistent developer commands and a repository map; default scan output ignored |

Repository cleanup preserves all supported detectors, independent package entry points, offline fonts/licenses and evaluation truth. An exact-content comparison of all 383 tracked files found only required entry-point and font/license copies. Static unused-symbol analysis found only required context-manager exception parameters. No defensible large source-file reduction was found; capabilities added in the preceding implementation increased source size. Removing these files would sacrifice supported installs, evidence or coverage. The final audit adds no production runtime module or dependency.

Fresh public-page checks: [PQCLens](https://pqcrypto.ai/pqclens/) advertises continuous agents and migration priorities; [Tailscale quickstart](https://tailscale.com/kb/1017/install) documents device installation and identity/access workflows; [Vault](https://developer.hashicorp.com/vault/docs) documents dynamic credentials, identity and audit; [Semgrep Code](https://semgrep.dev/docs/semgrep-code/overview) documents local/CI scans, data-flow rules and triage. PQCSuite supports local evidence, prioritization, export and CI, but lacks comparable managed fleet enrollment/ownership, continuous agent inventory and broader cross-language analysis. Its archive Vault is not a dynamic-secret service. IBM's requested Explorer URL resolved to a general product directory; no specialized claims were inferred. These are public documentation comparisons, not authenticated product tests.

Remaining meaningful gaps: additional language relationship adapters, runtime-to-deployment attribution, whole-project quotas/cancellation, durable multi-user history/RBAC, signed desktop installers/enrollment and externally reviewed crypto protocols. Real privileged VPNs, Windows/macOS laptops, managed Kubernetes/cloud accounts and days-long load remain separate validation requirements. The default container supplies the base TLS/Vault/VPN/readiness runtime; repository scanning requires the documented optional packages installed from this checkout until Wolf Pack 1.3.0 is published.


Final validation (completed 1 October 2026):

- Shared release runner: **361 passed, 12 skipped, 4,446 subtests passed**. JUnit evidence includes subtests (4,819 total records, 12 skipped, zero failures); it is not a claim of 4,819 independent tests. New gate regressions cover failing function-style tests, empty suites and missing/failed evidence with green CI.
- Browser: **35 passed** using installed Chromium, covering live console APIs, certificate issue/revoke, repository onboarding, Python/TypeScript evidence, Readiness, exports, responsive layouts and accessibility.
- Additional Debian 13 container: **17 real-service tests passed, no skips**, exercising nginx, PostgreSQL, Redis, MQTT, OpenSSH and scan/scenario workflows that required unavailable host services. Privileged VPN/dataplane and native laptop checks remain unrun here.
- Ruff, basic mypy (60 source files), compilation, dependency consistency, doctor, workflow checks by review, both wheel builds and clean installs passed. Base scans report missing web parsers; installing the extra enables real TypeScript relationships. Runtime/VPN/KMS/parser dependency audit found no known vulnerabilities.
- All seven pinned public repositories rescanned successfully without executing their code. Full development-corpus/ablation regression, production CBOM baseline, official CycloneDX schema (zero errors), whole-repository scan, sample regeneration and repeatable website publishing passed. Classifier results unchanged; this is not independent precision/recall evidence.
- TLS tour, clinic/bank demos and the production-container tour passed. Container build initially failed on proxy CA trust; a temporary external Dockerfile supplied the host CA bundle as a BuildKit secret without disabling TLS verification or changing the shipped Dockerfile. The test-only integration image restored pip through `python -m ensurepip` and used `python -m pip`.
- One-minute soak: 6,094 successful connections, zero failures, 3/3 revoked certificates refused; no resource-growth problems detected. Release benchmark: 200 hybrid handshakes, 2.27 ms median; 32-client/10-second loopback load, 1,042 connections/s, zero errors. These are local indicative measurements, not production sizing or days-long reliability.

No product regression was reproduced. The defects fixed were incomplete release/CI discovery, an insufficient local-evidence release check, missing integration triggers/parser dependency audits and stale guidance. Remote CI success on the final pushed commit is not asserted. No PR, release publication, force push or protection bypass is part of this audit.


## Follow-up: customer migration workspace — 1 October 2026

Implemented the local remediation loop: sample/approved repository → scan → assign owner/deadline or expiring exception → edit → rescan → review changed evidence. Full latest assessments and recent comparisons now survive restart; all previous detector and endpoint workflows remain. The website exposes current language coverage and a sample assessment. Scan cancellation and file/byte/time budgets preserve earlier results.

This historical milestone addressed local adoption, persistence and action tracking. The subsequent accuracy milestone adds syntax reuse and guided setup. Java/Go relationship adapters and an independent audit remain open; team access and native installer signing are excluded. Real deployment validation requires the respective platforms/accounts. Static absence remains labeled “not observed,” not “verified secure.”

The installed-wheel customer test exercised actual console startup, sample creation, scan, owner assignment, process restart, source edit and rescan. The persisted assignment and previous evidence survived. Backend regressions cover denied scope changes/symlinks, invalid exception/owner/date input, bounded private state, concurrent updates and cancellation/quotas without overwriting completed evidence. Browser regressions cover remediation validation, escaping, rescan persistence and accessibility. A newly introduced website code-block contrast issue was caught and corrected; the sample-link assertion was updated for the new CTA.


## Five-product verification — 1 October 2026

The owner paused roadmap expansion and requested verification of the five existing products. Checked from `1d42417`, followed by the VPN correction below.

| Product | Executed checks | Result and boundary |
|---|---|---|
| TLS / mTLS | Certificate/policy/revocation tests, real nginx and service scenarios, CLI tour, clinic/bank demos, one-minute revocation soak | Passed. Soak: 5,907 connections, zero failures, 3/3 revocations enforced. Not a long-duration production test. |
| VPN | Protocol/controller/platform regression tests; real strongSwan 6.1.0 hybrid ML-KEM + PPK key agreement, rotation and revocation; userspace WireGuard split-tunnel traffic, PSK rotation and revocation | Passed for these paths. Real IPsec encrypted traffic and WireGuard full-tunnel recovery/kill-switch attempts remain blocked by this kernel, as detailed below. Native Windows/macOS not run here. |
| Vault | Encryption/decryption, recipient/signature handling, tamper refusal and real backup/restore scenarios | Passed. Live external KMS/HSM accounts are not validated by local tests. |
| Readiness | Real TLS/SSH probes, service scenarios, reports/exports, console error paths and persisted repository remediation | Passed. Endpoint and static source observations remain distinct evidence. |
| Wolf Pack / Code Crawler | All corpus/ablation configurations, seven pinned public static scans, production CBOM baseline, official schema, console callers/exports and installed-package workflows | Passed. Unsupported relationships and unresolved dynamic dispatch remain explicit. |

Final shared Python suite: **369 passed, 12 prerequisite skips, 4,462 subtests passed**. Browser suite: **37 passed**. Additional current-code Debian service/container checks: **78 passed, 3 VPN prerequisite skips, 3,574 subtests passed**. Updated real IPsec control-plane tests: **10 passed**. The WireGuard run exercised 12 passing tests, including real split-tunnel traffic; the separate full-tunnel test failed on the unavailable IPv6 firewall capability and was not counted as passing. These suites overlap and their counts must not be added into a unique-test total. Lint, basic mypy (60 files), compilation, dependency audit, package builds, CBOM baseline/schema and customer restart workflow passed.

The deep VPN test exposed a product defect: an established IKE session without an installed child SA could count as protected, and the initiator could wait for the normal rotation interval before retrying. The controller, metrics and overview now share a predicate requiring an installed encrypted child plus ML-KEM/PPK; the VPN page shows “IKE only · no encrypted tunnel,” and missing children trigger retry. Regression tests prove missing/installing/deleting children and missing PQ negotiation are not protected. The real dataplane test now waits for installed children before sending test traffic, so an unencrypted ping cannot establish success.

Two environment failures were preserved, not bypassed: strongSwan negotiated the expected IKE algorithms but the kernel returned “Requested type not found” while installing IPsec SAs; WireGuard's full-tunnel setup could not load the IPv6 `addrtype` firewall matcher. The container also lacked native WireGuard devices, so supported userspace WireGuard was used with an isolated TUN device. Its initial read-only forwarding setting was corrected only inside the test container. No crypto checks, IPv6 protection, kill-switch rules or failing assertions were disabled. A complete VPN dataplane sign-off still requires a Linux kernel with the required XFRM/ESP and firewall support plus the native laptop checks in the release gates.


## Reliability recheck — 1 October 2026

Rechecked from `2ae48bb`, preserving the pause on broader roadmap work.

| Before | After |
|---|---|
| Broken VICI sockets stayed attached; a status-query exception could stop the initiator thread | Transport failures discard the session; the next request reconnects, and status failures use bounded retry backoff. Uncertain commands are not automatically replayed. |
| A restarted responder daemon lost its connection configuration | Key agreement reinstalls responder configuration with the required wildcard PPK selector. A real strongSwan restart test confirms recovery without restarting controllers. |
| An expired or future-dated CA could receive only a warning | Invalid certificate dates fail deployment preflight. |
| Backup headers could imply that two keys actually opened an archive | Checks describe unverified recipient metadata and require authenticated verification plus a restore drill. Header checks alone deliberately retain a warning. |

Validation: **374 Python tests passed, 13 prerequisite skips, 4,274 subtests passed**; **37 browser tests passed**; **73 real-service/container tests passed, 3,570 subtests passed**, including real strongSwan restart recovery. Counts overlap. Ruff and basic mypy (60 files) passed. Both production wheels built and installed into a separate environment; sample scan, owner assignment, restart, source edit and rescan preserved remediation evidence. CLI tour and clinic/bank workflows passed. One-minute TLS soak: **5,583 connections, zero failures, 3/3 revocations enforced**. All 20 scanner corpus/ablation rows were unchanged; the production CBOM baseline gate and official schema validation passed.

This pass adds no runtime dependency or production module. Changes reuse the existing VICI adapter, retry loop and preflight checks. Earlier VPN kernel limitations remain: the real restart test validates the IKE/control plane here, not encrypted IPsec traffic. Complete IPsec dataplane, WireGuard full-tunnel and native Windows/macOS validation still require suitable hosts. External KMS/HSM, managed deployments, independent review and long-duration production testing remain outside this local evidence.


## Remote platform validation — 1 October 2026

Inspected the actual [CI run for `afa39fa`](https://github.com/QubitMan-hub/PQCsuite/actions/runs/36836106173), including individual test logs. The Linux VPN job passed **34 IPsec/TLS tests** with `PQCSUITE_VPN_DATAPLANE=1`, including encrypted traffic and responder daemon restart recovery, followed by **13 WireGuard tests** including split-tunnel traffic, full-tunnel recovery and the kill switch. This resolves the earlier cloud-workspace kernel limitation for those tested paths. The Windows VPN job passed **16 tests**, including native tunnel creation, key rotation and removal. Kubernetes kind integration and image provisioning also passed.

That run was not wholly green: macOS exposed inconsistent resolved/unresolved source-path comparison; an isolated release-runner test unnecessarily required the host's PQ TLS library; Debian integration lacked Git; and the image vulnerability gate found patched OpenSSL/PCRE2 packages absent from the pinned base. Corrections resolve both publisher paths, isolate only the unit test's TLS version reporting, install Git in the integration job, and apply Debian package updates during image builds. Matrix jobs no longer cancel sibling platforms on the first failure. No production TLS requirement, security assertion or vulnerability gate was weakened.

Local regression verification after these corrections: **375 passed, 13 prerequisite skips, 4,207 subtests passed**; Ruff and repeat website publishing passed. The source changes are in `b2e5b3e`; [its remote CI](https://github.com/QubitMan-hub/PQCsuite/actions/runs/36837262594) is the authoritative platform result.

The updated local image installs `libssl3t64`/`openssl` **3.5.7-1~deb13u3** and `libpcre2-8-0` **10.46-1~deb13u3** and passes the existing Trivy fixable HIGH/CRITICAL gate, doctor and CLI tour. Findings with no available distribution fix remain subject to the existing reporting policy; this is not a claim of zero vulnerabilities.

Hosted native VPN checks establish configuration acceptance, rotation and removal. They do not establish end-to-end Windows/macOS traffic, full-tunnel kill-switch behavior, sleep/wake or roaming on customer laptops. Those scenarios need dedicated machines and a peer gateway. Real cloud accounts, managed Kubernetes, independent external security review and days-long production testing remain separate requirements.


The corrected run passed macOS (373 tests plus the native WireGuard test), but Windows Python 3.11 exposed a concurrent CA update failure: `msvcrt.LK_LOCK` exhausts ten retries under contention. The shared state-lock implementation now waits using nonblocking acquisition and retries only contention errors, matching POSIX blocking behavior. Reentrant ownership is recorded only after successful acquisition; otherwise an error or interruption could leave a false ownership marker and bypass a subsequent lock. Regression tests exercise both failures and contention without weakening the existing six-process issuance/revocation test. Final platform results must include that fix before this pass can be considered complete.


[All 15 CI jobs on `048c03e`](https://github.com/QubitMan-hub/PQCsuite/actions/runs/36837393428) and its CodeQL jobs passed, confirming the earlier platform/environment/image corrections. The subsequent Windows lock fix is deliberately retained despite that green run because the preceding run demonstrated intermittent contention failure. Local tests for the lock fix passed; its remote Windows validation remains pending because the environment's GitHub credential expired during this task. Do not treat the preceding green commit as verification of the later lock change.


Publishing the cloud environment restored GitHub access on 1 October 2026, allowing the final Windows locking correction (`cfb7646`) to be synchronized with `main`. Its local validation passed **376 tests, 13 prerequisite skips and 4,358 subtests**, plus Ruff and basic mypy. The latest commit’s remote CI is required to validate that correction; the earlier green run does not cover it.


## Real application and repository validation — 1 October 2026

Started from `f573521`. Application instances were disposable, isolated and controlled by this test environment; no third-party production endpoints were probed. Public repositories were cloned at the commits below and scanned statically, without installing their dependencies or executing their code. Findings were reviewed by the assistant doing the implementation; there is no independent complete truth set or precision/recall claim.

| Product | Real target and workflow | Verified result |
|---|---|---|
| TLS / mTLS | nginx reached by independent OpenSSL clients; PostgreSQL queries, Redis SET/GET and MQTT publish/subscribe through terminating/originating edges | Real payloads, hybrid negotiation, classical transition policy, concurrent clients, enrollment and revoked-client refusal passed. |
| VPN | Redis SET/GET in isolated gateway/client namespaces before and after key rotation | Real userspace WireGuard passed locally; revocation removed the peer and Redis access. The Linux CI VPN gate executes the matching IPsec application check only after installed encrypted children are confirmed. Local IPsec validation remains control-plane-only because of kernel support. |
| Vault | PostgreSQL custom-format dump with Unicode rows; two archive recipients; authenticate through recovery recipient, restore, then run `pg_restore` | Database rows matched the original after the dump and table were removed. Existing 40 MiB backup/retention/signature/tamper checks also passed. This validates a dump, not a crash-consistent backup of live PostgreSQL data files. |
| Readiness | Real OpenSSH and TLS endpoints with strict hybrid, transition, classical-only, legacy TLS and closed-port configurations | Existing probes/reports completed and distinguished observed configurations; expected TLS grades A/B/C/C/F passed. Endpoint evidence does not establish which source findings are deployed. |
| Wolf Pack / Code Crawler | Additional Python/TypeScript repository scans, report/relationship exports and official CycloneDX schema | All scans completed. Scope bug fixed as described below; graph and attribution limits remain explicit. |

| Public repository | Pinned commit | Assets | Supported AST files | Resolved / observed calls | Seconds |
|---|---|---:|---|---:|---:|
| django/django | `50eef95591b1e5d8c47b2e8c96066cb0c516753a` | 12 | Python 2,931; JavaScript 43 | 17,278 / 100,000 | 37.78 |
| Legrandin/pycryptodome | `a1e52c70302a51077e9d6a20a6abc6a04da1b5e6` | 73 | Python 228; JavaScript 2 | 1,484 / 19,766 | 12.80 |
| paulmillr/noble-post-quantum | `48e493397e69fa3e377bd454ff5261b1a7e22651` | 22 | TypeScript 20 | 400 / 1,494 | 0.91 |

Timing reflects one Linux/Python 3.12 run before the scope correction and is indicative. Django's entire repository reached the 100,000-call graph cap; a deliberately invalid Python test fixture and two JavaScript syntax failures were reported. Scanning only Django’s `django/` application source completed in 9.88 seconds with 37,552 calls and no graph cap (907 Python and 20 JavaScript files); one JavaScript relationship syntax gap remained. PyCryptodome's C implementation files have detector coverage without an AST relationship adapter. These are explicit partial-coverage results, not complete call graphs.

Reviewed findings show why source inventory is not a vulnerability verdict:

- Django's optional `MD5PasswordHasher.encode` is a real weak-password-hasher implementation worth checking against a deployment's configured hashers. Its static-files `file_hash` also uses MD5, explicitly with `usedforsecurity=False`; that cache fingerprint is not evidence of a password or signature vulnerability. Django's default HMAC-SHA1 helper and SHA1 used inside PBKDF2 require purpose/context review; SHA1 collision attacks do not establish that HMAC or PBKDF2 is broken. The scanner records primitives and candidate callers, not effective application settings.
- PyCryptodome really implements RSA, ECC and legacy algorithms; RSA-OAEP defaults to SHA1 if its caller supplies no hash. That is a compatibility/default observation, not an exploit proof. RSA-1536 fixtures under Wycheproof `test_vectors` incorrectly entered the production queue. Recognizing `test_vectors` and `SelfTest` as test scope retains all **73 assets** while reducing production migration candidates **25 → 17**. Regressions prove production uses still count and test evidence is preserved.
- noble-post-quantum's ML-KEM/ML-DSA/SLH-DSA/FN-DSA implementations were recognized. Its ECDH findings include a classical component combined with ML-KEM in hybrid presets, so a generic ECDH priority does not show the complete hybrid is quantum-vulnerable. A local variable named `dsa` actually holds ML-DSA signers and produces a false classical DSA finding in test code. That alias-attribution gap remains in advanced/test evidence. AES DRBG key-size inference also requires review; the observed helper is `rngAesCtrDrbg256`, so its generic AES label must not be taken as AES-128.

Validation after the scope fix: **378 local Python tests passed, 14 prerequisite skips, 4,485 subtests passed**; **54 real-service/container tests passed, 3,568 subtests passed**; real userspace WireGuard Redis/rotation/revocation passed. These counts overlap. All 20 development corpus/ablation configurations ran; full pack remains 163 labeled pairs with zero false positives/negatives, as a tuned regression result only. Production CBOM baseline gate and official CycloneDX 1.6 validation passed for every new repository CBOM. Ruff, basic mypy and both production wheels passed. All **37 local browser tests passed** after restoring the environment’s Chromium prerequisite. Final remote platform checks are recorded by the latest commit's CI; do not infer unexecuted paths from local prerequisite skips.

## Current roadmap scope — 1 October 2026

The owner resumed product improvements and subsequently excluded team access (SSO/RBAC) and native installer code signing. Neither feature is implemented in this checkout. Earlier gap lists describe the historical review, not a commitment to implement these excluded features. The existing administrator-token login, verification of third-party installer signatures, and certificate/Vault cryptographic signing remain required.

Continue scanner accuracy and large-repository performance, migration evidence, easier setup/diagnostics and realistic customer-condition validation. Independent review and real laptop/cloud validation still require actual reviewers and environments.

## Accuracy milestone: before and after (2 October 2026)

Before: generic password-hash advice, a false classical DSA alias in a PQ signer table, scan-order-dependent graph truncation, repeated parsing, and source remediation without authenticated endpoint observations.

After: password-specific Argon2id/scrypt advice, narrow AST alias resolution with mutation/shadowing traps, candidate hybrid context without safety downgrades, production-first relationships, bounded syntax reuse and explicit uncertainty. The console adds guided prerequisites/enrollment and advanced endpoint verification. Graph compression fixes large-project persistence without retaining source snippets. Existing detectors remain shared; no production dependency was added. This milestone adds tested capabilities and does not reduce total source size.

Validation: 391 full-suite tests passed with 14 host prerequisite skips; the additional storage-version and cache-hasher tests passed in the 39-test focused run. All 38 browser checks passed. Both wheels built, lint/basic type checks and the suite CBOM high-risk baseline passed. The 20-minute recovery run completed 96,792 successful connections, zero failures, 49/49 revocations and eight certificate renewals. These are local evidence, not real customer laptop or independent review results.

The corpus grew from 163 to 166 labeled pairs by adding two explicit alias examples; existing labels were unchanged. The following regression table is tuned development data, not independent accuracy evidence.

| Configuration | Before P/R/F1 | After P/R/F1 | Before FP/FN | After FP/FN |
|---|---|---|---|---|
| full pack | 1.000/1.000/1.000 | 1.000/1.000/1.000 | 0/0 | 0/0 |
| without den | 0.845/1.000/0.916 | 0.847/1.000/0.917 | 30/0 | 30/0 |
| without corroboration | 1.000/0.994/0.997 | 1.000/0.994/0.997 | 0/1 | 0/1 |
| without second look | 1.000/0.914/0.955 | 1.000/0.916/0.956 | 0/14 | 0/14 |
| without flow | 1.000/0.933/0.965 | 1.000/0.934/0.966 | 0/11 | 0/11 |
| without registries | 1.000/0.988/0.994 | 1.000/0.988/0.994 | 0/2 | 0/2 |
| without siblings | 1.000/0.994/0.997 | 1.000/0.994/0.997 | 0/1 | 0/1 |
| without recognition | 0.982/1.000/0.991 | 0.982/1.000/0.991 | 3/0 | 3/0 |
| without propagation | 1.000/0.988/0.994 | 1.000/0.988/0.994 | 0/2 | 0/2 |
| without cross-file | 1.000/0.988/0.994 | 1.000/0.988/0.994 | 0/2 | 0/2 |
| without source scouts | 1.000/0.356/0.525 | 1.000/0.349/0.518 | 0/105 | 0/108 |
| without names | 1.000/0.963/0.981 | 1.000/0.958/0.978 | 0/6 | 0/7 |
| without concat | 1.000/0.994/0.997 | 1.000/0.994/0.997 | 0/1 | 0/1 |
| without symbols | 1.000/0.957/0.978 | 1.000/0.958/0.978 | 0/7 | 0/7 |
| without parameters | 1.000/0.994/0.997 | 1.000/0.994/0.997 | 0/1 | 0/1 |
| without implementation scouts | 1.000/0.982/0.991 | 1.000/0.982/0.991 | 0/3 | 0/3 |
| without config scouts | 1.000/0.748/0.856 | 1.000/0.753/0.859 | 0/41 | 0/41 |
| without lists | 1.000/0.969/0.984 | 1.000/0.970/0.985 | 0/5 | 0/5 |
| without artifact scouts | 1.000/0.933/0.965 | 1.000/0.934/0.966 | 0/11 | 0/11 |
| without binary scouts | 1.000/0.988/0.994 | 1.000/0.988/0.994 | 0/2 | 0/2 |

Remaining gaps: ambiguous dynamic signer aliases, Java/Go/C relationship adapters, hard resource isolation, cryptographically established source-to-deployment provenance, real Windows/macOS laptop sleep/roaming/kill-switch evidence, days-long production runs, three actual customer pilots and independent security review. Protocols and a private metric ledger are prepared; no reviewer or customer participation is implied. Team access and native installer code signing remain excluded. Public competitor feature comparisons in this document remain observations, not a claim of superiority.

Final pinned public-repository rerun (static analysis only; no target source executed):

| Repository | First / repeat seconds | Reused syntax on repeat | Assets | Saved workspace bytes |
|---|---|---|---|---|
| noble-post-quantum | 0.95 / 0.92 | 20 | 22 | 56088 |
| pycryptodome | 12.61 / 11.85 | 230 | 73 | 771319 |
| django | 48.02 / 39.42 | 2976 | 14 | 2393776 |

Every saved graph reloaded identically. Django has 1,653 truncated test files and no truncated production files; its one invalid Python file remains a reported parse failure. Noble’s immutable signer-table DSA false finding is absent; dynamic aliases elsewhere still require review. Timings share a host with other tests and are not controlled performance benchmarks. All five final CBOMs (corpus, suite and three public projects) validate with zero CycloneDX 1.6 errors. Current-code container checks: 61 passed, 3,570 subtests, against real services/TLS/Vault.

## Competitive recheck — 4 October 2026

Public pages re-read: [PQCvpn](https://pqcrypto.ai/pqcvpn/) (Windows 10/11 and macOS 13+ downloads, "one-click connection", ML-KEM/ML-DSA/SLH-DSA named, protocol not stated), [PQCLens](https://pqcrypto.ai/pqclens/) (agent-based discovery, severity and environment breakdowns, readiness score and roadmap, 30-day trends), [Q-Vault](https://pqcrypto.ai/qvault/) (PQC encryption of backups before upload to 70+ storage services). These are advertised capabilities, not tested products. The PQCvpn source the owner mentioned was not available in this environment.

| Customer need | PQCrypto (public claims) | PQC Suite now | Status |
|---|---|---|---|
| Join a VPN without technical steps | Desktop installer, one click | One invitation file and one command (`vpn join`), checks rights and WireGuard first, plain Protected / Connecting / Not protected status | Partial: no desktop app or signed installer (signing excluded by the owner) |
| Know whether you are protected | Not described | Protected only after a tunnel handshake with the latest post-quantum key; TLS group and certificate algorithm shown; `vpn status` | Covered |
| Site-to-site | Contact sales | strongSwan IKEv2 with ML-KEM + PPK, rotation, revocation, console telemetry | Stronger (self-serve, documented) |
| Find vulnerable cryptography | Agents across infrastructure | Wolf Pack: code, configs, keys, certificates, binaries, dependencies, live TLS/SSH, cross-file values and callers, security patterns | Different shape: no fleet agents; deeper, evidence-cited code analysis |
| Readiness overview and priorities | Score, severity, trends | Dashboard with action counts, "do these first", per-area CNSA 2.0 deadlines, code evidence with callers, history in the console | Covered without an invented score |
| Protect backups | Many cloud destinations | Local hybrid-PQ archives, signatures, recovery recipients, verify and restore; any sync tool moves them | Destinations deliberately left to existing tools |
| Certificates and TLS edge | Not offered as products | ML-DSA CA, EST, ACME, PQ TLS edge | PQC Suite only |

Remaining gaps a customer would notice: no desktop VPN app, no fleet agents for continuous inventory across machines, and relationship analysis only for Python and JavaScript/TypeScript.
