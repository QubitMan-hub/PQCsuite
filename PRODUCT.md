# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- Security leaders at regulated enterprises, banks first (a CISO or head of security architecture), deciding which post-quantum vendor to pilot. They read the overview, how-it-works and security pages and need to trust the vendor before a meeting.
- The engineers who will install and run it (system, network and platform administrators). They read set-up, the manual and the demo, and judge the vendor by whether the commands are safe and work the first time.
- Compliance and risk teams who need evidence for auditors (NIST IR 8547, CNSA 2.0, a CycloneDX CBOM).

## Product Purpose

Acxelin Quantum sells post-quantum security products, each standalone, so a customer installs only the one that fits the problem:

- Acxelin Readiness + CBOM: finds the cryptography an organisation depends on, shows what a quantum computer breaks, ranks what to migrate first, writes a CycloneDX 1.6 CBOM.
- Acxelin TLS: post-quantum TLS 1.3 and mutual TLS in front of services that do not change, with its own ML-DSA certificate authority.
- Acxelin VPN (moving into its own product now): post-quantum site-to-site IPsec and WireGuard remote access with a desktop app.
- Acxelin Q-Vault (after VPN): quantum-safe encryption for files and backups.

The website's job: let a visitor see, within a minute, which product answers their problem, that it really works, and how to start safely.

## Positioning

- It protects traffic and data against "harvest now, decrypt later" today, with standardised algorithms (ML-KEM, ML-DSA), not research prototypes.
- Everything shown is real: demo output and the sample report are generated from the products at build time, and the site build fails rather than show invented output.
- Honest about limits: every product states what it does not claim (for example browsers cannot verify ML-DSA yet; HSM signing is not yet tested against real hardware).
- Runs on the customer's own machines, offline from a release folder; it never contacts Acxelin Quantum.

## Operating Context

Visitors evaluate it at work, often on a laptop between meetings, sometimes on a phone from a link; installers run it on Linux servers, Windows and macOS. Releases ship as an offline folder (wheels, installers, manual, licence) and as container images on GHCR.

## Capabilities and Constraints

- The site is static HTML built by `tools/build_site.py` from `website/` and each product's `docs/manual.md`, deployed to GitHub Pages; no external scripts or trackers.
- Each product's pages name only that product; the home page routes between products.
- Contact route: the company site, acxelinquantum.com.

## Brand Commitments

- Name and logo: Acxelin Quantum (`website/assets/acxelin-quantum.svg`); product names Acxelin Readiness, Acxelin TLS, Acxelin VPN, Acxelin Q-Vault.
- Amber is the brand colour; Host Grotesk is the display face (both kept by owner decision).
- Voice: plain, precise, honest; short sentences; no hype; British spelling.
- Copyright line: © 2026 Acxelin Quantum, all rights reserved.

## Evidence on Hand

- Real artifacts: `acxelin-tls try` output, the Readiness sample report and CBOM (generated at build time), console screenshots (`website/assets/*.png`).
- Standards the products implement: ML-KEM (FIPS 203), ML-DSA (FIPS 204), CycloneDX 1.6, EST (RFC 7030), ACME (RFC 8555), NIST IR 8547 and CNSA 2.0 checks, IKEv2 hybrid key exchange (RFC 9370), post-quantum PPK (RFC 8784).
- No public customers, testimonials, case studies, benchmarks or prices exist: none may be shown or implied.

## Product Principles

1. Show the mechanism working; never describe what could be demonstrated.
2. State limits next to claims.
3. One product per page; no product depends on another.
4. Safe by default for the installer: verifiable releases, nothing that weakens their machine.

## Accessibility & Inclusion

WCAG 2.2 AA; light and dark themes; usable at 390px wide; checked in CI with axe.
