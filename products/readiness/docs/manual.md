# Acxelin Readiness manual

## What it finds

| Source | What is read |
|---|---|
| Code | Python, JavaScript, TypeScript, Java, Go, C and C++, Rust, C#, Swift, PHP, Ruby, shell, Dockerfiles and more: calls, imports, constants, names and parameters |
| Config | YAML, JSON, TOML, INI, nginx, Apache, sshd, Kubernetes, Terraform: algorithm and cipher lists |
| Artifacts | PEM and DER certificates, keys, keystores, SSH keys and known hosts |
| Binaries and images | Library versions and algorithm strings in compiled files; container images saved with `docker save` or as OCI archives |
| Dependencies | Package manifests and lockfiles of the common ecosystems |
| Live | TLS endpoints (accepted groups, certificate, grade) and SSH servers (algorithm lists, host keys) |
| Captures | Handshakes in `.pcap` and `.pcapng` files: what clients and servers actually negotiated |

## How a finding becomes a result

1. **Detectors** report everything they see, noisily.
2. **Verification** gives each detection a confidence from its evidence (a call outweighs a name, corroboration raises it). Above the threshold (default 0.6) it is *accepted*; below, *quarantined*; known false patterns are *rejected*; lines marked `acxelin:ignore` are *suppressed*.
3. **Ranking** groups accepted detections into assets and gives each a tier (critical, high, medium, low, ok) from the algorithm, its key size, whether it protects data that must stay secret, and your timeline (shelf life, migration time, assumed quantum date).

## Tiers and the timeline

The tier follows Mosca's inequality: an asset is urgent when the years its data must stay secret, plus the years your migration takes, exceed the years until a quantum computer can break it. Set the three numbers with `--shelf-life`, `--migration` and `--crqc-year` or in the settings file.

## Standards

`--profile nist-ir-8547` flags quantum-vulnerable public-key cryptography with NIST's deprecation (2030) and disallowance (2035) dates and anything below 112 bits now. `--profile cnsa-2.0` checks the CNSA 2.0 suite (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87). A key size that wasn't observed is reported as unverified, never as compliant.

Own rules go in `[policy]` in the settings file: `forbid`, `min_bits`, `require_hybrid`, `as_of`.

## The console

`acxelin-readiness console` opens a page in your browser, already signed in, with two parts:
- **Projects:** add a folder, scan it, cancel a running scan (the previous result is kept), and see priorities and history.
- **Endpoints:** scan hosts, see what changed since the last scan, and export the CBOM.

The console listens only on this machine. From a remote server, forward a port and ask for a fresh link:
```
ssh -L 8900:127.0.0.1:8900 server
acxelin-readiness console link --port 8900     # run in that SSH session; open the address it prints
```
In Docker, publish to loopback only (`-p 127.0.0.1:8900:8900`) and run `docker exec -it NAME acxelin-readiness console link`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Finished |
| 1 | Bad usage or unreadable input |
| 2 | A gate fired: `--fail-on` tier reached, or `--fail-on-policy` with a broken rule |
