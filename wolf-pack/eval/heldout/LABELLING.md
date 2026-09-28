# Labelling guide

You are building the answer key for a benchmark of cryptography scanners. For every file on your sheet, write down which cryptographic algorithms that file uses, and which it only declares. Your labels are the ground truth that both Wolf Pack and IBM CBOMkit are scored against, so they must come from reading the code, not from any tool.

## Who labels

Under amendment 1 of the pre-registration, two isolated AI labellers and an AI adjudicator write the labels, following this guide exactly. A person then audits a random 10% sample; the rules below about scanners and blindness apply to both. The auditor must not use an AI assistant.

## Before you start

- **You must not be the author of Wolf Pack**, and you must not have seen any tool's output on these repositories.
- **Do not run** Wolf Pack, CBOMkit, Semgrep crypto rules, or any other crypto scanner on these repos until every sheet is finished and committed.
- **Do not use an AI assistant** to label. Plain text search (your editor, `grep`, `findstr`) is fine and encouraged.
- Keep a log in `labels/<your name>/LOG.md`: minutes spent per repo, and anything you were unsure about.

Setup (PowerShell, from the repo root):

```powershell
python eval/heldout/heldout.py fetch                     # clones the 18 repos at their pinned commits
python eval/heldout/heldout.py sheets --labeller <name>  # one blank sheet per repo in eval/heldout/labels/<name>/
python eval/heldout/heldout.py check --labeller <name>   # run as often as you like; it only checks your labels
```

Open each sheet (`.csv`) in Excel or LibreOffice. Save it as **CSV UTF-8**. The files it lists are in `eval/heldout/repos/<repo>/`. Tests, examples, build output and vendored dependencies are already left off the sheet.

## The sheet

| file | used | declared | notes |
|---|---|---|---|
| app/vault.py | AES; RSA; SHA-256; SHA-1 | - | RSA-OAEP here uses SHA-1 by default |
| app/algorithms.py | - | AES; RSA; ECDSA; HMAC; SHA-256; SHA-384; SHA-512 | table of supported algorithm names |
| setup.py | - | - | |

- Fill **both** `used` and `declared` on every row. Write `-` for none. A blank cell means "not labelled yet", and scoring refuses to run while any remain.
- Separate families with `;`. Order and case don't matter.
- A family goes in `used` or in `declared`, never both. If it is used, that is enough.
- Use `notes` for anything uncertain; start the note with `?` so it can be found later.

## Which names to use

Label at the **family** level. Key sizes, modes and curves don't matter: AES-128-GCM is `AES`, RSA-2048 is `RSA`, ECDSA on P-384 is `ECDSA`.

The vocabulary:

> RSA, DSA, DH, ECC, ECDSA, ECDH, Ed25519, Ed448, X25519, X448, ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, X25519MLKEM768, sntrup761x25519, SecP256r1MLKEM768, SecP384r1MLKEM1024, AES, ChaCha20, 3DES, DES, RC4, RC2, Blowfish, MD4, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2, HMAC, PBKDF2, HKDF, scrypt, Argon2, bcrypt, SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3

Anything outside the vocabulary gets `OTHER:<name>`, for example `OTHER:Salsa20`, `OTHER:SipHash`, `OTHER:SPAKE2`, `OTHER:Poly1305`, `OTHER:MD2`, `OTHER:RIPEMD-160`, `OTHER:SHAKE256`, `OTHER:Camellia`. Do not squeeze an algorithm into the nearest vocabulary name. Scanners that don't know an algorithm should lose points for it.

### Mapping rules

| You see | Label |
|---|---|
| A signature scheme: `SHA256withRSA`, `RS256`, `PS384`, `ES256`, `rsa-sha2-512` | the signature family **and** the hash: `RSA; SHA-256` |
| `EdDSA` with no curve named | `Ed25519` (use `Ed448` if that is what the code picks) |
| HMAC: `HmacSHA256`, `HS256`, `hmac.new(key, msg, sha1)`, `hmac-sha2-256` | `HMAC` **and** the hash: `HMAC; SHA-256` |
| HOTP or TOTP | `HMAC` and the hash it uses (SHA-1 by default) |
| A KDF: `PBKDF2WithHmacSHA256`, HKDF-SHA256 | the KDF **and** the hash: `PBKDF2; SHA-256`. Do not add `HMAC` for the HMAC hidden inside PBKDF2 or HKDF. |
| bcrypt | `bcrypt` only, not `Blowfish` (unless Blowfish is also used as a cipher) |
| ChaCha20-Poly1305, XChaCha20-Poly1305, ChaCha20 | `ChaCha20` |
| NaCl `secretbox` (XSalsa20-Poly1305) | `OTHER:Salsa20` |
| NaCl `box` | `X25519; OTHER:Salsa20` |
| SHA-512/224 or SHA-512/256 | `SHA-512` (it is SHA-512 truncated) |
| TripleDES, DESede, DES-EDE3 | `3DES` |
| EC key agreement on any curve | `ECDH`; on Curve25519, `X25519` |
| An EC key generated or loaded, with no visible use | `ECC` |
| A pinned or configured protocol version: `MinVersion: tls.VersionTLS12`, `ssl.PROTOCOL_TLSv1_2` | `TLS 1.2` (just calling an `https://` URL is not a label) |
| A certificate or key file | the key's family, plus the certificate's signature family and hash |

### Used, declared, or neither

**Used**: the file calls, instantiates, implements or configures the algorithm, or an algorithm name in this file flows into a crypto call in this file. Examples:
- `Cipher.getInstance("AES/GCM/NoPadding")`
- `hashlib.sha256(data)`
- a C file implementing AES rounds
- a default argument that is really used when the caller passes nothing (`def mgf1(seed, hasher="SHA-1")`)
- a config file that turns a cipher on

**Declared**: the algorithm is named as something the software supports or may select, but this file does not use it itself. Examples:
- a JWA identifier table
- an enum of supported hashes
- a constant `KEY_ALG_NAME = "AES"` defined here and used in another file (the other file gets `used`)
- a registry that maps names to implementations defined elsewhere

**Neither**:
- comments and documentation, including docstrings
- log messages, error messages and exception text
- lists used only to **recognise or reject** formats, such as SSH key prefixes used to sniff a key type, or a deny-list of disabled algorithms
- random number generators (`SecureRandom`, `os.urandom`) and non-cryptographic checksums (CRC, Adler)
- encodings (Base64, hex)

When a file both uses and declares a family, it goes in `used` only.

### Hard cases

- **Wrappers.** A class `Sha256` that forwards to libsodium is `used: SHA-256`; the file is the crypto in this codebase.
- **A generic function that takes the algorithm as a parameter**, for example `sign(key, alg)`, uses nothing by itself unless it has a default or a branch on concrete names. A branch like `if alg == "RS256": ...` means the file uses RSA and SHA-256.
- **Generated or vendored code that is still on the sheet.** Label it like any other file and write `vendored` in notes.
- **Unsure?** Pick the reading you believe is most likely, and put `?` and your reason in `notes`. Never leave a cell blank because you are unsure.

## When you finish

1. `python eval/heldout/heldout.py check --labeller <name>` reports no problems.
2. Commit `eval/heldout/labels/<name>/` and your `LOG.md` before anyone runs a scanner on these repos. The commit time is the proof that labels came first.
3. Labels are never edited after scoring. If you find a mistake later, record it in `LOG.md` with the date; the paper reports it.

A second labeller, working independently, labels at least four repos from three languages. `heldout.py agree <you> <them>` measures how often you agree. That number goes in the paper next to the results.
