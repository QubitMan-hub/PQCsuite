# The pack

Wolf Pack's architecture is a hunting pack. Each role is a separate component with one job. Each one can be switched off, so its contribution can be measured rather than asserted. The metaphor itself is not the contribution: the Grey Wolf Optimizer (Mirjalili 2014) already exists. The contribution is the design it names: scouts that over-report on purpose, a den that verifies with an audit trail, and an alpha that re-examines what was held and ranks the rest.

## The hunt

```
elders (knowledge)
   |
scouts ──hunt──> sightings ──> den ──verify──> accepted / held / rejected / suppressed
   ^                                                  |
   └──────────────── alpha: trails, second look <─────┘
                            |
                         lead: tiers, alerts ──> howl: CBOM, SARIF, report, audit trail
```

`pack.run` performs exactly these stages in this order: `hunt` (scouts), `alpha.follow_trails`, `den.verify`, `alpha.second_look`, `alpha.recognise`, `den.assets`, then `alpha.lead`. `cli.py` writes the outputs.

## Roles

Each switch is passed as `wolfpack hunt PATH --without ROLE`, or as `pack.Roles.without(...)` in code. The last column is the change on the dev corpus when that role alone is off (`wolfpack bench bench/corpus`, 136 labels). The corpus is overfit by construction, so these numbers show each role is live, not how much it matters on real code.

| Role | Module | Job | Switch | Corpus effect when off |
|---|---|---|---|---|
| Elders | `elders.py` | Knowledge base: algorithms, aliases, OIDs, security levels, NIST dates, replacements | none (every stage consults it) | n/a |
| Source scouts | `scouts/source.py`, `pysrc.py`, `rules.py`, `lexer.py` | Python AST, per-language rules (OpenSSL, JCA, commons-codec, Go, Node, sjcl, .NET, Rust, libsodium in C/PHP/JS/C#), string literals | `source` | recall 1.000 → 0.353 |
| Source scouts: names | `scouts/names.py` | Code named for its algorithm: calls, constructors and type definitions such as `aes_encrypt()`, `BCrypt.HashPassword()`, `class HkdfSha256`. Not counted: prototypes, `extern`/`partial` declarations, Java enum constants, `.d.ts` typings, test names, predicates (`isRsaKey`), error and not-supported helpers, attributes. Evidence `identifier`. | `names` | recall → 0.985; on held-out code (tuned on it) recall 0.911 → 0.646 |
| Source scouts: symbols | `names.symbols` | All-caps constants and enum members that name an algorithm where code uses them: `case KEY_ED25519:`, `kex[KEX_DH_GRP14_SHA256]`, `crypto.SHA1`, TLS cipher-suite constants. Not counted: their own definitions, `#define`/`#if` lines, enum declarations, headers, size/error/flag names (`SHA512_DIGEST_LENGTH`, `OPENSSL_NO_RSA`), and `case` labels whose branch only throws. Evidence `identifier`. | `symbols` | recall → 0.963 |
| Source scouts: parameters | `scouts/params.py`, `scouts/pyflow.py` | A crypto API called with a parameter (`MessageDigest.getInstance(alg)`, `createHash(alg)`, `hashlib.new(name)`) is resolved from the literal arguments at every call of that function in the repository. The rebuilt call goes through the ordinary rules. Java, JavaScript/TypeScript, Python. For Python the syntax tree goes further: a function whose parameters reach a crypto call is re-read once per value its callers or defaults give them (constants, class attributes, `CONFIG["hash"]`, a caller's own parameter, up to 4 hops), so `make_key(KEY_BITS)` yields RSA-1024 at the key generation. A value that cannot be resolved stays unresolved. | `parameters` | recall → 0.977 |
| Source scouts: concatenation | `source.concatenated` | A literal glued to a runtime value (`"RSA-SHA" + bits`, `"PBKDF2WithHmac" + name`) reports only its complete parts; fragments like `"SHA-" + bits` are never guessed | `concat` | recall → 0.993 |
| Implementation scouts | `scouts/implementations.py` | Algorithms implemented in source, recognised by published constants (round constants, IVs, S-boxes, curve primes) | `implementations` | recall → 0.978 |
| Config scouts | `scouts/config.py`, `suites.py` | TLS/SSH/OpenSSL/app configs, including extensionless files with 2+ TLS/SSH directives | `config` | recall → 0.757 |
| Config scouts: lists | `config.list_items` | Entries of multi-line YAML and JSON lists are read as if written on their key's line; deny-named keys (`disabled_ciphers`) stay skipped | `lists` | recall → 0.963 |
| Artifact scouts | `scouts/artifacts.py` | Certificates, keys, embedded PEM | `artifacts` | recall → 0.934 |
| Binary scouts | `scouts/binary.py` | Native constants (the implementation scout's tables as bytes), library versions, JAR/class constants | `binary` | recall → 0.985 |
| Dependency scouts | `scouts/deps.py` | Crypto libraries in manifests, checked against imports | none (libraries, not sightings) | n/a |
| Live scouts | `scouts/tls.py`, `probe.py` | TLS handshake and group probe, SSH KEXINIT | only when `--tls`/`--ssh` given | n/a |
| Scouts' memory | `source.propagate`, `PyScout.consts` | Constant propagation inside a file: strings from any declaration, integers only from `final`/`const`/`readonly`/`#define` | `propagation` | recall → 0.985; also recovers key sizes (RSA-1024 instead of RSA) |
| Scouts' shared memory | `source.shared_constants`, `source.js_imports`, `scouts/pyflow.py` | Constants reached from other files: `Owner.NAME` (Java, Kotlin, C#), `pkg.Name` (Go), `#define` in an included C header, `export const` values imported by name from a relative JavaScript/TypeScript module, and Python module constants, class attributes and re-exported names followed through imports (`from .settings import DIGEST`, `from hashlib import sha1 as quick_digest` re-exported). A Python constant whose value reaches a crypto call counts as used where it is defined. Names with conflicting values are dropped. | `cross-file` | recall → 0.971 |
| Den | `den.py` | Confidence per evidence type, hard rejects (comment, docstring, prose), suppression, threshold | `den` | precision 1.000 → 0.824 |
| Den: look-alikes | `pyflow.facts`, `den.settle` | A Python name sighting that is only a local definition named like an algorithm (`def md5(text): return "md5:" + text`, `class rsa:`), and calls to it, is rejected when the definition does no cryptography: no bit operations, no imports and no calls beyond Python builtins | `lookalikes` | precision → 0.989 |
| Den: reachability | `pyflow.facts`, `den.settle` | A sighting in Python code that can never run (`if False:`, `while 0:`, the dead branch of `if True:`, statements after `return`, `raise`, `break` or `continue`) is held, not dropped: it stays in `findings.json` | `reachability` | precision → 0.989 |
| Den: corroboration | `den.verify` | +0.25 when a different evidence type in the same file backs a sighting | `corroboration` | recall → 0.993 |
| Alpha: trails | `alpha.follow_trails` | Finds configs and code that load a key or certificate, so it is weighted as deployed | `trails` | none at family level; changes exposure and tier |
| Alpha: second look, flow | `alpha.flows` | Promotes a held literal that flows into a call (byte and raw literals included), or that the code branches on (`case "AES256":`, `alg == "EdDSA"`) | `flow` | recall → 0.941 |
| Alpha: second look, registries | `alpha.registries` | Promotes a list of 3+ algorithm names, unless its variable is named like a deny-list | `registries` | recall → 0.985 |
| Alpha: second look, siblings | `alpha.siblings` | Halves of one literal ("RS256" gives RSA and SHA-256) share fate | `siblings` | recall → 0.993 |
| Alpha: recognition | `alpha.sniffs`, `alpha.recognise` | A list whose entries are only searched for inside input data (`key.startswith(FORMATS)`, `any(p in data for p in FORMATS)`, a loop calling `HasPrefix`) is format sniffing: never promoted, and held back even if the den let it in | `recognition` | precision → 0.978 |
| Alpha: purpose | `alpha.declared_non_security`, `assess` | A Python `hashlib` call with `usedforsecurity=False` is a declared non-security use; an asset whose every use is declared ranks low, and those lines become SARIF notes | `purpose` | none at family level; changes tier |
| Alpha: trust store | `alpha.trust_stores`, `assess`, `alerts` | A file of 5+ certificates, every one self-signed and nothing else, is a trust store (roots the project trusts, not keys it holds): its per-certificate alerts become one line, an asset found only there ranks low, and its lines become SARIF notes | `trust-store` | none at family level; changes tier and alerts |
| Alpha: lead | `alpha.lead`, `assess`, `alerts` | Mosca tiers, hybrid awareness, exposure weighting, test demotion, hygiene alerts | none (ranking, not detection) | n/a |
| Patterns | `scouts/patterns.py` | Security patterns around cryptography, one line at a time on comment-free code: WPC001 certificate verification off (CWE-295), WPC002 secret in code (CWE-798, value redacted), WPC003 non-cryptographic random for key material (CWE-338), WPC004 token accepted without its signature (CWE-347), WPC005 fixed or zero IV (CWE-329). Python, JavaScript/TypeScript, Java/Kotlin, Go, C#, C/C++/PHP, Rust, Ruby. Pattern detection, not taint tracking; test code ranks low; `wolfpack:ignore` suppresses | `patterns` | none (not CBOM assets); SARIF, report, `findings.json` |

`--without second-look` switches off flow, registries and siblings together.

## Glossary

| Term | Meaning |
|---|---|
| hunt | One scan. `wolfpack hunt` is an alias of `wolfpack scan`. |
| carried hash | A primitive parameterised with a hash (HMAC-SHA256, PBKDF2 over SHA-1, SHA256withRSA) also reports the hash, applied once at the end of the hunt. This follows the labelling convention the owner confirmed. |
| sighting | One scout's report of one algorithm at one location, with its evidence type. Scouts over-report on purpose. |
| evidence | How a sighting was seen: `live`, `artifact`, `config`, `call`, `constant`, `binary`, `identifier`, `import`, `string`. Each has a base confidence in `den.BASE`. |
| verdict | What the den decided: `accepted` enters the CBOM; `quarantined` is held in the den (kept in `findings.json`, may be promoted on a second look); `rejected` is a comment, docstring, prose or unknown algorithm; `suppressed` is a `wolfpack:ignore`. |
| second look | The alpha sending the pack back over held sightings. |
| trail | A reference from code or config to a key or certificate file. |
| asset | Accepted sightings grouped by algorithm variant: one CBOM component. |
| tier | The alpha's priority: critical, high, medium, low, ok. |
| howl | The outputs: CBOM, SARIF, HTML report, audit trail. |

## Naming rules

Roles, pipeline stages and CLI verbs use pack names. Data keeps the names of the standards it maps to: CycloneDX (`Asset`, `Library`, `Artifact`), algorithm names, and evidence types. Crypto readers and reviewers should never have to decode a metaphor to read the output.

A new heuristic belongs to exactly one role and gets a switch in `pack.Roles`. It ships with a corpus case it must fire on, a trap it must not fire on, and a test that it changes the result when switched off (CLAUDE.md rule 2).

## What the family-level ablation cannot see

`bench` scores (file, algorithm family) pairs. Roles that improve parameters or ranking rather than detection show little or no change there: propagation recovers key sizes, and trails move exposure and tier. The paper needs a variant-level or tier-level measure to credit them.
