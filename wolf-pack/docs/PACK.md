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

Each switch is passed as `wolfpack hunt PATH --without ROLE`, or as `pack.Roles.without(...)` in code. The last column is the change on the dev corpus when that role alone is off (`wolfpack bench bench/corpus`, 100 labels). The corpus is overfit by construction, so these numbers show each role is live, not how much it matters on real code.

| Role | Module | Job | Switch | Corpus effect when off |
|---|---|---|---|---|
| Elders | `elders.py` | Knowledge base: algorithms, aliases, OIDs, security levels, NIST dates, replacements | none (every stage consults it) | n/a |
| Source scouts | `scouts/source.py`, `pysrc.py`, `rules.py`, `lexer.py` | Python AST, per-language rules (OpenSSL, JCA, commons-codec, Go, Node, sjcl, .NET, Rust, libsodium in C/PHP/JS/C#), string literals | `source` | recall 1.000 → 0.323 |
| Implementation scouts | `scouts/implementations.py` | Algorithms implemented in source, recognised by published constants (round constants, IVs, S-boxes, curve primes) | `implementations` | recall → 0.962 |
| Config scouts | `scouts/config.py`, `suites.py` | TLS/SSH/OpenSSL/app configs, including extensionless files with 2+ TLS/SSH directives | `config` | recall → 0.783 |
| Artifact scouts | `scouts/artifacts.py` | Certificates, keys, embedded PEM | `artifacts` | recall → 0.915 |
| Binary scouts | `scouts/binary.py` | Native constants (the implementation scout's tables as bytes), library versions, JAR/class constants | `binary` | recall → 0.981 |
| Dependency scouts | `scouts/deps.py` | Crypto libraries in manifests, checked against imports | none (libraries, not sightings) | n/a |
| Live scouts | `scouts/tls.py`, `probe.py` | TLS handshake and group probe, SSH KEXINIT | only when `--tls`/`--ssh` given | n/a |
| Scouts' memory | `source.propagate`, `PyScout.consts` | Constant propagation inside a file: strings from any declaration, integers only from `final`/`const`/`readonly`/`#define` | `propagation` | recall → 0.991; also recovers key sizes (RSA-1024 instead of RSA) |
| Scouts' shared memory | `source.shared_constants` | Constants reached from other files: `Owner.NAME` (Java, Kotlin, C#), `pkg.Name` (Go), `#define` in an included C header. Names with conflicting values are dropped. Needs `propagation`. | `cross-file` | recall → 0.991 |
| Den | `den.py` | Confidence per evidence type, hard rejects (comment, docstring, prose), suppression, threshold | `den` | precision 1.000 → 0.791 |
| Den: corroboration | `den.verify` | +0.25 when a different evidence type in the same file backs a sighting | `corroboration` | recall → 0.991 |
| Alpha: trails | `alpha.follow_trails` | Finds configs and code that load a key or certificate, so it is weighted as deployed | `trails` | none at family level; changes exposure and tier |
| Alpha: second look, flow | `alpha.flows` | Promotes a held literal that flows into a call | `flow` | recall → 0.991 |
| Alpha: second look, registries | `alpha.registries` | Promotes a list of 3+ algorithm names, unless its variable is named like a deny-list | `registries` | recall → 0.981 |
| Alpha: second look, siblings | `alpha.siblings` | Halves of one literal ("RS256" gives RSA and SHA-256) share fate | `siblings` | recall → 0.991 |
| Alpha: recognition | `alpha.sniffs`, `alpha.recognise` | A list whose entries are only searched for inside input data (`key.startswith(FORMATS)`, `any(p in data for p in FORMATS)`, a loop calling `HasPrefix`) is format sniffing: never promoted, and held back even if the den let it in | `recognition` | precision → 0.972 |
| Alpha: purpose | `alpha.declared_non_security`, `assess` | A Python `hashlib` call with `usedforsecurity=False` is a declared non-security use; an asset whose every use is declared ranks low, and those lines become SARIF notes | `purpose` | none at family level; changes tier |
| Alpha: trust store | `alpha.trust_stores`, `assess`, `alerts` | A file of 5+ certificates, every one self-signed and nothing else, is a trust store (roots the project trusts, not keys it holds): its per-certificate alerts become one line, an asset found only there ranks low, and its lines become SARIF notes | `trust-store` | none at family level; changes tier and alerts |
| Alpha: lead | `alpha.lead`, `assess`, `alerts` | Mosca tiers, hybrid awareness, exposure weighting, test demotion, hygiene alerts | none (ranking, not detection) | n/a |

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
