# Stage 0: Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record what today's code does, and what this environment can verify, before any product code moves.

**Architecture:** Stage 0 adds only repository tooling, fixtures and records under `tools/` and `tests/golden/`. It changes no product code. It produces:
- the environment findings and the baseline test record (`tools/baseline.md`)
- a file-to-destination map with per-product baseline coverage
- the Readiness quality baseline
- golden fixtures written by today's code, with tests that today's code passes

**Tech Stack:** Python 3.12 here (CI covers 3.11–3.14), pytest, coverage, ruff, OpenSSL 3.5.9 built from source, and the existing `pqcsuite` and `wolfpack` packages.

**Spec:** `docs/superpowers/specs/2026-10-16-four-standalone-products-design.md` (revision 3), sections "Testing strategy", "Environment findings" and "Stages".

## Global Constraints

- No change under `pqcsuite/`, `wolf-pack/wolfpack/`, `tests/` (except the new `tests/golden/`), `site/` or `.github/` in this stage.
- Work on branch `restructure/stage-0`, created from `5f8c349a102e566560708ee12b9b1574e4a6e6cc` plus the spec commits.
- OpenSSL version: 3.5.9, the version CI builds, installed to `/opt/pqc`.
- Every key, certificate, token and passphrase in fixtures is synthetic and created by `tools/make_fixtures.py`. Names end in `.invalid`. The passphrase is `golden-test-only`.
- Fixture lifetimes don't expire within the window the fixtures are used: certificates and CA 36,500 days, CRL next update 36,500 days, invitation expiry `2099-01-01T00:00:00+00:00`.
- Precision and recall are recorded at three decimals from the full-pack row of today's benchmark.
- A finding is recorded only from a command actually run, with its output. A finding that can't be established here is recorded as "not established" with the reason.

## Review Focus

1. **Fixture expiry.** A CRL with the default 7-day next update or 397-day certificates would make golden tests fail weeks later. The Task 5 tests assert every fixture lifetime reaches past 2099.
2. **Binary fixtures altered by Git.** Line-ending conversion on Windows would corrupt archives. `tests/golden/.gitattributes` marks everything `-text`, and the manifest hash test catches any change.
3. **Skips counted as passes.** The baseline lists skips separately, with their reasons, so a TLS test skipped for lack of OpenSSL isn't counted as passing.
4. **Coverage measured without OpenSSL.** That would understate TLS and VPN coverage. Task 2 runs with `PQCSUITE_OPENSSL=/opt/pqc/lib` and records whether the TLS tests ran.
5. **Secret scanners flagging fixture keys.** Fixture private keys are passphrase-encrypted and listed in `tests/golden/README.md` as synthetic and disposable.

---

### Task 1: Environment findings

**Files:**
- Create: `tools/baseline.md` (section "Environment findings")

**Interfaces:**
- Produces: `/opt/pqc/lib` (OpenSSL 3.5.9), used by Tasks 2 and 5; findings F1–F6, used by the Stage 1 plan.

- [ ] **Step 1: F1, OpenSSL 3.5.9**

Run: download `https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz` (as `.github/workflows/ci.yml` does). If that download fails, use the `codeload.github.com` tag archive. Then run `./Configure --prefix=/opt/pqc --libdir=lib shared no-tests && make -j4 && make install_sw`.

Expected: `/opt/pqc/bin/openssl version` prints `OpenSSL 3.5.9`. Record the version, or the failing command and its error.

- [ ] **Step 2: F2, `cryptography>=49` and its bundled OpenSSL**

Run in a fresh venv:
```
pip install "cryptography>=49"
python -c "from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa; k = mlkem.MLKEM768PrivateKey.generate(); print('ML-KEM ok'); s = mldsa.MLDSA65PrivateKey.generate(); print('ML-DSA ok')"
```
Use exactly these names if the module exposes them; otherwise use the class names that `pqcsuite/pki/__init__.py` and `pqcsuite/vault.py` import.

Expected: both lines print, with `LD_LIBRARY_PATH` unset. Record the installed version and the result.

- [ ] **Step 3: F3, strongSwan and network namespaces**

Run: `unshare -n true && echo netns-ok`. Then try building strongSwan 6.1.0 against `/opt/pqc` with the configure flags from `.github/workflows/ci.yml`.

Expected: record whether each works. A failure is a finding, not a blocker.

- [ ] **Step 4: F4, Playwright browser**

Run: `cd tests/browser && npm ci && npx playwright install chromium`.

Expected: record success, or the blocked host from the error.

- [ ] **Step 5: F5, publishing**

Run: `git ls-remote https://github.com/QubitMan-hub/PQCsuite HEAD` and `git push --dry-run origin HEAD:refs/heads/restructure/stage-0`.

Expected: record whether a push is possible. If no credentials are present, record that the owner must push for CI evidence.

- [ ] **Step 6: F6, TLS tests on Windows and macOS CI**

Run: `grep -n "skip" tests/test_tls.py tests/helpers.py` and read the Windows and macOS jobs in `.github/workflows/ci.yml`.

Expected: record which jobs provide OpenSSL 3.5 and which TLS tests skip without it. Label the result "static finding; confirm in a CI log".

- [ ] **Step 7: Commit**

```bash
git add tools/baseline.md
git commit -m "stage 0: environment findings"
```

### Task 2: Baseline test run

**Files:**
- Modify: `tools/baseline.md` (sections "Baseline run" and "Dependencies")

**Interfaces:**
- Consumes: `/opt/pqc/lib` from Task 1 (if F1 succeeded).
- Produces: `.coverage` at the repository root, used by Task 3.

- [ ] **Step 1: Install the baseline environment**

Run:
```
python -m venv /home/claude/venv-baseline
. /home/claude/venv-baseline/bin/activate
pip install -e "./wolf-pack[dev,crawler]" -e ".[test,integration,scan-web]"
pip freeze > /tmp/freeze.txt
```

Expected: install succeeds. Record `pip freeze`, `python -VV`, `uname -a`, `/etc/os-release` and the OpenSSL version that Python's `ssl` reports.

- [ ] **Step 2: Run the suite with coverage**

Run: `PQCSUITE_OPENSSL=/opt/pqc/lib LD_LIBRARY_PATH=/opt/pqc/lib python -m coverage run -m pytest -q -rfEs`. Omit the two variables if F1 failed, and say so in the record.

Expected: finishes. Record pass, fail, error and skip counts. List each failure and skip with its reason, and record whether `tests/test_tls.py` ran or skipped.

- [ ] **Step 3: Lint**

Run: `ruff check .`

Expected: record the result exactly.

- [ ] **Step 4: Commit**

```bash
git add tools/baseline.md
git commit -m "stage 0: baseline test run"
```

### Task 3: Coverage map and per-product baseline

**Files:**
- Create: `tools/coverage_map.toml`
- Create: `tools/coverage_by_product.py`
- Create: `tools/tests/test_coverage_map.py`
- Modify: `tools/baseline.md` (section "Coverage by product")

**Interfaces:**
- Consumes: `.coverage` from Task 2.
- Produces: `load_map(path: Path) -> dict[str, tuple[str, str]]`, mapping a repository-relative file to (destination, reason). Also produces `aggregate(stats: dict[str, tuple[int, int]], mapping: dict[str, tuple[str, str]]) -> dict[str, float]`, where `stats` maps a file to (statements, missed) and the result maps a destination to percent covered. Later stages use both to compare like-for-like.

- [ ] **Step 1: Write the failing tests**

```python
DESTINATIONS = {"core", "tls", "vpn", "readiness", "vault", "deleted"}

def test_every_source_file_mapped_once():
    files = {p.as_posix() for root in ("pqcsuite", "wolf-pack/wolfpack") for p in Path(root).rglob("*")
             if p.suffix in {".py", ".html", ".js"}}
    assert set(load_map(MAP)) == files

def test_destinations_valid_and_deletions_explained():
    for f, (dest, reason) in load_map(MAP).items():
        assert dest in DESTINATIONS, f
        assert dest != "deleted" or reason, f

def test_aggregate_excludes_deleted_and_weights_by_statements():
    m = {"a.py": ("core", ""), "b.py": ("core", ""), "c.py": ("deleted", "suite hub")}
    assert aggregate({"a.py": (10, 0), "b.py": (30, 15), "c.py": (50, 50)}, m) == {"core": 62.5}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tools/tests/test_coverage_map.py -v`

Expected: FAIL, because `tools/coverage_map.toml` and `tools/coverage_by_product.py` don't exist yet.

- [ ] **Step 3: Write `tools/coverage_map.toml` and `tools/coverage_by_product.py`**

The map has one table per destination, listing files with the spec's assignments ("Shared core", "Products", "Architecture changes"). Entries under `deleted` carry a reason string. `coverage_by_product.py` reads `.coverage` with the `coverage` API (`Coverage().load()`, `analysis2`), calls `aggregate`, and prints one line per destination.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tools/tests/test_coverage_map.py -v`

Expected: 3 passed.

- [ ] **Step 5: Record the per-product coverage**

Run: `python tools/coverage_by_product.py`

Expected: one percentage per destination, copied into `tools/baseline.md`.

- [ ] **Step 6: Commit**

```bash
git add tools/coverage_map.toml tools/coverage_by_product.py tools/tests/test_coverage_map.py tools/baseline.md
git commit -m "stage 0: coverage map and per-product baseline"
```

### Task 4: Readiness quality baseline

**Files:**
- Create: `tools/quality_baseline.json`
- Modify: `tools/baseline.md` (section "Readiness quality")

**Interfaces:**
- Produces: `tools/quality_baseline.json` as `{"precision": float, "recall": float, "truth_sha256": str, "corpus": "wolf-pack/bench/corpus"}`. The Stage 1 quality gate fails below these values.

- [ ] **Step 1: Run today's benchmark**

Run: `cd wolf-pack && python -m wolfpack bench bench/corpus --json /tmp/bench.json`. If the flag name differs, use whatever `wolfpack bench --help` shows for `bench.main`'s `json_path`.

Expected: a table whose first row is the full pack, with no roles switched off.

- [ ] **Step 2: Write `tools/quality_baseline.json`**

Take the precision and recall of the row whose `without` list is empty, and `sha256sum wolf-pack/bench/truth.json`. Copy both numbers and the hash into `tools/baseline.md`.

- [ ] **Step 3: Commit**

```bash
git add tools/quality_baseline.json tools/baseline.md
git commit -m "stage 0: readiness quality baseline"
```

### Task 5: Golden fixtures

**Files:**
- Create: `tools/make_fixtures.py`
- Create: `tests/golden/` (fixtures, `MANIFEST.json`, `README.md`, `.gitattributes`)
- Create: `tests/golden/test_golden_old_code.py`

**Interfaces:**
- Consumes: today's APIs:
  - `pqcsuite.pki.CA.init(root, name, algorithm, days, passphrase)`, `CA.issue(common_name, kind, names, days, algorithm, out, passphrase)`, `CA.revoke(serial, reason)` and `CA.crl(days)`
  - `pqcsuite.vault.Identity.generate(cnsa2)`, `.save(path, passphrase)` and `.load(path, passphrase)`
  - `vault.encrypt(source, out, recipients, signer)`, `vault.decrypt(file, out, identity, ca, crl, signer, require_signature)` and `vault.load_signer(cert, key, passphrase)`
  - `pqcsuite.vpn.join.parse(text)`
  - the invitation fields written by `cli/vpn.py:cmd_invite`
  - `wolfpack` scanning through `python -m wolfpack scan PATH -o OUT`
- Produces: `main(out: Path) -> dict[str, str]`, which writes every fixture under `out` and returns `{relative path: sha256}`, the content of `MANIFEST.json`. Later stages point the same tests at new code.

- [ ] **Step 1: Write the failing tests**

```python
G = Path(__file__).parent

def test_manifest_hashes_match():
    for rel, digest in json.loads((G / "MANIFEST.json").read_text()).items():
        assert hashlib.sha256((G / rel).read_bytes()).hexdigest() == digest, rel

def test_vault_archives_open_and_match_plaintext(tmp_path):  # unsigned.pqv, signed.pqv, cnsa2.pqv
    ...  # decrypt each with its fixture key and passphrase "golden-test-only"; bytes equal vault/plain.txt

def test_signed_archive_verifies_against_fixture_ca(tmp_path):
    ...  # decrypt signed.pqv with ca=pki/ca/ca.crt, crl=pki/ca/crl.pem, require_signature=True

def test_ca_folder_lists_revoked_certificate_in_crl():
    ...  # CA("pki/ca", "golden-test-only"); the revoked.golden.invalid serial appears in crl.pem

def test_fixture_lifetimes_reach_past_2099():
    ...  # every certificate's not_valid_after, the CRL's next_update and the invitation's expires are after 2099-01-01

def test_invitation_parses_with_old_reader():
    assert join.parse((G / "vpn/invite.pqcinvite").read_text())["name"] == "laptop.golden.invalid"

def test_cbom_baseline_validates_and_ignore_comment_suppresses():
    ...  # wolf-pack/scripts/validate_cbom.py on readiness/baseline/cbom.json reports 0 errors;
         # the MD5 line marked `wolfpack:ignore` in readiness/project/app.py is suppressed in findings.json

def test_example_configs_load_with_old_loaders():
    ...  # edge.toml, vpn-hq.toml, vpn-branch.toml, wireguard-gateway.toml load with the functions
         # cli/edge.py and cli/vpn.py call for them
```

- [ ] **Step 2: Run them to verify they fail**

Run: `pytest tests/golden -v`

Expected: FAIL, because `MANIFEST.json` and the fixtures don't exist.

- [ ] **Step 3: Implement `main(out: Path) -> dict[str, str]` in `tools/make_fixtures.py`**

It writes these fixtures, using the Global Constraints lifetimes and names:
- **`pki/ca`:** a CA named "Golden Test CA". It issues `edge.golden.invalid`, `signer.golden.invalid` and `revoked.golden.invalid`, revokes the last one, and signs the CRL.
- **`vault/`:** `plain.txt` and keys. Then `unsigned.pqv`, `signed.pqv` (signed with the `signer.golden.invalid` certificate) and `cnsa2.pqv`.
- **`vpn/invite.pqcinvite`:** the fields from `cmd_invite`, with token `golden-token-not-secret`.
- **`readiness/project/`:** `app.py` using MD5 on a line marked `# wolfpack:ignore`, plus RSA-2048 key generation and AES-GCM, and a `.wolfpack.toml` with one `exclude`.
- **`readiness/baseline/`:** the output of scanning that project.
- **`configs/`:** copies of the four example TOMLs.

Finally it writes `README.md` (synthetic, disposable, regenerate with `python tools/make_fixtures.py tests/golden`), `.gitattributes` (`* -text`) and `MANIFEST.json`.

- [ ] **Step 4: Generate the fixtures**

Run: `PQCSUITE_OPENSSL=/opt/pqc/lib LD_LIBRARY_PATH=/opt/pqc/lib python tools/make_fixtures.py tests/golden`

Expected: the files listed in Step 3 and a `MANIFEST.json` with one entry per file.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/golden -v`

Expected: 8 passed on today's code.

- [ ] **Step 6: Commit**

```bash
git add tools/make_fixtures.py tests/golden
git commit -m "stage 0: golden fixtures from today's code"
```

### Task 6: Stage 0 report

**Files:**
- Modify: `tools/baseline.md` (section "Stage 0 summary")

- [ ] **Step 1: Write the summary**

It covers:
- findings F1–F6, each established or not, with evidence
- the baseline counts
- coverage by product
- precision and recall
- the fixture list
- what each finding means for Stage 1: in particular, whether the full-handshake contract can be executed here, or Stage 1 is pending CI

- [ ] **Step 2: Verify the stage**

Run: `pytest tools/tests tests/golden -q && git diff --stat 5f8c349 -- pqcsuite wolf-pack/wolfpack tests site .github | grep -v "^ tests/golden"`

Expected: tests pass, and the diff command prints nothing outside `tests/golden`, confirming no product code changed.

- [ ] **Step 3: Commit**

```bash
git add tools/baseline.md
git commit -m "stage 0: report"
```
