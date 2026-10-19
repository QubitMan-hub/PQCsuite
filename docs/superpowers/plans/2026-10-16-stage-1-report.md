# Stage 1 report: Acxelin Readiness + CBOM

Branch `restructure/stage-0`, from base `5f8c349`.

## Evidence (all executed here)
- `core/tests` and `products/readiness/tests`: 224 passed (includes the wheel install test with `ACXELIN_INSTALL_TEST=1`, 9 console journeys and 8 website journeys in Chromium 141, axe in light, dark and 390px).
- Root suite (old `pqcsuite`, plus golden fixtures): 293 passed, 28 skipped, 1 known-flaky test deselected. The 28 skips are the privileged and optional-service tests listed in `tools/baseline.md`.
- Quality gate: precision 1.000, recall 1.000 on 174 pairs, `truth.json` hash unchanged.
- `ruff check .` clean.

## Delivered
- `acxelin-core`: config, files, http, console access contract, OpenSSL binding (`ACXELIN_OPENSSL`), `pki.algorithm_of`.
- `acxelin-readiness`: no Wolf Pack names or structure; role switchboard and ablation flags removed (archived at tag `research-archive-2026-10`); CBOM merge contract; CNSA 2.0 unverified-AES fix; old names read through 1.x; `scan`, `grade`, `report`, `merge`, `doctor`, `console`, `console link`; console with Playwright journeys; Dockerfile (non-root) and Action; website section with sample report built from a real scan.

## Remaining gaps
- Deployment verification (`verify_endpoint`) and its console journey wait for core `pki` (Stage 2). Until then it lives in `pqcsuite/project.py`.
- `.github/workflows/pages.yml` is broken until Stage 5; the new site builds with `python tools/build_site.py`.
- No CI workflow exists yet for the new products; none has run on Windows or macOS. Supported-platform claims are unverified outside Linux.
- Not pushed: the sandbox has no GitHub credentials. The branch is delivered as a git bundle.
- The report page keeps its existing kicker-and-stat-cards layout (an established design), not redesigned.
