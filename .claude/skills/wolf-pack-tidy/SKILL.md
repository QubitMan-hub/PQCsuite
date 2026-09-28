---
name: wolf-pack-tidy
description: Keep Wolf Pack (the wolf-pack/ folder) minimal without changing what it finds. Use when asked to clean up, simplify, minimise or de-duplicate code, tables, files or docs in wolf-pack/. Run every command from wolf-pack/.
---

# Tidy

Goal: fewer lines and files, the same output. Minimal comments, no speculative abstractions.

## 1. Measure first

- `wc -l wolfpack/*.py wolfpack/scouts/*.py | tail -1`
- `python -m wolfpack bench bench/corpus > before.txt`
- Snapshot everything the pack reports (sightings with verdicts, assets with tiers, CBOM components) on the dev corpus and any unseen repos you have locally. **Never on `eval/heldout/repos/`.**

## 2. Look for

- **Dead code:** `python -m vulture wolfpack --min-confidence 60` (the `_` rule functions are registered by decorator; ignore them) and `python -m pyflakes wolfpack tests scripts`.
- **Restated tables:** a dict or list that repeats data another module already holds (the elders' `CATALOG`, `ALIAS`, `CURVES`, `HYBRIDS`, `MODES`; the implementation scout's constants). Derive it instead.
- **Identity maps** such as `{"GCM": "gcm", ...}`: use a set and `.lower()`.
- **Two regexes or lists for one idea**, such as deny-list words: keep one in `scouts/__init__.py` or `elders.py`.
- **Duplicate CLI flags or config**, such as a flag that `--without ROLE` already covers, or dependencies declared in two places.
- **Tracked generated files:** outputs, caches and `__pycache__` belong in `.gitignore`.
- **Stale docs:** test counts, line counts, flags and file maps in `README.md`, `CLAUDE.md` and `docs/`.

## 3. Rules

- One change per step. Rerun the snapshot after each step. Any difference must be explained and intended, or reverted.
- Never edit `bench/truth.json`, the pre-registration, `eval/heldout/heldout.py` or the committed labels.
- Don't merge code that only looks alike when the behaviour differs. Readable beats short.

## 4. Finish

- `python -m unittest discover -s tests`, the bench (it must match `before.txt`), then `scan` plus `scripts/validate_cbom.py` with 0 errors.
- Report lines before and after, every intended output difference, and what was left alone and why.
