---
name: pqcsuite-project-scan
description: Run and review PQCsuite local cryptographic project scans with bounded static code relationships and private evidence.
---

Use when asked to inventory local source cryptography or investigate migration impact.

1. Read `docs/CODE-CRAWLER.md` and the project's instructions. Use the existing virtual environment; from this checkout install `./wolf-pack[crawler]` and `.[scan-web]` for Python plus JavaScript/TypeScript relationships, or the base `./wolf-pack` and `.[scan]` for Python if needed. Do not claim an unpublished version is on PyPI.
2. Run `pqcsuite scan PATH --out OUTPUT` on an authorized local project. Keep output outside the scanned source or use `pqcsuite-out`. Scanning does not authorize execution of project code, network endpoint probes, uploads or dependency installation from the scanned project.
3. Inspect assessment.json, report.html and relationships.json. Distinguish accepted uses, imports, declarations and test-only findings. Report unresolved dispatch and graph limits. Follow supported callers as static evidence; do not infer business ownership or runtime security.
4. Keep outputs private. Unified exports omit snippets and raw source literals but still contain file and symbol names. Share only when authorized. For the console register folders with `--project` or choose the administrator-approved parent with `--repositories`. Add repository accepts only immediate child names and rejects outside paths and symlinks. Preserve that restriction. Summary history uses shared private locking; advanced views expose coverage gaps and test-only assets.
5. Validate changes with the crawler/project fixtures and appropriate browser tests. Use the measured results in the documentation; don't invent accuracy or product superiority claims. Update AGENT_HANDOFF.md for another contributor.
