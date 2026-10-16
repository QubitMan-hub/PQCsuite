# Stage 0 ledger

- Ruling: the strongSwan build is skipped in Stage 0 and attempted in Stage 4. Why: the sandbox has 1 CPU, the OpenSSL build already takes over the tool time limit, and only Stage 4 uses strongSwan. Cost if wrong: Stage 4 starts without knowing whether strongSwan builds here; the CI job builds it anyway.
- Ruling: F4 corrects the spec. The browser is available, so Stage 5's Playwright evidence can be produced here and Stage 5 need not be pending on CI. Why: Chromium launched. Cost if wrong: none; it ran.
- Ruling: OpenSSL is built in the background with `setsid`. Why: a foreground build exceeds the 300 s tool limit, and an earlier background build died with its tool call. Cost if wrong: none.
- Ruling: coverage is re-run with `--source=pqcsuite,wolf-pack/wolfpack`. Why: `pyproject.toml` limits coverage to `pqcsuite`, so Task 2's data has no Readiness engine lines. Cost if wrong: one extra 3-minute run.
