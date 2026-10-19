# Golden fixtures

Written by `tools/make_fixtures.py` from the suite at commit 5f8c349 (Stage 0 of the four-product restructure).
Every key, certificate, token and passphrase here is synthetic, made for these tests and disposable. Names end in
`.invalid`; the passphrase is `golden-test-only`. None of it protects anything.

Regenerate with `python tools/make_fixtures.py tests/golden` (with OpenSSL 3.5+ for the suite), then update
`MANIFEST.json` in the same commit. Regenerating changes every key, so do it only on purpose.
