# Threat model

## What Acxelin Readiness does

It reads files and talks to the endpoints you name, then writes reports. It never changes the scanned files and never sends their content anywhere.

## Hostile input

The scanned repository, image or capture may be hostile.

| Risk | Defence |
|---|---|
| Huge files | Source files over 2 MB are skipped and named in the report |
| Huge trees | Project scans stop at 50,000 files, 512 MB or 300 seconds, with a clear message |
| Deep nesting | Python too deeply nested to analyse is read for strings and comments only, and named in the report |
| Container layers | Archives are unpacked with path checks; entries that escape the target folder are refused |

## Network

- Endpoint probes send only handshakes: no application data, and no credentials.
- Certificate checks during probes are not trust decisions. They record what the server presented.

## Secrets in outputs

- Reports name where key material sits and of what kind. They never include the key itself.
- `findings.json` holds short code snippets around each detection. Treat the output folder as sensitive as the code you scanned.

## Not covered

Proving cryptography absent, judging whether a found use is correct, and verifying claims made in comments (`acxelin:ignore`, `usedforsecurity=False`). These are the developer's statements, and the report marks them as such.
