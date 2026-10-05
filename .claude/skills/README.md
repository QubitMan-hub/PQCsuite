# Agent skills for Claude Code sessions in this repository

| Skill | What it does | Version | Source | Licence |
|---|---|---|---|---|
| `archify` | Architecture, workflow, sequence, data-flow and lifecycle diagrams as standalone HTML, checked against the repository's source lines | 3.0.1 | https://github.com/tt-a1i/archify | MIT (`archify/LICENSE`, `archify/THIRD_PARTY_NOTICES.md`) |

Vendored without its own test suite and development lockfile; it needs Node.js 18+ and nothing else at run time
(`node .claude/skills/archify/bin/archify.mjs doctor`). Not shipped with the product and excluded from CodeQL.
Diagrams made with it live in `docs/architecture/` (the `.architecture.json` file is the source; the `.html` is the result).

To update: `npx skills add tt-a1i/archify -g`, read the changes, then copy `~/.agents/skills/archify` here again
without `test/`, `node_modules/` and `package-lock.json`.
