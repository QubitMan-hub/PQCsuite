# Architecture diagrams

Interactive diagrams drawn from the code with the archify skill (`.claude/skills/archify`). Each box links to the source lines it
summarises, pinned to the commit in the file, and archify checks those lines exist before it renders.

| Diagram | Page | Source |
|---|---|---|
| The whole suite: the console, the four products, Wolf Pack, and what each one talks to | [site/architecture/pqc-suite.html](../../site/architecture/pqc-suite.html) | [pqc-suite.architecture.json](pqc-suite.architecture.json) |
| The Acxelin VPN desktop app: what runs as you, what runs as administrator, and how keys are agreed | [site/architecture/acxelin-vpn-desktop.html](../../site/architecture/acxelin-vpn-desktop.html) | [acxelin-vpn-desktop.architecture.json](acxelin-vpn-desktop.architecture.json) |

The pages are published with the website. To change one, edit its JSON and run:

```sh
node .claude/skills/archify/bin/archify.mjs finalize architecture docs/architecture/NAME.architecture.json site/architecture/NAME.html --repo-root . --quality showcase
```

Set `ARCHIFY_CHROME` to a Chrome or Chromium executable so its browser check runs. When the code moves, update the cited
lines and the pinned `revision`; archify refuses lines that do not exist at that commit.
