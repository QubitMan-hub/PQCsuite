"""The documentation and the website describe the product as it is: every quoted command and option exists, and every link
inside the repository and the site leads somewhere."""
import argparse
import html
import re
import unittest
from pathlib import Path

from pqcsuite.cli import parser

ROOT = Path(__file__).resolve().parent.parent
# Commands that moved to Acxelin Readiness, Acxelin TLS and Acxelin VPN; the old documents that still name them are replaced in Stage 6, when this list goes.
MOVED = {"scan", "readiness", "ca", "tls", "vpn"}
DOCS = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs/*.md", "pqcsuite/console/console.html", "examples/*.toml",
        "deploy/**/*.service", "deploy/**/*.yaml", "deploy/**/*.tpl", "deploy/**/*.hcl", "deploy/**/*.sh"]
COMMAND = re.compile(r"(?<!-t )(?:^|(?<=[\s$/]))pqcsuite ((?:[a-z][\w-]*)(?: [a-z][\w-]*)?)([^\n;|&#)]*)")


def files(patterns):
    return sorted({p for pattern in patterns for p in ROOT.glob(pattern) if p.is_file()})


def code(path):
    """The parts of a file that are code: fenced blocks and `spans` in Markdown, <pre> and <code> in HTML, everything else whole."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        fenced = re.findall(r"```[^\n]*\n(.*?)```", text, re.S)
        return fenced + re.findall(r"`([^`\n]+)`", re.sub(r"```.*?```", "", text, flags=re.S))
    if path.suffix == ".html":
        return [html.unescape(re.sub(r"<[^>]+>", "", m)) for m in re.findall(r"<(pre|code)\b[^>]*>(.*?)</\1>", text, re.S) for m in [m[1]]]
    return [text]


def commands():
    """{subcommand path: option strings} for every command the CLI has."""
    out = {}

    def walk(p, path):
        out[path] = {o for a in p._actions for o in a.option_strings}
        for a in p._actions:
            if isinstance(a, argparse._SubParsersAction):
                for name, sub in a.choices.items():
                    walk(sub, (*path, name))
    walk(parser(), ())
    return out


class DocsTest(unittest.TestCase):
    def test_every_quoted_command_and_option_exists(self):
        known, wrong, seen = commands(), [], 0
        for path in files(DOCS):
            for block in code(path):
                for line in block.splitlines():
                    for m in COMMAND.finditer(line):
                        words = m.group(1).split()
                        cmd = next((tuple(words[:n]) for n in (2, 1) if tuple(words[:n]) in known), None)
                        where = f"{path.relative_to(ROOT)}: pqcsuite {m.group(1)}{m.group(2)}".strip()
                        if cmd is None:
                            if words[0] in MOVED:
                                continue
                            wrong.append(f"{where}  (no such command)")
                            continue
                        seen += 1
                        rest = " ".join(words[len(cmd):]) + m.group(2)
                        wrong += [f"{where}  (no option {o})" for o in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*|-[a-z])\b", rest)
                                  if o not in known[cmd]]
        self.assertGreater(seen, 20, "the command pattern stopped matching the documentation")  # 27 quoted commands once the VPN left
        self.assertEqual(wrong, [])

    def test_links_inside_the_repository_lead_somewhere(self):
        broken = []
        for path in files(["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs/*.md"]):
            for target in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
                if re.match(r"[a-z]+:", target) or target.startswith("#"):
                    continue
                if not (path.parent / target.split("#")[0]).exists():
                    broken.append(f"{path.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
