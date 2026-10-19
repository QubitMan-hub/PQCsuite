"""The commands the manual, upgrade notes and README show are ones the product accepts: every command in a code block parses in
full, and every `acxelin-vpn ...` named in the text is a real command, so the docs cannot drift from the product."""
import re
import shlex
from pathlib import Path

import pytest

from acxelin_vpn import cli

DOCS = [Path(__file__).resolve().parents[1] / p for p in ("README.md", "docs/manual.md", "docs/upgrade.md")]


def blocks(text):
    for block in re.findall(r"```\n(.*?)```", text, re.S):
        for line in block.replace("\\\n", " ").splitlines():
            parts = re.split(r"(?:^|\s)acxelin-vpn\s", line)
            if len(parts) > 1 and not line.startswith(("wrote", "Send", "acxelin-vpn 1.0")):
                yield parts[-1].split("  #")[0].strip()


def named(text):
    for span in re.findall(r"`acxelin-vpn ([^`]+)`", re.sub(r"```.*?```", "", text, flags=re.S)):
        for alternative in span.split("\\|"):
            yield alternative.split()[:2]


def known(words):
    sub = next(a for a in cli.parser()._actions if a.dest == "cmd").choices
    if words[0] not in sub:
        return False
    nested = next((a for a in sub[words[0]]._actions if a.dest == "ca_cmd"), None)
    return nested is None or len(words) < 2 or words[1] in nested.choices or words[1] == "..."


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_command_in_a_code_block_parses(doc):
    bad = []
    for c in blocks(doc.read_text(encoding="utf-8")):
        try:
            cli.parser().parse_args(shlex.split(c))
        except SystemExit:
            bad.append(c)
    assert bad == []


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_command_named_in_the_text_exists(doc):
    spans = list(named(doc.read_text(encoding="utf-8")))
    assert (spans or doc.name == "README.md") and [s for s in spans if not known(s)] == []
