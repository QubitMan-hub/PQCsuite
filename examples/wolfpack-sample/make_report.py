"""Scans payments-api with Wolf Pack and writes the report the website links to (site/wolf-pack-sample.html)."""
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "wolf-pack"))
from wolfpack import cli  # noqa: E402

with tempfile.TemporaryDirectory() as out:
    cli.main(["scan", str(HERE / "payments-api"), "-o", out, "-q"])
    shutil.copy(Path(out) / "report.html", ROOT / "site" / "wolf-pack-sample.html")
print("wrote site/wolf-pack-sample.html")
