"""Scans the example systems with Wolf Pack and writes the pages the website links to: payments-api's report
(site/wolf-pack-sample.html) and the organisation dashboard of all three (site/wolf-pack-inventory.html)."""
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SYSTEMS = ["payments-api", "customer-portal", "batch-jobs"]
sys.path.insert(0, str(ROOT / "wolf-pack"))
from wolfpack import cli  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp)
    for name in SYSTEMS:
        cli.main(["scan", str(HERE / name), "-o", str(out / name), "--policy", "nist-ir-8547", "-q"])
    cli.main(["merge", *(str(out / n / "cbom.json") for n in SYSTEMS), "--name", "Example Bank", "-o", str(out / "inventory"), "-q"])
    shutil.copy(out / "payments-api" / "report.html", ROOT / "site" / "wolf-pack-sample.html")
    shutil.copy(out / "inventory" / "inventory.html", ROOT / "site" / "wolf-pack-inventory.html")
print("wrote site/wolf-pack-sample.html and site/wolf-pack-inventory.html")
