"""Build a product's wheelhouse: its wheel, acxelin-core's, and every third-party wheel they need.

    python tools/wheelhouse.py readiness OUT
    pip install --no-index --find-links OUT acxelin-readiness
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(product, out, extras=""):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--quiet", "--wheel-dir", str(out), str(ROOT / "core"),
                    f"{ROOT / 'products' / product}{extras}"], check=True)
    return out


if __name__ == "__main__":
    print(build(sys.argv[1], sys.argv[2]))
