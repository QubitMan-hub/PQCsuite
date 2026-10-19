"""Build what a customer receives for one product: its wheel, acxelin-core's and every third-party wheel they need, with the
product's installers, README, manual and other docs, licence, example settings and service units. Nothing of another product.

    python tools/wheelhouse.py readiness OUT
    sh OUT/install.sh            (or install.ps1 on Windows)
"""
import shutil
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


CUSTOMER = ["install.sh", "install.ps1", "README.md", "LICENSE", "CHANGELOG.md", "docs", "config", "deploy/systemd"]


def package(product, out):
    out = build(product, out)
    src = ROOT / "products" / product
    for name in CUSTOMER:
        if (src / name).is_dir():
            shutil.copytree(src / name, out / name, dirs_exist_ok=True)
        elif (src / name).exists():
            shutil.copy2(src / name, out / name)
    return out


if __name__ == "__main__":
    print(package(sys.argv[1], sys.argv[2]))
