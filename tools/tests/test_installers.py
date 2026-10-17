"""The one-command installers: a client runs ./install.sh (Linux, macOS) or install.ps1 (Windows, tested in CI) and gets a
working command on PATH, from a checkout or offline from a release wheelhouse."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="the POSIX installer; install.ps1 runs in Windows CI")
slow = pytest.mark.skipif(os.environ.get("ACXELIN_INSTALL_TEST") != "1", reason="set ACXELIN_INSTALL_TEST=1")


def install(script, tmp_path, *args):
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH")}
    env |= {"ACXELIN_PREFIX": str(tmp_path / "prefix"), "ACXELIN_BIN": str(tmp_path / "bin"), "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin"}
    return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=280)


@slow
@pytest.mark.parametrize("product,first", [("readiness", "scan"), ("tls", "console")])
def test_install_from_a_checkout_then_use_reinstall_and_uninstall(tmp_path, product, first):
    r = install(ROOT / f"products/{product}/install.sh", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    cmd = tmp_path / "bin" / f"acxelin-{product}"
    assert subprocess.run([str(cmd), "--version"], capture_output=True, text=True).stdout.strip() == f"acxelin-{product} 1.0.0"
    assert f"acxelin-{product} {first}" in r.stdout, "the installer ends by saying what to do next"
    again = install(ROOT / f"products/{product}/install.sh", tmp_path)
    assert again.returncode == 0, again.stderr
    gone = install(ROOT / f"products/{product}/install.sh", tmp_path, "--uninstall")
    assert gone.returncode == 0 and not cmd.exists() and not (tmp_path / "prefix" / product).exists()


@slow
def test_install_offline_from_a_release_wheelhouse(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import build
    house = build("tls", tmp_path / "acxelin-tls-1.0.0-wheelhouse")
    shutil.copy(ROOT / "products/tls/install.sh", house / "install.sh")
    r = install(house / "install.sh", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "from the wheels next to it" in r.stdout
    out = subprocess.run([str(tmp_path / "bin/acxelin-tls"), "ca", "init", "--name", "R", "--dir", str(tmp_path / "pki"), "--no-encrypt"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_the_installers_of_both_products_differ_only_in_the_product_name():
    for name in ("install.sh", "install.ps1"):
        a, b = ((ROOT / f"products/{p}/{name}").read_text().replace(p, "PRODUCT") for p in ("tls", "readiness"))
        assert a == b, name
