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
@pytest.mark.parametrize("product,first", [("readiness", "scan"), ("tls", "console"), ("vpn", "join")])
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
def test_the_readiness_folder_installs_offline_everywhere_with_the_crawler(tmp_path):
    """The folder carries compiled wheels for every system it supports, and the installer adds the crawler, so a customer's
    offline scan follows values through JavaScript, TypeScript, Java and Go like the image and the sample report."""
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import package
    house = package("readiness", tmp_path / "acxelin-readiness-1.0.0-wheelhouse")
    names = [w.name for w in house.glob("*.whl")]
    for dist in ("cryptography", "tree_sitter-", "tree_sitter_typescript"):
        for plat in ("win_amd64", "macosx_11_0_arm64", "manylinux2014_aarch64"):
            assert any(n.startswith(dist) and plat in n for n in names), (dist, plat)
    assert all(any(n.startswith("tree_sitter-") and f"cp{v}-" in n for n in names) for v in ("311", "312", "313", "314"))
    r = install(house / "install.sh", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    python = tmp_path / "prefix/readiness/bin/python"
    assert subprocess.run([str(python), "-c", "import tree_sitter, tree_sitter_typescript"]).returncode == 0, "the crawler is installed"


@slow
def test_install_offline_from_a_release_wheelhouse(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import package
    house = package("tls", tmp_path / "acxelin-tls-1.0.0-wheelhouse")
    shipped = {p.relative_to(house).as_posix() for p in house.rglob("*") if p.is_file()}
    assert {"install.sh", "install.ps1", "README.md", "LICENSE", "docs/manual.md", "config/example.toml", "deploy/systemd/acxelin-tls-edge.service"} <= shipped
    assert not [n for n in shipped if n.startswith("acxelin_readiness")], shipped
    r = install(house / "install.sh", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "from the wheels next to it" in r.stdout
    out = subprocess.run([str(tmp_path / "bin/acxelin-tls"), "ca", "init", "--name", "R", "--dir", str(tmp_path / "pki"), "--no-encrypt"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


@slow
def test_the_vpn_release_folder_installs_offline_and_carries_its_units(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from wheelhouse import package
    house = package("vpn", tmp_path / "acxelin-vpn-1.0.0-wheelhouse")
    shipped = {p.relative_to(house).as_posix() for p in house.rglob("*") if p.is_file()}
    units = {f"deploy/systemd/{u}" for u in ("acxelin-vpn-ipsec.service", "acxelin-vpn-wireguard.service", "strongswan-pqc.service",
                                              "acxelin-vpn-enroll.service", "acxelin-vpn-ca-maintain.service", "acxelin-vpn-ca-maintain.timer")}
    assert {"install.sh", "install.ps1", "README.md", "LICENSE", "CHANGELOG.md", "docs/manual.md", "config/site-hq.toml",
            "config/gateway.toml"} | units <= shipped
    assert any(n.startswith("vici-") for n in shipped), "a gateway installs acxelin-vpn[vpn] from the folder, offline"
    assert not [n for n in shipped if n.startswith(("acxelin_readiness", "acxelin_tls"))], shipped
    r = install(house / "install.sh", tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "from the wheels next to it" in r.stdout and "acxelin-vpn join" in r.stdout
    cmd = str(tmp_path / "bin/acxelin-vpn")
    assert "usage: acxelin-vpn" in subprocess.run([cmd, "--help"], capture_output=True, text=True).stdout
    doctor = subprocess.run([cmd, "doctor"], capture_output=True, text=True)
    assert doctor.returncode in (0, 3) and "acxelin-vpn 1.0.0" in doctor.stdout, doctor.stdout + doctor.stderr


def test_the_installers_of_every_product_differ_only_in_the_product_name():
    for name in ("install.sh", "install.ps1"):
        a, *rest = ((ROOT / f"products/{p}/{name}").read_text().replace(p, "PRODUCT") for p in ("tls", "readiness", "vpn"))
        assert all(a == b for b in rest), name


@slow
def test_an_old_system_openssl_gets_a_way_forward_not_just_a_failure(tmp_path):
    fake = tmp_path / "fake"
    fake.mkdir()
    (fake / "openssl").write_text("#!/bin/sh\necho 'OpenSSL 3.0.13 30 Jan 2024'\n")
    (fake / "openssl").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH", "ACXELIN_OPENSSL", "LD_LIBRARY_PATH")}
    env |= {"ACXELIN_PREFIX": str(tmp_path / "prefix"), "ACXELIN_BIN": str(tmp_path / "bin"), "PATH": f"{fake}:{Path(sys.executable).parent}:/usr/bin:/bin"}
    r = subprocess.run(["sh", str(ROOT / "products/tls/install.sh")], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=280)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ACXELIN_OPENSSL=/path/to/openssl-3.5/lib sh " in r.stdout


@pytest.mark.skipif(not shutil.which("pwsh"), reason="needs PowerShell (GitHub's Ubuntu runners have it)")
@pytest.mark.parametrize("product", ["tls", "readiness", "vpn"])
def test_install_ps1_passes_py_its_arguments_whole(tmp_path, product):
    """With the Windows py launcher present, the Python check must run `py -3 -c CODE`. A splatted string reached it as
    `py - 3 -c CODE`, and `-` made Python read a program from the console: the installer stopped at Python's >>> prompt."""
    script = (ROOT / f"products/{product}/install.ps1").read_text()
    probe = script[script.index("$py = $null"):script.index("if (-not $py)")]
    (tmp_path / "py").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/argv"\n')
    (tmp_path / "py").chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-Command", probe], env=env, cwd=tmp_path, timeout=60, check=True)
    assert (tmp_path / "argv").read_text().splitlines()[:2] == ["-3", "-c"]
