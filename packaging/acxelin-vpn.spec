# PyInstaller: one folder holding "Acxelin VPN" (the desktop app, no console) and "acxelin-vpn" (the same program with a
# console, for support and scripts), sharing one copy of Python and the libraries. Built by packaging/build.py.
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

root = Path(SPECPATH).parent
openssl = os.environ.get("ACXELIN_OPENSSL")
icon = os.environ.get("ACXELIN_ICON")
version = os.environ.get("ACXELIN_VERSION", "0")
TRAYS = {"win32": ["win32"], "darwin": ["darwin"]}.get(sys.platform, ["xorg", "appindicator", "gtk"]) + ["dummy"]  # importing pystray needs a display
binaries = [(str(p), "openssl") for p in Path(openssl).iterdir() if p.suffix in (".dll", ".dylib")] if openssl else []

a = Analysis([str(root / "packaging" / "acxelin_vpn.py")], pathex=[str(root)], binaries=binaries,
             datas=collect_data_files("pqcsuite"),
             hiddenimports=collect_submodules("pqcsuite") + ["PIL.Image", "PIL.ImageDraw"] + [f"pystray._{b}" for b in TRAYS],
             excludes=["tkinter", "wolfpack", "boto3", "botocore", "pytest", "hypothesis"])
pyz = PYZ(a.pure)
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="Acxelin VPN", console=False, icon=icon)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="acxelin-vpn", console=True, icon=icon)
coll = COLLECT(gui, cli, a.binaries, a.datas, name="Acxelin VPN")
if sys.platform == "darwin":
    app = BUNDLE(coll, name="Acxelin VPN.app", icon=icon, bundle_identifier="com.acxelin.vpn",
                 info_plist={"LSUIElement": True, "CFBundleShortVersionString": version, "CFBundleVersion": version,
                             "NSHumanReadableCopyright": "Acxelin Quantum"})
