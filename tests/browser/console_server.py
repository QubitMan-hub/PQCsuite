"""The console for the browser tests: a fresh CA with a few certificates, token "browser-test", on 127.0.0.1:8900."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

d = Path(tempfile.mkdtemp())
run = lambda *a: subprocess.run([sys.executable, "-m", "pqcsuite", *a], check=True, cwd=d, stdout=subprocess.DEVNULL)
run("ca", "init", "--dir", "ca", "--name", "Browser Test Root", "--no-encrypt")
for kind, name, days in [("server", "api.example.test", "397"), ("client", "operator", "397"), ("server", "old.example.test", "10")]:
    run("ca", "issue", "--dir", "ca", kind, name, "--out", name, "--days", days)
os.environ["PQCSUITE_CONSOLE_TOKEN"] = "browser-test"
os.execv(sys.executable, [sys.executable, "-m", "pqcsuite", "console", "--ca", str(d / "ca"), "--listen", "127.0.0.1:8900"])
