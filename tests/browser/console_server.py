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
project = d / "payments-api"
project.mkdir()
(project / "keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\ndef make():\n return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
(project / "service.py").write_text("from keys import make\ndef checkout():\n return make()\n")
repositories = d / "repositories"
repositories.mkdir()
web = repositories / "web-api"
web.mkdir()
(web / "keys.ts").write_text('import crypto from "node:crypto";\nexport function digest(data: string) { return crypto.createHash("sha256").update(data); }')
(web / "api.ts").write_text('import {digest} from "./keys";\nexport function checkout(data: string) { return digest(data); }')
os.environ["PQCSUITE_CONSOLE_TOKEN"] = "browser-test"
os.chdir(d)  # audit output belongs to this disposable fixture, not the checkout
os.execv(sys.executable, [sys.executable, "-m", "pqcsuite", "console", "--ca", str(d / "ca"), "--listen", "127.0.0.1:8900", "--project", str(project), "--repositories", str(repositories), "--project-history", str(d / "history.json"), "--scan", "localhost:1"])
