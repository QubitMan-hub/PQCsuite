"""The VPN window: a page on this machine's loopback address that joins from an invitation, connects, disconnects and says
whether this machine is protected. `pqcsuite vpn app` holds the tunnel; closing the page leaves it as it is.

The page is reachable only on 127.0.0.1, only with the random token in the address the command opens, and only under its
own host name (a page from elsewhere cannot borrow it through DNS rebinding). Passphrases go from the page to this process
and nowhere else; they are never written or logged."""
import hmac
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .. import HTTP_IDLE, content_length, explain
from ..console import Backoff, policy
from ..pki import encrypted
from ..storage import write
from . import join
from .wireguard import Client


class App:
    def __init__(self, invitation=None, folder=None, interface="wg0", apply=True):
        self.folder = Path(folder) if folder else Path.home() / ".pqcsuite" / "vpn"
        self.invitation = Path(invitation) if invitation else self.newest()
        self.interface, self.apply = interface, apply
        self.client = self.thread = None
        self.lock, self.token = threading.Lock(), secrets.token_urlsafe(24)

    def newest(self):
        found = sorted(self.folder.glob("*.pqcinvite"), key=lambda p: p.stat().st_mtime) if self.folder.is_dir() else []
        return found[-1] if found else None

    def state(self):
        out = {"invitation": None, "enrolled": False, "needs_passphrase": False, "error": None, "apply": self.apply}
        if self.invitation:
            try:
                inv = join.read(self.invitation)
                device = join.device_for(self.invitation)
                out |= {"invitation": {"file": self.invitation.name, "name": inv["name"], "gateway": inv["gateway"], "expires": inv.get("expires")},
                        "enrolled": (device / "cert.pem").exists(), "needs_passphrase": not (device / "cert.pem").exists() or encrypted(device / "key.pem")}
            except ValueError as e:
                out["error"] = str(e)
        client = self.client
        out["status"] = client.status() if client else {"state": "disconnected"}
        return out

    def load(self, name, text):
        """Keep an invitation the person opened in the page next to the device folder it will create."""
        inv = join.parse(text, "the chosen file")
        stem = re.sub(r"[^A-Za-z0-9_-]", "_", Path(str(name)).stem)[:60] or inv["name"]
        path = self.folder / f"{stem}.pqcinvite"
        if path.exists() and join.read(path)["name"] != inv["name"]:
            raise ValueError(f"{path.name} already holds an invitation for someone else; rename the file and open it again")
        if not path.exists():
            write(path, text.encode(), secret=True)
        with self.lock:
            self.invitation = path
        return self.state()

    def connect(self, passphrase="", repeat=None):
        with self.lock:
            if self.client:
                raise ValueError("already connected or connecting; disconnect first")
            if not self.invitation:
                raise ValueError("open the invitation file your administrator sent first")
            inv, device = join.read(self.invitation), join.device_for(self.invitation)
            if self.apply:
                join.preflight("pqcsuite vpn app")
            secret = passphrase.encode() if passphrase else None
            if join.must_enroll(inv, device):
                if not secret or repeat is None or passphrase != repeat:
                    raise ValueError("choose a passphrase for this device's key and type it twice; nothing was changed")
                join.enroll(inv, device, self.invitation, secret)
            elif encrypted(device / "key.pem"):
                try:
                    load_pem_private_key((device / "key.pem").read_bytes(), secret)
                except (TypeError, ValueError):
                    raise ValueError("that passphrase does not unlock this device's key; try again") from None
            self.client = Client(inv["gateway"], device, self.interface, inv.get("server_name"), self.apply, key_passphrase=secret)
            self.thread = threading.Thread(target=self.client.run, daemon=True)
            self.thread.start()
        return self.state()

    def disconnect(self):
        with self.lock:
            client, thread, self.client = self.client, self.thread, None
        if client:
            client.stop.set()
            thread.join(15)
            client.close()
        return self.state()

    def handle(self, method, path, body):
        try:
            if method == "GET" and path == "/api/state":
                return 200, self.state()
            if method == "POST" and path == "/api/invitation":
                if not isinstance(body.get("text"), str) or len(body["text"]) > 64_000:
                    raise ValueError("choose the .pqcinvite file your administrator sent")
                return 200, self.load(body.get("name") or "invitation", body["text"])
            if method == "POST" and path == "/api/connect":
                fields = [body.get(k) for k in ("passphrase", "repeat")]
                if not isinstance(fields[0], str) or not isinstance(fields[1], (str, type(None))) or any(len(f or "") > 1024 for f in fields):
                    raise ValueError("enter the device key passphrase")
                return 200, self.connect(*fields)
            if method == "POST" and path == "/api/disconnect":
                return 200, self.disconnect()
            return 404, {"error": "not found"}
        except (ValueError, OSError) as e:
            return 400, {"error": explain(e), "state": self.state()}
        except Exception as e:  # a failure must reach the page as words, never as a dropped request
            return 500, {"error": f"{e.__class__.__name__}: {explain(e)}", "state": self.state()}


def serve(app, listen=("127.0.0.1", 0)):
    html = resources.files(__package__).joinpath("app.html").read_bytes()
    csp, backoff = policy(html), Backoff()

    class Handler(BaseHTTPRequestHandler):
        timeout = HTTP_IDLE

        def reply(self, status, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                         ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", csp)):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def route(self, method):
            port = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                return self.reply(421, {"error": "wrong host"})
            path = self.path.split("?")[0]
            if method == "GET" and path == "/":
                return self.reply(200, html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            if backoff.blocked(self.client_address[0]):
                return self.reply(429, {"error": "too many wrong tokens; wait a minute"})
            if not hmac.compare_digest(self.headers.get("Authorization", "").removeprefix("Bearer ").encode(), app.token.encode()):
                backoff.failed(self.client_address[0])
                return self.reply(401, {"error": "open the address printed by `pqcsuite vpn app` again"})
            n = content_length(self.headers)
            if n is None or n > 1 << 17:
                return self.reply(400, {"error": "bad request size"})
            try:
                body = json.loads(self.rfile.read(n)) if n else {}
            except ValueError:
                return self.reply(400, {"error": "invalid JSON"})
            self.reply(*app.handle(method, path, body if isinstance(body, dict) else {}))

        def do_GET(self):
            self.route("GET")

        def do_POST(self):
            self.route("POST")

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer(listen, Handler)
