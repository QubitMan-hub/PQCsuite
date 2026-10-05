"""The console: one page for certificates, edges, VPN tunnels, backups and readiness scans.

It listens on localhost and wants a bearer token on every API call. Put `pqcsuite tls edge --policy transition` in front of it for
remote access: browsers already do X25519MLKEM768, though they cannot verify ML-DSA certificates yet.
"""
import base64
import hashlib
import hmac
import http.client
import json
import logging
import os
import secrets
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from .. import HTTP_IDLE, NAME, __version__, build, content_length, read_toml
from ..pki import CA, CAError, append, encrypted
from ..tls import hostport
from ..vpn.charon import protected

log = logging.getLogger("pqcsuite.console")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@dataclass
class Settings:
    listen: str = "127.0.0.1:8900"
    ca: str = ""
    edges: list = field(default_factory=list)
    vpn: list = field(default_factory=list)
    wireguard: list = field(default_factory=list)
    backups: list = field(default_factory=list)
    project_roots: list = field(default_factory=list)
    project_history: str = ""
    project_state: str = ""
    repository_directory: str = ""
    scan_targets: list = field(default_factory=list)
    scan_every_hours: float = 0.0
    check_updates: bool = False
    audit_log: str = "console-audit.jsonl"

    @classmethod
    def load(cls, path):
        d = read_toml(path).get("console", {})
        s = build(cls, d, "[console]")
        if s.scan_every_hours and s.scan_every_hours < 0.25:
            raise ValueError("[console]: scan_every_hours must be at least 0.25 (15 minutes), or 0 for no scheduled scans")
        return s


class App:
    def __init__(self, settings, token=None):
        self.s = settings
        self.token = token or os.environ.get("PQCSUITE_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
        self.last_scan, self.scanning, self.scan_error = None, False, None
        self.latest, self.latest_checked = None, 0.0
        self.lock = threading.Lock()
        self.project_cancel = threading.Event()
        self.projects = [Path(p).resolve() for p in settings.project_roots]
        self.repository_directory = Path(settings.repository_directory).resolve() if settings.repository_directory else None
        self.project_cache = None
        self.project_scan = {"running": False, "stage": "", "last": None, "error": None, "selected": 0}
        from ..project import ProjectStore
        self.project_store = ProjectStore(settings.project_state) if settings.project_state else None
        if self.project_store:
            if self.repository_directory:
                for name in self.project_store.read()['registrations'].get(self.project_store.key(self.repository_directory), []):
                    try:
                        path = self.approved_project(name)
                        if path not in self.projects:
                            self.projects.append(path)
                    except (OSError, ValueError):
                        pass  # Persisted names never grant access beyond today's approved parent.
            saved = [self.project_store.assessment(p) for p in self.projects]
            self.project_scan['last'] = max((a for a in saved if a), key=lambda a: a['finished'], default=None)
            if self.project_scan['last']:
                self.project_scan['selected'] = saved.index(self.project_scan['last'])

    def ca(self):
        if not self.s.ca:
            raise CAError("no CA configured (start the console with --ca)")
        pw = os.environ.get("PQCSUITE_CA_PASSPHRASE")
        return CA(self.s.ca, pw.encode() if pw and encrypted(Path(self.s.ca) / "ca.key") else None)

    def audit(self, action, detail):
        line = json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action, **detail})
        with self.lock:
            append(self.s.audit_log, line)
        log.info("console: %s %s", action, detail)

    def certificates(self):
        ca = self.ca()
        import datetime as dt
        now = dt.datetime.now(dt.timezone.utc)
        rows = [vars(r) | {"days_left": (dt.datetime.fromisoformat(r.not_after) - now).days} for r in ca.records()]
        return {"root": {"subject": ca.cert.subject.rfc4514_string(), "expires": ca.cert.not_valid_after_utc.date().isoformat(),
                         "algorithm": ca.algorithm}, "certificates": rows}

    def edges(self):
        return self._statuses(self.s.edges, "name", "an edge")

    def tunnels(self):
        from ..vpn.charon import Charon, CharonError
        out = []
        for uri in self.s.vpn:
            try:
                with Charon(uri) as ch:
                    out += [{"source": uri, **t} for t in ch.tunnels()]
            except (CharonError, OSError, ImportError) as e:
                out.append({"source": uri, "error": str(e)})
        return out

    def remote_users(self):
        return self._statuses(self.s.wireguard, "user", "a WireGuard gateway", skip="_events")

    @staticmethod
    def _statuses(urls, key, what, skip=None):
        """One row per entry of each service's /status; an address that is down or answers like something else is one error row."""
        out = []
        for url in urls:
            try:
                with NO_PROXY.open(url.rstrip("/") + "/status", timeout=3) as r:
                    status = json.loads(r.read())
                entries = {k: v for k, v in status.items() if k != skip} if isinstance(status, dict) else None
                if entries is None or not all(isinstance(v, dict) for v in entries.values()):
                    raise ValueError(f"this address does not answer like {what}'s /status")
                out += [{"source": url, key: k, **v} for k, v in entries.items()]
            except (OSError, ValueError, http.client.HTTPException) as e:
                out.append({"source": url, "error": str(e)})
        return out

    def backups(self):
        from ..vault import VaultError, inspect
        out = []
        for folder in self.s.backups:
            for f in sorted(Path(folder).glob("*.pqv"), reverse=True)[:200]:
                try:
                    out.append({"file": str(f), **inspect(f)})
                except (VaultError, OSError, ValueError) as e:
                    out.append({"file": str(f), "error": str(e)})
        return out

    def run_scan(self, targets):
        targets = list(targets)
        from ..readiness import scan
        with self.lock:
            if self.scanning:
                raise CAError("a scan is already running")
            self.scanning, self.scan_error = True, None

        def work():
            try:
                results = scan.scan(targets)
                before = {e["target"]: e["grade"] for e in (self.last_scan or {}).get("endpoints", [])}
                changes = [{"target": r["target"], "before": before.get(r["target"]), "after": r["grade"]}
                           for r in results if self.last_scan and before.get(r["target"]) != r["grade"]]
                for c in changes:
                    log.warning("readiness: %s went from %s to %s", c["target"], c["before"] or "not scanned", c["after"])
                self.last_scan = {"finished": time.time(), "targets": targets, "summary": scan.summary(results), "endpoints": results, "changes": changes}
            except Exception as e:
                log.exception("readiness scan failed")
                self.scan_error = f"the scan failed: {e}"
            finally:
                self.scanning = False
        threading.Thread(target=work, daemon=True).start()

    def schedule(self):
        """With scan_every_hours and scan_targets set, scan them now and then again every scan_every_hours; each scan lists
        the endpoints whose grade changed since the one before."""
        if not (self.s.scan_every_hours and self.s.scan_targets):
            return

        def loop():
            while True:
                if not self.scanning:
                    try:
                        self.run_scan(self.s.scan_targets)
                        self.audit("scan", {"targets": len(self.s.scan_targets), "scheduled": True})
                    except (CAError, OSError) as e:
                        log.error("scheduled scan: %s", e)
                time.sleep(self.s.scan_every_hours * 3600)
        threading.Thread(target=loop, daemon=True, name="scheduled-scan").start()

    def update(self):
        """The newest release when check_updates is on and it is newer than this one; looked up at most once a day, in the
        background, so a network without internet access only loses the notice."""
        if not self.s.check_updates:
            return None
        if time.time() - self.latest_checked > 86400:
            self.latest_checked = time.time()

            def check():
                from .. import latest_release
                try:
                    self.latest = latest_release()
                except (OSError, ValueError) as e:
                    log.info("update check failed: %s", e)
            threading.Thread(target=check, daemon=True).start()
        return self.latest if self.latest and self.latest["newer"] else None

    def overview(self):
        out = {"product": NAME, "version": __version__, "update": self.update()}
        try:
            certs = self.certificates()["certificates"]
            out["certificates"] = {"valid": sum(c["status"] == "valid" and c["days_left"] >= 0 for c in certs), "revoked": sum(c["status"] == "revoked" for c in certs),
                                   "expiring_30d": sum(c["status"] == "valid" and 0 <= c["days_left"] <= 30 for c in certs)}
        except CAError as e:
            out["certificates"] = {"error": str(e)}
        edges = self.edges()
        out["edges"] = {"routes": sum("error" not in e for e in edges), "unreachable": sum("error" in e for e in edges),
                        "active": sum(e.get("active", 0) for e in edges), "handshakes": sum(e.get("handshakes", 0) for e in edges),
                        "failed": sum(e.get("handshake_failed", 0) for e in edges)}
        tunnels, remote = self.tunnels(), self.remote_users()
        tun = [t for t in tunnels if "error" not in t]
        users = [u for u in remote if "error" not in u]
        out["vpn"] = {"tunnels": len(tun), "quantum_safe": sum(protected(t) for t in tun),
                      "unreachable": sum("error" in t for t in tunnels + remote), "remote_users": len(users), "remote_online": sum(time.time() - u.get("latest_handshake", 0) < 180 for u in users)}
        b = [x for x in self.backups() if "error" not in x]
        out["backups"] = {"count": len(b), "latest": max(x["created"] for x in b) if b else None, "signed": sum(bool(x["signed_by"]) for x in b)}
        out["readiness"] = self.last_scan["summary"] | {"changes": len(self.last_scan.get("changes", [])),
                                                        "finished": self.last_scan["finished"]} if self.last_scan else None
        return out

    def handle(self, method, path, body):
        routes = {
            ("GET", "/api/overview"): lambda: self.overview(),
            ("GET", "/api/certificates"): lambda: self.certificates(),
            ("GET", "/api/edges"): lambda: self.edges(),
            ("GET", "/api/tunnels"): lambda: self.tunnels(),
            ("GET", "/api/remote"): lambda: self.remote_users(),
            ("GET", "/api/backups"): lambda: self.backups(),
            ("GET", "/api/projects"): self.project_status,
            ("GET", "/api/projects/status"): lambda: self.project_status(brief=True),
            ("POST", "/api/projects/register"): lambda: self.register_project(body),
            ("POST", "/api/projects/cancel"): self.cancel_project,
            ("POST", "/api/projects/scan"): lambda: self.start_project(body),
            ("POST", "/api/projects/select"): lambda: self.select_project(body),
            ("POST", "/api/projects/track"): lambda: self.track_project(body),
            ("POST", "/api/projects/verify"): lambda: self.verify_project(body),
            ("GET", "/api/scan"): lambda: {"running": self.scanning, "last": self.last_scan, "error": self.scan_error, "targets": self.s.scan_targets,
                                           "every_hours": self.s.scan_every_hours},
            ("POST", "/api/certificates/issue"): lambda: self.issue(body),
            ("POST", "/api/certificates/revoke"): lambda: self.revoke(body),
            ("POST", "/api/certificates/maintain"): lambda: self.maintain(),
            ("POST", "/api/scan"): lambda: self.start_scan(body),
        }
        fn = routes.get((method, path))
        if not fn:
            return 404, {"error": "no such endpoint"}
        try:
            return 200, fn()
        except KeyError as e:
            return 400, {"error": f"missing field {e.args[0]}"}
        except (CAError, ValueError, OSError) as e:
            return 400, {"error": str(e)}
        except Exception:
            log.exception("%s %s failed", method, path)
            return 500, {"error": "internal error; the details are in the console's log"}

    def issue(self, b):
        kind, cn = b["kind"], b["common_name"]
        if not isinstance(cn, str) or not isinstance(b.get("names", ""), str):
            raise ValueError("common_name and names must be text")
        cn = cn.strip()
        if not cn:
            raise ValueError("a common name is needed")
        names = [n.strip() for n in str(b.get("names", "")).split(",") if n.strip()]
        days = b.get("days", 397)
        out, rec = self.ca().issue(cn, kind, names, int(days) if isinstance(days, str) and days.strip().isdigit() else days)
        self.audit("issue", {"serial": rec.serial, "common_name": cn, "kind": kind})
        return {"serial": rec.serial, "folder": str(out)}

    def revoke(self, b):
        ca = self.ca()
        ca.revoke(b["serial"], b.get("reason", "unspecified"))
        self.audit("revoke", {"serial": b["serial"], "reason": b.get("reason", "unspecified")})
        return {"revoked": b["serial"]}

    def maintain(self):
        renewed, skipped = self.ca().maintain()
        self.audit("maintain", {"renewed": [r.serial for r in renewed]})
        return {"renewed": [r.common_name for r in renewed], "skipped": [r.common_name for r in skipped]}

    def project_status(self, brief=False):
        with self.lock:
            state = dict(self.project_scan)
            projects = [{"id": i, "name": p.name, **({"key": self.project_store.key(p)} if self.project_store else {})} for i, p in enumerate(self.projects)]
        if brief:
            return {k: state[k] for k in ("running", "stage", "error")}
        workspace_error = None
        if self.project_store and state['last'] and self.projects:
            try:
                saved = self.project_store.assessment(self.projects[state['selected']])
                if saved and saved['finished'] >= state['last']['finished']:
                    state['last'] = saved
            except (OSError, ValueError):
                workspace_error = 'Saved workspace is unavailable; current session evidence is retained.'
        available, directory_error = [], None
        if self.repository_directory:
            try:
                available = sorted(p.name for p in self.repository_directory.iterdir() if not p.name.startswith(".") and p.is_dir() and not p.is_symlink())[:200]
            except OSError:
                directory_error = "The approved repository folder is unavailable. Ask its administrator to check access."
        history, history_error = (state["last"].get("history", []) if state["last"] else []), None
        if self.s.project_history:
            from ..project import read_history
            try:
                history = read_history(self.s.project_history)
            except (OSError, ValueError):
                history_error = "History is unavailable; check the configured history file."
        return state | {"verification_targets": self.s.scan_targets, "workspace_error": workspace_error, "persistent": bool(self.project_store), "projects": projects, "available": available, "directory_error": directory_error, "history": history, "history_error": history_error}

    def approved_project(self, name):
        root = self.repository_directory
        if not root or not isinstance(name, str) or not name or len(name) > 255 or Path(name).name != name or name.startswith(".") or "/" in name or "\\" in name:
            raise ValueError("Choose a repository inside the administrator-approved folder")
        candidate = root / name
        path = candidate.resolve()
        if candidate.is_symlink() or not path.is_relative_to(root) or not path.is_dir():
            raise ValueError("Choose an existing repository folder; symlinks and outside paths are not accepted")
        return path

    def register_project(self, body):
        path = self.approved_project(body.get('name'))
        if self.project_store:
            self.project_store.register(self.repository_directory, path.name)
        with self.lock:
            if path not in self.projects:
                self.projects.append(path)
            index = self.projects.index(path)
        self.audit("project-register", {"project_id": index})
        return {"project": index}

    def selected_project(self, body):
        i = body.get('project')
        if type(i) is not int or not 0 <= i < len(self.projects):
            raise ValueError('Choose a registered project')
        path = self.projects[i]
        if path.is_symlink() or path.resolve() != path or not path.is_dir():
            raise ValueError('Registered repository is unavailable or has become a symlink')
        if path.parent == self.repository_directory:
            self.approved_project(path.name)
        return i, path

    def select_project(self, body):
        i, path = self.selected_project(body)
        if not self.project_store:
            raise ValueError('Start the console with --project-state to save assessments')
        with self.lock:
            if self.project_scan['running']:
                raise ValueError('Wait for the active scan to finish')
            self.project_scan['last'] = self.project_store.assessment(path)
            self.project_scan['selected'] = i
            self.project_scan.update(error=None, stage='Saved assessment loaded' if self.project_scan['last'] else 'Ready to scan')
        return {'selected': i}

    def track_project(self, body):
        i, path = self.selected_project(body)
        if not self.project_store:
            raise ValueError('Start the console with --project-state to track findings')
        with self.lock:
            result = self.project_store.track(path, body)
            if self.project_scan['last'] and self.project_scan['last'].get('project_key') == self.project_store.key(path):
                self.project_scan['last'] = result
        self.audit('project-triage', {'project_id': i, 'finding': body.get('finding'), 'status': body.get('status')})
        return {'saved': True}

    def cancel_project(self):
        with self.lock:
            if not self.project_scan['running']:
                raise ValueError('No project scan is running')
            self.project_cancel.set()
            self.project_scan['stage'] = 'Cancelling at the next analysis checkpoint'
        self.audit('project-cancel', {})
        return {'requested': True}

    def verify_project(self, body):
        import re
        from ..project import verify_endpoint
        i, path = self.selected_project(body)
        if not self.project_store:
            raise ValueError('Deployment evidence needs a persistent project workspace')
        binding = {k: body.get(k, '') for k in ('finding', 'target', 'release', 'association', 'expected_sha256')}
        if any(not isinstance(v, str) or not v.strip() for v in binding.values()):
            raise ValueError('Choose a finding and endpoint; supply release, association evidence and expected certificate SHA-256')
        if binding['target'] not in self.s.scan_targets:
            raise ValueError('Choose an endpoint from the administrator-configured scan_targets')
        if len(binding['release']) > 120 or len(binding['association']) > 1000 or not re.fullmatch('[0-9a-fA-F]{64}', binding['expected_sha256']):
            raise ValueError('Release: at most 120 characters; association: at most 1000; certificate SHA-256: 64 hexadecimal characters')
        binding['expected_sha256'] = binding['expected_sha256'].lower()
        with self.lock:
            if self.project_scan['running']:
                raise ValueError('Wait for the project scan before verifying deployment')
            assessment = self.project_store.assessment(path)
            if not assessment or binding['finding'] not in {a['id'] for a in assessment['assets'] + assessment.get('not_observed', [])}:
                raise ValueError('Choose a finding from a completed assessment')
        observation = verify_endpoint(binding['target'], self.ca().anchor, binding['expected_sha256'], Path(self.s.ca)/'crl.pem')
        with self.lock:
            result = self.project_store.record_verification(path, binding, observation, assessment['finished'])
            if self.project_scan['last'] and self.project_scan['last'].get('project_key') == result.get('project_key'):
                self.project_scan['last'] = result
        self.audit('project-verify', {'project_id': i, 'finding': binding['finding'], 'state': observation['state']})
        return result

    def start_project(self, body):
        from ..project import scan, scanner, ScanStopped
        i, path = self.selected_project(body)
        scanner()  # Explain missing optional capability before acknowledging a job.
        with self.lock:
            if self.project_scan["running"]:
                raise ValueError("A project scan is already running")
            if self.project_cache is None:
                from wolfpack.crawler import ParseCache
                self.project_cache = ParseCache()
            self.project_cancel.clear()
            self.project_scan.update(running=True, stage="Preparing project", error=None, selected=i)
        def progress(stage):
            with self.lock:
                self.project_scan["stage"] = stage
        def work():
            try:
                result = scan(path, history=self.s.project_history or None, progress=progress,
                              exclude=[self.project_store.path] if self.project_store else [], cancel=self.project_cancel, cache=self.project_cache)
                if self.project_store:
                    result['project_key'] = self.project_store.key(path)
                    try:
                        result = self.project_store.save(path, result)
                    except (OSError, ValueError):
                        result['notes'].append('Workspace could not be saved. This scan is available until restart; check workspace permissions and size.')
                with self.lock:
                    self.project_scan["last"] = result
            except ScanStopped as error:
                with self.lock:
                    self.project_scan['error'] = str(error)
            except Exception:
                # Source-sensitive analysis errors are not logged with source/exception contents.
                with self.lock:
                    self.project_scan["error"] = "Project scan failed. Check folder permissions, source syntax and the configured history file; retry from the CLI for diagnostics."
            finally:
                with self.lock:
                    self.project_scan["running"] = False
        threading.Thread(target=work, daemon=True, name="project-scan").start()
        self.audit("project-scan", {"project_id": i})
        return {"started": i}

    def start_scan(self, b):
        raw = b.get("targets", "")
        if not isinstance(raw, (str, list)):
            raise ValueError("targets must be text (one per line) or a list")
        items = raw if isinstance(raw, list) else raw.replace("\n", ",").split(",")
        targets = [str(t).strip() for t in items if str(t).strip()] or self.s.scan_targets
        from ..readiness.scan import endpoint
        for t in targets:
            endpoint(t)
        if not targets:
            raise ValueError("no targets to scan")
        if len(targets) > 500:
            raise ValueError("at most 500 targets per scan")
        self.run_scan(targets)
        self.audit("scan", {"targets": len(targets)})
        return {"started": len(targets)}


def page():
    return with_tour(resources.files(__package__).joinpath("console.html").read_bytes())


def with_tour(html):
    """Put the shared guided tour (pqcsuite/tour.js) at the start of the page's one inline script, so its hash covers both."""
    return html.replace(b"<script>", b"<script>\n" + resources.files("pqcsuite").joinpath("tour.js").read_bytes(), 1)


def policy(html):
    """The page's one inline script is allowed by its hash, so no other script can run even if markup were ever injected."""
    script = html.split(b"<script>", 1)[1].split(b"</script>", 1)[0]
    digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
    return f"default-src 'self'; img-src 'self' data:; font-src data:; style-src 'self' 'unsafe-inline'; script-src 'sha256-{digest}'; frame-ancestors 'none'"


class Backoff:
    """After 10 wrong tokens from one address within a minute, that address is refused until the minute is over."""

    def __init__(self, limit=10, window=60.0):
        self.limit, self.window, self.lock, self.failures = limit, window, threading.Lock(), {}

    def blocked(self, addr):
        with self.lock:
            recent = [t for t in self.failures.pop(addr, []) if time.monotonic() - t < self.window]
            if recent:
                self.failures[addr] = recent
            return len(recent) >= self.limit

    def failed(self, addr):
        with self.lock:
            self.failures.setdefault(addr, []).append(time.monotonic())


class Handler(BaseHTTPRequestHandler):
    """A loopback JSON API behind one HTML page: every answer uncached, unsniffable and under the page's CSP."""
    csp = ""

    def reply(self, status, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(status)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                     ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", self.csp)):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authorised(self, token):
        return hmac.compare_digest(self.headers.get("Authorization", "").removeprefix("Bearer ").encode(), token.encode())

    def json_body(self, limit):
        """The request's JSON object, or the (status, error) to answer instead."""
        n = content_length(self.headers)
        if n is None:
            return 400, {"error": "bad Content-Length"}
        if n > limit:
            return 413, {"error": "request too large"}
        try:
            body = json.loads(self.rfile.read(n)) if n else {}
        except ValueError:
            return 400, {"error": "invalid JSON"}
        return body if isinstance(body, dict) else (400, {"error": "the body must be a JSON object"})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)


def serve(app):
    html = page()
    backoff = Backoff()

    class Console(Handler):
        csp, server_version, timeout = policy(html), f"{NAME}/{__version__}", HTTP_IDLE

        def route(self, method):
            path = self.path.split("?")[0]
            if method == "GET" and path in ("/", "/index.html"):
                return self.reply(200, html, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.reply(404, {"error": "not found"})
            if backoff.blocked(self.client_address[0]):
                return self.reply(429, {"error": "too many wrong tokens; wait a minute"})
            if not self.authorised(app.token):
                backoff.failed(self.client_address[0])
                return self.reply(401, {"error": "missing or wrong token"})
            body = self.json_body(1 << 20)
            self.reply(*(app.handle(method, path, body) if isinstance(body, dict) else body))

    return ThreadingHTTPServer(hostport(app.s.listen, "127.0.0.1"), Console)
