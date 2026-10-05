"""VPN: site-to-site IPsec, the WireGuard gateway, and laptops (join, the app, the desktop tray)."""
import argparse
import json
import logging
import os
import sys
import threading
from pathlib import Path

from .. import JSON, METRICS, NAME, ConfigWatch, env_passphrase, restart, serve_http, tls
from ..pki import CA, encrypted
from ..vpn.charon import CharonError
from .common import ask, positive, run_until_signal


def cmd_vpn(a):
    from ..vpn import load_config
    from ..vpn.charon import Charon
    if a.vpn_cmd in ("gateway", "connect", "disconnect", "install", "uninstall"):
        return cmd_wireguard(a)
    if a.vpn_cmd == "up":
        from ..vpn.controller import Controller
        site = load_config(a.config)
        ctl = Controller(site)
        ctl.start()
        if site.metrics:
            serve_http(site.metrics, {"/metrics": (METRICS, ctl.metrics), "/status": (JSON, lambda: json.dumps(ctl.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, load_config, lambda new: new != site and (again.set(), ctl.shutdown()))
        run_until_signal(ctl.stop.wait, ctl.shutdown, watch.poke)
        if again.is_set():
            restart()
        return 0
    if a.vpn_cmd == "status" and not (a.config or a.vici):
        from ..vpn import platforms
        path = platforms.folder() / f"{a.interface}.status.json"
        if path.exists():
            return laptop_status(path, a)
    if a.vpn_cmd in ("invite", "join", "app", "desktop"):
        return {"invite": cmd_invite, "join": cmd_join, "app": cmd_app, "desktop": cmd_desktop}[a.vpn_cmd](a)
    try:
        ch = Charon(load_config(a.config).vici if a.config else a.vici or "unix:///var/run/charon.vici")
    except CharonError:
        if a.vpn_cmd != "status" or a.config or a.vici:
            raise
        print("Not connected. No VPN client is running on this machine and no strongSwan site is reachable here.\n"
              "Laptop: pqcsuite vpn join YOUR.pqcinvite (administrator terminal). Gateway: start strongSwan, or give --config or --vici.")
        return 1
    if a.vpn_cmd == "check":
        kems = ch.ml_kem()
        print(f"{ch.version()} at {ch.uri}\nML-KEM key exchanges: {', '.join(kems) or 'none (needs strongSwan 6.0.2+ with OpenSSL 3.5+ or the ml plugin)'}")
        return 0 if kems else 1
    tunnels = ch.tunnels()
    if a.json:
        print(json.dumps(tunnels, indent=1))
    elif not tunnels:
        print("no tunnels")
    for t in [] if a.json else tunnels:
        print(f"{t['peer']:16} {t['state']:12} {t['key_exchange']:32} PPK {'yes' if t['ppk'] else 'NO '}  up {t['established_s']}s")
        for c in t["children"]:
            print(f"  {c['name']:14} {c['state']:12} {c['encryption']:14} in {c['bytes_in']} B / out {c['bytes_out']} B")
    return 0


def laptop_status(path, a):
    import time
    s = json.loads(path.read_text(encoding="utf-8"))
    if s["state"] not in ("disconnected",) and time.time() - s.get("updated", 0) > 30:
        s |= {"state": "stopped", "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.get("updated", 0)))}
    print(json.dumps(s, indent=1) if a.json else describe_vpn(s, a.details))
    return 0 if s["state"] == "protected" else 1


def cmd_invite(a):
    import datetime as dt
    from cryptography.x509 import load_pem_x509_certificate
    from ..pki.est import create_token, fingerprint
    tls.hostport(a.gateway)
    if not a.enroll.startswith("https://"):
        raise ValueError("--enroll must be the https:// address of `pqcsuite ca serve`")
    ca = CA(a.dir)
    token = create_token(ca, a.name, "client", hours=a.hours)
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=a.hours)).replace(microsecond=0).isoformat()
    out = Path(a.out or f"{a.name}.pqcinvite")
    if out.exists():
        raise ValueError(f"{out} already exists; choose another --out")
    from ..storage import write
    write(out, json.dumps({"pqcsuite_invite": 1, "name": a.name, "enroll": a.enroll, "ca_fingerprint": fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes())),
                           "gateway": a.gateway, "server_name": a.server_name, "expires": expires, "token": token}, indent=1).encode(), secret=True)
    print(f"wrote {out}: it lets {a.name} enroll once before {expires} and then connect to {a.gateway}.\n"
          f"Send it through a channel you trust (it holds a one-time token and the CA fingerprint the device will trust).\n"
          f"On the device, in an administrator terminal: pqcsuite vpn join {out.name}")
    return 0


def cmd_join(a):
    """Enroll from an invitation (if this machine has no certificate yet) and connect, asking only for the device key passphrase."""
    from ..vpn import join
    inv = join.read(a.invitation)
    device = join.device_for(a.invitation, a.device)
    if not a.no_apply:
        join.preflight(f"pqcsuite vpn join {a.invitation}")
    enroll = join.must_enroll(inv, device)
    passphrase = env_passphrase(a.key_passphrase_env)
    if enroll:
        if passphrase is None:
            passphrase = ask("Choose a passphrase for this device's key: ", "supply --key-passphrase-env with a protected environment variable")
            if not passphrase or passphrase != ask("Repeat it: ", "supply --key-passphrase-env"):
                raise ValueError("the passphrases were empty or did not match; nothing was changed")
        print(f"Enrolling {inv['name']} with {inv['enroll']} (CA pinned by the invitation's fingerprint) ...", flush=True)
        cert = join.enroll(inv, device, a.invitation, passphrase)
        print(f"Enrolled: certificate valid until {cert.not_valid_after_utc.date()}, key encrypted in {device}. The invitation's one-time token is used up.", flush=True)
    elif passphrase is None and encrypted(device / "key.pem"):
        passphrase = ask("Device key passphrase: ", "supply --key-passphrase-env with a protected environment variable")
    return connect(a, inv["gateway"], device, passphrase, inv.get("server_name"))


def cmd_app(a):
    """The VPN window's service: a page on 127.0.0.1 behind a one-time address; this process holds the tunnel until stopped.
    With --session (how `vpn desktop` starts it, with administrator rights) the port and key come from the tray's file,
    output goes to a log next to it, and problems are shown in the window instead of ending the process."""
    import webbrowser
    from ..storage import write
    from ..vpn import app, join
    window = app.App(a.invitation, a.folder, interface=a.interface, apply=not a.no_apply)
    held, running = app.claim(window.folder, f"{a.interface}.app")
    if not held:
        if not running:
            raise ValueError(f"another `pqcsuite vpn app` holds {a.interface}; stop it, or use --interface")
        url = f"http://127.0.0.1:{running['port']}/#{app.request(running['port'], running['token'], 'POST', '/api/ticket')['ticket']}"
        print(f"The VPN window for {a.interface} is already running: {url}", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
        return 0
    port, record = 0, window.folder / f"{a.interface}.app.json"
    if a.session:
        session = json.loads(Path(a.session).read_text(encoding="utf-8"))
        window.token, port = session["token"], int(session["port"])
        log = os.fdopen(os.open(window.folder / f"{a.interface}.service.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
        for h in logging.getLogger().handlers:
            h.setStream(log)
    elif not a.no_apply:
        join.preflight("pqcsuite vpn app" + (f" {a.invitation}" if a.invitation else ""))
    srv = app.serve(window, ("127.0.0.1", port))
    window.on_quit = lambda: threading.Thread(target=srv.shutdown).start()
    port = srv.server_address[1]
    if not a.session:
        write(record, json.dumps({"port": port, "token": window.token}).encode(), secret=True)
    if a.session:
        logging.getLogger(NAME).info("VPN service for the desktop app on 127.0.0.1:%s", port)
    else:
        url = f"http://127.0.0.1:{port}/#{window.ticket()}"
        print(f"VPN window: {url}\nKeep this running; closing the window does not disconnect. Ctrl+C disconnects and stops it.", flush=True)
        if not a.no_browser:
            webbrowser.open(url)
    try:
        run_until_signal(srv.serve_forever, window.on_quit)
    finally:
        window.disconnect()
        srv.server_close()
        if not a.session:
            record.unlink(missing_ok=True)
        held.close()
    return 0


def cmd_desktop(a):
    from ..vpn import desktop
    if a.launcher or a.remove_launcher:
        path = desktop.launcher(remove=a.remove_launcher)
        print(f"removed {path}" if a.remove_launcher else f"added {desktop.NAME}: {path}")
        return 0
    if a.start_at_login:
        desktop.autostart(a.start_at_login == "on")
        print(f"{desktop.NAME} {'starts' if a.start_at_login == 'on' else 'no longer starts'} when you log in"
              + (" (the tray icon only; connecting still asks for your passphrase)" if a.start_at_login == "on" else ""))
        return 0
    return desktop.main(a.invitation, a.interface, not a.no_apply, a.background)


def cmd_wireguard(a):
    from ..vpn import wireguard as wg
    if a.vpn_cmd == "gateway":
        gw = wg.Gateway(wg.load_gateway(a.config)).start()
        print(f"WireGuard gateway {gw.cfg.name} on {gw.cfg.interface}, key agreement on {gw.cfg.keyring_listen}, public key {gw.public}")
        if gw.cfg.metrics:
            serve_http(gw.cfg.metrics, {"/metrics": (METRICS, gw.metrics), "/status": (JSON, lambda: json.dumps(gw.status(), default=str))})
        again = threading.Event()
        watch = ConfigWatch(a.config, wg.load_gateway, lambda new: gw.reconfigure(new) or (again.set(), gw.shutdown()))
        run_until_signal(gw.stop.wait, gw.shutdown, watch.poke)
        if again.is_set():
            restart()
        return 0
    from ..vpn import platforms
    if a.vpn_cmd == "disconnect":
        tunnel, kill_switch = platforms.this_machine(a.interface)
        tunnel.down()
        kill_switch.off()
        print(f"{a.interface} is down and nothing is blocked any more")
        return 0
    if a.vpn_cmd == "uninstall":
        print(f"removed {platforms.uninstall()}; the VPN no longer starts with this machine (pqcsuite vpn disconnect takes it down now)")
        return 0
    if a.vpn_cmd == "install":
        if encrypted(Path(a.cert_dir) / 'key.pem'):
            raise ValueError('Built-in startup installation cannot unlock encrypted device keys; use interactive vpn connect or an administrator-managed service with --key-passphrase-env. Keep the key encrypted.')
        argv = [sys.executable, "-m", "pqcsuite", "vpn", "connect", a.keyring, "--cert-dir", str(Path(a.cert_dir).resolve()), "--interface", a.interface]
        argv += [*(["--ca", str(Path(a.ca).resolve())] if a.ca else []), *(["--server-name", a.server_name] if a.server_name else [])]
        wg.Client(a.keyring, a.cert_dir, a.interface, a.server_name, apply=False, ca=a.ca).agree()
        print(f"the gateway accepted this certificate; wrote {platforms.install(argv)}: the VPN now starts with this machine and restarts if it stops")
        return 0
    passphrase = env_passphrase(a.key_passphrase_env)
    if passphrase is None and encrypted(Path(a.cert_dir) / 'key.pem'):
        passphrase = ask('Device key passphrase: ', 'supply --key-passphrase-env with a protected environment variable')
    return connect(a, a.keyring, a.cert_dir, passphrase)


def connect(a, keyring, cert_dir, passphrase, server_name=None):
    from ..vpn import wireguard as wg
    c = wg.Client(keyring, cert_dir, a.interface, server_name or getattr(a, "server_name", None), not a.no_apply, getattr(a, "config_out", None),
                  passphrase, ca=getattr(a, "ca", None), on_status=lambda s: print(describe_vpn(s), flush=True))
    if a.once:
        r = c.once()
        print(f"key agreement confirmed for {r['address']} through {r['endpoint']}; routes {', '.join(r['routes'])}; "
              f"{'no tunnel activated (--no-apply)' if a.no_apply else 'tunnel configured; verify a WireGuard handshake'}; "
              f"the PSK expires in about {r['rotate_s'] * 3}s; --once does not keep keys fresh")
        return 0
    print(f"Connecting to {keyring} as {c.name}. Keep this window open; Ctrl+C disconnects.", flush=True)
    run_until_signal(c.run, c.stop.set)
    c.close()
    return 0


def describe_vpn(s, details=False):
    """Plain words first (protected or not, and why); the algorithms underneath for anyone who asks."""
    state = s["state"]
    if state == "protected":
        scope = "All traffic (full tunnel, kill switch on)" if s["full_tunnel"] else f"Traffic to {', '.join(s['routes'])} (split tunnel)"
        lines = [f"Protected. {scope} goes through {s['gateway']} as {s['address']}."]
    elif state == "connecting":
        lines = [f"Connecting. Keys agreed with {s['gateway']}; waiting for the tunnel's first handshake."]
    elif state == "agreed":
        lines = [f"Keys agreed with {s['gateway']} for {s['address']}; no tunnel configured (--no-apply), so this machine is not protected."]
    elif state == "disconnected":
        lines = ["Disconnected. The tunnel is down and nothing is blocked."]
    elif state == "stopped":
        lines = [f"Not running. The VPN client last reported at {s['last_seen']}; start it again with `pqcsuite vpn join` or `pqcsuite vpn connect`."]
    else:
        lines = [f"Not protected. {s.get('error') or 'Not connected yet'}. Retrying automatically; full-tunnel traffic stays blocked meanwhile."]
    k = s.get("key_agreement")
    if k and (details or state == "protected"):
        kind = "Post-quantum" if k["post_quantum"] else "Classical (NOT post-quantum)"
        lines.append(f"  {kind} key agreement: TLS group {k['tls_group']}, gateway certificate {k['gateway_certificate']}; "
                     f"the WireGuard pre-shared key is renewed every {k['psk_rotation_s']} s")
    if details and k:
        age = s.get("handshake_age_s")
        lines.append(f"  last handshake {'never' if age is None else f'{age} s ago'}; next key in {s['next_key_s']} s; "
                     f"device {s['device']}; routes {', '.join(s['routes'])}")
    return "\n".join(lines)

def add(sub, common):
    v = sub.add_parser("vpn", help="VPN: post-quantum site-to-site IPsec (strongSwan), and remote access for laptops (WireGuard, the Acxelin VPN app)").add_subparsers(dest="vpn_cmd", required=True)
    p = v.add_parser("up", help="run a site: key agreement, rotation, revocation, metrics")
    p.add_argument("--config", required=True, help="site TOML (see examples/vpn-hq.toml)")
    for name, text in (("status", "is this machine protected? (laptop) or tunnels, algorithms and traffic (site)"),
                       ("check", "is strongSwan reachable and does it have ML-KEM?")):
        p = v.add_parser(name, help=text)
        p.add_argument("--config", help="read the VICI address from a site TOML")
        p.add_argument("--vici", help="strongSwan control socket (default unix:///var/run/charon.vici)")
        p.add_argument("--json", action="store_true")
        if name == "status":
            p.add_argument("--interface", default="wg0", help="the laptop tunnel to report on (default: wg0)")
            p.add_argument("--details", action="store_true", help="also show algorithms, handshake and key timing")
    p = v.add_parser("invite", parents=[common], help="administrator: one file that lets a person enroll and connect with `vpn join`")
    p.add_argument("name", help="the person's or device's certificate name (also add it to the gateway's users list, if it has one)")
    p.add_argument("--enroll", required=True, metavar="URL", help="the EST enrollment service, https://host:9443 (see `ca serve`)")
    p.add_argument("--gateway", required=True, metavar="HOST:PORT", help="the WireGuard gateway's key agreement address")
    p.add_argument("--server-name", help="the gateway's certificate name, if it differs from HOST")
    p.add_argument("--hours", type=positive(float), default=24, help="how long the invitation can be used (default: 24)")
    p.add_argument("--out", help="the invitation file (default: NAME.pqcinvite)")
    p = v.add_parser("join", help="enroll this machine from an invitation file and connect it, in one step")
    p.add_argument("invitation", help="the .pqcinvite file from your administrator")
    p.add_argument("--device", help="folder for this machine's certificate and key (default: next to the invitation, named after it)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--key-passphrase-env", help="read the device key passphrase from this environment variable instead of asking")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("app", help="a window in the browser to join, connect, disconnect and see whether this machine is protected")
    p.add_argument("invitation", nargs="?", help="the .pqcinvite file (default: the newest in ~/.pqcsuite/vpn; the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-browser", action="store_true", help="print the address instead of opening it")
    p.add_argument("--folder", help="where invitations and this computer's keys are kept (default: ~/.pqcsuite/vpn)")
    p.add_argument("--session", help=argparse.SUPPRESS)
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p = v.add_parser("desktop", help="the desktop app: a tray icon that shows whether this computer is protected, and the VPN window")
    p.add_argument("invitation", nargs="?", help="the .pqcinvite file (the window can also open one)")
    p.add_argument("--interface", default="wg0")
    p.add_argument("--no-apply", action="store_true", help="enroll and agree keys, but do not configure a tunnel (a check, not a connection)")
    p.add_argument("--launcher", action="store_true", help="add Acxelin VPN to the Start menu, Applications or the application list")
    p.add_argument("--remove-launcher", action="store_true", help="remove what --launcher added")
    p.add_argument("--start-at-login", choices=("on", "off"), help="show the tray icon when you log in (it connects only when you ask)")
    p.add_argument("--background", action="store_true", help="start in the tray without opening the window")
    p = v.add_parser("gateway", help="WireGuard remote-access gateway: address pool, PSK from ML-DSA mutual TLS, rotation, revocation")
    p.add_argument("--config", required=True, help="TOML with a [wireguard] section (see examples/wireguard-gateway.toml)")
    for name, text in (("connect", "connect this machine (Linux, Windows or macOS) to a WireGuard gateway and keep its PSK fresh"),
                       ("install", "check gateway access and install a service that connects at machine startup")):
        p = v.add_parser(name, help=text)
        p.add_argument("keyring", help="the gateway's key agreement address, host:port")
        p.add_argument("--cert-dir", required=True, help="folder with cert.pem, chain.pem, key.pem and ca.crt (as written by `ca enroll`)")
        p.add_argument("--ca", help="trust this CA file instead of CERT_DIR/ca.crt")
        p.add_argument("--interface", default="wg0")
        p.add_argument("--server-name", help="the gateway's certificate name, if it differs from the keyring host")
        if name == "connect":
            p.add_argument("--no-apply", action="store_true", help="do not configure the tunnel (use with --config-out)")
            p.add_argument("--config-out", help="also write a wg-quick configuration here after every key agreement")
            p.add_argument("--key-passphrase-env")
            p.add_argument("--once", action="store_true", help="agree once and exit")
    p = v.add_parser("disconnect", help="take the tunnel down and lift the kill switch")
    p.add_argument("--interface", default="wg0")
    v.add_parser("uninstall", help="stop starting the VPN with this machine")
    for c in v.choices.values():
        c.set_defaults(func=cmd_vpn)
