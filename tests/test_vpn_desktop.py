"""The desktop app: the tray drives a real background VPN service through its loopback API, without a display."""
import importlib.util
import json
import os
import re
import shlex
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

os.environ.setdefault("PYSTRAY_BACKEND", "dummy")
NEEDS = [m for m in ("pystray", "PIL") if not importlib.util.find_spec(m)]


@unittest.skipIf(NEEDS, f"needs the desktop extra ({', '.join(NEEDS)})")
class DesktopTest(unittest.TestCase):
    def setUp(self):
        from pqcsuite.vpn import desktop
        self.desktop = desktop
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)

    def test_each_state_has_its_own_icon_and_words(self):
        d = self.desktop
        centres = {w: d.image(w).getpixel((32, 8)) for w in ("protected", "connecting", "not_protected", "disconnected", "stopped")}
        self.assertEqual(len({centres[w] for w in ("protected", "connecting", "not_protected", "disconnected")}), 4)
        self.assertEqual(d.image("protected").getpixel((0, 0))[3], 0, "the corners are transparent")
        protected = {"invitation": {"name": "bob"}, "status": {"state": "protected", "address": "10.99.0.2/24"}}
        self.assertEqual(d.headline(protected), "Protected · 10.99.0.2")
        self.assertEqual(d.headline(None), "VPN service not running")
        self.assertEqual(d.summary({"invitation": None, "status": {"state": "disconnected"}}), "none")

    def test_the_menu_offers_what_the_state_allows(self):
        tray = self.desktop.Tray(home=self.d, apply=False)
        texts = lambda: [i.text for i in tray.menu().items if i.visible and i.text and not i.text.startswith("- ")]
        tray.state = None
        self.assertEqual(texts(), ["VPN service not running", "Open Acxelin VPN", "Start VPN service", "Start at login", "Quit and disconnect"])
        tray.state = {"invitation": {"name": "bob"}, "status": {"state": "protected", "address": "10.99.0.2/24"}}
        self.assertEqual(texts(), ["Protected · 10.99.0.2", "Open Acxelin VPN", "Disconnect", "Start at login", "Quit and disconnect"])

    def test_administrator_prompts_keep_the_command_intact(self):
        command = [sys.executable, "-m", "pqcsuite", "vpn", "app", "--folder", '/Users/a "b"\\c/vpn', "x'y.pqcinvite"]
        with mock.patch.object(sys, "platform", "darwin"):
            osa = self.desktop.elevated(command)
        literal = re.fullmatch(r'do shell script "(.*)" with administrator privileges', osa[2]).group(1)
        script = re.sub(r'\\(.)', r'\1', literal)
        self.assertEqual(shlex.split(script.removesuffix(" >/dev/null 2>&1 &"))[2:], command)
        with mock.patch.object(sys, "platform", "linux"), mock.patch("shutil.which", return_value="/usr/bin/pkexec"):
            linux = self.desktop.elevated(command)
        self.assertEqual((linux[:2], linux[3:]), (["pkexec", "env"], command))
        self.assertTrue(linux[2].startswith("PYTHONPATH="), "root finds a per-user or virtualenv install")
        with mock.patch.object(sys, "platform", "linux"), mock.patch("shutil.which", return_value=None), self.assertRaisesRegex(ValueError, "sudo pqcsuite vpn app"):
            self.desktop.elevated(command)

    def test_the_tray_starts_reuses_and_stops_the_service(self):
        tray = self.desktop.Tray(home=self.d, apply=False)
        self.assertTrue(tray.start(wait=60), (self.d / "wg0.service.log").read_text() if (self.d / "wg0.service.log").exists() else "no log")
        self.addCleanup(tray.quit)
        if os.name != "nt":
            self.assertEqual((self.d / "wg0.desktop.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.d / "wg0.service.log").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.desktop.summary(tray.state), "none")
        terminal = self.desktop.Tray(home=self.d, interface="wg9", apply=False)
        (self.d / "wg9.app.json").write_text(json.dumps(tray.session))
        self.assertTrue(terminal.start(wait=0), "the tray attaches to a window service started in a terminal")
        again = self.desktop.Tray(home=self.d, apply=False)
        self.assertTrue(again.start(wait=0), "a second tray reuses the running service")
        self.assertEqual(again.session, tray.session)
        with mock.patch.object(self.desktop, "open_window") as window:
            tray.open()
        url = window.call_args.args[0]
        self.assertTrue(url.startswith(f"http://127.0.0.1:{tray.session['port']}/#"))
        self.assertNotIn(tray.session["token"], url)
        self.assertNotIn(tray.session["token"], (self.d / "wg0.service.log").read_text())
        tray.quit()
        for _ in range(40):
            if tray.refresh() is None:
                break
            time.sleep(0.25)
        self.assertIsNone(tray.state, "quitting stops the service")

    @unittest.skipUnless(os.name == "nt" or sys.platform == "darwin" or os.environ.get("DISPLAY"), "needs a desktop session")
    def test_the_icon_appears_in_the_system_tray(self):
        import subprocess
        code = ("import time, pystray\nfrom pqcsuite.vpn import desktop\nt = desktop.Tray(apply=False)\nt.state = None\n"
                "def setup(icon):\n    icon.visible = True\n    time.sleep(2)\n    print('shown:', icon.visible, flush=True)\n    icon.stop()\n"
                "pystray.Icon('acxelin-vpn-test', desktop.image('protected'), 'Acxelin VPN', t.menu()).run(setup)\n")
        env = {k: v for k, v in os.environ.items() if k != "PYSTRAY_BACKEND"} | {"HOME": str(self.d), "USERPROFILE": str(self.d)}
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "shown: True"), r.stderr)

    def test_the_window_profile_never_offers_to_save_the_passphrase(self):
        with mock.patch.object(self.desktop, "browser", return_value=sys.executable), mock.patch("subprocess.Popen") as popen:
            (self.d / "Default").mkdir()
            (self.d / "Default" / "Preferences").write_text('{"profile": {"name": "kept"}}')
            self.desktop.open_window("http://127.0.0.1:1/#t", self.d)
        args = popen.call_args.args[0]
        self.assertIn("--app=http://127.0.0.1:1/#t", args)
        self.assertIn(f"--user-data-dir={self.d}", args)
        prefs = json.loads((self.d / "Default" / "Preferences").read_text())
        self.assertEqual((prefs["credentials_enable_service"], prefs["profile"]), (False, {"name": "kept", "password_manager_enabled": False}))

    def test_launcher_adds_and_removes_the_app(self):
        env = {"APPDATA": str(self.d / "appdata"), "XDG_DATA_HOME": str(self.d / "share")}
        with mock.patch.dict(os.environ, env), mock.patch.object(Path, "home", return_value=self.d):
            (self.d / "appdata").mkdir()
            if os.name == "nt":
                (self.d / "appdata" / "Microsoft" / "Windows" / "Start Menu" / "Programs").mkdir(parents=True)
            path = self.desktop.launcher()
            self.assertTrue(path.exists(), path)
            if sys.platform == "darwin":
                self.assertIn("<key>LSUIElement</key><true/>", (path / "Contents" / "Info.plist").read_text())
                self.assertTrue(os.access(path / "Contents" / "MacOS" / "acxelin-vpn", os.X_OK))
            elif os.name != "nt":
                text = path.read_text()
                self.assertIn("Name=Acxelin VPN", text)
                self.assertIn("-m pqcsuite vpn desktop", text)
                self.assertTrue(Path(re.search(r"^Icon=(.*)$", text, re.M).group(1)).exists())
            self.desktop.launcher(remove=True)
            self.assertFalse(path.exists())


    def test_start_at_login_shows_only_the_tray_and_can_be_turned_off(self):
        env = {"XDG_CONFIG_HOME": str(self.d / "config"), "HOME": str(self.d), "USERPROFILE": str(self.d)}
        winreg_key = None
        if os.name == "nt":
            import winreg
            winreg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, winreg_key) as k:
                    before = winreg.QueryValueEx(k, self.desktop.NAME)[0]
            except FileNotFoundError:
                before = None
            self.addCleanup(lambda: self.desktop.autostart(False) if before is None else None)
        with mock.patch.dict(os.environ, env), mock.patch.object(Path, "home", return_value=self.d):
            self.assertTrue(self.desktop.autostart(True))
            self.assertTrue(self.desktop.autostart())
            if winreg_key:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, winreg_key) as k:
                    value = winreg.QueryValueEx(k, self.desktop.NAME)[0]
            elif sys.platform == "darwin":
                import plistlib
                value = " ".join(plistlib.loads((self.d / "Library" / "LaunchAgents" / "com.acxelin.vpn.plist").read_bytes())["ProgramArguments"])
            else:
                value = (self.d / "config" / "autostart" / "acxelin-vpn.desktop").read_text()
                self.assertIn("X-GNOME-Autostart-enabled=true", value)
            self.assertIn("vpn desktop --background", value, "at login: the tray only, no window and no administrator prompt")
            tray = self.desktop.Tray(home=self.d, apply=False)
            item = next(i for i in tray.menu().items if i.text == "Start at login")
            self.assertTrue(item.checked)
            self.assertFalse(self.desktop.autostart(False))
            self.assertFalse(self.desktop.autostart())
            self.assertFalse(item.checked)

    def test_a_launcher_path_with_spaces_and_quotes_survives(self):
        with mock.patch.object(Path, "home", return_value=self.d):
            text = self.desktop.desktop_entry(["/opt/Acxelin VPN/run", 'say "hi" $x', "plain"])
        self.assertIn('Exec="/opt/Acxelin VPN/run" "say \\"hi\\" \\$x" plain', text)


class WithoutTheExtraTest(unittest.TestCase):
    def test_says_how_to_get_it(self):
        from pqcsuite.vpn import desktop
        with mock.patch.dict(sys.modules, {"pystray": None}), self.assertRaisesRegex(ImportError, r"pqcsuite\[desktop\]"):
            desktop.main()
