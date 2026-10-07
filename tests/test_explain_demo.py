import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ExplainDemoTest(unittest.TestCase):
    def test_every_step_ends_as_the_story_says(self):
        with tempfile.TemporaryDirectory() as d:
            script = Path(shutil.copy(Path(__file__).parent.parent / "examples" / "explain_demo.py", d))
            r = subprocess.run([sys.executable, str(script), "--auto"], capture_output=True, text=True, encoding="utf-8", timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(r.stdout.count("REFUSED"), 4)  # no card, forged card, revoked partner, revoked branch
            for word in ("EXPOSED", "SAFE", "grade C", "payroll-october.csv"):
                self.assertIn(word, r.stdout)
            self.assertIn("ID card cancelled", (script.parent / "explain-demo-results.html").read_text(encoding="utf-8"))
