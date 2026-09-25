import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval" / "heldout"))

import heldout


class Sheets(unittest.TestCase):
    def test_cells(self):
        self.assertIsNone(heldout.parse_cell(""))
        self.assertEqual(heldout.parse_cell("-"), (set(), []))
        self.assertEqual(heldout.parse_cell("rsa; sha-256;"), ({"RSA", "SHA-256"}, []))
        self.assertEqual(heldout.parse_cell("OTHER: Salsa20"), ({"OTHER:SALSA20"}, []))
        self.assertEqual(heldout.parse_cell("AES; SHA256"), ({"AES"}, ["SHA256"]))

    def test_used_wins_over_declared_and_blanks_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "r.csv"
            p.write_text("file,used,declared,notes\na.py,AES,AES; RSA,\nb.py,,-,\n", encoding="utf-8")
            labels, problems = heldout.load_labels(p)
        self.assertEqual(labels, {"a.py": ({"AES"}, {"RSA"})})
        self.assertEqual(len(problems), 1)
        self.assertEqual(heldout.gold(labels, "strict"), {("a.py", "AES")})
        self.assertEqual(heldout.gold(labels, "inclusive"), {("a.py", "AES"), ("a.py", "RSA")})

    def test_scope_skips_tests_and_lockfiles(self):
        with tempfile.TemporaryDirectory() as d:
            for f in ("src/app.py", "tests/test_app.py", "package-lock.json", "config/app.yaml", "README.md", ".github/workflows/ci.yml"):
                (Path(d) / f).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / f).write_text("x", encoding="utf-8")
            self.assertEqual(heldout.scope(d), ["config/app.yaml", "src/app.py"])


class Scoring(unittest.TestCase):
    def test_dev_corpus_through_the_kit_matches_bench(self):
        corpus = ROOT / "bench" / "corpus"
        truth = json.loads((ROOT / "bench" / "truth.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            sheet = Path(d) / "corpus.csv"
            with open(sheet, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(heldout.COLUMNS)
                for file, fams in truth.items():
                    w.writerow([file, "; ".join(fams) or "-", "-", ""])
            labels, problems = heldout.load_labels(sheet)
        self.assertEqual(problems, [])
        row = heldout.prf(heldout.wolfpack_pairs(corpus, set(labels)), heldout.gold(labels, "strict"))
        self.assertEqual(row[3:5], (1.0, 1.0))

    def test_bootstrap_is_repeatable(self):
        rows = [(3, 4, 5, 0, 0, 0), (1, 1, 2, 0, 0, 0), (0, 2, 1, 0, 0, 0)]
        self.assertEqual(heldout.bootstrap(rows, 200), heldout.bootstrap(rows, 200))
        (pl, ph), (rl, rh) = heldout.bootstrap(rows, 200)
        self.assertTrue(pl <= heldout.micro(rows)[0] <= ph and rl <= heldout.micro(rows)[1] <= rh)


if __name__ == "__main__":
    unittest.main()
