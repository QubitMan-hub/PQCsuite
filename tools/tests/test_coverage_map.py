import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from coverage_by_product import aggregate, load_map  # noqa: E402

MAP = ROOT / "tools" / "coverage_map.toml"
BASE = "5f8c349a102e566560708ee12b9b1574e4a6e6cc"  # the map describes the files at the base commit, before anything moves
DESTINATIONS = {"core", "tls", "vpn", "readiness", "vault", "deleted"}


def test_every_source_file_mapped_once():
    listed = subprocess.run(["git", "ls-tree", "-r", "--name-only", BASE, "--", "pqcsuite", "wolf-pack/wolfpack"],
                            cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = {f for f in listed if Path(f).suffix in {".py", ".html", ".js"}}
    assert set(load_map(MAP)) == files


def test_destinations_valid_and_deletions_explained():
    for f, (dest, reason) in load_map(MAP).items():
        assert dest in DESTINATIONS, f
        assert dest != "deleted" or reason, f


def test_aggregate_excludes_deleted_and_weights_by_statements():
    m = {"a.py": ("core", ""), "b.py": ("core", ""), "c.py": ("deleted", "suite hub")}
    assert aggregate({"a.py": (10, 0), "b.py": (30, 15), "c.py": (50, 50)}, m) == {"core": 62.5}
