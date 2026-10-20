"""The quality gate: precision and recall on the labelled corpus never drop below the Stage 0 floor.

The corpus is tuned on by construction, so these numbers are a regression floor, never a claim about unseen code.
Labels change only in commits titled `truth:` with a reason per label; then update TRUTH_SHA256 in the same commit.
"""
import hashlib
from pathlib import Path

from acxelin_readiness import bench

BENCH = Path(__file__).resolve().parents[1] / "bench"
FLOOR = {"precision": 1.0, "recall": 1.0}  # what the labelled corpus scores today; it must not drop
TRUTH_SHA256 = "03c80e1338a34c92586aab2ac696cc0109c90980fef279f56766432cf78379c4"


def test_truth_is_the_reviewed_one():
    assert hashlib.sha256((BENCH / "truth.json").read_bytes()).hexdigest() == TRUTH_SHA256


def test_precision_and_recall_hold_the_floor():
    row = bench.main(BENCH / "corpus", BENCH / "truth.json")
    assert row["pairs"] == 174
    assert row["precision"] >= FLOOR["precision"] and row["recall"] >= FLOOR["recall"], row
