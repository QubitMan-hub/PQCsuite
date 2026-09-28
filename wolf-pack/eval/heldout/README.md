# Held-out benchmark

**Status (25 September 2026):** labels are done and committed: `labels/ai-a`, `labels/ai-b`, and the adjudicated `labels/final` (see `labels/LOG.md` and pre-registration amendments 1 and 2). The last step before scoring is the human audit of `labels/audit/` (63 files).

The benchmark for the paper: 18 real repositories that Wolf Pack was not developed on, labelled blind by someone other than the author, then used to score Wolf Pack, its ablations and CBOMkit. The development corpus in `bench/` only shows that each part of the pack works. This benchmark is the one that measures it.

| File | What it is |
|---|---|
| `repos.json` | The 18 repositories, each pinned to a commit, with the reason it was chosen |
| `PREREGISTRATION.md` | Metrics and expectations, signed off before labelling, with dated amendments |
| `LABELLING.md` | The guide the labellers follow |
| `heldout.py` | `fetch`, `sheets`, `check`, `agree`, `merge`, `sample`, `score` |
| `labels/<labeller>/` | The labellers' sheets and logs (committed before any tool runs) |
| `repos/` | The fetched repositories (not committed) |

## Order of work

1. **Pre-register.** The owner signs off `PREREGISTRATION.md` and commits it.
2. **Fetch and make sheets.** Run `fetch`, then `sheets --labeller <name>` for each labeller.
3. **Label blind.** Follow `LABELLING.md`. `check` must report no problems.
4. **Commit the labels.** Their commit time proves they came before any tool output.
5. **Measure agreement.** `agree <primary> <second>`.
6. **Run CBOMkit** on the 12 Java, Python, Go and C# repos (see `eval/cbomkit/README.md`), saving `<dir>/<repo>/cbom.json`.
7. **Score.** `score --labeller <primary> --ablations --cbomkit <dir> --per-repo --json results.json`, then commit `results.json`.

## Commands

```powershell
python eval/heldout/heldout.py fetch
python eval/heldout/heldout.py sheets --labeller alice
python eval/heldout/heldout.py check --labeller alice
python eval/heldout/heldout.py agree alice bob
python eval/heldout/heldout.py score --labeller alice --ablations --cbomkit ck-out --per-repo --json eval/heldout/results.json
```

`score` refuses to run until every sheet is complete and valid. `--partial` overrides that for a dry run of the pipeline, never for reported numbers.

## Scope and size

About 600 files across the 18 repos, from 3 (iron) to 103 (nsec). Most are short, and most will be `-`. `sheets` lists every non-test source, config, key and certificate file, so "no crypto here" is an explicit answer rather than a gap. Recall therefore counts misses in files a scanner never flagged, too.
