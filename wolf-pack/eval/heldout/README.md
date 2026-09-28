# Held-out benchmark

**Status (28 September 2026):** labels are done and committed: `labels/ai-a`, `labels/ai-b`, and the adjudicated `labels/final` (see `labels/LOG.md` and pre-registration amendments 1 and 2). No person was available for the human audit, so amendment 3 replaced it with a label-support check and an AI audit (28 September 2026). AI-audit agreement is Dice 0.939 strict and 0.960 inclusive. Of 393 `used` labels, 1 looks doubtful. The details are in `labels/SUPPORT.md`. Wolf Pack is scored (below). The CBOMkit comparison (step 6) has not been run yet.

The benchmark for the paper: 18 real repositories that Wolf Pack was not developed on, labelled blind by someone other than the author, then used to score Wolf Pack, its ablations and CBOMkit. The development corpus in `bench/` only shows that each part of the pack works. This benchmark is the one that measures it.

## Results (28 September 2026)

These are micro-averaged over 18 repos and about 600 files, with 95% bootstrap intervals over repos. Labels: `final`. The full per-repo tables and every ablation are in the JSON files.

| Version | Policy | Precision | Recall | F1 |
|---|---|---|---|---|
| **Headline: `158d69f`** (amendment 2) | strict (primary) | 0.886 [0.79, 1.00] | 0.336 [0.19, 0.50] | 0.487 |
| **Headline: `158d69f`** | inclusive | 0.987 [0.97, 1.00] | 0.277 [0.14, 0.47] | 0.432 |
| Later version: 1.1.0 (`78ec4ed`) | strict | 0.820 [0.70, 1.00] | 0.430 [0.29, 0.57] | 0.564 |
| Later version: 1.1.0 | inclusive | 0.976 [0.96, 1.00] | 0.379 [0.26, 0.50] | 0.545 |
| **After tuning on held-out data:** 1.2.0 | strict | 0.803 [0.68, 0.94] | 0.911 [0.87, 0.95] | 0.853 |
| After tuning on held-out data: 1.2.0 | inclusive | 0.946 [0.91, 0.98] | 0.795 [0.73, 0.87] | 0.864 |

Files: `results-headline-158d69f.json`, `results-later-1.1.0.json` and `results-tuned-1.2.0.json`.

- **1.1.0** includes the stress-test fixes but was not tuned on these repos.
- **1.2.0** was built after reading 1.1.0's misses on these repos, so its row is **after tuning on held-out data**. It shows how far the pack can go on this code, not how it does on code it has never seen. Its new rules were then checked on ten unseen repos and on twelve larger ones (`eval/unseen/`), by the developer's own review:

- ten unseen repos: 77% of the pairs it adds are used, and 91% are used or declared;
- twelve larger repos, 80 random pairs: 91% used, 100% used or declared. The headline stays 158d69f.

**What the numbers say.** Wolf Pack is precise on unseen code, but it finds about a third of the used pairs. Recall is lowest where cryptography is implemented by hand, or reached through the project's own wrappers, with no library call or algorithm name to match:

| Repo | Headline recall | Why |
|---|---|---|
| crypto-algorithms | 0.00 | Hand-written ciphers and hashes in C |
| node-bcrypt | 0.00 | A native binding |
| wireguard-tools | 0.04 | Curve25519 hidden behind `wg genkey` and `wg_generate_*` |
| nsec | 0.07 | libsodium through P/Invoke |
| password4j | 0.08 | Argon2, bcrypt, scrypt and BLAKE2b written in pure Java, and JCA names built at run time |

The later version lifts nsec to 0.67 and crypto-algorithms to 0.28 through its implementation scout. The one precision failure is otp-java, where 5 found pairs match 0 used pairs (all 5 are `declared`).

**Exploratory, not pre-registered:** 1.2.0 marks findings that are only named in an algorithm list or table as `declared`. `score --used-only` leaves those out, and under the strict policy (after tuning) it scores P 0.834, R 0.906, F1 0.868. The gain is small because most remaining strict false positives are classes that declare algorithms (nsec), not lists.

**Expectations** (pre-registration):

- **H2 holds.** Precision is higher under the inclusive policy: 0.987 against 0.886.
- **H3 holds.** Without the den, precision drops from 0.886 to 0.744 (strict). Without the second look, recall drops from 0.336 to 0.229.
- **H1 is untested.** It needs the CBOMkit run in step 6.
- **Removing the den raises F1** (0.487 to 0.584 strict), because on this code it rejects more true pairs than false ones. The paper reports this.

**Caveats.**

- Every gold label was written by AI, and there was no human check (amendment 3, item 4).
- One gold pair is doubtful (`labels/SUPPORT.md`).

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
