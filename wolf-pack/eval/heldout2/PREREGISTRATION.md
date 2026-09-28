# Pre-registration: second held-out benchmark

Status: written on 28 September 2026, before any label exists and before Wolf Pack has run on any of these repositories. From this commit on, the file is not edited except to append dated amendments at the bottom.

## Why a second set

The first held-out set (`../heldout`) was scored and then used to tune Wolf Pack 1.2.0, so its 1.2.0 numbers are "after tuning". This set measures the current version on code it has never seen.

## Frozen version

The scored version is **Wolf Pack at commit `d9a4de0`** (version 1.2.0 as of that commit). It is the parent of the commit that adds this file. Any later change to Wolf Pack is scored separately and reported as "later version", never in place of this one.

## Data

- **Repositories:** the 18 in `repos.json`, pinned to exact commits and covering Java, Python, Go, JavaScript/TypeScript, C, C#, Rust and PHP. None appears in any earlier set: held-out, fresh, stress, CBOMkit, or either `eval/unseen` round.
- **Scope:** every file `heldout.py sheets` lists, 686 in all. smallstep-crypto has 175, more than the 100 the first set aimed for; it stays because a large Go library is realistic.
- **Labels:** written blind, following `../heldout/LABELLING.md` unchanged, and committed before Wolf Pack runs on these repositories. Who labels is recorded in `labels/LOG.md` before scoring. People are preferred. If AI labellers are used, the process is the one in the first set's amendment 1: two isolated labellers who see only the repositories and the guide, then an adjudicator. The paper says which was used.

## Metrics

The same as the first set. A pair is (file, algorithm family). Precision, recall and F1 are micro-averaged, with 95% bootstrap intervals over repositories (2000 resamples, seed 0).

- **Strict (primary):** `used` labels only.
- **Inclusive (secondary):** `used` plus `declared`.
- **Exploratory:** `score --used-only`, reported as exploratory.

The family vocabulary is the first set's, frozen; anything outside it is labelled and scored as `OTHER:<NAME>`.

## Commands (run with `HELDOUT_KIT` pointing at this folder)

```
HELDOUT_KIT=eval/heldout2 python eval/heldout/heldout.py fetch
HELDOUT_KIT=eval/heldout2 python eval/heldout/heldout.py sheets --labeller <name>
HELDOUT_KIT=eval/heldout2 python eval/heldout/heldout.py check --labeller <name>
HELDOUT_KIT=eval/heldout2 python eval/heldout/heldout.py score --labeller final --per-repo --json eval/heldout2/results.json
```

The scoring run checks out commit `d9a4de0` first (a git worktree), as the first set did for its headline.

## Expectations, written before labelling

- **E1.** Strict precision is at least 0.75. On the first set, after tuning, it was 0.80.
- **E2.** Strict recall is lower than the first set's tuned 0.91, because the rules were shaped on that code. The first set's untuned recall, 0.43, is the floor to beat.
- **E3.** Hand-written implementations (sha2, libscrypt, argon2, noble-ciphers, bcrypt.js, sha256-simd) are found mostly through the `names` and `implementations` roles.

Whatever the results, they are reported.
