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

## Amendments

### Amendment 1: 5 October 2026, by the owner (QubitMan), before any label was written

The owner dropped this set on 28 September 2026 and revived it on 5 October 2026. No label had been written and Wolf Pack had not run on these repositories in between; the kit was restored unchanged from git history (commit `a06d310`).

1. **Labels come from AI labellers**, under the first set's amendment 1, items 1 to 3: labeller A (Claude Opus) and labeller B (Claude Sonnet), each in a fresh context and an isolated workspace holding only these 18 repositories (no `.git`), `LABELLING.md`, blank sheets and the format checker; then `heldout.py merge`, and an isolated Claude Opus adjudicator for every disagreement. Isolation is enforced by the workspace and the instructions, not by the operating system. Each labeller's work may be split across several agents by repository; every agent starts fresh.
2. **Audit:** the first set's amendment 3 applies unchanged: an AI audit of a stratified 10% sample (`heldout.py sample --from final --to audit --fraction 0.1 --seed 0`), filled from the source by the assistant that develops Wolf Pack before it opens `final/`, `ai-a/` or `ai-b/`, plus the label-support check. Both are reported as checks on the labels, never as their accuracy, and neither changes a label or the score.
3. **Versions:** the headline stays commit `d9a4de0` (1.2.0). Wolf Pack changed between 28 September and today (versions 1.3.0 to 1.4.1); those changes were made without running Wolf Pack on, or reading, these repositories, but their author had seen the repository names in `repos.json`. The current version (1.4.1, the commit before this amendment's label commit) is scored separately and reported as "later version", never in place of the headline.
4. **Unchanged:** repositories, commits, scope, metrics, vocabulary, expectations E1 to E3, and the rule that labels are committed before Wolf Pack runs on these repositories.
