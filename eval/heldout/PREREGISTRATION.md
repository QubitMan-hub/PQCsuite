# Pre-registration: Wolf Pack held-out benchmark

Status: **signed off by the owner, QubitMan, on 25 September 2026**, before any label was written. From this commit on, the file is not edited except to append dated amendments at the bottom.

The labelling conventions in `LABELLING.md` were confirmed at the same time. The strict policy is primary. An HMAC or KDF is labelled together with its hash (`HmacSHA256` is HMAC and SHA-256), and SHA-512/224 and SHA-512/256 are labelled SHA-512. Wolf Pack was aligned with both conventions before labelling, using only the development corpus.

## Question

On real code that was not used to develop it, how accurately does Wolf Pack inventory cryptography at the level of (file, algorithm family)? How does it compare with IBM CBOMkit on the languages CBOMkit supports? And what does each role of the pack contribute?

## Data

- **Repositories:** the 18 listed in `repos.json`, pinned to exact commits: three each in Java, Python, Go, JavaScript, C and C#. None was used while developing Wolf Pack; the eight repos used during development (pyjwt, node-jsonwebtoken, age, paramiko, java-jwt, jjwt, python-jose, python-rsa) are excluded.
- **Selection:** the author's assistant chose them for real cryptographic use, active or well-known projects, a mix of applications, libraries and raw implementations, and a labelling effort of at most about 100 files each. Wolf Pack has not been run on any of them.
- **Scope:** every non-test source, configuration, key and certificate file that `heldout.py sheets` lists. Binaries are out of scope because a human cannot label them.
- **Labels:** written blind by one primary labeller who is not the author, following `LABELLING.md`, and committed before any tool runs. A second, independent labeller covers at least four repos across three languages.

## Metrics

- A **pair** is (file, algorithm family). Tools are scored on the pairs they report as accepted; for Wolf Pack that is verdict `accepted` in `findings.json`.
- **Precision, recall and F1** are micro-averaged over all in-scope files of all repos, with 95% bootstrap intervals from resampling repositories (2000 resamples, seed 0).
- **Two labelling policies**, both reported:
  - **strict** (primary): gold pairs are the `used` labels only.
  - **inclusive** (secondary): gold pairs are `used` plus `declared`.
- **Labeller agreement:** Dice overlap of the two labellers' pair sets under each policy, on the repos both labelled.
- **Per repository:** precision and recall for each repo, reported in full.

## Comparisons

1. **Wolf Pack alone:** the full pack on all 18 repos, under both policies.
2. **Wolf Pack against CBOMkit:** both tools restricted to Java, Python, Go and C# files on the 12 repos in those languages.
   - CBOMkit-action runs at the version recorded with the results, with Java projects built first where the build works on JDK 21. A repo whose build fails is scanned without a build, and the paper says so.
   - `OTHER:` families count as gold for both tools.
3. **Ablation:** every single-role ablation in `wolfpack bench` (`heldout.py score --ablations`).

## Expectations, written before labelling

- **H1.** Under the strict policy, Wolf Pack's recall on CBOMkit's languages is higher than CBOMkit's.
- **H2.** Wolf Pack's precision is higher under the inclusive policy than under the strict one, because it reports declared support.
- **H3.** Removing the den lowers precision and removing the second look lowers recall, on held-out code as on the development corpus.

Any of these may turn out false, and the paper reports whichever way they fall.

## Rules for what happens after scoring

- **Versions:** the Wolf Pack commit and version used for the first scoring run are recorded in the results file. Those are the headline numbers.
- **Later fixes:** if held-out errors lead to fixes, numbers from the fixed version are reported separately, labelled "after tuning on held-out data", and never replace the first run.
- **Frozen labels:** labels are not changed after scoring. Mistakes found later are logged with dates and reported.
- **Excluded repos:** a repository that cannot be scanned by one tool is reported as such, not dropped silently.

## Amendments

(none)
