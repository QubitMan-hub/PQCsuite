# Labelling log

25 September 2026. Labels written under pre-registration amendment 1.

## Labellers

- **Labeller A** (Claude Opus, `ai-a/`) and **labeller B** (Claude Sonnet, `ai-b/`): 7 groups of repositories each, every agent in a fresh context, in an isolated workspace holding only the 18 repositories (no `.git`), `LABELLING.md`, blank sheets and a format checker.
- **Adjudicators** (Claude Opus, 3 agents): resolved the 111 cells where A and B disagreed. They sided with A 102 times, with B 4 times, and with neither 4 times. The result is in `final/`.
- **Agreement:** 1,103 of 1,214 cells agreed before adjudication. Per-repo Dice agreement is in the table from `heldout.py agree ai-a ai-b`, reproduced in `eval/heldout/README.md`.

## Deviations the agents reported

- **Partial reading:** labeller A for crypto-algorithms, tiny-aes-c and wireguard-tools first keyword-searched about 30 files instead of reading them. The operator asked for a full re-read before merging; 5 rows changed (wireguard-tools shell scripts).
- **Helper scripts:** labeller A for armadillo, password4j and otp-java wrote a comment-stripping helper and a CSV writer in the scratchpad, outside the workspace; neither analyses cryptography. Labeller A for jwcrypto, magic-wormhole and pyotp briefly wrote a temporary grep output file inside its own sheet folder and deleted it. One adjudicator kept a small CSV helper script in the scratchpad root.
- **Report exposure:** the labellers' final reports, which included some of their judgement calls, were returned to the operator (the assistant that develops Wolf Pack). Under amendment 2, the headline Wolf Pack version is the one committed before any label existed, so this exposure cannot influence the headline result.

## Human audit

`audit/` holds blank sheets for a stratified 10% sample (seed 0). A person fills them from the source, without seeing `final/`, `ai-a/`, `ai-b/` or any tool output, and without AI help. `heldout.py agree final audit` then gives the accuracy of the gold labels. Scoring waits for this.
