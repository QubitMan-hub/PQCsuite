# Audit log (amendment 3)

28 September 2026. The 63-file sample in this folder, labelled by the assistant that develops Wolf Pack, following `LABELLING.md`.

- Every file was read in full from `repos/` (not keyword-searched). `final/`, `ai-a/` and `ai-b/` were not opened, and no scanner was run on these repositories, before this commit.
- The auditor knows Wolf Pack's rules; the paper reports that this could pull its labels toward what Wolf Pack finds. The audit only measures the gold labels; it changes neither them nor any score.
- Uncertain calls are marked `?` in notes. The main ones: WireGuard scripts that generate or set Curve25519 keys (labelled X25519); a Noise session driven with no primitive named (left `-`); P/Invoke bindings for Argon2 (declared); an EC key loader with no signing (ECC); a header that configures AES-128 (AES).
