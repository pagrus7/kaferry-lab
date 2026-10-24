# Implementation handoff

## Current step

- M0 follow-up source ready to freeze: P1 strict Fetch batch admission fix integrated and tested; initial review at `0af3e7b` retained. NOT pushed. M0 incomplete until affected follow-ups and native AMD64 final-commit CI. M1 staged only; M2–M6 unimplemented.
- Base commit `49ee1487c5730d8eec6bafed4af4757b18938689`; target v0.6.0 resolves to `d7d485b96a52b711cb10d76dca09aa9b155dec5e`.
- Permissions and TLS repaired by user. Coordinator can write repo/.git; `SSL_CERT_FILE=/etc/ssl/cert.pem gh api repos/pagrus7/kaferry-lab` reports push=true. Resumed agents retain old sandbox and stage authorized files in external workspace; coordinator integrates.
- No Kaferry qualification or milestone completion yet. Local live observer attempt f passed on actual Linux ARM64 brokers; do not call it native AMD64 qualification.

## Evidence and decisions

- Read-only tagged research copied into `.cache/research/{coverage-network,coverage-archive,observer-research}.md`.
- Audit compares 11 M2/M3/M5 cases and M4 mechanisms against exact core tests; some tests run in process, others launch test helpers or CLI with optional source build fallback. Blocked stderr alone already has core coverage.
- Measured mandatory gap: Kafka accepts -2ms timestamps but Sarama cannot observe them faithfully. Select protocol-level kafka-go scanner only after its explicit byte/negative/transaction controls pass; retain Sarama as admin/transaction helper. High-level kafka-go reader also collapses nil/empty; never use it as byte oracle. Default Sarama partitioner is FNV-1a.
- Host Go `go1.27.2 darwin/arm64`; Docker `linux/aarch64`. User confirmed AMD64 emulation works; label it emulated. Final required native AMD64 campaign will use GitHub Actions `ubuntu-24.04`.
- Kaferry sibling read-only, pre-existing untracked logo assets preserved. Never source-build qualification artifacts.

## Ownership and resources

- Coordinator: PROGRESS.md, runtime fixture/CI/integration/git; staged `internal/calibration/{standin,run}.go` M1 actual child-process control (not compiled/tested yet; cmd/lab not written).
- `observer_research`: owns staged observer fix + module deps. P1: kafka-go v0.4.49 (also .51) can suppress malformed trailing records/batches; strict raw v11 Fetch frame/batch admission needed before codec output can establish completeness. No custom proxy/general protocol stack; keep API, remove redundant secondary test reader.
- `archive_audit`: completed identity/docs slice (integrated); now owns staged `internal/evidence/` M1 offline-checker slice, held until M0 reviewed increment.
- `coverage_audit`: completed coverage inventory (integrated; 44 cited tests verified); now owns staged `internal/artifact/` M1 verification slice, held until M0 reviewed increment.
- Shared staging root: `/Users/pg/Documents/Codex/2026-10-24-work-in-users-pg-documents-codex/kaferry-lab-handoff/staged/`. Preserve disjoint ownership; copy only completed files.
- No live lab resources. Fixtures a/b/c cleaned with broker logs retained; c cleanup `.cache/m0/fixture-c-cleanup.json`. State retained for idempotent cleanup: `go run ./cmd/fixture down m0-local-20261024c`. Actual local Docker Linux ARM64; native CI pending.
- Original fixture a exposed identical Apache default cluster IDs; failed topology observation retained, logs captured and all a resources cleaned. New fixture b records crypto-random distinct cluster IDs. Add regression control; do not relabel initial run as pass.
- Initial review reports `.cache/reviews/0af3e7b0dd4e46a8c968323954657ddb2cfa01c7/`: docs passed; simplicity no blockers (optional redundant test reader); test/oracle requests P1 strict batch admission plus malformed multi-record/multi-batch sensitivity control. Source healthy runs do not discharge that defect. Native AMD64 CI pending; no pass claimed.
- After P1 fix, format/vet/race passed `.cache/m0/strict-final-unit.log`; live integrated h passed `.cache/m0/m0-observer-20261024h.log` (g staging passed). New literal controls reproduce decoder [0,2] successful-prefix loss then reject malformed raw evidence. Old b–f results retained. Unsupported LAT/unknown tails stay fail-closed; no native CI yet.

## Next actions

1. Commit integrated P1 fix/docs/handoff, then obtain affected docs/test-oracle/simplicity follow-ups on exact SHA. No push during source reviews; then push only after blockers resolved.
2. Resolve review findings, push reviewed increment, inspect native `Harness CI` final-commit checks and retain artifact; test reviewer must inspect actual CI evidence before M0 accepted.
3. Integrate held M1 artifact/checker slices, implement actual trusted `gh attestation verify` boundary, offline check CLI and killed commit-before-produce calibration stand-in. Contract root: `df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46` (sorted source doc hashes in `.cache/m0/tagged-contract.sha256`).
4. Complete M0 acceptance, continue M1–M6 without routine confirmation; update this handoff before long boundaries.
