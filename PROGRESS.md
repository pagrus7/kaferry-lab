# Implementation handoff

## Current state

- Setup only. M0–M6 are not implemented; no Kaferry qualification has run here.
- Target: published v0.6.0, source commit `d7d485b96a52b711cb10d76dca09aa9b155dec5e`.
- Kaferry checkout: `../kaferry` when available; read-only reference. Tagged source is authoritative, not its current branch.
- User explicitly removed prior-syntax rejection and wants additional adversarial evidence beyond the core suite.
- Configuration: GPT-6.1 Sol / high, with up to three delegated agents.

## Next actions

1. Inspect `git status --short`, read ROADMAP.md M0 and docs/evidence.md.
2. Check `go version`, `docker version`, `docker compose version`, and `gh auth status` (never print tokens). Pick a disposable Linux runner if the host cannot execute Linux binaries natively.
3. Complete M0's tagged coverage inventory and observer capability spike. Create the smallest Go module and CI that support those checks; do not construct the whole harness speculatively.
4. Replace this checklist with exact commands and evidence as work progresses.

## Milestones

| Milestone | State | Evidence / remaining work |
| --- | --- | --- |
| M0 Independence and coverage | Not started | Audit core tests, select/validate observer, bootstrap Go/CI |
| M1 Evidence and checker | Not started | Artifact identity, offline checker and controls |
| M2 Crash and timeout campaign | Not started | First integrated release qualification |
| M3 Ownership and network timing | Not started | Proven reassignment, delayed/failed links, transactions |
| M4 Archive and storage faults | Not started | Real archive recovery, physical record obligations |
| M5 Replication and interference | Not started | Leader/coordinator failures, shutdown contention |
| M6 Campaigns and delivery | Not started | Bounded compositions, retention, CI, final reviews |

## Blockers, resources, and reviews

- No implementation blocker investigated yet.
- No lab containers, workers, or fault processes started.
- No delegated implementation owners active.
- Setup review and validation: pending initial repository publication.
- Raw design discussions are local-only under `.cache/brainstorm/`; they contain superseded proposals and are not requirements.
