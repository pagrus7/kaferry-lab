# Contributor instructions

## Scope and independence

- Complete the required milestones in ROADMAP.md. The objective is tool resilience and data integrity: test how the released Kaferry data-copy executable, initially v0.6.0, handles failures and recovers while preserving records and saved progress. Do not add old-syntax rejection, parser coverage, broad upgrade testing, or basic regression matrices.
- Read PROGRESS.md at entry and after compaction. Read only the relevant roadmap, contract, and evidence sections next; do not reload transcripts or whole logs.
- Before adding a scenario, inspect the tagged core tests and record the additional failure mechanism or observation in docs/coverage.md. Independent execution of the release and independent checking can add value even when a basic fault already exists. Merely duplicating a core test cannot.
- Qualification runs immutable published artifacts only. No Kaferry imports, internal codecs, source build fallback, local replace directives, or in-process application calls. Read tagged source as evidence, never use its implementation as the oracle. Calibration specimens are visibly separate.
- Keep the Kaferry repository read-only. Report reproducible product defects with bundles; do not fix them here, rewrite tags, or change Kaferry release workflows.
- Prefer ordinary Go functions and narrow components. No scenario language, plugin system, custom Kafka protocol proxy, dashboard, or generalized virtual filesystem without a demonstrated unmet requirement.
- Functional scenarios use Given/When/Then. Every fault needs a bounded trigger, proof it was reached, recovery, and a specific oracle. Unreached faults and missing evidence cannot pass.

## Autonomy and delegation

- Continue milestone to milestone without asking whether to proceed. Planning, scaffolding, a green smoke test, or an intermediate commit is not completion. Use the current environment and authorized GitHub repository to implement, test, commit, and push focused changes.
- Use native sub-agents as needed, explicitly authorized for this roadmap. Use GPT-6.1 Sol with high effort. Assign nonoverlapping file ownership and acceptance criteria; tell workers they share the checkout and must preserve others' edits. Only the coordinator edits PROGRESS.md, coordinates integration, and commits/pushes.
- Delegate bounded research, independent checker review, or an isolated implementation slice. Send file paths, contract excerpts, and a concrete question rather than the full conversation. Reuse a relevant agent; close finished agents. Do not recursively spawn unbounded teams.
- Before each implementation milestone is considered done, obtain independent docs, test/oracle, and simplicity reviews on a frozen commit using local Codex subscription agents. Reviewers read the actual patch and relevant contracts, do not edit source or run tests, and report scope, findings, and limits. The test reviewer also inspects final-commit CI/evidence. Record reports in `.cache/reviews/`; keep a concise outcome in PROGRESS.md. Fix findings and request affected follow-up reviews; stale approvals do not count. Do not push during source reviews.
- Implement meaningful checker and controller tests, including failure detection controls. Do not add tests that only mirror implementation. Run targeted checks during edits and required final CI once per final change; retain failures, do not rerun until green without explaining the change.

## Context and progress

- PROGRESS.md is a compact handoff, not a diary (target at most 150 lines). Update it before compaction, before a likely long boundary, and after every milestone/review. Record the active step, exact next command, commit, tests actually run, evidence paths, unresolved findings, delegated ownership, and live resource identifiers.
- Put lasting decisions in the relevant design document and raw material in ignored storage. Preserve minimized failures and evidence references. Do not rely on chat, agent memory, or temporary transcripts for requirements.
- After resuming, inspect git status and actual resources, reconcile PROGRESS.md, and continue the first unfinished requirement. Never equate context exhaustion with completion. If a hard runtime/session limit forces a stop, leave a restartable handoff and state exactly what remains.
- A real external blocker must include the failed command, evidence, smallest missing prerequisite, and independent work completed meanwhile. Do not mark blocked milestones done, weaken requirements, fabricate evidence, or silently substitute models/artifacts/environments.

## Operations and publication

- Faults may target only this lab's uniquely named disposable containers, networks, processes, and volumes. Record ownership. No host disk filling, host clock changes, global Docker prune, real brokers, production credentials, or unbounded resource consumption.
- Restore faults and reap child processes even on errors/cancellation. Keep evidence before cleaning lab-owned resources. Bind local services to loopback where feasible. CI has explicit time/resource budgets and least-privilege tokens; untrusted PR code receives no publishing credentials.
- Store generated files under `.cache/` or `artifacts/`, never force-add them. Publish only reviewed, redacted evidence containing synthetic inputs. Do not print credentials or upload raw consultation transcripts.
- Keep docs honest about implemented versus planned commands and measured versus expected behavior. Passing harness CI is not a passing Kaferry qualification. A detected product violation is useful evidence, never a reason to suppress a test.
