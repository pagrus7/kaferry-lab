# Executing the roadmap

## Entry and environment

Read AGENTS.md, PROGRESS.md, and the current milestone. Inspect the worktree before editing. The project config selects `gpt-6.1-sol` and `high` for the parent and sub-agents. Use a trusted checkout; the README command explicitly selects the parent's settings. If the model is unavailable, report that rather than silently changing it. Host permissions and subscription login remain outside the repository config.

M0 establishes Go, Docker/Compose, GitHub CLI, a Linux runtime for the release executable, and network access for pinned dependencies/artifacts. Do not assume the setup repository already has these or that harness commands exist. Pin exact resolved versions in implementation. Use local Docker where suitable, otherwise GitHub Linux runners in this repository. A real Docker/image/storage limitation is a prerequisite to resolve or document, not a passing skipped scenario.

Kaferry is a read-only reference: use `git show v0.6.0:path` in a sibling checkout, or fetch the exact tagged source to `.cache/upstream/`. Do not reset a user's checkout, alter its assets, or import its implementation. Keep download credentials outside artifacts. Record provenance verification failures without relabeling an unverified executable as qualified.

## Working increment

1. Select one milestone acceptance slice; define the fault, observation, assertion, and closest core test before coding.
2. Delegate independent exploration or nonoverlapping implementation where useful. A good assignment names owned files, requirements, evidence and test expectations, and reminds the worker that others share the checkout. Agree on small shared types before parallel work. The coordinator integrates and owns git operations.
3. Implement only needed boundaries: artifact acquisition, environment/process control, independent observation, evidence serialization, offline checker, scenarios. Keep verdict logic independent of fault controllers and Kaferry logs. Do not turn this list into an obligatory package per noun.
4. Run focused unit/control tests, then the real scenario. Store commands, exit status and raw output outside context. Preserve failing histories before reduction/fixes. Distinguish a lab defect from a reproducible product violation.
5. Update operating docs and coverage map. Freeze a commit, request independent docs/test-oracle/simplicity reviews, fix findings and obtain follow-ups. Record exact reviewed commit and limits; never count a launched reviewer as completed review.
6. Push the reviewed increment, inspect final-commit CI, resolve issues and update PROGRESS.md. Continue to the next requirement automatically. A real product finding does not authorize changing release bytes or expectations.

For the initial setup commit, validate links/configuration and the scope/instructions with independent reviews. There is no harness CI or product run to claim yet. Implementation milestones add CI in M0 and require it thereafter.

## Persistent context

Use PROGRESS.md as the only short execution handoff. Include exact commit/worktree state, active milestone, tested commands/results, artifact paths or URLs, unresolved findings, agent assignments, disposable resources and the next command. Keep it under approximately 150 lines by moving durable decisions to their relevant docs and detailed evidence to ignored paths.

Before compaction or a long test boundary, persist enough to continue without the conversation. After compaction, reconcile git status and live resources rather than blindly replaying a stale command. Read summaries and small relevant file ranges; do not dump large histories into the model. Save reduced counterexamples as reviewed synthetic fixtures when suitable.

An agent or session ending is not project completion. On a hard limit, write a handoff with the unfinished acceptance criteria and exact restart instructions. The same CODEX_PROMPT.md resumes from that state. No prompt can bypass runtime quotas or an external blocker; report those honestly and complete independent work while possible.

## Reviews and finish

The docs reviewer checks current commands, prerequisites, evidence claims and clarity. The test/oracle reviewer looks for tautological expected values, false passes, incomplete scans, unobserved faults, unsupported timing assumptions and missing negative controls. The simplicity reviewer challenges unnecessary abstraction and redundant scenarios while preserving independent evidence. Give all the same frozen patch and contracts without steering their initial findings.

Record reports locally under `.cache/reviews/<commit>/`; PROGRESS.md retains their scope and outcomes. Reviewers may read CI metadata and evidence but cannot publish, edit source or run the implementation. After fixes, the affected reviewers recheck the new commit, including cross-cutting consequences. The test reviewer must inspect final-commit CI and recorded campaign outcomes, not only source.

Required completion means M0–M6 implemented and evidenced, final reviews/CI complete, campaign bundles retained and offline rechecked, usable instructions, no untracked source surprises, and pushed commits. Missing mandatory faults or harness failures leave roadmap work unfinished. Genuine product violations can remain as findings while the lab implementation finishes; release qualification stays failed.

## Scratch and resource hygiene

Use `.cache/` for downloads, investigation, review reports and raw design discussions; `artifacts/` for run bundles. Gitignore is not a secrecy boundary: redact before publishing and never force-add. The local brainstorm archive contains superseded proposals, including syntax rejection and migration; the current roadmap and user's correction take precedence.

Give every run a unique ID and scoped resource labels. Always recover faults, terminate/reap workers, and clean only lab-owned resources; keep evidence first. Avoid global prune, host pressure, and touching unrelated Kafka groups/files. Record incomplete cleanup in the handoff. Publish durable synthetic evidence through the implemented lab workflow with explicit hashes and unique names, not by committing logs.
