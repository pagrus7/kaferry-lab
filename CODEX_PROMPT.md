Resume the Kaferry tool resilience and data integrity project in `/Users/pg/Documents/Codex/kaferry-lab`.

Purpose

Kaferry is the tool under test. Exercise its published data-copy executable under bounded process, Kafka, network and storage failures. Check record membership, byte fidelity, routing and saved progress independently, then observe recovery after faults are removed. The objective is evidence of tool resilience and data integrity. Harness calibration validates the observations and checker; it does not qualify Kaferry.

Authorization and execution boundary

Pavel authorizes implementation and testing in this lab repository and its uniquely named disposable runtime resources. The workload uses synthetic records and lab-generated credentials. Workload traffic must stay within the lab's own Kafka clusters, workers, fault proxies and test receivers. Normal access to dependency/release/documentation sources and `pagrus7/kaferry-lab` GitHub repository/CI is authorized.

Before a runtime mutation, identify the exact lab-owned process handle or resource name, run ID and ownership label from the run manifest. Process signals may target only children started by this harness. Broker pauses/restarts, directional link delays/resets, capacity-limited storage faults, and temporary broker configuration/ACL changes may target only the disposable resources created for that run. Use recorded time/resource budgets, confirm the intended condition was reached, restore the condition and reap owned processes even on failure. Store evidence before cleanup.

Do not target production, unrelated containers/services, third-party systems or real broker credentials. Do not change the host clock, host firewall or global Docker state, fill host storage, or disable platform safeguards. Offline malformed/corrupted evidence controls operate on synthetic fixtures. If an action is denied by a safety or approval control, retain its exact action, notice and reason; do not retry through another route around that denial. Continue independent permitted work and identify the precise prerequisite for the blocked step.

Resume from actual state

Read AGENTS.md and PROGRESS.md, inspect the branch/worktree and live resources, then read the relevant ROADMAP.md, contract and evidence sections. Preserve existing uncommitted work. Continue on `codex/resilience-release-lab`, tracking `origin/codex/resilience-release-lab`. M0 is accepted at `9d3231a7a314a29c7b91d58bee8c186befb98df1` and M1 at `c1eb315ef80186d74576d5710cb6005580e0cb44`; M2 is the first unfinished milestone. Preserve existing work, including any uncommitted edits and the isolated implementation proposals. PROGRESS.md, actual files and retained evidence determine the current step; do not repeat completed research or infer completion from this prompt.

Required work

Complete every required M0–M6 roadmap acceptance criterion, starting with the first unfinished requirement. Test verified, digest-pinned published Kaferry v0.6.0 artifacts against the reviewed tagged contract. Keep the sibling Kaferry repository read-only. No source-build fallback, Kaferry imports/internal codecs as oracles, prior-syntax rejection, broad migration coverage or redundant core regression matrices. Preserve the scope and individual acceptance criteria in ROADMAP.md.

Use independent observations and offline checking for record fidelity, membership, routing, saved progress and recovery. Missing observations, unreached conditions, incomplete scans and product violations never become passing results. Separate calibration histories and faulty stand-ins from release evidence. The user selected native Linux ARM64 under local OrbStack on 2026-10-26, replacing Linux AMD64 as the required final target. Keep execution and private evidence on the Mac and do not enroll Tailscale. Preserve earlier AMD64 evidence as historical measurements; it does not establish ARM64 behavior. AMD64 emulation remains development evidence only. The existing artifact, process, image and observer gates require measured ARM64 adaptation before qualification; see docs/local-linux-arm64.md. Local Go/build/test/vet/typecheck, attestation-cache and packet-capture stops remain binding; a runner, VM or changed cache is not permission to retry denied operations.

Use GPT-6.1 Sol/high native sub-agents for bounded research, disjoint implementation and independent docs/test-oracle/simplicity reviews. Assign explicit file ownership and preserve others' changes. The coordinator owns integration, PROGRESS.md and git operations. Freeze reviewed increments, resolve findings, push the feature branch and inspect final-commit CI. Do not push during source reviews. Continue routine work within this authorization without asking whether to proceed.

Keep PROGRESS.md concise and restartable: current step, commit, measured evidence, decisions, blockers, ownership, live resources and exact next commands. Put large logs in ignored .cache/ or artifacts/. Before compaction or session handoff, update progress; after resuming, reconcile it with actual state.

Open a PR against main once the entire required roadmap, evidence, reviews and final CI are complete. Do not merge automatically. If genuinely blocked, finish independent work and leave exact evidence and resume instructions without claiming completion.
