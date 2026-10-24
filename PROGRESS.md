# Implementation handoff

## Current step

- M0 accepted at `9d3231a7a314a29c7b91d58bee8c186befb98df1`, pushed on `codex/adversarial-release-lab`. Main remote unchanged. User requests PR **after entire required roadmap is done**, not an interim PR.
- M1 in progress: artifact verifier/checker/CLI/actual calibration stand-in integrated; controller controls and operating docs/CI added. Initial frozen review at `1c55a1a` found four checker gaps; fixes and control tests are ready for affected follow-ups, then native final-head CI. M2–M6 not implemented.
- Target v0.6.0 / `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Kaferry sibling stays read-only. No qualification campaign has run.

## Acceptance and evidence

| Milestone | State | Evidence / remaining |
| --- | --- | --- |
| M0 | Accepted | Three independent source follow-ups + final-CI oracle approval at `.cache/reviews/9d3231a7a314a29c7b91d58bee8c186befb98df1/`; native Ubuntu24 AMD64 CI [40139173038](https://github.com/pagrus7/kaferry-lab/actions/runs/40139173038), unit+observer success. Download `.cache/ci/40139173038/`. |
| M1 | In progress | Prior integrated suite and actual calibration retained. Resume offline rechecks retain healthy PASS / faulty VIOLATION at `.cache/m1/resume-recheck-*.json`. Controller/CLI controls and ownership records integrated. Initial docs/simplicity passed; oracle found two P1/two P2 gaps. Fixed tail omission, stale triggers, conflicting positions and destination identity; targeted controls, test framing simplification and CI coverage now await follow-up reviews and final-head CI. Local verifier remains UNVERIFIED after platform denial. |
| M2–M6 | Not started | All required real fault scenarios/campaigns/operating delivery remain; no product verdict. |

- M0 P1 initial review found kafka-go decoder successful-prefix suppression. Resolved with strict raw fixed-v11 admission + literal malformed multi-batch controls; old reviews and a–h observations retained under `.cache/reviews/` / `.cache/m0/`.
- Selected primary scanner: kafka-go protocol payload decoder guarded by strict framing/count/CRC/decompression/metadata admission; Sarama admin/transaction producer + independent known-byte cross-read. Negative -2ms/epoch/modern CreateTime measured. LAT remains unsupported; affected runs must not pass. No broad parser/old-syntax/core regression tests.
- Current source/scenario bounds: 1024 ledger entries, 256 partitions and 64MiB streams in evidence-v1; larger/unknown/archive cases explicitly unsupported until reviewed extensions. Full campaign qualification is always false in this initial checker.
- Published archive digest `d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f`; binary `becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770` (23814268 bytes). Public verifier/checker pin these despite GitHub mutable release flag.
- Actual trusted `gh attestation verify` succeeded with repo/workflow/source/ref policy: `.cache/m1/gh-attestation.json` + `.err`. This preliminary provenance check did not execute the binary. CLI must still demonstrate full path/version observation.
- Resumed full `lab verify .cache/releases/m1-resume-20261024a` exited2 before execution. Exact diagnostic notices in `.cache/m1/attestation-diagnostic.stderr`: platform denied gh TUF cache writes under `/Users/pg/.cache/gh/.sigstore/root/` (`operation not permitted`). No local cache redirect, disabled cache, custom root or alternate verifier used. Native CI must independently supply full verification/version evidence with its ordinary permitted cache.
- Go controller/CLI test command was denied default module/build-cache writes; exact raw log `.cache/m1/controller-cli-first.log`. Delegate had already retried with redirected caches before coordinator stopped it; `.cache/m1/controller-cli-cache-fixed.log` is retained but excluded from acceptance. No further rerouted Go tests. Final native CI required. Full actionlint likewise unavailable after default module-cache denial; YAML/Bash/embedded-Python syntax and diff checks passed.
- Python source retrieval emitted macOS preference-read denials. Exact actions/notices/reasons and no-retry disposition: `.cache/m1/resume-platform-notices.txt`. These preference files are not lab prerequisites. No denied file was accessed through another route.
- M1 initial review reports: `.cache/reviews/1c55a1aa764756a22539eb5580308671328cef33/`. All four findings addressed in source, plus partial-output trigger invalidation and sampled trigger tail controls. New code has only source formatting/syntax checks locally; no unapproved test reruns. CI records unit/runtime Go profiles for full changed-line review. Calibration histories now receive fresh random run IDs.
- M2 read-only tagged-source/controller research retained at `.cache/m2/research.md`; no scenario implementation or fault run. Fixed one-second save intervals and flush behavior prevent treating linger as a deterministic crash barrier. Failed threshold-drain entry needs additional independent support or remains inconclusive.
- Tagged contract root `df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46`; source hashes `.cache/m0/tagged-contract.sha256`. Summary docs are not the contract hash.

## Ownership, resources, and environment

- Coordinator owns integration, PROGRESS and git. GPT-6.1 Sol/high bounded implementation/research delegates are complete. Independent reviewers `m1_docs_review`, `m1_oracle_review`, `m1_simplicity_review` completed initial source reports; affected follow-ups pending on next freeze. No live delegated edits. No pushes during source reviews.
- Original staged module preserved at `/Users/pg/Documents/Codex/2026-10-24-work-in-users-pg-documents-codex/kaferry-lab-handoff/staged/` because resumed workers had stale sandbox roots. Parent has repaired full permissions.
- No live lab containers/networks/processes. Resume label inventory empty. Prior fixtures cleaned and calibration children reaped; retained bundles `.cache/calibration/cal-20261024a/{healthy-pause,faulty}/bundle`. New test retry reported all owned children absent/reaped. No version container started: verifier stopped at trust initialization.
- Host Go1.27.2 macOS ARM64, Docker Linux ARM64. AMD64 emulation is development evidence only; final release campaign requires native AMD64 runner. M0 native evidence is actual GitHub hosted Ubuntu24.
- GitHub commands use `SSL_CERT_FILE=/etc/ssl/cert.pem`; Git push uses trusted CA + command-scoped gh credential helper. Never print tokens. Local verification/Go test cache writes are blocked by platform controls; do not route around denials. Native CI is independent permitted work.

## Exact next actions

1. Freeze checker/CI follow-up commit after `git diff --check` and source formatting/shell/YAML/Python checks (no Go cache mutation). Request affected docs/oracle/simplicity reviews on exact new SHA; no push while reviews run.
2. Resolve follow-up findings, freeze and refresh approvals as needed. Reviewers read actual full M1 patch plus fix delta; no tests/code execution. Reports `.cache/reviews/<SHA>/`.
3. Push reviewed feature commit, inspect native CI including real artifact verification/version, controller controls, no-network offline rechecks, live observer and cleanup; download hash-verified retained evidence and obtain test/oracle CI plus full changed-line coverage review, then simplicity coverage follow-up. Do not count local denials or redirected tests as passes.
4. User requested a clearer new-session prompt after seeing a cybersecurity guardrail notice not exposed in these tool results. CODEX_PROMPT.md now puts exact authorized disposable-resource scope first, preserves every roadmap requirement, and requires recording an actual denial without routing around it. This doc change is committed at `1c55a1a` and passed initial independent docs review; retain it through final M1 acceptance.
5. Continue M2–M6 within that scope; preserve failed/missing observations. Open final PR only once all required acceptance/reviews/CI/delivery are complete.
