# Implementation handoff

## Current step

- First unfinished milestone: M2. M0 accepted at `9d3231a7a314a29c7b91d58bee8c186befb98df1`; M1 accepted at `c1eb315ef80186d74576d5710cb6005580e0cb44`. Feature branch `codex/adversarial-release-lab` preserved; main remote unchanged. PR only after all M0–M6 implementation/evidence/reviews/final CI/publication.
- Latest pushed and attempted source: `e4ebbaad3b5b2c41f6ac4ce4d44fde94ba8c02dd`. Native CI40148937571 failed one unit fixture; m1 and observer jobs, including actual M2 controller calibration, passed. This is not M2 acceptance.
- Helper fixture correction at `e1da95fb654e81ebe93eb42e9c6fbea03d266229`: child-owned GOCOVERDIR prevents runtime coverage diagnostics entering calibrated streams; exact8192-byte assertions stay unchanged. Oracle/simplicity source follow-ups passed; docs follow-up found stale handoff claims. This handoff correction needs fresh affected review before push. Corrected helper has not run.
- Target remains published v0.6.0 / `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Kaferry sibling read-only. No real released-worker fault campaign or product qualification exists. Typed M2 fault evidence/checker, actual scenario/CLI execution and M3–M6 remain unfinished.

## Acceptance and evidence

| Milestone | State | Evidence / remaining |
| --- | --- | --- |
| M0 | Accepted | Native CI40139173038; `.cache/reviews/9d3231a7a314a29c7b91d58bee8c186befb98df1/`, `.cache/ci/40139173038/`. |
| M1 | Accepted | Native CI [40145529275](https://github.com/pagrus7/kaferry-lab/actions/runs/40145529275) at `c1eb315`. All source/evidence/coverage reviews passed in `.cache/reviews/c1eb315ef80186d74576d5710cb6005580e0cb44/`. Verified artifact/native version, reached healthy/faulty stand-ins, no-network offline rechecks, cleanup. |
| M2 | In progress | Process/broker/Kafka helpers implemented. First native helper CI [40148937571](https://github.com/pagrus7/kaferry-lab/actions/runs/40148937571) has one unit-fixture failure; corrected code awaits final reviews/CI. Actual controller calibration passed; no released-binary M2 scenario yet. |
| M3–M6 | Not started | Required real interactions/campaigns/publication remain. |

- Final M1 digest-verified archives/raw API metadata: `.cache/ci/40145529275/manifest.json`. Linux x86_64 / Go1.26.0 / GH2.102.0. Release binary reports v0.6.0 at pinned product commit (release build Go1.27.3).
- M1 full final coverage: 730 missed/partial changed lines, 245 zero-count blocks, 49 accepted retain groups; 9,662 repeated unit rows summed. Complete ledger under `.cache/reviews/c1eb315ef80186d74576d5710cb6005580e0cb44/9d3231a7a314a29c7b91d58bee8c186befb98df1/collected/`. No Codecov configured. Earlier failed reviews/runs remain retained.
- M2 first native artifacts/raw metadata/ZIP digest checks: `.cache/ci/40148937571/manifest.json`. Unit `TestProcessCalibrationLogOverflowIsEvidenceFailure` observed stdout8192/stderr8246; overflow correctly flagged and child reaped. Extra54 bytes match Go's missing-GOCOVERDIR warning. Strict counts retained; new helper-owned coverage directory is an unrun correction. No unchanged rerun.
- M2 actual controller calibration log/profile: `.cache/ci/40148937571/m0-e4ebbaad3b5b2c41f6ac4ce4d44fde94ba8c02dd-40148937571-1/m2/`. Passed16-record known-byte source readback, all-partition empty destination, explicit absent(-1) group offsets, independently reached pause/API impairment, restoration, source/destination restarts, recovered input and cleanup. No Kaferry subject ran in this calibration.
- M2 source reviews: `db74c06` found stale M1 docs, failed-inspect Env leakage and final-send cancellation success; fixed and all source follow-ups passed at `e4ebbaa`. `e1da95f` oracle/simplicity approved fixture correction; docs rejected stale PROGRESS. Current status correction must be reread/reviewed. No M2 CI/coverage acceptance yet.
- Scanner remains guarded kafka-go Fetch-v11 admission plus Sarama producer/admin and known-byte cross-read. Negative -2ms/epoch/modern CreateTime measured. LogAppendTime unsupported; affected runs cannot pass. Evidence-v1 bounds: 1,024 ledger entries, 256 partitions, 64MiB streams; archive/unknown/larger scopes unsupported; all results release_qualified:false.
- Pins: archive `d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f`; binary `becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770` (23,814,268 bytes); tagged contract root `df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46`.

## Denials and tooling limits

- Exact actions/notices/reasons: `.cache/m1/resume-platform-notices.txt`. Local `lab verify .cache/releases/m1-resume-20261024a` remains UNVERIFIED after denied ordinary gh TUF-cache writes (`operation not permitted`). No local cache redirect, disabled cache/custom root/alternate verifier. Independent native CI used its ordinary permitted cache and succeeded.
- Local Go module/build-cache writes denied: `.cache/m1/controller-cli-first.log`. Delegate's already-completed redirected-cache retry `.cache/m1/controller-cli-cache-fixed.log` is retained but excluded from acceptance. No further local Go builds/tests or redirected-cache retries. Actionlint notice `.cache/m1/actionlint-platform-notice.txt`; source formatting/shell/YAML/Python syntax checks passed.
- macOS preference-read denials during source retrieval/push and threshold research retained in the notice file above, `.cache/m2/threshold-platform-notices.txt`, and `.cache/{m1,m2}/push-*.stderr`. No denied file accessed through another route. Pushes succeeded.
- `ps` denied: `PermissionError: [Errno 1] Operation not permitted: 'ps'`; no alternate process enumeration. Read-only tooling session44635 (`gh run view 40143532502 --json headSha,status,conclusion,jobs`) remains unconfirmed exited; stdin closed/Ctrl-C did not report completion. Do not claim reaped or retry denied inspection.
- Use bounded HTTPS curl with `/etc/ssl/cert.pem` for metadata because gh network API/status calls stalled. Bounded readers were reaped on timeout. Protected artifact downloads used normal gh auth token only in memory/stdin, never printed/persisted. Verify ZIP hashes against API digests.

## Current implementation and resources

- Main source owns integrated `internal/campaign/`: fixed release/native process gate, owned handles/receipts, one reaper, joined cancellation monitor, bounded logs; broker ID/name/label/image/port checks and independent Kafka probes; phased warmup/input publication, verified ledger/routes, complete output scans and raw assignment/saved-offset snapshots. Absent offset stays -1, not fabricated0; equal ends never prove quiescence.
- Process `Cleanup` must follow `Wait` before freezing receipts; it joins the monitor and returns late evidence errors. Sarama calls use finite client timeouts and can return after caller deadline; post-call checks report cancellation while retaining actual acknowledgments. Failed inspect diagnostics discard unsafe full Config.Env/error text.
- CI live calibration uses a four-minute Go-test budget with fresh restoration cleanup, retained live coverage/logs; observer job budget explicitly12→16m. Only helper calibration has executed; M2 scenario implementation/qualification remains absent.
- No local Kafka/version containers or lab fault processes started during this resume. Prior local fixtures/calibration children cleaned/reaped. Native job cleanup reported successful; independent M2 evidence review pending. Unresolved read-only tooling query noted above.
- Coordinator owns integration/PROGRESS/git. GPT-6.1 Sol/high implementation/research delegates finished. Source reviewers `m1_docs_review`, `m1_oracle_review`, `m1_simplicity_review` finished `e1da95f` reports; fresh affected follow-up pending after handoff correction. No live edits; no push during source reviews.
- Preserved isolated backup: `/Users/pg/tmp/kaferry-lab-m2-20261024`, branch `codex/m2-owned-process-controls`, base163398a. Eight process/broker files were copied with initial hashes `.cache/m2/integrated-controls.json`; main has subsequent fixes/Kafka/live files and is authoritative. Isolated checker-test change was included in accepted M1; do not integrate twice. Earlier staged backup remains at `/Users/pg/Documents/Codex/2026-10-24-work-in-users-pg-documents-codex/kaferry-lab-handoff/staged/`.
- Research/drafts: `.cache/m2/{research,process-controls,evidence-v2-plan,threshold-observation-research}.md`. Linger is not a deterministic crash barrier. Threshold independent accepted-work observation needs supported standard capture/decoder; default Noble tshark4.2.2 cannot decode expected Produce11. Official Wireshark Developers Noble PPA trust/pinning steps retained; not installed/measured. Wire distinct IDs imply an acceptance lower bound; exact drain entry is contract inference with diagnostic corroboration. No log-only or unsupported decoding counts as reached.

## Exact next actions

1. Freeze/reread this handoff correction, request affected docs/oracle/simplicity follow-ups on exact new head. Keep helper correction unrun until source reviews complete; no local Go cache retries or push during reviews.
2. Push reviewed head with bounded command/trusted CA and run native CI once for changed source. Retain failed run40148937571; do not rerun it unchanged. Download/hash-check exact-head artifacts; inspect component/live outcomes and complete required independent evidence/coverage follow-ups.
3. Implement typed M2 fault evidence/checker, actual compiled scenario functions and CLI, supported/pinned independent observation tools, then every required real released-binary M2 variant/healthy control on native Linux AMD64. Missing/unreached faults, unsupported observations/incomplete scans cannot pass. Preserve/reproduce genuine product violations without fixing Kaferry.
4. Accept M2 only after full required runs, offline rechecks, independent source/evidence/coverage reviews and final-head CI. Continue M3–M6 automatically; M1 or helper success is not qualification.
5. Open final PR only after all required implementation/evidence/reviews/native campaign/CI/publication; do not merge automatically.
