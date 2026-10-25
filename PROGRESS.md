# Implementation handoff

## Current step

- First unfinished milestone: M2. M0 accepted at `9d3231a7a314a29c7b91d58bee8c186befb98df1`; M1 accepted at `c1eb315ef80186d74576d5710cb6005580e0cb44`. Feature branch `codex/adversarial-release-lab` is preserved; main remote unchanged. PR only after all M0–M6 acceptance/evidence/reviews/final CI.
- Latest pushed/tested source `c1eb315ef80186d74576d5710cb6005580e0cb44` passed all source reviews, native CI and independent evidence/coverage reviews. Native CI [40145529275](https://github.com/pagrus7/kaferry-lab/actions/runs/40145529275) and digest-verified artifacts `.cache/ci/40145529275/`.
- M2 owned process/broker controls and independent Kafka preparation/ledger/group/offset/output snapshots are integrated. Process cancellation-monitor join corrected; source-only controls added. No builds/tests or real M2 faults yet. Next freeze these helpers for review/native CI, while developing typed fault evidence/checker + actual scenarios. Scaffolding is not completion.
- Target remains published v0.6.0 / `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Kaferry sibling stays read-only. No product fault campaign or qualification result exists.

## Acceptance and evidence

| Milestone | State | Evidence / remaining |
| --- | --- | --- |
| M0 | Accepted | `.cache/reviews/9d3231a7a314a29c7b91d58bee8c186befb98df1/`; native CI [40139173038](https://github.com/pagrus7/kaferry-lab/actions/runs/40139173038), unit+observer success. Download `.cache/ci/40139173038/`. |
| M1 | Accepted | `c1eb315`; native CI40145529275 unit/m1/observer success. All three source reviews, test/oracle evidence+coverage and simplicity retained-gap follow-up passed at `.cache/reviews/c1eb315ef80186d74576d5710cb6005580e0cb44/`. Real artifact/version, reached calibration and offline rechecks; no product qualification. |
| M2 | In progress | Owned process/broker and Kafka observation helpers in focused source increment, untested. No real release fault runs or acceptance. |
| M3–M6 | Not started | All required integrated mechanisms/campaigns/publication remain. |

- Final M1 native evidence: `.cache/ci/40145529275/manifest.json`, raw API metadata, three ZIP archives with matching API SHA256s and extracted directories. Native M1 build: Linux x86_64 / Go1.26.0 / GH2.102.0. Published executable version is v0.6.0 at pinned product commit (release build Go1.27.3).
- Accepted M1 reports: `.cache/reviews/c1eb315ef80186d74576d5710cb6005580e0cb44/`. Complete final 730-line/245-zero-block ledger with 49 accepted retained-gap groups under `9d3231a7a314a29c7b91d58bee8c186befb98df1/collected/`. 9,662 duplicate unit rows summed. No Codecov configured. Earlier failed reviews/native run40143532502 remain retained rather than replaced.
- Eight direct completion/current-trigger/allowed-forbidden ambiguity controls passed. Optional Docker version controller and redundant byte/archive checks removed. M1 `verify` requires native Go/kernel AMD64; macOS may orchestrate native CI.
- Earlier oracle findings (unscanned tails, stale trigger, cross-audit byte conflict, ambiguous destination identity) and random-run-ID ownership assertion were fixed before `163398a`; reports at `1c55a1a…`, `8566332…` and `163398a…` retained. These earlier findings are resolved; accepted exact-head follow-ups are at `c1eb315`.
- Scanner: kafka-go payload decoder behind strict fixed-v11 admission; Sarama admin/producer and independent known-byte cross-read. Negative -2ms/epoch/modern CreateTime measured. LogAppendTime remains unsupported; affected runs must not pass. M0 decoder successful-prefix issue is resolved and retained controls remain.
- Bounds: evidence-v1 has 1,024 ledger entries, 256 partitions, 64MiB event streams. Archive/larger/unknown scopes unsupported. Every result still has `release_qualified:false`.
- Pins: archive `d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f`; binary `becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770` (23,814,268 bytes); tagged contract root `df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46`.

## Denials and tooling limits

- Exact actions/notices/reasons retained in `.cache/m1/resume-platform-notices.txt`. Local verifier attempt `.cache/releases/m1-resume-20261024a` is UNVERIFIED: platform denied ordinary gh TUF-cache writes (`operation not permitted`). No cache redirect, disabled cache, custom root or alternate verifier was used. Independent native CI succeeded with its ordinary permitted cache.
- Local Go module/build-cache writes were denied: `.cache/m1/controller-cli-first.log`. Delegate had already retried with redirected caches before coordinator stopped it; `.cache/m1/controller-cli-cache-fixed.log` is retained but **excluded from acceptance**. No further local Go builds/tests or redirected-cache retries. Actionlint denial: `.cache/m1/actionlint-platform-notice.txt`; shell/YAML/embedded-Python syntax checks passed.
- macOS preference-file reads were denied during source retrieval and git push; exact notices retained, no denied file read through another route. Push succeeded.
- `ps` inspection was denied: `PermissionError: [Errno 1] Operation not permitted: 'ps'`. No alternate process enumeration. Tool session `44635` (`gh run view 40143532502 --json headSha,status,conclusion,jobs`) remains unconfirmed exited; stdin is closed and Ctrl-C did not report completion. It is a read-only tooling query, not a lab experiment. Do not claim it reaped or retry denied inspection.
- gh network status/API calls stalled; bounded readers timed out and were reaped. Ordinary bounded HTTPS via curl with `/etc/ssl/cert.pem` fetched public metadata. Artifact downloads used normal `gh auth token` only in memory, passed to curl through stdin; no token printed/persisted. Download ZIP hashes match API digests.

## Ownership, resources, and isolated M2 work

- Coordinator owns PROGRESS/integration/git. All GPT-6.1 Sol/high implementation/research/review delegates finished; no live edits. M1 reviews complete; M2 reviews not yet assigned. Do not push during source reviews.
- No new local Kafka/version containers or lab fault processes were started during this resume. Prior fixtures/calibration children were cleaned/reaped; native CI fixture cleanup independently reviewed. Local Docker label inventory at resume was empty. The tooling query above is unresolved.
- M2 worktree: `/Users/pg/tmp/kaferry-lab-m2-20261024`, branch `codex/m2-owned-process-controls`, based on `163398a`. Eight untracked `internal/campaign/{process*,broker*}.go` files, now copied into main with matching hashes. Preserve both until safely integrated/committed. The tracked checker-test change there was included in accepted M1; do not accidentally integrate it twice.
- M2 process controls: fixed release digest/native platform, exclusive ownership receipts, retained child handle, independent /proc stopped/start identity, one reaper, bounded cancellation/cleanup and logs. Fresh calibration IDs; monotonic launch-relative elapsed nanoseconds. Call Cleanup after Wait before freezing receipts. Only source formatting checked; no native tests or reviews yet. Handoff `.cache/m2/process-controls.md` and research `.cache/m2/research.md`. Broker methods verify immutable Docker ID/labels/image/port mapping and independently probe owned Kafka API; missing pause/recovery evidence fails. No actual controller runs yet.
- M2 Kafka helpers: `openKafka`, phased `Publish`, `VerifyInputs`, `SnapshotOutput`, `SnapshotGroup`, `Close`. Three source partitions, 3/5 destination PRESERVE/KEY, 8–1024 inputs, explicit CreateTime/retention configuration, warmup separate from exact undecorated byte fixtures/stress IDs, idempotent producer, independently verified source ledger. Absent saved offset remains absent, never fabricated0. Snapshot equality is not quiescence. No helper has executed yet.
- Threshold observation research `.cache/m2/threshold-observation-research.md`: default Noble tshark4.2.2 cannot decode expected Produce11; supported standard tshark>=4.4 is needed for bounded owned-link capture if used as independent acceptance proof. Official Wireshark Developers stable Noble AMD64 PPA resolution/key/index pin steps retained; not installed/measured. Wire distinct IDs give a lower bound on accepted submissions; exact drain entry remains an explicit contract inference with diagnostics corroboration. Do not count log-only proof or unsupported decoding as reached.
- Research: one-second saves/flushes mean linger is not a deterministic crash barrier. Empty-source preflight/suspension can prepare a finite verified ledger. Failed threshold-drain entry or exact commit timing needs supported observation; otherwise inconclusive.
- Host Go1.27.2 macOS ARM64; Docker Linux ARM64. Native qualification requires actual Linux AMD64. Earlier staged-module backup remains preserved at `/Users/pg/Documents/Codex/2026-10-24-work-in-users-pg-documents-codex/kaferry-lab-handoff/staged/`.

## Exact next actions

1. Freeze the focused `internal/campaign/` process/broker/Kafka helper increment after `git diff --check`/gofmt checks. Obtain independent docs/oracle/simplicity reviews and native component CI; preserve failed runs. Build typed M2 evidence/checker and actual scenarios next; no log-only trigger proof.
2. Freeze a focused increment, get independent docs/oracle/simplicity reviews, fix findings, push reviewed head and inspect native CI. Local Go/cache retries remain prohibited; no push during source reviews. Keep generated artifacts ignored.
3. Implement and run all M2 required variants/healthy controls against freshly verified published bytes on native Linux AMD64. Missing/unreached timing, unsupported observations or incomplete scans cannot pass. Preserve real product violations and repeat independently.
4. Complete M2 milestone source/evidence/coverage reviews and final-head native CI before acceptance, then continue M3–M6. M1 acceptance does not qualify Kaferry.
5. Open final PR only after all required implementation, evidence, reviews, native campaign/CI and publication complete; do not merge automatically.
