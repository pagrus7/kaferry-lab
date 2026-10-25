# Implementation handoff

## Current step

- First unfinished milestone: M1. M0 accepted at `9d3231a7a314a29c7b91d58bee8c186befb98df1`. Feature branch `codex/adversarial-release-lab` is preserved; main remote unchanged. User requires the PR only after all M0–M6 acceptance, evidence, reviews and final CI.
- Latest pushed/tested source: `163398a6e58ed14be82ab5734f3257363a94a8f7`. Three source reviews passed; native CI passed. Independent CI-evidence review passed, but changed-line coverage reviews found four P2 gaps and redundant checks. M1 is **not accepted**.
- Follow-up fixes are implemented for the next freeze: eight direct checker controls; optional nonnative Docker version controller removed; native Go/kernel architecture gate retained; duplicate byte prechecks and a tautological archive-shape guard removed. Formatting/shell/diff checks passed. These changes have not run; fresh source reviews and exact-head native CI/coverage are required.
- Target remains published v0.6.0 / `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Kaferry sibling stays read-only. No product fault campaign or qualification result exists.

## Acceptance and evidence

| Milestone | State | Evidence / remaining |
| --- | --- | --- |
| M0 | Accepted | `.cache/reviews/9d3231a7a314a29c7b91d58bee8c186befb98df1/`; native CI [40139173038](https://github.com/pagrus7/kaferry-lab/actions/runs/40139173038), unit+observer success. Download `.cache/ci/40139173038/`. |
| M1 | In progress | Native CI [40143532502](https://github.com/pagrus7/kaferry-lab/actions/runs/40143532502) passed unit/m1/observer at `163398a`. Real full pinned artifact/provenance/version path, healthy PASS/faulty VIOLATION calibration, twice-identical no-network rechecks and cleanup retained. New coverage fixes await reviews/CI. |
| M2 | Source slice only | Uncommitted owned-process controls in isolated worktree below. No builds, tests, real release scenarios or acceptance. |
| M3–M6 | Not started | All required integrated mechanisms/campaigns/publication remain. |

- Native evidence: `.cache/ci/40143532502/manifest.json`, raw API metadata, three ZIP archives with matching API SHA256s and extracted directories. Native M1 build: Linux x86_64 / Go1.26.0 / GH2.102.0. Published executable version is v0.6.0 at pinned product commit (release build Go1.27.3).
- Independent source/evidence reports: `.cache/reviews/163398a6e58ed14be82ab5734f3257363a94a8f7/`. CI execution/provenance passed; `test-oracle-ci.md` and `simplicity-coverage.md` withheld acceptance. All 801 missed/partial lines and 273 zero-count blocks have decisions under `9d3231a7a314a29c7b91d58bee8c186befb98df1/collected/`; profiles sum 9,788 repeated unit rows rather than overwrite. No Codecov configured.
- Coverage fixes: complete-looking histories with missing saved/quiescence/cleanup/budget evidence; current complete trigger with no lag; allowed/forbidden identical bytes. Each now has a direct INCONCLUSIVE control. Optional Docker version cleanup removed rather than add unnecessary controller machinery. M1 CLI version execution now requires native Linux AMD64; macOS may orchestrate native CI.
- Earlier oracle findings (unscanned tails, stale trigger, cross-audit byte conflict, ambiguous destination identity) and random-run-ID ownership assertion were fixed before `163398a`; reports at `1c55a1a…`, `8566332…` and `163398a…` retained. No stale approval applies to new source.
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

- Coordinator owns PROGRESS/integration/git. All GPT-6.1 Sol/high implementation/research/review delegates finished; no live edits. Request fresh affected reviewers for next frozen M1 head. Do not push during source reviews.
- No new local Kafka/version containers or lab fault processes were started during this resume. Prior fixtures/calibration children were cleaned/reaped; native CI fixture cleanup independently reviewed. Local Docker label inventory at resume was empty. The tooling query above is unresolved.
- M2 worktree: `/Users/pg/tmp/kaferry-lab-m2-20261024`, branch `codex/m2-owned-process-controls`, based on `163398a`. Five untracked `internal/campaign/process*.go` files. Preserve them. The tracked checker-test change there was copied into main for this M1 follow-up; do not accidentally integrate it twice.
- M2 controls: fixed release digest/native platform, exclusive ownership receipts, retained child handle, independent /proc stopped/start identity, one reaper, bounded cancellation/cleanup and logs. Fresh calibration IDs; monotonic launch-relative elapsed nanoseconds. Call Cleanup after Wait before freezing receipts. Only source formatting checked; no native tests or reviews yet. Handoff `.cache/m2/process-controls.md` and research `.cache/m2/research.md`.
- Research: one-second saves/flushes mean linger is not a deterministic crash barrier. Empty-source preflight/suspension can prepare a finite verified ledger. Failed threshold-drain entry or exact commit timing needs supported observation; otherwise inconclusive.
- Host Go1.27.2 macOS ARM64; Docker Linux ARM64. Native qualification requires actual Linux AMD64. Earlier staged-module backup remains preserved at `/Users/pg/Documents/Codex/2026-10-24-work-in-users-pg-documents-codex/kaferry-lab-handoff/staged/`.

## Exact next actions

1. `git diff --check` and source-only formatting/syntax checks; freeze the M1 coverage fixes, then request docs/oracle/simplicity follow-ups on the actual full M1 patch plus delta. No local Go retries or push during reviews.
2. Resolve findings, push reviewed feature head with trusted CA/command-scoped gh credential helper, run native CI once for final changes, retain failures. Use bounded network commands; no unbounded gh watcher.
3. Download/hash-check exact-head artifacts. Obtain independent test/oracle CI + complete changed-line coverage review, then simplicity review of every retained gap. Old `163398a` CI is evidence for that head only. M1 accepted only after all gates pass.
4. Integrate isolated M2 process files preserving hashes/work. Implement typed independent Kafka snapshots/audits, real required M2 variants and offline-checkable fault evidence; complete reviews and native final-head CI. Source scaffolding is not M2 completion.
5. Continue M3–M6 within authorization. Preserve every failed/unreached observation. Open final PR only once all required implementation, evidence, reviews, final native campaign/CI and publication are complete; do not merge automatically.
