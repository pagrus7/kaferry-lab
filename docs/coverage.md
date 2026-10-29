# Additional evidence beyond the core suite

Comparison source is [v0.6.0 commit `d7d485b`](https://github.com/pagrus7/kaferry/tree/d7d485b96a52b711cb10d76dca09aa9b155dec5e). All core paths and exact names below refer to it. This inventory covers every required [M2–M6 scenario](../ROADMAP.md). The executable bindings below distinguish implemented development paths from measured fault acceptance; a source path alone establishes no reached fault or qualification. Related core coverage is substantial; these comparisons do not establish absence of other coverage.

## Execution and oracle boundaries

- `tests/compat/acceptance_test.go` `TestWorkerCrashBeforeDeliveryProcessingReplaysWithoutLoss` launches the Go test executable with an injected producer callback calling `os.Exit(99)`. Its real-broker crash is not a release CLI run. `loggedWorker` builds checkout application modules in process; churn and transaction cases use it.
- `tests/compat/process_test.go` `startCLI`/`binaryWorker` launch subprocesses. `tests/compat/signal_test.go` `testBinary` selects `KAFERRY_TEST_BINARY`, optionally checks `KAFERRY_EXPECT_BINARY_SHA256`, and otherwise builds source. `tests/compat/directions_test.go` `execute` uses a supplied binary only when that environment variable is set, otherwise calling `app.Execute` in process. `.github/workflows/suites.yml` selects a packaged artifact when supplied and builds otherwise. Source alone cannot prove historical runs used published bytes.
- `internal/franz/recovery_test.go` runs production adapters/Runner in process against kfake; `internal/copy` tests below use component fixtures. Archive component tests and compatibility fixtures use internal readers/codecs; capture process tests launch the test executable. These implementations are never the lab oracle.
- Core already uses goavro in `internal/archive/avro/codec_test.go` `TestFidelityAndIndependentReader` and `TestIndependentWriter`. Added evidence comes from independent expectations, physical archive/checkpoint interpretation and verified release execution, not goavro alone.

Every row requires a healthy control, finite independently verified input, recorded budgets/configuration, Given/When/Then, requested/reached/recovered fault evidence and an offline-recheckable bundle under [the evidence rules](evidence.md). “Kafka audit” means complete membership/bytes/routing scans to fixed recorded ends, and saved-next-offset comparison against independently justified required prefixes, initial positions, known gaps and supported filter/skip explanations. “Archive audit” adds independent physical file/ordinal/block identities, selected-file hashes, acknowledged extents, checkpoint cursors and output multiplicities. Logical IDs, Kafka positions and archive physical identities remain distinct. These are acceptance requirements, not existing observations.

## M1 — Harness sensitivity

`internal/evidence/testdata/` contains literal synthetic histories for byte corruption, missing required output, unsafe saved prefixes, aborted output, wrong routing, missing triggers and truncated evidence; permitted duplicates pass. They test the independent checker rather than repeat a product scenario. `internal/calibration/run_test.go` exercises real owned stand-in children at an independently read saved/output barrier, including death before the barrier, invalid barriers, cancellation and reaping. `cmd/lab/main_test.go` checks command statuses and unchanged offline rechecks. The deliberately faulty stand-in saves before producing; detecting that loss tests orchestration plus checking, not whether a real Kaferry fault window was reached. All these histories remain calibration evidence.

Hosted encrypted-upload controls are historical and inactive. Their original
failure evidence remains retained. New local custody controls challenge exclusive
prior-attempt preservation, interrupted callbacks, unapproved source, path
aliasing, tampered bytes and read/write/sync/close failures with fixed synthetic
files. Workspace replacement and runner-restart persistence remain unmeasured
until their runtime gates are exercised. They
are harness measurement controls rather than product scenarios; no core Kaferry
scenario is duplicated or qualified by them. The local-retention workflow has
no application process or fault, and its post-job callback is not a reap/writer
proof. See [the local contract](private-notices.md).

## M2 — Crashes, stalls and timeouts

Use named restart groups, at least three selected partitions, short recorded timeouts and verified finite input. Start PRESERVE; repeat only routing-sensitive faults with KEY.

| Planned ID | Exact closest core test and path | Added mechanism and reached proof | Oracle |
| --- | --- | --- | --- |
| `M2.crash-unresolved` | `tests/compat/acceptance_test.go`: `TestWorkerCrashBeforeDeliveryProcessingReplaysWithoutLoss`; `tests/compat/signal_test.go`: `TestCLIInterruptCommitsAndResumeDoesNotRecopy` | Repeated same-group release-process crashes while output lags verified input. Separately establish visible writes before a later observed save, then actual kill/exit/restart. Core crash injects one callback exit; signal case stops after output. | Kafka audit at crash/recovery and final resume, allowing duplicates without the core's one-crash bound. Lag does not identify pending callbacks; unestablished timing cannot count as reached. |
| `M2.delivery-outage-stop` | `internal/franz/recovery_test.go`: `TestAmbiguousDeliveryReplaysWithoutLosingProgress`; `internal/copy/worker_stop_test.go`: `TestWorkerStopFailuresSaveOnlyConfirmedProgress/{delivery,timeout,commit}`; `tests/compat/soak_test.go`: `TestStreamingSoakFidelityCommitLagMemoryAndShutdown` | Measured destination impairment past delivery timeout with required output absent, separately combined with SIGTERM and threshold drain. Record actual timeout/exit, interval, restoration and resume. Core soak pauses for one second and shuts down after verified catch-up. | Kafka audit proves no loss/unsafe save; measure overshoot and replay amplification. Threshold/log counters do not prove drain. Tracked-work caps and RSS are different measurements. |
| `M2.source-startup-save-outage` | `internal/franz/recovery_test.go`: `TestProductionCopyClosesBlockedStartupAndFetchRequests/{coordinator,join,offset fetch,offset lookup,initial commit,fetch}`; `tests/compat/fault_test.go`: `TestBlockingCommitAcrossBrokerOutage`; `internal/copy/runner_test.go`: `TestRevocationCommitFailures` | Release startup against observed cold/inaccessible coordinator; separate source disconnection with output active and saves due, restore/restart. Core real-broker test calls adapter Save directly; kfake intercepts exact requests. | Kafka audit and bounded recovery; distinguish startup/periodic failure from revocation replay behavior. A timer/outage alone cannot prove a particular commit was hit. |

### M2 two-phase checker preparation

The integrated evidence-version3 checker (`internal/evidence/m3_*.go`) adds a
fixed warmup3/full96 admission boundary for M2 delivery experiments; the filename
is a schema version, not roadmap milestone M3. Closest tagged v0.6.0 tests read:
`internal/copy/worker_stop_test.go`:
`TestWorkerStopCapsBatchedWritesAcrossPartitions`,
`TestWorkerStopCountsAcrossProgressSaves`,
`TestWorkerStopFailuresSaveOnlyConfirmedProgress/{delivery,timeout,commit}`;
`tests/compat/worker_stop_test.go`: `TestWorkerStopAcrossEndpointDirections`;
and `internal/franz/recovery_test.go`:
`TestAmbiguousDeliveryReplaysWithoutLosingProgress`. Those controls inspect
in-process acceptance/flush failures or restart with a new cap. The added lab
observation is an immutable final declaration followed by complete independent
source scans of warmup and additive full input while the same primary is
observed stopped, exact profile binding, phase-bound audits, and settled full
membership/saved-prefix checking. The first profile ID explicitly selects
`primary-threshold4` or, only for `delivery-stop`, `primary-unlimited`; the second
is always `recovery-unlimited`. The existing threshold-labelled admission is
preserved and is not reinterpreted as unlimited live-TERM evidence. In the new
unlimited variant both invocations have zero threshold and identical SQL and
settings except their separate SQL argument paths. Actual live TERM and reached
delivery-timeout proof remain missing. Warmup progress names the
same live primary, with output/saved/group scans after completed launch. Recovery
requires completed broker health before launch and fresh settled safety after
any later impairment/restoration. Full-source readback must begin at or after completed
relevant restart/restore; its later end cannot hide an overlapping start. Profiles
differ only at SQL argument slot2. The fixed v3 history requires a serial controller: each
pause/restore/restart interval must begin at or after the preceding event's
`elapsed_ns`, with its receipt retained before the next controller operation.
Delayed broker receipts cannot backdate mutations across readback, launch or
settled-safety witnesses; a later fault after completed readback remains valid.
Literal negative histories challenge omitted scans, replaced prefixes/identities,
prelaunch/stale/foreign progress, overlapping restoration, stale settled safety,
publication/STOP/CONT ordering, rebound configuration-path changes, profiles and
warmup-only completion. Declared future input creates no
early delivery obligation; saving past the verified published end is still a
violation. The byte-identical imported profile/checker/writer at `6ba34a7`
passed native run40248058277: six new profile/writer test functions, including
seven mixed-profile negatives and five writer cases. Earlier threshold-only
`73d407e` evidence remains preserved. These are proposal-head observations;
the integrated successor still requires its own final-head native CI. All40
new uncovered/partial decisions remain unapproved, and late writer I/O/multiple
error failures were not injected. `WritePhaseBundle` exclusively reserves a new
four-file version3 history; completion binds bytes, not a passing verdict. It
supplies no real phase controller, measurement extension or mechanism witness.
Valid data admission remains `UNSUPPORTED`
for delivery/failed-threshold mechanism acceptance; counts, timers and logs do
not establish ACK receipt or drain-path entry. Historical evidence-v2 semantics
and all required M2 live observations remain unchanged.

### M2 periodic source-save staging preparation

Before adding this preparation, the tagged v0.6.0 source comparison was reread:
`tests/compat/fault_test.go::TestBlockingCommitAcrossBrokerOutage` invokes the
production adapter's `Save` directly during broker pause and after recovery;
`internal/franz/recovery_test.go::TestProductionCopyClosesBlockedStartupAndFetchRequests`
intercepts startup/fetch requests, including initial commit; and
`internal/copy/runner_test.go::TestRevocationCommitFailures` distinguishes
recoverable revocation handling from a failing periodic commit in process.
This is an additional observation for the existing source-save scenario, not a
new scenario or duplicate product fault: [source-save staging](source-save-staging.md)
adds a single `input-0003` publication and exact four-input independent readback
between the existing three-warmup and full finite-input stages. The eventual
release-process experiment must retain the same primary while independently
establishing newly visible but unsaved output and a current periodic-save origin.
The source verifier scans all three partitions and rejects future/extra input,
loss, changed nullable bytes, routing/provenance errors and ambiguous absence;
its four-entry ledger cannot claim full96 membership. Synthetic producer/scan
controls exercise these refusals and the no-second-attempt rule for an ambiguous
probe send. The functions are implemented but unwired. The new fixed schema3
source-save checker adds independent3/4/96 ledgers and a separate sampled
visible-unsaved audit gate, followed by same-primary observed STOP, full
readback, CONT and settled recovery checks. This adds an observation absent
from the tagged direct-Save test; it does not identify a current periodic call.
Complete data remains Unsupported/mechanism_unobserved, with violations retaining
precedence. Original-parent custody, actual release evidence, reached failure,
recovery, final full membership and M2 qualification remain incomplete.

### M2 executable bindings

`lab scenario RUN_ID CASE ROUTING NEW_OUT_DIR` runs a partial case against the
fixture created for `RUN_ID`, with fresh verification of the published executable.
`internal/campaign/scenario*.go` retains operation receipts and translates complete
observations to version2 bundles checked by `internal/evidence/m2_*.go`.

| Inventory ID | Case and current observation boundary |
| --- | --- |
| Healthy comparisons | `healthy PRESERVE` and `healthy KEY`: finite known bytes, complete scans, stopped/reaped worker and settled saved-prefix audit. |
| `M2.crash-unresolved` | `repeated-kill`: seeks two output-lag kills and a separately observed visible-unsaved crash, each followed by same-group restart and safety audit. An observed new destination tail prompts suspension and a fresh complete scan; only decoded known bytes with a later unsaved position establish the visible-write case. Recovery completion also needs independently observed saved positions through every finite source end; existing output alone cannot establish it. An unreached window remains incomplete. |
| `M2.delivery-outage-stop` | `delivery-stop` retains destination pause past the configured timeout, TERM and recovery; actual submission/timeout-path proof remains incomplete. `delivery-threshold` remains unsupported pending independent threshold observation. |
| `M2.source-startup-save-outage` | `source-startup` observes source impairment before launch, bounded failed startup/exit, restoration and same-group copying. `source-save` retains an attempted outage/recovery but cannot establish the precise periodic commit and remains incomplete. |

The native CI development matrix includes the two healthy controls and
source-startup and repeated-kill. Packet capture is unavailable; CI retains its
`UNSUPPORTED` status and denied run reference without attempting capture. That
status is separate from the data verdict. Compiled runs retain Linux owned-child
wait RSS/CPU; the checker derives SIGTERM-to-wait ranges/overshoot and final
observed output/input volume. Native run `40164631081` at `9ff5f9b` retains
independently reviewed measurements and four narrow executions: healthy
PRESERVE/KEY, source-startup and repeated-kill. That evidence does not accept
M2 or approve later source changes. All required M2 variants need native
evidence, offline rechecks and independent acceptance reviews.

The completion-loop calibration controls in `internal/campaign/scenario_test.go`
exercise worker exit during a complete audit, repeated old output with unknown
ownership or saved-zero progress, and unknown→stable-zero→stable-complete
progress. They require a live worker and independently supplied completion facts;
the stale cases must fail within the numerical audit bound. These synthetic
controls test the harness and add no release fault coverage.

The source-only `ReadSubjectPointMap` observer reads the exact pinned public
ELF with standard Go metadata readers. Calibration compares an owned harness
function with its independent runtime pointer. The owned image uses the same
unique public runtime-entry/ELF-entry base proof as the release; no ELF symbol
table is required. Wrong or missing entry anchors remain unsupported. The
native data-only probe reads
the already verified release. Neither source nor static addresses establish
a reached instruction, debugger capability, acknowledgment, fault or data
property. No breakpoint, target-memory access, application import or source
build is used. Predecessor probes in retained native runs 40224306022 and 40225832123
mapped four static function ranges. Native `525bb5ea` and `b18a691e` passed
the shared-reader/owned-image calibration, independent pointer comparison and
wrong/missing-entry controls; b18 also passed wrong-source, unsupported-ELF,
mixed missing-point and out-of-text-range controls. These are static metadata
results. Native `b61b6145` also passed eight isolated lifecycle controls,
literal long-delay/pending timing predicates, the 169-control helper gate and
46 retained caller controls. Actual complete driver/proxy execution remains
unmeasured. No live Kaferry path or proxy capability follows.

### Private evidence handoff calibration

The filesystem handoff is a measurement boundary, not another Kaferry scenario.
Sixteen local synthetic Python controls exercise exclusive capsule retention,
identity/closure rejection, collision/quota, short writes, joined write/close
causes and terminal sync/close uncertainty. Twenty-six data-only controls execute
the exact workflow preflight/store projections and reject malformed identities,
boolean counts, changed hashes/storage binding and extra private fields; they
also check the public upload allowlist and fixed public failure handling for
entry/report-write errors and no repeated write after a failed private sink,
retaining an available original privately. First or
terminal diagnostic-sink failures can remain incomplete. No real capsule, crypto, native storage
mount, lifecycle recovery or product-path observation is established by these
controls. Original raw writers remain unchanged; early failures before completed
sealing can remain unavailable/incomplete. Live calibration is disabled and
unknown-notice CMS is excluded from public uploads. Actual custody and required
M2 mechanisms still need independent reached evidence.

A further synthetic storage control interrupts a write or sync while closing
also fails, and interrupts close after a failed write. It checks both exact
causes survive privately without a successful completion marker or receipt.
This covers cancellation error accounting missed by the earlier ordinary-I/O
write/close control; it adds no product scenario or reached Kaferry mechanism.

## M3 — Ownership, links, transactions and discovery

| Planned ID | Exact closest core test and path | Added mechanism and reached proof | Oracle |
| --- | --- | --- | --- |
| `M3.owner-loss-late-output` | `tests/compat/churn_test.go`: `TestRebalanceChurnPreservesConfirmedProgressUnderFailFastCommits`; `internal/copy/runner_test.go`: `TestRevokeFencesLateOutcomesAndLostOwnershipNeverCommits/{revoked,lost}`; `internal/copy/progress_test.go`: `TestOldGenerationDeliveryCannotAdvanceNewOwner` | Suspend release worker with outstanding output while survivor lives. Capture stable group excluding old member and decoded assignment of its former partitions to identified survivor; restore destination, resume old worker and observe its exit. Core churn leaves gracefully. | Kafka audit across ownership. Aggregate counts lack identity. DescribeGroups exposes no generation number; do not claim every stale callback was observed. |
| `M3.directional-delay-churn` | `internal/franz/recovery_test.go`: `TestAmbiguousDeliveryReplaysWithoutLosingProgress`; `internal/franz/reply_gate_test.go`: `replyGate` helper; churn above | Standard TCP proxy covers every advertised worker endpoint; observer/admin path stays healthy. Downstream delay/reset during writes, then rebalance or kill/restart. Record affected connections, direction and interval. | Kafka audit and at-least-once recovery. Core gate identifies Produce replies; generic TCP proof cannot identify a lost reply or establish acknowledgment order. |
| `M3.open-transaction-interruption` | `tests/compat/transactions_test.go`: `TestNoMatchLookupOpenTransactionAndTrailingMarker/{commit,abort}`, `TestOpenTransactionReachesTipWaitInsteadOfSuccessfulCompletion` | Independently observed open transaction at tail plus worker/source interruption; separate commit/abort, bounded tip-wait and recovered success. Record decisions/tail/interruption overlap; core uses internal tip logs without path interruption. | Eligible committed membership, no aborted output or premature completion losing subsequent eligible input. Apply tagged cutoff/resolved windows; offset spans are not counts. |
| `M3.partition-discovery-churn` | `internal/app/partition_cli_test.go`: `TestPartitionCLISelectsWithoutFetchingOrCommittingExcludedPartitions`; `tests/compat/signal_test.go`: `TestCLIInterruptCommitsAndResumeDoesNotRecopy`; `internal/franz/source_test.go`: `TestAssignmentRejectsNewMissingPartitionBeforeInitialCommit` | Sparse IN/NOT IN plus real additions/reassignment, matching/missing destination cases. Record creation and eligible assignment, not guessed discovery timer. Core selection uses in-process Execute/kfake; signal test expands both topics. | IN additions excluded; NOT IN additions required after observed eligible assignment while active. PRESERVE retains original partition or explicitly fails, possibly after partial output. Output absence cannot prove excluded partitions never fetched. |

The optional stock-link fixture source (`internal/fixture/links.go`) and
`TestLiveOwnedWorkerLinkTopology` check planned worker Metadata/coordinator
routes against independently healthy direct endpoints.
`TestLiveOwnedLinkDirectionalLatency` supplies a separate exact-nonce
calibration for 400ms upstream/downstream delay, persistent/new sockets,
toxicity zero, and quiescent removal. The additional source assertions cover
20s downstream delays and independently server-written replies whose client
reads remain outstanding at removal. They record actual first-byte/full-read
and deletion intervals without assuming queued-byte disposition. This adds
measurement beyond the tagged reply gate: generic TCP timing cannot identify
Kafka response types or worker ACK receipt. The dedicated driver adds bounded
subreaper/anchor wait controls and run-journal-based cleanup of the extra nonce
container; these calibrate evidence ownership, not a Kaferry scenario.
At source a6175b1, native run `links-native-20261028e` passed independent
review of the bounded generic TCP calibration:19 unique32-byte nonce exchanges
covered400ms upstream/downstream delay,20s downstream delay, existing/new
sockets, toxicity zero, removal and recovery. Exact mapping readbacks, private
startup logs before removal, original process waits and an empty owned-resource
inventory were retained locally. Full native campaign custody/CI integration
and all Kaferry mechanism observations remain incomplete.

Earlier c2ab5fc and de52517 histories remain failed. The former returned `{}`
without retained startup logs; its cause is unknown. The latter loaded the
startup mapping but the checker rejected the stock empty `Logger` member.
The first-create0600 file-owner binding, bounded log retention and narrow
optional-empty-Logger allowance have separate failure controls; empty mappings,
unknown fields and malformed Logger values remain fatal without retry or API
population. These are measurement preconditions, not new Kaferry scenarios.

For the pending response in run E, the first byte arrived51,459ns after measured
HTTP return, within the larger removal callback/evidence-retention envelope.
The separate API journal timing must accompany the callback interval; neither
identifies queued-byte disposition. Generic TCP calibration establishes no
Kafka response type, worker ACK, timeout, threshold drain, source save or M3
release coverage.

## M4 — Archive storage and replay

Small independent healthy controls cover topic→file, file→topic and file→file. Closest controls: `tests/compat/archive_test.go` `TestAvroCaptureAndReplayCLI`, `tests/compat/directions_test.go` `TestAllFileDirectionsAndResume`, and `tests/compat/archive_load_test.go` `TestLoadArchiveCopy`; they do not establish independent archive checking.

| Planned ID | Exact closest core test and path | Added mechanism and reached proof | Oracle |
| --- | --- | --- | --- |
| `M4.capture-storage-owner-loss` | `internal/archive/capture/failures_test.go`: `TestEveryCaptureIOCutPreservesAcknowledgedRecords`, `TestEveryRecoveryIOCutCanBeRetriedByANewOwner`; `internal/archive/capture/process_test.go`: `TestKilledWorkerReleasesLockAndRetainsOnlySavedPrefix`; `internal/archive/capture/policy_test.go`: `TestCaptureCapsOpenFilesAndPublishesLeastRecentlyUsed` | Concurrent release owners, small rotation/open-file budgets, volume-scoped ENOSPC/stall, kill/reassignment and repeatedly interrupted recovery. Prove failure affected active work, death/reassignment and recovery while another owner lives. Core recovery cuts normally precede healthy retry; killed child is component writer. | Independently decode recoverable acknowledged output before Kafka prefix verdict. Archive/Kafka audits check recovered prefix, completed-file hash/length immutability, live/released locks and duplicates. Never fill host storage. |
| `M4.replay-pressure-publication` | `internal/archive/replay/files_test.go`: `TestMergePreservesDuplicatesFullRecordsAndPhysicalTiesWithBoundedResources`, `TestRestartUsesPhysicalCursorsAndIgnoresNewFiles`; `internal/archive/replay/order_test.go`: `TestDifferentSourceIdentitiesDoNotMergeTheirOffsets`; `tests/compat/archive_overlap_load_test.go`: `TestLoadArchiveOverlap` | Exceed both handle/cache budgets with overlapping physical duplicates/equal offsets from distinct sources; output delay, repeated kill/restart and new publication. Record actual pressure, affected links and chronology. Core overlap load exceeds default cache but not handle budget. | Archive audit preserves each selected physical occurrence and provenance routing; independently decode selection/checkpoints and confirm fixed IDs/hashes across same-group resumes. New files stay excluded; equal source offsets cannot deduplicate inputs. |
| `M4.checkpoint-input-disturbance` | `internal/archive/replay/files_test.go`: `TestIncompleteRestartRejectsMissingResizedOrModifiedSelectedInput`; `internal/archive/replay/session_test.go`: `TestSaveFailureStopsIntakeWithoutAdvancingMemoryOrRetryingWrites`; `internal/archive/replay/partition_filter_test.go`: `TestPartitionSelectionNeverReadsExcludedPayloads`, `TestExcludedArchiveHeadersStillRequireAValidFileIdentity`, `TestPartitionReplayPinsOnlyMatchingFilesAndKeepsThatSnapshotOnResume` | Repeated actual checkpoint/process interruption; separately remove/corrupt pinned selected input. Observe incomplete selection, changed bytes/availability and interrupted recovery; restore originals. Distinguish excluded payload corruption and excluded removal after pinning. | Explicit failure for incomplete selected-input corruption/omission, safe cursor and recovered resume. Initial selection validates all completed headers; selected payloads/incomplete-resume selected files need validation. Fully completed groups remain complete despite missing input. Unproved write timing cannot count as reached checkpoint-write interruption. |
| `M4.container-mounted-shutdown` | `tests/compat/container_test.go`: `TestContainerShutdownAndResume` | Digest-pinned release image, actual UID, mounted archive/checkpoint volumes; SIGTERM during reached storage/output contention. Record image/executable IDs, mounts/runtime boundary, signal and exit. Core uses healthy topic→topic rounds before stop. | Archive/Kafka audits, configured deadline and safe resume under actual mounts. Targeted packaging case; SIGKILL does not remove page cache or prove power-loss/cross-host durability. |

Archive observers independently interpret OCF header/block boundaries and physical ordinals, published header/record identity, capture state acknowledged extents and replay fixed selection/per-file cursors. Golden format evidence: `internal/archive/capture/journal_test.go` `TestStateWireContract`; `internal/archive/replay/journal_test.go` `TestPartialCheckpointWireContract` and `internal/archive/replay/testdata/partial-checkpoint-v1.json`. Never import these implementations or generate expected results with them. A logical record list cannot check byte/block cursors. Identical byte-only fixtures may hide loss compensated by replay; record that limit separately from identifiable stress records.

## M5 — Replication and interference

Use three brokers where required; record RF/ISR/acks and availability assumptions. Configured substrate data loss is not automatically a Kaferry violation.

| Planned ID | Exact closest core test and path | Added mechanism and reached proof | Oracle |
| --- | --- | --- | --- |
| `M5.source-movement-transaction` | M3 transaction cases; `internal/franz/recovery_test.go`: `TestCompactedOffsetsReachTheBoundedEnd`; `tests/compat/qualification_test.go`: `TestReplicatedClusterLeaderFailurePreservesCopy` | Observed source leader movement or completed reassignment while transaction/ownership churn overlap. Capture pre/post metadata or completed reassignment plus transaction decisions and control/aborted gaps. Core replicated case targets destination; compacted case uses crafted kfake batches. | Kafka audit of required committed records/no false completion. Retention/compaction needs retained ledger/availability assumptions; offsets do not count records. |
| `M5.failover-uncertain-progress` | `tests/compat/qualification_test.go`: `TestReplicatedClusterLeaderFailurePreservesCopy`; `tests/compat/fault_test.go`: `TestBlockingCommitAcrossBrokerOutage` | Coordinator/destination leader change with active output/progress and link delay; independently prove old/new identity and affected connections, then same-group restart. Core RF3/minISR2 case stops known destination leader after 16 writes and copies to 64; no replacement-leader snapshot/delay. | Per-partition Kafka prefix audit and complete recovery, not reconnect/exit zero. Commit interval cannot establish exact save timing. |
| `M5.runtime-async-rejection` | `tests/compat/qualification_test.go`: `TestSaslTlsRestrictedAclCopyAndDeniedConfigPreflight`; `internal/copy/policy_test.go`: `TestAsynchronousDeliveryFailureCannotBeSkipped` | After successful release output, revoke write or change batch limit; observe actual resulting async error, restore/resume. Static preflight and simulated async SKIP rejection already exist. | Async failure cannot silently succeed under SKIP/save past required output. Kafka audit checks safe prefix/resumed membership. Accepted configuration without observed effect is unreached. |
| `M5.shutdown-interference` | `internal/app/shutdown_test.go`: `TestForcedShutdownExitsWithAFullUndrainedStderrPipe`, `TestShutdownDeadlineCoversFinalErrorPrinting`; `internal/observability/export_test.go`: `TestReceiverFailuresDoNotDelayShutdownOrRetry/{503,no response}` | Block lab stderr or stall OTLP while delivery/storage also stalls; signal release. Prove both overlapping impairments; measure whole-process deadline on separate channel. Add small bounded container CPU/memory-pressure variant with measured limits/cleanup. Core tests full-pipe forced exit and exporter stalls separately. | Safe resume/prefix audit and shutdown against configured contract. Separate OOM/resource exhaustion/observer failure from product failure. Isolated blocked stderr repeats core coverage. |

## M6 — Compositions and delivery

Reuse reviewed M2–M5 components and their exact core comparisons. A seed records a schedule; distributed reruns are new observations, not deterministic replay. Each required component must be reached in overlap, recovered and audited.

| Planned combination | Closest comparison/scenario | Additional reached proof and oracle |
| --- | --- | --- |
| `M6.delay-kill` | M3 delay + M2 crash; `TestAmbiguousDeliveryReplaysWithoutLosingProgress`, `TestWorkerCrashBeforeDeliveryProcessingReplaysWithoutLoss` | Affected downstream connections overlap worker kill/outstanding obligations; Kafka audit after repeated same-group restart. |
| `M6.outage-rebalance` | M2 outage + M3 ownership; `TestStreamingSoakFidelityCommitLagMemoryAndShutdown`, `TestRebalanceChurnPreservesConfirmedProgressUnderFailFastCommits` | Destination impairment overlaps decoded reassignment; restore and audit all selected prefixes/output. |
| `M6.coordinator-signal` | M2 coordinator; `TestBlockingCommitAcrossBrokerOutage`, `TestCLIInterruptCommitsAndResumeDoesNotRecopy` | Actual coordinator impairment overlaps signal/exit; bounded shutdown, recovered service and same-group safe prefixes. |
| `M6.storage-owner-loss` | M4 capture; `TestEveryCaptureIOCutPreservesAcknowledgedRecords`, `TestKilledWorkerReleasesLockAndRetainsOnlySavedPrefix` | Volume exhaustion overlaps owner death/reassignment; archive/Kafka audits through repeated recovery. |
| `M6.replay-delay-publication` | M4 replay; `TestRestartUsesPhysicalCursorsAndIgnoresNewFiles`, `TestLoadArchiveOverlap` | Output delay, repeated exits and new publication share recorded schedule; physical multiplicity/routing/fixed-selection audit. |
| `M6.source-movement-transaction` | M5 movement + M3 transaction; `TestNoMatchLookupOpenTransactionAndTrailingMarker`, `TestReplicatedClusterLeaderFailurePreservesCopy` | Independently proved source movement while transaction open; decisions/gaps derive membership/completion oracle. |

| Roadmap requirement | Closest core comparison | Additional lab evidence and acceptance |
| --- | --- | --- |
| M6.2 Bounded reduction/retention | Fault tests above; no equivalent distributed reducer established by this audit | Remove events/reduce input/repeat within budgets; record reached conditions and whether each attempt reproduced same property failure. Retain original/reduced/flaky/inconclusive histories; retries cannot replace failures. |
| M6.3 Verdicts/measurements | `tests/compat/soak_test.go`: `TestStreamingSoakFidelityCommitLagMemoryAndShutdown`; `tests/compat/load_report_test.go`: `TestLoadReportIdentifiesExecutedBinary`; `scripts/test_performance.py`: `PerformanceTest.test_pair_ratios_are_paired_before_summarizing`, `PerformanceTest.test_calibration_always_runs_but_unchanged_comparison_can_skip` | Per-property verdicts/counterexamples/reached coverage, unique-record goodput, replay amplification, recovery/visibility latency, shutdown and RSS/CPU. Preserve identities/precision; A/A before interleaved A/B, no invented thresholds/SLO. Existing calibration is not a missing core feature. |
| M6.4 Workflows/publication | `.github/workflows/qualification.yml`, `.github/workflows/suites.yml`; `scripts/test_ci.py`: `SelectedTestsTest.test_required_test_must_have_a_completed_pass_event` | Manual/bounded scheduled campaigns accept reviewed published identity/contract; unknown contract yields UNSUPPORTED/review task. Separate harness CI from product verdict. Versioned redacted synthetic assets retain hashes/manifest/run links/failures without overwrite; PR jobs cannot publish. Passing named tests alone is not complete fault evidence. |
| M6.5 Bounded usable commands | `tests/compat/process_test.go` CLI helpers; selected-test gate above is closest control, not a lab command test | Provide setup, one scenario, complete campaign, calibration, offline recheck and cleanup; exercise each with explicit sub-budgets (initial targets ≤10m/scenario, ≤90m/job). Timeout retains evidence/cannot qualify. Record budget adjustments, never silently truncate. |
| M6.6 Integrated acceptance | Selected-test gate above; `review/README.md` supplies core review process, not qualification evidence | Independent docs/test-oracle/simplicity reviews on frozen final state, final-commit CI, complete required native Linux ARM64 campaign and offline recheck without Kafka/network/executable. Retain sensitive controls for corruption/loss/unsafe save/aborted leak/wrong routing/missing trigger/truncation; duplicates pass. Resolve harness gaps; report product violations without weaker assertions. Committed/pushed source and M0–M6 acceptance records complete delivery. |

## Recording completed coverage

Readiness controls and mapping/cleanup-format controls are harness calibration. The first enabled linked setup at
`bfc99057` retained an EOF before any valid broker readiness response. New
owned-peer controls distinguish zero-byte EOF from header-only/partial/invalid
responses and observe close errors that the pinned client can otherwise discard.
They cannot establish Kaferry accepted work, drain, progress saving or ACK receipt.


The metadata diagnostic is harness calibration, not another Kaferry scenario.
The prior tag-metadata HTTP403 occurred before the executable or fault started;
the discarded response cannot establish its cause. The narrow capture retains
one newly selected original-endpoint response, bounded client-decoded fields,
body and errors, with actual child/writer closure and encrypted custody. Its
synthetic HTTP, child-cleanup and admission controls establish measurement
sensitivity only. Neither a complete HTTP200/403 nor recovered ciphertext
fulfills any M2 fault, recovery or saved-progress requirement.

Bind each planned ID to executable test/command, exact variants, reviewed source identity and durable evidence URL/path when implemented. Keep this a coverage map; histories belong in bundles and milestone status in PROGRESS.md. Missing mandatory observations block their scenarios. At audits stop/reap workers, restore services, state stabilization assumptions and fully scan to fixed ends; unchanged ends alone do not exclude pending output. Retain INCONCLUSIVE if late output can change verdict. Compare only promised per-session order and permit at-least-once duplicates.

No required scenario is removed. Combined faults, independent release checking and observed output/progress boundaries add evidence; parser/obsolete syntax, standalone routing/ACL/codec matrices and broad migration remain outside scope.

The `cefef523` linked attempt reached and passed topology, but failed initial
latency mapping readback before applying a delay. Its old response bytes are
unavailable. New source retains exact bounded raw readback and comparison facts,
requires explicit mapping/toxic fields, and treats only an explicit expected
zero collection's null/empty encodings alike. Exact one-leading-LF container
absence framing is covered separately from permission/unknown-prefix failures;
these are authored measurement controls, not new Kaferry qualification cases.

## Native image-store and caller calibration (in progress)

No new Kaferry scenario is introduced by this harness work. The native ARM64
transition independently checks the fixture trust boundary and guest/host caller
observations. Docker29.1.3's containerd store returned an image index/manifest
digest where the old admission expected a configuration digest; the first native
linked development run failed before any test child or delay fault. The original
STOPPED record and failed verdict remain. Exact local image target, selected
manifest, configuration, platform and owned-container identities must be proved
separately before this backend is admitted; an index alone cannot pass.

The repaired standalone linked caller has67 data-only refusal/closure controls, including
wrong native metadata, missing foreground return, dropped output and quiescent
failed outcomes. These controls are separate from native fault calibration and
Kaferry qualification. Native execution/custody, current review and final CI are
required independently. Unstarted disposable image-identity specimens may measure
the backend's identity fields with exact ownership and removal; they do not
establish broker/proxy behavior or a reached Kaferry fault.

The first source review found four contradictory passing histories that the
caller admitted, plus case-name shadowing that skipped the exact missing-file
assertion. The repaired controls first reproduced those four admissions, then
required rejection; all67 distinctly named controls passed after the gate fix.
A separate Linux-only save-controller control is authored for an actual exited
producer whose owned descendant holds both pipes open. It must reach the drain
deadline, refuse false EOF/completion, preserve STOP/no-retry and observe actual
bounded descendant wait/reap. Authoring is not a native passing observation.
