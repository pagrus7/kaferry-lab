# Periodic source-save input staging

This is implemented controller/checker preparation for the existing required
`M2.source-startup-save-outage` scenario. It is **unwired and unqualified**.
`scenario.go` still reports the periodic source-save mechanism unsupported;
M2 and release qualification remain incomplete. These functions add no command,
new scenario, process observer, fault trigger, or evidence schema.

## Required observation and tagged comparison

The eventual periodic-save experiment needs independently verified warmups,
then one newly published record observed at the destination while its source
position remains unsaved, then the rest of the finite input. The same primary
must remain alive through the first two stages. A current periodic-save origin,
an impaired save failure, recovery, complete final membership and safe saved
prefixes still need separate evidence. Startup, final save, revocation,
historical same-thread activity and broker processing cannot substitute for
that observation.

The inspected read-only v0.6.0 tag resolves to
`d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Its
`tests/compat/fault_test.go::TestBlockingCommitAcrossBrokerOutage` directly calls
the production adapter's `Save` during a paused broker and saves again after
recovery. `internal/franz/recovery_test.go::TestProductionCopyClosesBlockedStartupAndFetchRequests`
intercepts startup/fetch requests, including the initial commit, in kfake.
`internal/copy/runner_test.go::TestRevocationCommitFailures` distinguishes
recoverable revocation errors from a failing periodic commit in process. The
additional lab observation is a staged, independently read source ledger for a
later immutable-release subprocess experiment. This slice does not itself
observe any product save failure. See [coverage](coverage.md).

## Narrow entrypoints

`kafkaRun.Publish(ctx, true)` retains its three-warmup behavior.
`PublishSaveProbe(ctx)` adds exactly one controller attempt for `input-0003`,
the existing index3 fixture on source partition0. Its key and value remain null,
its headers remain empty, its fixed CreateTime remains unchanged, and no logical
stress identity is inserted. The helper refuses a changed probe fixture or
missing, unknown, duplicate, misordered or inconsistent attempted identities
before a producer call. It requires exactly the original three ordered warmup
attempts and the original bounded known declaration. The caller must first
retain successful independent warmup readback; attempt receipts alone do not
prove visibility.

A probe send error remains ambiguous. The controller retains its outcome and
never retries it. A repeated `PublishSaveProbe` call refuses without another
send, whether the first send was acknowledged or ambiguous. Independent full
readback can establish that the ambiguous record exists; an absent record
cannot complete verification. `Publish(ctx, false)` subsequently sends only
unattempted remaining input: in the required 96-record plan, 92 records after
the probe. Its existing bulk-only callers and `VerifyInputs(ctx, bool)` remain
available without adopting this new stage.

`VerifySaveProbeInputs(ctx)` admits exactly four ordered attempts and reads
**all three source partitions from zero**, with stable complete sampled bounds.
It shares the snapshot comparison with the existing source verifier and passes
the exact four declarations, attempts and whole-record scans to
`kafkaSourceLedger`. That independent comparison checks exact nullable bytes,
headers, timestamps, source coordinates, topic/cluster provenance and derived
PRESERVE/KEY destination obligations. Unknown, corrupt, duplicate, misrouted,
unpublished future or extra records fail; missing partitions, loss and truncated
scans fail. No filtering of later or foreign attempts can manufacture this stage.

`Complete` on this result means only that the four-record source publication
stage was independently verified. The result contains four required entries,
not 96. It proves neither destination visibility, unsaved progress, primary
liveness, periodic-save entry, failure nor settled recovery. Equal source bounds
also cannot exclude a pending write. A subsequent full 96-record readback and
full obligation ledger remain required before final completion.

## Controls and integration limits

The schema3 checker now admits a fixed `source-save` data profile using the
existing event fields. Given the immutable96-entry declaration, it checks
`warmup`3 → `save-probe`4 → `full`96, with source ends1/1/1 →2/1/1 →32/32/32.
Only one primary-unlimited and a distinct recovery-unlimited are allowed.
The probe audit must independently show all four exact output records and
present saved-next1 on all three partitions while that same primary is live.
That sampled visible-unsaved observation precedes an observed owned STOP;
full publication/readback and one CONT follow. It proves no later save attempt.

Complete data still returns `Unsupported`, with
`source_save_admission_complete` and `mechanism_unobserved`; no PASS or release
qualification is added. Missing, corrupt or misrouted records and settled
unsafe prefixes retain precedence over the missing mechanism. A live snapshot
does not become quiescence, and an already saved probe is an unreached window.
Existing delivery profiles and v1/v2 behavior remain unchanged. This is additive
compiled schema3 vocabulary; old checkers reject the new scenario as unsupported.
No wire field, generic stage language, writer or loader was added.

`internal/evidence/m3_source_save_test.go` supplies independent asymmetric
histories and seven controls for data, order, ownership, unreached probes,
settled violations and deterministic writer/load rechecks. The targeted host
check passed in2.276s. The exact10702eff3b7be2880130de1c929ae90b74328c33
native full check passed in83.888s, and its independent docs, test/oracle and
simplicity reviews passed within this preparation scope. Validation and reviews
of the combined main head are separate requirements. These data controls do not
execute a broker or release.

`internal/campaign/kafka_save_staging_test.go` contains synthetic fake-producer
controls that decode whole producer messages into complete three-partition
scans. They cover 3→4→96 selection, exact nullable probe/provenance/routing,
one ambiguous probe attempt without retry, invalid prerequisites before a
producer call, foreign/repeated/misordered stage identities, and failure
controls for loss, byte corruption, misrouting, future input, missing/duplicate
partitions, truncated or moving scans and inconsistent acknowledged coordinates.
They are harness controls, not release qualification evidence. The coordinator's targeted portable controls passed all six top-level tests in1.987s; no
broker or released process ran. The exact50437c23c9bbdbf01dfc1099430ef70d30568a3f
native full check passed in54.869s and its three independent review scopes passed
before integration. Those measured controls do not supply the missing live
source-save mechanism, required campaign or final integrated CI.

There is deliberately no call from `scenario.go`. Integration depends on the
current periodic-save witness, original-parent/process custody and actual
same-primary observations. The two-stage delivery profiles remain unchanged;
source-save's three-stage checker does not supply its missing mechanism.
Adding staging helpers or data admission cannot turn that unsupported
mechanism into a passing scenario.
