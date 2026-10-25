# Offline evidence contracts

`LoadAndCheck(directory) Result` reads only four fixed flat regular files:
`manifest.json`, `artifact.json`, `events.jsonl`, `complete.json`. It needs no
network, Kafka, Docker, executable, or Kaferry imports. Public Go structs in
`schema.go` define version1; `m2_schema.go` defines version2. All non-omitempty fields are mandatory, including
zero/false scalar observations; required slices serialize as arrays, not null.
Integers represented by `identity.Int64` use JSON decimal strings.

## Version 1 histories

The manifest binds run/scenario/group, Given/When/Then, time budget, exact
subject/contract identity, mandatory lab source commit/dirty/proof and explicit
orchestrator/execution platform, runtime, storage, topology and limits,
artifact/event byte hashes and sizes, required faults,
event count, and final audit ID. The completion marker binds the exact manifest,
event digest/count and run. JSONL sequences start at one and increase by one;
every line is newline terminated, has the same run ID and nondecreasing elapsed
milliseconds, and contains exactly the payload selected by its event kind.
Calibration may explicitly record unavailable lab VCS as commit `unavailable`,
dirty true, with proof; release histories require a known canonical 40hex lab
commit and execution platform matching the pinned executable platform.
Unknown versions, unexpected files, links, alternate manifest paths, hash/count
mismatches, duplicate/case-conflicting JSON fields, and omitted required fields
cannot pass. Keep the bundle directory stable while checking it.

An artifact attachment retains source document hashes, recorded checksum text,
asset identity, executable identity, version output, provenance verification
status and detail. Release metadata must use the exact pinned tag/commit,
contract root, Linux AMD64 archive and executable digest measured from that
archive. Available release provenance must be
verified. The checker validates recorded metadata consistency. It does not
re-run cryptographic verification or authenticate a hostile author's claim to
have downloaded/executed an artifact. Upstream `verify` supplies that evidence.

A history begins with `ledger`, then `inputs_verified` before any observed work
or fault. The ledger enumerates source partition initial/end intervals and known
gaps, fixed destination cluster/topic-ID/partition/initial positions, exact byte
records, required/permitted/forbidden dispositions and supported reasons, and
allowed topic/partition routes. Source offsets plus explicit proved gaps must
cover each source interval completely. No offset difference is a record count.
V1 admits destination partitions from exactly one fixed cluster, topic name and
topic ID. A ledger mixing any of those identities is a HARNESS_ERROR; matching
topic names in another cluster or topic incarnation cannot satisfy its routes.

For each audit, append `output` events before its `audit` event. Each output is a
physical destination position plus independently observed bytes, not a trusted
asserted ledger ID. Every audit scans every prepared destination partition,
retaining sampled end, reached cursor, stable boundary and gap proofs. Record
positions plus proved gaps must cover the entire declared scan interval without
duplicates or omissions. An audit is a fixed snapshot: later output cannot be
appended to it, and repeated scans are never summed as extra output.
Repeated observations of the same full destination cluster/topic/topic-ID,
partition and offset must have identical record bytes, headers and timestamps.
Conflicting observations across audits are a HARNESS_ERROR.

A `snapshot` audit can support sampled output lag. A `quiescent` audit also
requires independently observed `workers_stopped`, or `standin_barrier` in a
stand-in calibration, and resolved pending output. It records source saved next
offsets and group identity. Missing quiescence or incomplete stable boundaries
is INCONCLUSIVE. Each saved required prefix must have corresponding output in
that same audit; later recovery cannot repair an earlier unsafe save finding.
Quiescent and final scans require `end == reached == stable_end`; a declared
stable tail beyond the scanned end is INCONCLUSIVE. A snapshot may scan a
sampled prefix with `end == reached <= stable_end`. The manifest's final audit
is quiescent and checks full required membership.

Initial faults are deliberately narrow: `process_kill` with trigger predicate
`required_output_outstanding`. `trigger` cites the latest finalized non-final
audit; the checker computes that required records are still absent, rather than
trusting a claimed count. A trigger audit must scan through every observed
destination end: an unscanned tail could contain the required output. A stale
audit reference or unscanned trigger tail is INCONCLUSIVE. Any output
observation newer than the cited audit and before the fault request invalidates
the trigger as INCONCLUSIVE, including output whose audit is still being
collected. A finalized audit between trigger and request also invalidates it.
Record a fresh history with a current trigger observation.
Snapshot lag describes its sampled interval; it does not prove work remained
unresolved at the actual signal without an independent timing/barrier proof.
The required lifecycle is `fault_requested`,
`fault_reached`, `fault_recovered`. Record the requested PID/signal, independently
observed matching signal and wait exit code -1, then a distinct recovered PID,
with observer identity and actual proof detail at every step. Normal nonzero
exit does not prove a requested kill reached. End with one `run_finished` event
confirming bounded cleanup; timeout or missing lifecycle proof cannot pass.

Byte/routing comparison permits at-least-once replay, gives each observation to
at most one required occurrence, and does not cap product duplicates. Identical
byte-only records are checked for aggregate multiplicity with an explicit limit:
replay may conceal loss of a particular indistinguishable occurrence. Identical
allowed and forbidden bytes make forbidden-record absence inconclusive.

Calibration subjects are visibly synthetic-history or standin, with a required
calibration label and no release tag/commit. Every result has
`release_qualified:false`: this initial checker checks one partial history and
cannot qualify an M0-M6 campaign. Full archive physical selection/checkpoint
checking is explicitly UNSUPPORTED until M4, even if Kafka properties pass.
Other faults/scopes/contracts are unsupported rather than skipped.

V1 reading limits are 1 MiB manifest/completion, 4 MiB artifact metadata/event
line, 64 MiB event stream, 200,000 events, 1,024 ledger entries, 256 source and
destination partitions, and 16,384 observations per audit. Capacity rejection
is explicit and is a checker limitation, not a product duplicate bound.

`testdata/` contains authored literal synthetic valid/invalid histories and
fixed expected controls. They are not release runs. Tests recompute framing
hashes only when deliberately mutating a control to reach a semantic check;
record obligations and expected verdicts never come from the checker.

## M2 histories: version 2

`m2_schema.go` defines a closed version2 manifest/event/completion schema. The
artifact attachment keeps its version1 verification contract. `LoadAndCheck`
dispatches by manifest version; `WriteM2Bundle` reserves a new directory and writes
the completion marker last. It does not overwrite attempts or make an incomplete
history valid. The same four flat filenames, hash checks, JSON limits and strict
required-field rules apply. All results still have `release_qualified:false`.

M2 records the generated SQL and TOML, their hashes, worker arguments/environment,
routing, work/cleanup budgets and delivery/shutdown settings. The checker accepts
the narrow generated configuration form and binds its endpoints, topics, named
group and routing to the independently observed identities. It rejects unsupported
configuration rather than treating unknown settings as the tested defaults.

Worker events identify an owned invocation by worker ID, PID, Linux start ticks,
executable/argument/environment hashes, observed stopped state, actual wait exit,
reaping and final cleanup. Broker events bind run label, immutable container ID,
pinned image, endpoint and cluster identity to state observations and independent
Kafka availability probes. Requested actions alone never establish impairment or
recovery. Campaign-wide monotonic intervals order these observations; per-handle
elapsed times remain separate measurements.

Input readbacks must preserve the exact finite ledger. Audits retain full
partition scans, raw group assignments and saved-next-offset observations.
Absent progress is explicitly `present:false` with offset `-1`; saved zero is a
different fact. A settled safety audit requires all workers stopped/reaped/cleaned,
service restoration, broker restart after worker exit to settle pending requests,
and successful source-input verification. Each settled audit checks saved-prefix
safety; a live snapshot cannot decide it while output may remain pending. The
final settled audit requires full input membership and observed saved next
positions at every prepared finite source end. Complete output with absent or
unfinished saved progress is INCONCLUSIVE; it cannot establish completed recovery.
This completeness requirement is limited to M2's finite, gap-free, nontransactional
input. Intermediate safety audits may retain absent or unfinished safe prefixes.
Later recovery cannot repair an earlier proved violation.

An exactly empty assignment in `PreparingRebalance` or `CompletingRebalance`
means ownership is unknown. Raw member identity and empty bytes remain retained;
they cannot satisfy an assignment-dependent trigger. Empty stable assignments
and any nonempty malformed assignment are harness errors. Group-wide saved
completion does not identify a particular callback, generation or member's save.

The compiled scenario IDs are `healthy`, `repeated-kill`, `delivery-stop`,
`delivery-threshold`, `source-startup` and `source-save`. Healthy histories need no
invented fault. Crash histories need two independently reached output-lag kills and an identified
visible-output/unsaved-position crash, each with matching signal exit, restart and
audits. The visible crash may have complete output; it counts as a lag kill only
when its own fresh audit also shows missing required output. Newer output or scan observations before the actual fault
request invalidate an older trigger even when the new audit's saved/group read
finishes after that request. Startup histories need source impairment before invocation,
observed bounded worker exit, recovery and successful same-group copying.
Delivery-stop histories additionally need independent timeout-path observations;
logs can corroborate the path but never replace record scans.

The current threshold observer is experimental: its capture/PDML candidates do
not establish accepted-work threshold handling, response absence or output.
Threshold histories remain `UNSUPPORTED`. Precise source-save interruption
remains `INCONCLUSIVE` without an independent commit observation. Missing
mandatory facts, unsupported observations, timeout, cleanup or evidence-write
failure cannot produce a passing run. Version2 synthetic controls remain
calibration histories; they do not establish real released-binary fault coverage.

M2 settings with `measurements_version:1` require Linux owned-child wait accounting on every exit. The exit observation binds availability, source/scope, peak RSS in KiB and bytes, and user/system CPU in nanoseconds. Missing/unavailable accounting is nonpassing; inconsistent units or overflow are harness errors. Histories without this setting check data properties without claiming measurements. The checker derives timing ranges from SIGTERM and wait intervals, and output/input volume from the complete settled final scan. These derived summaries are not trusted input. Wait includes controller/log-drain time, RSS is not a tracked-work cap, and aggregate replay volume cannot establish required membership.
