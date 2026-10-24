# Offline evidence v1

`LoadAndCheck(directory) Result` reads only four fixed flat regular files:
`manifest.json`, `artifact.json`, `events.jsonl`, `complete.json`. It needs no
network, Kafka, Docker, executable, or Kaferry imports. Public Go structs in
`schema.go` are the wire schema. All non-omitempty fields are mandatory, including
zero/false scalar observations; required slices serialize as arrays, not null.
Integers represented by `identity.Int64` use JSON decimal strings.

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

For each audit, append `output` events before its `audit` event. Each output is a
physical destination position plus independently observed bytes, not a trusted
asserted ledger ID. Every audit scans every prepared destination partition,
retaining sampled end, reached cursor, stable boundary and gap proofs. Record
positions plus proved gaps must cover the entire declared scan interval without
duplicates or omissions. An audit is a fixed snapshot: later output cannot be
appended to it, and repeated scans are never summed as extra output.

A `snapshot` audit can support sampled output lag. A `quiescent` audit also
requires independently observed `workers_stopped`, or `standin_barrier` in a
stand-in calibration, and resolved pending output. It records source saved next
offsets and group identity. Missing quiescence or incomplete stable boundaries
is INCONCLUSIVE. Each saved required prefix must have corresponding output in
that same audit; later recovery cannot repair an earlier unsafe save finding.
The manifest's final audit is quiescent and checks full required membership.

Initial faults are deliberately narrow: `process_kill` with trigger predicate
`required_output_outstanding`. `trigger` cites an earlier finalized non-final
audit; the checker computes that required records are still absent, rather than
trusting a claimed count. The required lifecycle is `fault_requested`,
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
