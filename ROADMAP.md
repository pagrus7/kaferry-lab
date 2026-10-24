# Required implementation roadmap

## Objective and boundaries

Produce independent, replayable evidence of how the **published v0.6.0 executable** behaves under faults that cross process, broker, ownership, network, and storage boundaries. Cover useful interactions beyond the core tests; do not enumerate every configuration. The required scope is M0–M6 below. A milestone is done only when its implementation, runs, evidence, reviews, and final-commit CI meet its exit criteria.

No old-syntax rejection, parser testing, broad version migration, CLI option matrix, or wholesale copy of the core suite. Minimal healthy controls establish that each scenario and observer work. No changes to Kaferry itself. The optional research at the end is not required for completion.

Start with Linux AMD64, two disposable single-broker KRaft clusters, Kafka 3.9.2, Go orchestration, and one independent Kafka client. Pin resolved broker/proxy image digests and Go dependencies. Later milestones add replication and targeted runtime-container checks. Host macOS may orchestrate a Linux execution environment; report actual platform and storage boundaries. Do not run Linux release binaries as host macOS processes or call emulation native evidence.

## M0 — Establish what the lab can observe

1. Audit tagged core tests and finish [coverage inventory](docs/coverage.md). For each required scenario, state the missing interaction/observer and its closest existing test. Replace a redundant scenario with a stronger interaction while retaining its required property; document the reason. Do not remove requirements merely because they are difficult.
2. Create a separate Go module `github.com/pagrus7/kaferry-lab`, basic CI, formatting/vet/unit checks, and explicit integration time budgets. Avoid empty package scaffolding.
3. Spike IBM Sarama as the primary producer/observer/admin stack; choose another independent stack only if mandatory capabilities fail. Validate null versus empty bytes, ordered duplicate binary headers, manual partition scans, timestamps in the required domain, transactions/read-committed, group assignment decoding, and destination partition observations. Validate Murmur2 using independent known vectors. Use known golden/wire fixtures and a distinct-client cross-check, not just a same-client round trip. Do not use Kaferry/franz-go's decoded result as truth.
4. Establish three independent identities: logical test record, Kafka source position, archive physical file/record. Record byte fidelity fixtures separately from uniquely identifiable stress records; adding ID headers to every record would invalidate no-header/size-boundary fixtures.

**Exit:** committed capability tests and inventory; one selected client; measured supported/unsupported capabilities with evidence. Mandatory missing capabilities block affected qualification, never silently skip. Healthy control reads have independently known expectations. CI is green for implemented checks.

## M1 — Artifact identity, evidence, and an offline checker

Implement these small command boundaries as needed (exact flag names may evolve):

- `lab verify`: resolve a published tag to commit and platform assets; verify checksums and available provenance; record executable digest, version output, release identity and tagged contract hash. Start with v0.6.0 at `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. Refuse silent main/latest drift, unknown contract versions, and source-build fallback.
- `lab check <bundle>`: deterministic, network-free checking of a complete evidence bundle. No need for Docker or the target executable to recheck. Reject incomplete/truncated/untrusted schema versions explicitly.
- `lab qualify`: only verified published Kaferry artifacts, reviewed contract, and required scenario sets. Allow targeted development runs but label them partial and never issue full qualification from a subset.
- `lab calibrate`: separate report namespace for synthetic histories, a deliberately faulty stand-in, and later defective builds. It cannot produce a release qualification result.

Follow [evidence rules](docs/evidence.md). Implement corrupt-byte, lost-required-record, unsafe-saved-prefix, aborted-record leak, wrong-partition, missing-trigger and truncated-evidence checker controls; permitted duplicates must pass. Add an orchestration stand-in that deliberately commits before producing and exposes a deterministic kill window. This tests the lab, not Kaferry internals. A faulty specimen undetected by a scenario remains a recorded limitation.

**Exit:** golden valid/invalid histories produce the specified verdicts; changing run identity or removing required evidence cannot yield PASS; stand-in fault reached and detected; identical bundle rechecks have identical verdicts. No production release is claimed qualified yet.

## M2 — Integrated crashes, long stalls, and timeouts

Build the first usable end-to-end release campaign. Use explicit named groups for restart, at least three selected partitions, finite verified input, and a healthy comparison run. Use short recorded timeout settings, not long arbitrary sleeps. First run PRESERVE; repeat only routing-sensitive faults with KEY.

Required scenarios:

1. **Kill with unresolved deliveries:** interrupt the real process while independently observed output lags the known source ledger; restart the same group repeatedly. Include crash after visible destination writes but before a subsequently observed saved position. Timing that cannot be established must not be claimed. Check complete final required membership, bytes, routing, and saved-prefix safety at audit points; permit replay duplicates.
2. **Delivery outage past timeout plus stop:** pause destination service while selected records remain undelivered; hold beyond configured delivery timeout, combine separately with SIGTERM and worker record-threshold drain. Observe actual timeout/exit and restore service. Resume and verify no lost required records or saved progress beyond output. Record deadline overshoot and amplification. Resource counters describe tracked work; RSS is a measurement, not the same bound.
3. **Source/coordinator startup and save outage:** start against a cold or inaccessible source coordinator, and separately interrupt source connectivity while output is outstanding and saves are due. Recover and resume; distinguish startup/periodic commit failures from revocation's documented retry/replay behavior. Do not infer that an outage precisely hit a commit without supporting observation.

**Exit:** real downloaded binary, all fault-reached evidence, full scans and offline recheck for every required case, bounded process cleanup, healthy controls, calibrated harness, recorded product verdicts. A real product violation does not invalidate the harness if independently reproduced and accurately classified. Missing fault evidence does block completion of that scenario.

## M3 — Ownership, delayed links, transactions, and changing layouts

1. **Ownership loss with late output:** suspend a worker with outstanding output while another worker remains live. Prove the suspended member disappeared and its former partitions were assigned to the survivor in a stable group, then resume it with destination service restored. Check old-worker exit and final saved-prefix/output consistency. DescribeGroups does not expose generation numbers; do not invent them or claim every stale callback was observed.
2. **Directional delay/reset with churn:** add a standard TCP fault proxy for worker-to-broker links, including every advertised broker endpoint. Keep the independent observer/admin path healthy. Exercise delayed downstream responses/connection resets during destination writes, then rebalance or kill/restart. Record actual connections affected and interval reached; a TCP proxy does not identify which Produce response was lost. Test at-least-once recovery without asserting unobserved acknowledgment order.
3. **Open transaction under interruption:** hold an input transaction open at the observed tail, then interrupt the worker/source path and separately commit or abort. Verify no aborted output and no premature completion that loses subsequently eligible committed input. Use a bounded tip-wait case and a successful recovery case. Derive expected input from transaction decisions and the tagged cutoff contract, not all records with in-range timestamps.
4. **Partition discovery during churn:** use sparse IN and NOT IN selections while adding source partitions and forcing reassignment. Required records in additions become obligations after observed eligible assignment, not after a guessed timer. Add the matching destination partition in one case and omit it in another. Under PRESERVE, missing layout may fail after partial output; it must not silently reroute to another partition. Do not add standalone option/layout validation matrices.

**Exit:** each interaction has observed triggers and audit evidence; observer traffic is isolated from faulted links; assignment snapshots support selection/ownership claims. Compare only the per-session ordering the release promises. Save any unreproduced suspected product failures without promoting them to proved violations.

## M4 — Archive recovery under storage and delivery faults

Use an independent Avro reader (goavro is the initial candidate), independently specified header/checkpoint readers where needed, and real release subprocesses. Cover topic→file, file→topic, and file→file in addition to M2's topic→topic. Small known physical-record fixtures and healthy controls are prerequisites, not a broad codec regression suite.

1. **Capture contention and failed storage:** use multiple workers, small rotation/open-file budgets, disposable capacity-limited storage, and ENOSPC or a controlled I/O stall. Combine with one worker kill/reassignment, then repeated recovery. Independently decode all recoverable acknowledged output before deciding whether Kafka saved prefixes are safe. Check completed-file immutability, recovered prefixes, released versus live locks, and duplicates. Scope full-disk faults to a lab volume; never fill the host filesystem.
2. **Replay pressure plus acknowledgment ambiguity:** exceed handle/overlap-cache budgets with overlapping files, including physical duplicate source records and equal offsets from distinct identities. Delay output responses, kill/restart repeatedly, and publish new capture files concurrently. Check each selected physical record obligation, provenance-based routing, and the saved selection remaining fixed. New files are not silently added on same-group resume.
3. **Checkpoint/recovery disturbance:** interrupt real checkpoint writes/processes and separately make a selected file unavailable or corrupt after initial selection. Distinguish selected corruption from excluded payload corruption and excluded-file removal after selection. Verify explicit failure rather than success with omissions, and safe resume after restoring the original selected input. Exercise repeated interrupted recovery, not just one fault followed by a healthy restart.
4. **Mounted container shutdown:** run the digest-pinned released container under its actual UID with mounted archive/checkpoint volumes, then SIGTERM during storage/output contention. Record container and executable identities and deadline behavior. This is a targeted packaging/termination experiment, not a second complete matrix.

**Exit:** fault bundles and independent Avro decoding show physical multiplicity, selection, saved cursor, immutability, and recovery outcomes. Report any point whose durability cannot be externally established as inconclusive. SIGKILL is process failure, not loss of kernel page cache or proof about power failure. No custom general-purpose filesystem is required.

## M5 — Replicated brokers and interfering services

Extend only the scenarios whose fault mechanisms require replication. Use disposable three-broker fixtures with explicit replication/ISR/ack settings. State substrate assumptions; do not label configured broker data loss a Kaferry violation.

1. **Source leadership/replica movement with an open transaction and churn:** combine observed source leader movement or completed replica reassignment with M3's transaction/ownership scenario. Include control/aborted offset gaps. Check required committed records and absence of false completion. Compaction/retention changes require an independently retained ledger and explicit availability assumptions; they are not an excuse to infer record counts from offset gaps.
2. **Coordinator or destination leader failover during uncertain saves/delivery:** move leadership while progress and output are active; add a bounded link delay. Verify per-partition saved-prefix safety and same-group recovery, not just process reconnection. Prove actual leader/coordinator changes independently.
3. **Runtime authorization/configuration failure:** after successful output, revoke destination write permission or change a broker limit so batches fail asynchronously. Observe the change taking effect; restore it and resume. An async delivery error must not become silent success under SKIP. Use a targeted failure condition, not a comprehensive ACL matrix.
4. **Shutdown with interfering output:** block a lab-owned stderr pipe or stall a disposable OTLP receiver while delivery/storage is also stalled; signal the worker. Measure whole-process deadline and preserved resumability. Keep evidence collection on another channel; do not deadlock the harness's own log writer. Apply bounded CPU/memory pressure in containers for a small representative variant, with explicit limits and cleanup.

**Exit:** all four mechanisms reached in at least one reviewed supported environment, with healthy controls and final audit scans. Report resource exhaustion and observation failure separately from product failure. Record time to recover and shutdown timing with the configured contract/budget; don't invent an availability SLO the tool never promised.

## M6 — Bounded campaigns, retained findings, and usable delivery

1. Compose already validated faults using seeded schedules. Start with these six combinations: delayed destination + worker kill; destination outage + rebalance; source coordinator failure + signal; storage exhaustion + capture-owner loss; replay delay + repeated restart + new publication; source leader movement + open transaction. Reuse the independently verified M2–M5 scenarios rather than inventing arbitrary random events. Every required combination needs a reached run and offline-recheckable bundle.
2. Implement bounded schedule reduction for a failing run (remove events/reduce input/repeat); record whether the reduction reproduced the failure. A same-seed distributed rerun is a new observation, not deterministic replay. Retain original histories and all attempts, including flakes and inconclusive results.
3. Produce per-property verdicts, counterexamples, fault coverage, unique-record goodput, replay amplification, recovery/visibility latency, shutdown duration and RSS/CPU measurements. Timing comparisons use an A/A calibration before an interleaved A/B experiment; no unsupported performance thresholds. A small calibration experiment is enough; a benchmark service is outside scope.
4. Add manual GitHub workflows plus bounded scheduled campaigns against reviewed published release identities. Unknown new contracts produce an explicit unsupported result and review task; never auto-accept a new release's behavior. Keep harness CI distinct from product qualification. Publish redacted synthetic-data bundles to versioned lab release assets with hashes, manifest, run links, and retained failures. Avoid overwriting bundles, including reruns. PR workflows cannot publish.
5. Provide commands for setup, one scenario, complete required campaign, calibration, offline recheck, and cleanup. Make defaults bounded (initial target: <=10 minutes per individual scenario, <=90 minutes per full campaign job, explicit sub-budgets); adjust with recorded evidence, never silently truncate. A run timeout retains evidence and cannot qualify.
6. Complete independent docs, test/oracle and simplicity reviews of the integrated final state. Run final-commit CI and a complete required campaign on Linux AMD64; verify retained bundles recheck without Kafka/network/executable. Resolve harness failures and all missing mandatory observations. Record genuine reproducible Kaferry defects without weakening assertions or demanding a product patch in this repo.

**Exit:** M0–M6 acceptance records, complete working CLI and CI, full required fault coverage, control sensitivity, durable evidence for the pinned release, current operating docs, no unresolved harness failures, source committed and pushed. Qualification is PASS only if all required property verdicts pass; implementation may be complete with documented product violations. No blanket correctness or readiness claim follows from a count of clean runs.

## Optional follow-on work — not part of this execution

- Source-level deterministic Runner schedule fuzzing and bounded storage persistence modeling belong in Kaferry under its own reviews. Keep their evidence distinct from release execution. A SIGKILL campaign does not replace a storage persistence model.
- Broader broker/platform matrices, VM power-loss testing, cross-host filesystems, malformed Kafka protocol peers, and formal modeling require separate scope.
- Candidate gating in Kaferry's release workflow is a later decision after the lab demonstrates trustworthy fault coverage and controls. It requires approval to change that repository and the exact tested bytes must be the published bytes. This roadmap stays release-only.
