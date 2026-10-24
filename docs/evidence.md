# Evidence and verdict rules

## What is being tested

Kaferry promises at-least-once delivery of records selected before completion, subject to documented filters, SKIP, retention and stop rules. The lab tries to falsify loss, corruption, incorrect routing, unsafe saved progress, ownership misuse, or broken recovery. It records timing and resource behavior separately. Passing finite campaigns is evidence for those executions, not proof for every schedule.

The subject is the verified release executable. Input generation, observation and checking use independent code. Source inspection may explain a result but cannot manufacture missing observation. Assertions refer to the pinned tagged contract, not current main or a guessed stronger guarantee.

## Input and output obligations

- Prepare a finite ledger and verify acknowledged input before injecting faults. Resolve ambiguous producer timeouts by observation; do not assume timeout means absent. Disable retention/compaction initially. Later destructive broker scenarios must preserve original evidence and explicitly narrow availability assumptions.
- Encode raw bytes as base64 with explicit null markers, headers as ordered arrays, and signed 64-bit offsets/timestamps as decimal strings. Preserve null versus empty and repeated/non-UTF-8 header keys.
- Kafka source identity includes cluster, topic identity, partition and offset. Destination offsets are unrelated. Archive obligations use file identity plus physical record ordinal/cursor, with original Kafka provenance recorded separately. Duplicate physical inputs remain separate required occurrences.
- A visible unique test ID supports exact membership. Identical byte-only records support multiplicity but may hide one lost occurrence compensated by another replay; say so. Do not modify exact-fidelity fixtures to avoid this limit.
- Distinguish required, permitted and forbidden outputs from the contract and observed events. Permit at-least-once duplicates. Do not assert global ordering, exactly once, or a universal duplicate bound. IN additions remain excluded; NOT IN additions become required only after observed eligible assignment while the scenario remains active.
- Check timestamp windows using the actual saved/resolved bounds and completion rules. The cutoff heuristic can legitimately omit later-offset in-window records. Open/aborted transactions and offset gaps require transaction-aware expectations; offset differences are not record counts.

## Fault and audit evidence

Each scenario records Given/When/Then, configured budgets, trigger predicate, fault request, independent confirmation of the fault, recovery, and final scans. A requested sleep/kill/network rule is not proof it affected the intended work. Prefer barriers and bounded polling; record actual elapsed time and observation granularity.

For ownership loss, capture stable membership excluding the suspended worker and decoded reassignment of its former partitions to a known survivor. Group description has no generation field. For destination outages, show outstanding required work plus service/link impairment and the timeout/exit when that is the case's purpose. Proxy evidence supports TCP-level claims, not unseen Kafka request/ack causality.

At audit points, stop and reap workers, recover services, state the stabilization assumptions, record partition ends, and scan completely to those boundaries. Include a bounded broker restart where a scenario needs it to drain in-flight work. Two unchanged end readings alone do not prove no pending request remains. If pending-output ambiguity could change a safety verdict, retain INCONCLUSIVE.

Compare saved next offsets against the consumed-prefix obligations that are externally justified: each earlier required record must have output, or an independently supported filter/skip explanation. Include initial positions and known gaps. Archive saved cursors require the selected physical-record obligations and recovery state. These observations can reveal unsafe progress but cannot prove every historical acknowledgment preceded every historical save. Logs, exit zero, `status`, worker thresholds, metrics and a source rescan are never substitutes for a record ledger.

Time budgets bound experiments. A timeout is not by itself data loss. A liveness violation requires an explicit promised/configured bound and healthy recovery preconditions; otherwise unresolved completion is INCONCLUSIVE. A documented fail-fast exit followed by safe resume can pass the scenario's expected behavior.

## Bundle contents

Use a versioned manifest and append-only JSONL events. Finalize bundles with hashes and a completion marker only after all required evidence exists. Store:

- Release tag, commit, archive/binary/image digests, checksum/provenance verification, version output; lab/checker/contract versions and clean/dirty source identity.
- OS/architecture, runtime, Docker/kernel/storage boundaries, pinned broker/proxy images, topology and sanitized configuration, timeout/resource settings, seed and event schedule.
- Input ledger, output observations, initial and audit offsets, archive selections/checkpoints/file hashes, assignments/membership/leadership changes and scan boundaries.
- Requested/reached/recovered faults, actual times, signals, process exits/restarts, redacted logs, resource samples, cleanup outcomes and environmental errors.
- Per-property verdicts, limitations, minimal counterexamples where available, original failure history plus reduction/retry attempts, and offline-check command/version.

Hashing makes changes detectable; it does not prove an untrusted author observed reality. Check manifest paths safely and reject traversal, duplicate/conflicting events, truncated required streams, hash mismatches and unsupported versions. Never publish credentials, raw user datasets or consultation transcripts. Synthetic experiments must use lab-generated credentials and redact even those where unnecessary.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| PASS | Required evidence is complete, fault reached, property satisfied for this execution |
| VIOLATION | Complete evidence demonstrates a property breach; preserve a counterexample |
| INCONCLUSIVE | Evidence/observation/timing cannot decide the property |
| HARNESS_ERROR | The lab failed to execute, collect, or check as specified |
| UNSUPPORTED | A required environment, observer capability, or contract is unavailable |

Only PASS on all required properties/scenarios qualifies a release. Unreached faults, partial runs, missing mandatory capabilities and unknown contracts block qualification. Show expected failure scenarios as PASS only when their specific fail/resume guarantees were actually observed. Keep first failures visible; retries are additional results, not replacements. A functioning harness can report a product VIOLATION while its own tests pass.

## Calibration and limits

Use corrupted recorded histories to test checker sensitivity, a stand-in copier to test orchestration sensitivity, and only separately isolated defective builds to test product-specific detection. Label calibration prominently; it must not be accepted as release evidence. A stand-in's deterministic commit-before-produce window does not establish that the same fault reaches real Kaferry.

SIGKILL preserves kernel page cache. Disk-full, blocked writes, process death and power failure are distinct conditions. Local filesystems cannot establish cross-host lock/durability semantics. Broker acks and filesystem sync require stated substrate assumptions; arbitrary Byzantine brokers or storage that lies about sync are not automatically inside Kaferry's guarantee.
