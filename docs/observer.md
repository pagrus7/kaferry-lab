# Independent observer capabilities

The observer is part of the lab, not Kaferry. Qualification must execute verified
published artifacts and must not import Kaferry, its codecs, or its Kafka client
as the expected-result oracle. Tagged source describes the released contract and
the closest existing tests; it does not establish what happened in a lab run.

M0 selected **kafka-go v0.4.49's protocol-level API for primary scans**, after
measured mandatory failures in the initial candidates. Sarama v1.61.0 supplies
admin and transactional producer helpers and the distinct-client known-byte
cross-check. Its timestamp decoder cannot preserve an accepted negative Kafka
timestamp; kafka-go's high-level Reader collapses empty bytes and also cannot
serve as the byte oracle. Neither rejected path is used as the primary scanner.

The demonstrated initial domain uses CreateTime, retained finite ledgers and
no compaction. LogAppendTime is explicitly unsupported by the protocol API
because it omits the batch maximum needed for correct restamping. Empty
compacted tails without an observable final cursor fail closed. These limits
must block any affected qualification; they cannot become skipped passing
assertions. Full signed-int64 timestamp interoperability is not claimed.

Local integrated evidence: `.cache/m0/m0-observer-20261024h.log` (all five live
subtests passed), `.cache/m0/strict-final-unit.log` (format/vet/race controls). This
measured macOS ARM64 orchestration with Linux ARM64 brokers, not native AMD64
release behavior. Native AMD64 CI and independent reviews are required before
M0 is accepted. No Kaferry release has been qualified. See [coverage](coverage.md),
[setup](setup.md), and [evidence rules](evidence.md).

## Evidence identities and bytes

`internal/identity` separates three identities:

| Identity | Representation and purpose |
| --- | --- |
| Logical stress record | Optional `LogicalStressID` attached to an `Observation`, outside its `Record`. A scenario may independently extract an ID from deliberately identifiable synthetic records. The types never insert an ID header. Exact no-header and size-boundary byte fixtures remain undecorated. |
| Kafka source position | `SourcePosition` holds cluster ID, topic name, canonical topic ID, partition, and source offset. Recreated topics and equal offsets in different partitions/topics/clusters are distinct. Destination offsets are observed positions, not replacements for source provenance. |
| Archive occurrence | `ArchivePosition` holds writer/file identity, zero-based physical ordinal, byte-block/index cursor, and separate original Kafka provenance. Two physical records with equal source offsets remain two obligations, including duplicates within one file or across files. |

`Record` carries raw fidelity data. Key/value and header values use
`NullableBytes`: `{"null":true,"base64":""}` is null, while
`{"null":false,"base64":""}` is a present empty byte sequence. Base64 is
standard padded canonical base64, validated on serialization and decoding.
`Bytes()` preserves nil versus present empty slices. Ordered `[]Header` retains
duplicates; `key_base64` carries raw binary header names without UTF-8 conversion
or object-key normalization. A no-header record serializes as `headers:[]`.

Source offsets, timestamps, physical ordinals, and cursor integers use `Int64`,
serialized as signed decimal strings. This prevents rounding beyond 2^53 in JSON
consumers. Bare numbers, overflow, leading zeros, and alternate numeric forms
are rejected. Exact int64 evidence representation does **not** imply the chosen
Kafka client supports the entire signed millisecond timestamp domain.

Identity fields record observations; these small types do not validate a whole
run. The bundle checker must validate identity formats, schema versions,
nonnegative source/cursor domains, referenced files, expected timestamp kinds,
required event streams, and cross-event consistency before issuing verdicts.
Types alone cannot prove a record was produced or a fault reached its target.

## Capability acceptance plan

| Capability | Required evidence before relying on it | State |
| --- | --- | --- |
| Null/empty and binary bytes | Independently known bytes, golden/wire fixtures, ordered duplicate non-UTF-8 header names, independent-client cross-read. Include no-header fixtures without test ID decoration. | Measured: all null/empty combinations, no-header record, ordered duplicate binary header keys; known expectations and two-client cross-reads passed. |
| Source and destination positions | Manual partition fetches with explicit start and audit end, topic IDs/cluster identity, observed destination partition, record ledger independent of destination offset numbers. | Measured: distinct cluster/topic IDs, full partition 2 source / partition 4 destination scans and empty partition scan passed. |
| Timestamps | Golden signed millisecond decoding cases and live modern-domain byte cross-check; explicit unsupported result outside the client's demonstrated range. Observe CreateTime versus LogAppendTime rather than inferring it from requested producer timestamp. | Measured: modern, epoch 0, and -2ms CreateTime reads passed. Negative Sarama capability failed explicitly. LogAppendTime and full int64 domain unsupported. |
| Read-committed transactions | Independently decided open/commit/abort transactions, control/aborted offset gaps, fixed scan bounds, and an independent-client check. Open transactions must not appear as successfully completed tail scans. | Measured: open LSO below HW rejects full scan; commit/abort membership and control-tail cursor checks passed. |
| Group assignments | Golden assignment wire fixture decoding plus actual stable membership/partition assignment snapshots. DescribeGroups does not supply a generation number. | Literal assignment wire/truncation controls and stable one/two-member actual assignments plus known saved offsets passed. |
| KEY routing | Independently published Java Murmur2 known vectors, then observed actual destination partitions. Null keys require valid destination membership, not a fixed expected partition. | Apache Kafka Murmur2 raw golden hashes and Sarama partition comparisons passed; actual manual destination partition observations passed. Kaferry KEY routing remains an M2+ obligation. |
| Archive physical identity | Independent OCF/header/checkpoint reader with physical block boundaries/ordinals and known literal fixtures; decode all recoverable acknowledged output before judging Kafka saved-prefix safety. | Required for M4; not implemented by these evidence types. |

The coordinator records actual tests and evidence paths in the milestone
acceptance record. A capability remains unsupported or pending until its
mandatory checks are demonstrated; it must never be silently skipped.

## Timestamp and scan constraints

The tagged [client limitations](https://github.com/pagrus7/kaferry/blob/d7d485b96a52b711cb10d76dca09aa9b155dec5e/design/client-compatibility.md)
identify franz-go v1.22.2's Kafka-read timestamp problem outside
±9,223,372,036,854 Unix milliseconds. The lab must characterize that limitation
explicitly when encountered. It cannot use franz-go's decoded timestamp as truth
or weaken ordinary in-domain fidelity checks to accommodate it. File→Kafka
timestamps are a separate case, including possible LogAppendTime restamping.

The Sarama producer helper conservatively checks its domain rather than relying
on `time.Time.UnixNano()` outside its representable range. Negative timestamp
fixtures are produced/read through the validated protocol path. Sarama-produced
epoch zero is independently observed through that path; the protocol producer
itself restamps epoch zero, so it is not used to generate that fixture. Inputs
outside the demonstrated domain require explicit unsupported characterization
and must not become ordinary passing observations.
Golden serialization of `Int64(math.MinInt64)` tests evidence precision, not
Kafka timestamp interoperability.

A complete partition scan needs independently observed bounds and an advancing
offset cursor. An empty channel, a quiet interval, or the last data record's
offset cannot prove that the tail was consumed. Control/aborted/compacted offsets
are gaps, not counts of missing records. The low-level observer must retain
batch spans, control/aborted decisions, last stable offset and high watermark
where available, and reject truncated/partial/no-progress fetch evidence. A
fixed-v11 plaintext Fetch admission gate validates frame bounds/correlation,
requested topic/partition, batch lengths/CRCs, declared record counts, record
extents and offsets, bounded decompression, and complete consumption before the
client decoder is used. Declared spans admit legitimate sparse/empty batches;
visible application records alone never prove a complete batch. This narrow
gate is needed because kafka-go v0.4.49 (also .51) can suppress malformed
successful-prefix data. Literal multi-record/multi-batch failure controls
reproduce that defect and require rejection before scan completion.
Read-committed scans must not cross the independently supported stable boundary
while claiming to have read an open-transaction tail. Retention passing the
cursor invalidates the original availability assumptions.

For an audit, stop/reap workers, restore faulted services, state stabilization
assumptions, sample ends, and scan completely to those bounds. Two unchanged end
samples alone do not prove no pending produce request remains. Keep
INCONCLUSIVE when pending output ambiguity could change a safety verdict.

## Archive format boundary

The [v0.6.0 archive contract](https://github.com/pagrus7/kaferry/blob/d7d485b96a52b711cb10d76dca09aa9b155dec5e/design/archive.md)
specifies canonical metadata and SHA-256-enveloped writer/replay state. The
published [Avro schema](https://github.com/pagrus7/kaferry/blob/d7d485b96a52b711cb10d76dca09aa9b155dec5e/internal/archive/avro/schema.json)
uses binary header keys, nullable key/value/timestamp fields, signed long
offsets/timestamps, and fixed 16-byte topic IDs. Tagged literal metadata and
checkpoint fixtures can establish independent wire expectations. Importing
Kaferry's state decoders or regenerating expected fixtures with them cannot.

Replay checkpoints count confirmed physical records and retain per-file
block/index cursors; source offsets can repeat. Capture writer state records
acknowledged byte extents and record counts, not Kafka commits. Independently
recover/decode those prefixes and compare required record obligations with
observed output. Generic logical Avro decoding alone does not provide all byte
positions needed for this check. Completed selected files stay immutable;
same-group incomplete resume validates its fixed selection, and new files do
not silently join it. Excluded payload corruption, excluded-file removal after
selection, and selected-file corruption are different cases.

Use goavro as the initial independent Avro candidate with a narrow independent
OCF framing index as necessary. Core already has goavro cross-read tests, so the
lab's additional value is independent release execution, fault evidence, and
ledger checking under combined/repeated faults. No archive capability run or
durability result follows from this document.

## Retained development failures

Attempt a has an honest summary only (`.cache/m0/m0-observer-20261024a-summary.json`);
its original raw stdout was not saved and is not relied on as passing evidence.
Full failed attempts b–d are retained separately: b caught identical default
cluster IDs, c caught metadata caching and epoch-producer restamping, d caught
new-topic visibility. The controller now generates distinct cluster IDs, and
tests use bounded metadata readiness predicates. Attempt e passed in staging;
f passed after integration but a source review then found the decoder admission
defect; f alone could not discharge that missing sensitivity. After the fix,
g passed in staging and h after integration. The exact CRC-valid successful-prefix
counterexample is reproduced and rejected by committed unit controls. Retries
are separate observations, never replacements.
