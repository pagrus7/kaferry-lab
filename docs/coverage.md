# Additional evidence beyond the core suite

Initial inventory from the v0.6.0 source. M0 must confirm exact test names, executed paths (release subprocess versus checkout components), and the proposed observation before implementation. This table identifies a reason to investigate, not proof that the core suite has no related case.

All paths below are relative to [Kaferry v0.6.0](https://github.com/pagrus7/kaferry/tree/v0.6.0).

| Existing coverage | Lab addition | Milestone |
| --- | --- | --- |
| `tests/compat/acceptance_test.go`: crash-before-delivery handling, retention/source identity; some helpers run in process | Actual immutable release processes, repeated crash at uncertain output/save boundaries, independent ledger and offline checker | M2 |
| `tests/compat/churn_test.go`: graceful join/leave cycles | Suspended old owner, observed reassignment, late delivery, outage beyond deadline and same-group restart | M2/M3 |
| `tests/compat/transactions_test.go`: commit/abort tails, tip timeout | Open transaction plus directional faults, ownership churn, source leader movement or replica reassignment | M3/M5 |
| `tests/compat/qualification_test.go`: static security and replicated destination failover | Runtime authorization/config changes, observed coordinator/source failover while saves/output are uncertain | M5 |
| `internal/franz/recovery_test.go`: kfake acknowledgment ambiguity and compacted offsets | Real brokers and independently observed output under link delay/reset and process loss | M3/M5 |
| `internal/archive/capture/failures_test.go`: individual traced I/O failures | Multiple real capture owners, ENOSPC/stall plus kill/reassignment, repeatedly interrupted recovery | M4 |
| `internal/archive/capture/process_test.go`: killed component writer | Released CLI with Kafka progress, concurrent ownership and independently decoded recovered archives | M4 |
| `internal/archive/replay/{session,files}_test.go`: selection/cursor resume, changed input, checkpoint failures | Output response ambiguity and repeated restart while additional files are published | M4 |
| `tests/compat/archive_overlap_load_test.go`: overlap fidelity/cache pressure | Above-budget overlap with crashes and exact physical multiplicities independently checked | M4 |
| Core soak/load and shutdown tests: stalls, caps, component cleanup deadlines | Long delivery stall combined with signal/rebalance, blocked stdio/telemetry and storage pressure; record unique goodput and recovery | M2/M5/M6 |

For each implemented scenario append a short row with exact test/scenario ID, tagged comparison source, additional mechanism, observable trigger, oracle, and evidence path or durable bundle URL. Keep this a coverage map, not an execution log. If investigation shows a proposed scenario adds no useful evidence, document its replacement and retained property in ROADMAP.md.

Do not add parser, obsolete-syntax rejection, standalone routing-option validation, or migration tests. A small successful routing/byte control is useful to qualify the observer; a copied core regression matrix is not.
