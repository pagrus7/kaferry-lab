package evidence

import (
	"fmt"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

// This is the one compiled cumulative four-record stage, not an arbitrary
// prefix selector. Input-0003 retains the existing null byte fixture.
func sourceSaveProbeLedger(full Ledger) (Ledger, error) {
	probe := Ledger{Destinations: append([]identity.SourcePosition(nil), full.Destinations...), Partitions: []PartitionRange{}, Entries: []LedgerEntry{}}
	seen := map[int32]bool{}
	for _, p := range full.Partitions {
		if p.Source.Partition < 0 || p.Source.Partition > 2 || p.Source.Offset != 0 || seen[p.Source.Partition] {
			return Ledger{}, fmt.Errorf("source-save requires fixed zero-based partitions0,1,2")
		}
		seen[p.Source.Partition] = true
		p.End = 1
		if p.Source.Partition == 0 {
			p.End = 2
		}
		probe.Partitions = append(probe.Partitions, p)
	}
	if len(seen) != 3 {
		return Ledger{}, fmt.Errorf("source-save needs all three partitions")
	}
	for _, entry := range full.Entries {
		if entry.Source.Offset == 0 {
			if entry.ID != fmt.Sprintf("input-%04d", entry.Source.Partition) {
				return Ledger{}, fmt.Errorf("source-save warmup identities differ from the known declaration")
			}
			probe.Entries = append(probe.Entries, entry)
		} else if entry.Source.Partition == 0 && entry.Source.Offset == 1 {
			r := entry.Record
			if entry.ID != "input-0003" || r.Key != (identity.NullableBytes{Null: true}) || r.Value != (identity.NullableBytes{Null: true}) || len(r.Headers) != 0 || r.TimestampMS == nil || *r.TimestampMS != 1700000000123 || r.TimestampKind != "create_time" {
				return Ledger{}, fmt.Errorf("source-save requires the unchanged input-0003 null fixture at partition0/offset1")
			}
			probe.Entries = append(probe.Entries, entry)
		}
	}
	if len(probe.Entries) != 4 {
		return Ledger{}, fmt.Errorf("source-save probe stage must contain exactly four entries")
	}
	return probe, nil
}

// Called only after the ordinary audit checker validates all observations.
// This sampled data predicate deliberately differs from fully saved progress;
// it proves no later save attempt, impaired failure or output quiescence.
func sourceSaveProbeVisible(m PhaseManifest, l Ledger, a M2Audit, outputs []Output) bool {
	assigned, err := m2GroupAssigned(a.Group, m.Group, l.Partitions[0].Source.Topic)
	if err != nil || !assigned || len(unmatchedRequired(l.Entries, outputs, nil)) != 0 {
		return false
	}
	for _, scan := range a.Scans {
		if !scan.Complete || scan.Reached != scan.End || scan.StableEnd != scan.End {
			return false
		}
	}
	for _, saved := range a.Saved {
		if !saved.Present || saved.Source.Offset != 1 {
			return false
		}
	}
	return true
}
