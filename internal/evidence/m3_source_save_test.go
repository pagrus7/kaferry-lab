package evidence

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

// The existing literal metadata/worker/broker controls are reused; the new
// ledgers and asymmetric output expectations never call production derivation.
type sourceSaveControl struct {
	c     *phaseControl
	probe Ledger
}

func newSourceSaveControl() *sourceSaveControl {
	c := newPhaseControl()
	c.m.ScenarioID = "source-save"
	c.m.Then = "three independently read data stages; periodic-save mechanism remains unsupported"
	p := &c.m.Profiles[0]
	p.ID, p.Settings.RecordThreshold = "primary-unlimited", 0
	p.Settings.Args = append([]string(nil), p.Settings.Args...)
	p.Settings.Args[2] = "/synthetic/primary-unlimited.sql"
	p.Settings.SQL = c.m.Profiles[1].Settings.SQL
	p.Settings.SQLSHA256 = phaseTestHash([]byte(p.Settings.SQL))
	for i := range c.full.Entries {
		e := &c.full.Entries[i]
		e.ID = fmt.Sprintf("input-%04d", int(e.Source.Offset)*3+int(e.Source.Partition))
	}
	ms := identity.Int64(1700000000123)
	c.full.Entries[1].Record = identity.Record{Key: identity.NullableBytes{Null: true}, Value: identity.NullableBytes{Null: true}, Headers: []identity.Header{}, TimestampMS: &ms, TimestampKind: "create_time"}
	c.warm = Ledger{Partitions: []PartitionRange{}, Destinations: append([]identity.SourcePosition(nil), c.full.Destinations...), Entries: []LedgerEntry{c.full.Entries[0], c.full.Entries[32], c.full.Entries[64]}}
	probe := Ledger{Partitions: []PartitionRange{}, Destinations: append([]identity.SourcePosition(nil), c.full.Destinations...), Entries: []LedgerEntry{c.full.Entries[0], c.full.Entries[1], c.full.Entries[32], c.full.Entries[64]}}
	for p, end := range []identity.Int64{2, 1, 1} {
		r := c.full.Partitions[p]
		r.End = 1
		c.warm.Partitions = append(c.warm.Partitions, r)
		r.End = end
		probe.Partitions = append(probe.Partitions, r)
	}
	return &sourceSaveControl{c: c, probe: probe}
}

func (s *sourceSaveControl) publishProbe() {
	raw, _ := json.Marshal(s.probe)
	s.c.add(PhaseEvent{Kind: "input_published", Publication: &PhasePublication{PhaseID: "save-probe", WorkerID: "primary", Interval: s.c.interval(), LedgerSHA256: phaseTestHash(raw)}})
}
func (s *sourceSaveControl) verifyProbe() {
	v := &PhaseVerification{PhaseID: "save-probe", Interval: s.c.interval(), Ledger: s.probe, Scans: []Scan{}, Method: "independent_source_scan", Complete: true}
	for _, p := range s.probe.Partitions {
		v.Scans = append(v.Scans, Scan{PartitionRange: p, Reached: p.End, StableEnd: p.End, Complete: true, Proof: "literal zero-to-fixed-end source scan"})
	}
	phaseTestBind(v)
	s.c.add(PhaseEvent{Kind: "input_phase_verified", Verified: v})
}

func (s *sourceSaveControl) audit(id, phase string, ends, saved [3]int, settled, final bool) {
	c := s.c
	c.n += 1_000_000
	scan := M2Interval{StartNS: c.n}
	for p, end := range ends {
		for off := 0; off < end; off++ {
			c.n += 1_000_000
			destination := c.full.Destinations[p]
			destination.Offset = identity.Int64(off)
			c.add(PhaseEvent{Kind: "output", Output: &PhaseOutput{PhaseID: phase, Observation: Output{AuditID: id, Destination: destination, Record: c.full.Entries[p*32+off].Record}}})
		}
	}
	c.n += 1_000_000
	scan.EndNS = c.n
	a := M2Audit{ID: id, Mode: "snapshot", ScanInterval: scan, SavedInterval: c.interval(), GroupInterval: c.interval(), Scans: []Scan{}, Saved: []M2SavedPosition{}, Final: final, Group: M2Group{GroupID: c.m.Group, State: "Stable", ProtocolType: "consumer", Protocol: "cooperative-sticky", Members: []M2GroupMember{{ID: "literal-member", AssignmentBase64: "AAAAAAABAAVpbnB1dAAAAAMAAAAAAAAAAQAAAAL/////"}}}}
	if settled {
		a.Mode = "settled"
		a.Group = M2Group{GroupID: c.m.Group, State: "Empty", Members: []M2GroupMember{}}
	}
	for p, end := range ends {
		a.Scans = append(a.Scans, Scan{PartitionRange: PartitionRange{Source: c.full.Destinations[p], End: identity.Int64(end), Gaps: []Gap{}}, Reached: identity.Int64(end), StableEnd: identity.Int64(end), Complete: true, Proof: "literal complete asymmetric destination scan"})
		position := c.full.Partitions[p].Source
		position.Offset = identity.Int64(saved[p])
		a.Saved = append(a.Saved, M2SavedPosition{Source: position, Present: true, Group: c.m.Group})
	}
	worker := ""
	if phase != "full" {
		worker = "primary"
	}
	c.add(PhaseEvent{Kind: "audit", Audit: &PhaseAudit{PhaseID: phase, WorkerID: worker, Observation: a}})
}

func completeSourceSaveControl() *sourceSaveControl {
	s := newSourceSaveControl()
	c := s.c
	c.publish("warmup", "")
	c.verify("warmup")
	c.broker("source", "inspect")
	c.broker("destination", "inspect")
	c.worker("primary", "primary-unlimited", "start", "")
	s.audit("warm-copied-saved", "warmup", [3]int{1, 1, 1}, [3]int{1, 1, 1}, false, false)
	s.publishProbe()
	s.verifyProbe()
	s.audit("probe-visible-unsaved", "save-probe", [3]int{2, 1, 1}, [3]int{1, 1, 1}, false, false)
	c.worker("primary", "primary-unlimited", "signal", "SIGSTOP")
	c.publish("full", "primary")
	c.verify("full")
	c.worker("primary", "primary-unlimited", "signal", "SIGCONT")
	c.worker("primary", "primary-unlimited", "exit", "")
	c.worker("primary", "primary-unlimited", "cleanup", "")
	c.broker("destination", "restart")
	c.verify("full")
	s.audit("primary-safety", "full", [3]int{2, 1, 1}, [3]int{1, 1, 1}, true, false)
	c.worker("recovery", "recovery-unlimited", "start", "")
	c.worker("recovery", "recovery-unlimited", "exit", "")
	c.worker("recovery", "recovery-unlimited", "cleanup", "")
	c.broker("destination", "restart")
	c.verify("full")
	s.audit("final", "full", [3]int{32, 32, 32}, [3]int{32, 32, 32}, true, true)
	c.n += 1_000_000
	c.add(PhaseEvent{Kind: "run_finished", Finished: &RunFinished{CleanupComplete: true, Proof: "literal actual waits/restoration/closed data history, no mechanism witness"}})
	return s
}

func saveProbeVerification(s *sourceSaveControl) *PhaseVerification {
	for _, e := range s.c.e {
		if e.Verified != nil && e.Verified.PhaseID == "save-probe" {
			return e.Verified
		}
	}
	panic("missing literal probe")
}
func saveAudit(s *sourceSaveControl, id string) *PhaseAudit {
	for _, e := range s.c.e {
		if e.Audit != nil && e.Audit.Observation.ID == id {
			return e.Audit
		}
	}
	panic("missing literal audit")
}
func saveWorker(s *sourceSaveControl, worker, action, signal string) *M2Worker {
	for _, e := range s.c.e {
		if e.Worker != nil {
			w := &e.Worker.Observation
			if w.Identity.WorkerID == worker && w.Action == action && w.Signal == signal {
				return w
			}
		}
	}
	panic("missing literal worker")
}

func TestSourceSaveThreeStagesRemainUnsupported(t *testing.T) {
	s := completeSourceSaveControl()
	r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
	if r.Verdict != Unsupported || r.ReleaseQualified || !phaseFinding(r, "source_save_admission_complete") || !phaseFinding(r, "mechanism_unobserved") || len(r.Findings) != 2 {
		t.Fatalf("complete data acquired mechanism acceptance: %+v", r)
	}
	if phaseFinding(r, "phase_admission_complete") {
		t.Fatal("source-save reused delivery admission label")
	}
}

func TestSourceSaveThreeStagesRejectIndependentMutations(t *testing.T) {
	for name, change := range map[string]func(*sourceSaveControl){
		"missing-source-partition": func(s *sourceSaveControl) { v := saveProbeVerification(s); v.Scans = v.Scans[:2]; phaseTestBind(v) },
		"wrong-asymmetric-end": func(s *sourceSaveControl) {
			v := saveProbeVerification(s)
			v.Scans[1].End = 2
			v.Scans[1].Reached = 2
			v.Scans[1].StableEnd = 2
			phaseTestBind(v)
		},
		"future-source-tail":  func(s *sourceSaveControl) { v := saveProbeVerification(s); v.Scans[0].StableEnd = 3; phaseTestBind(v) },
		"ACK-is-not-readback": func(s *sourceSaveControl) { saveProbeVerification(s).Method = "producer_ACK" },
		"foreign-topic-incarnation": func(s *sourceSaveControl) {
			v := saveProbeVerification(s)
			v.Ledger.Partitions = append([]PartitionRange(nil), v.Ledger.Partitions...)
			v.Ledger.Partitions[0].Source.TopicID = strings.Repeat("9", 32)
			phaseTestBind(v)
		},
		"raw-typed-mismatch": func(s *sourceSaveControl) {
			v := saveProbeVerification(s)
			raw, _ := json.Marshal(PhaseSourceScan{Ledger: s.c.warm, Scans: v.Scans})
			v.RawObservationBase64 = base64.StdEncoding.EncodeToString(raw)
			v.RawObservationSHA256 = phaseTestHash(raw)
			v.RawObservationBytes = identity.Int64(len(raw))
		},
		"changed-probe-null-bytes": func(s *sourceSaveControl) {
			v := saveProbeVerification(s)
			v.Ledger.Entries = append([]LedgerEntry(nil), v.Ledger.Entries...)
			v.Ledger.Entries[1].Record.Value = identity.NullableBytes{Base64: ""}
			phaseTestBind(v)
		},
		"foreign-probe-worker": func(s *sourceSaveControl) { saveAudit(s, "probe-visible-unsaved").WorkerID = "replacement" },
		"foreign-group": func(s *sourceSaveControl) {
			saveAudit(s, "probe-visible-unsaved").Observation.Group.GroupID = "foreign"
		},
		"unseen-destination-tail": func(s *sourceSaveControl) { saveAudit(s, "probe-visible-unsaved").Observation.Scans[0].StableEnd++ },
		"missing-observed-STOP":   func(s *sourceSaveControl) { saveWorker(s, "primary", "signal", "SIGSTOP").ObservedState = "S" },
		"backdated-STOP": func(s *sourceSaveControl) {
			w := saveWorker(s, "primary", "signal", "SIGSTOP")
			w.Interval = M2Interval{StartNS: 1, EndNS: 2}
		},
		"backdated-primary-exit": func(s *sourceSaveControl) {
			w := saveWorker(s, "primary", "exit", "")
			w.Interval = M2Interval{StartNS: 1, EndNS: 2}
		},
		"wrong-primary-start": func(s *sourceSaveControl) {
			saveWorker(s, "primary", "signal", "SIGSTOP").Identity.StartTicks = "99999"
		},
		"early-CONT": func(s *sourceSaveControl) {
			saveWorker(s, "primary", "signal", "SIGCONT").Interval = M2Interval{StartNS: 1, EndNS: 2}
		},
		"threshold-profile": func(s *sourceSaveControl) { s.c.m.Profiles[0].ID = "primary-threshold4" },
		"probe-in-delivery": func(s *sourceSaveControl) { s.c.m.ScenarioID = "delivery-stop" },
		"premature-recovery": func(s *sourceSaveControl) {
			saveWorker(s, "recovery", "start", "").Interval = M2Interval{StartNS: 1, EndNS: 2}
		},
		"missing-actual-wait": func(s *sourceSaveControl) { saveWorker(s, "primary", "exit", "").Reaped = false },
		"four-only-final":     func(s *sourceSaveControl) { a := saveAudit(s, "final"); a.PhaseID = "save-probe" },
		"no-STOP-event": func(s *sourceSaveControl) {
			for i, e := range s.c.e {
				if e.Worker != nil && e.Worker.Observation.Signal == "SIGSTOP" {
					s.c.e = append(s.c.e[:i], s.c.e[i+1:]...)
					break
				}
			}
		},
		"source-revalidation-omitted": func(s *sourceSaveControl) {
			for i, e := range s.c.e {
				if e.Verified != nil && e.Verified.PhaseID == "full" && i > 0 && s.c.e[i-1].Broker != nil {
					s.c.e = append(s.c.e[:i], s.c.e[i+1:]...)
					break
				}
			}
		},
		"unfinished-phase-output": func(s *sourceSaveControl) {
			for _, e := range s.c.e {
				if e.Output != nil && e.Output.Observation.AuditID == "probe-visible-unsaved" {
					e.Output.Observation.AuditID = "not-finalized"
					break
				}
			}
		},
		"repeat-probe-publication": func(s *sourceSaveControl) {
			for i, e := range s.c.e {
				if e.Publication != nil && e.Publication.PhaseID == "save-probe" {
					s.c.e = append(s.c.e[:i+1], append([]PhaseEvent{e}, s.c.e[i+1:]...)...)
					break
				}
			}
		},
		"omitted-probe-publication": func(s *sourceSaveControl) {
			for i, e := range s.c.e {
				if e.Publication != nil && e.Publication.PhaseID == "save-probe" {
					s.c.e = append(s.c.e[:i], s.c.e[i+1:]...)
					break
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := completeSourceSaveControl()
			change(s)
			for i := range s.c.e {
				s.c.e[i].Seq = identity.Int64(i + 1)
			}
			r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
			if r.Verdict == Pass || phaseFinding(r, "source_save_admission_complete") {
				t.Fatalf("counterfeit stage retained admission: %+v", r)
			}
		})
	}
}

func TestSourceSaveUnsavedWindowCannotBeClaimedAfterSave(t *testing.T) {
	s := completeSourceSaveControl()
	saveAudit(s, "probe-visible-unsaved").Observation.Saved[0].Source.Offset = 2
	r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
	if r.Verdict != Unsupported || !phaseFinding(r, "phase_save_probe_unreached") || phaseFinding(r, "source_save_admission_complete") {
		t.Fatalf("already saved probe was declared reached: %+v", r)
	}
}

func TestSourceSaveMissingLiveProbeDoesNotBecomeSettledViolation(t *testing.T) {
	s := completeSourceSaveControl()
	for _, e := range s.c.e {
		if e.Output != nil && e.Output.Observation.AuditID == "probe-visible-unsaved" && e.Output.Observation.Destination.Partition == 0 && e.Output.Observation.Destination.Offset == 1 {
			e.Output.Observation.Record = s.c.full.Entries[0].Record
		}
	}
	r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
	if r.Verdict != Unsupported || !phaseFinding(r, "phase_save_probe_unreached") || phaseFinding(r, "unsafe_saved_prefix") || phaseFinding(r, "source_save_admission_complete") {
		t.Fatalf("live sampled replay acquired quiescence/admission: %+v", r)
	}
}

func TestSourceSaveFinalRequiredLossOverridesMechanismGap(t *testing.T) {
	s := completeSourceSaveControl()
	for _, e := range s.c.e {
		if e.Output != nil && e.Output.Observation.AuditID == "final" && e.Output.Observation.Destination.Partition == 2 && e.Output.Observation.Destination.Offset == 31 {
			e.Output.Observation.Record = s.c.full.Entries[94].Record
		}
	}
	r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
	if r.Verdict != Violation || !phaseFinding(r, "required_record_missing") || !phaseFinding(r, "unsafe_saved_prefix") || phaseFinding(r, "source_save_admission_complete") {
		t.Fatalf("final replay concealed missing required input: %+v", r)
	}
}

func TestSourceSaveSettledUnsafePrefixOverridesMechanismGap(t *testing.T) {
	s := completeSourceSaveControl()
	saveAudit(s, "primary-safety").Observation.Saved[0].Source.Offset = 3
	r := CheckPhaseHistory(s.c.m, s.c.a, s.c.e)
	if r.Verdict != Violation || !phaseFinding(r, "unsafe_saved_prefix") || r.ReleaseQualified || phaseFinding(r, "source_save_admission_complete") {
		t.Fatalf("real unsafe prefix hidden by mechanism gap: %+v", r)
	}
}

func TestSourceSaveWriterRechecksDeterministicallyAndDetectsChangedStage(t *testing.T) {
	s := completeSourceSaveControl()
	dir := filepath.Join(t.TempDir(), "source-save")
	if reserved, e := WritePhaseBundle(dir, s.c.m, s.c.a, s.c.e); e != nil || !reserved {
		t.Fatalf("write: %t %v", reserved, e)
	}
	first, second := LoadAndCheck(dir), LoadAndCheck(dir)
	if first.Verdict != Unsupported || !phaseFinding(first, "source_save_admission_complete") || !reflect.DeepEqual(first, second) {
		t.Fatalf("offline data acquired different meaning: %+v %+v", first, second)
	}
	p := filepath.Join(dir, EventsName)
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	raw = []byte(strings.Replace(string(raw), "save-probe", "full", 1))
	if e = os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	r := LoadAndCheck(dir)
	if r.Verdict != HarnessError || !phaseFinding(r, "events_integrity") || phaseFinding(r, "source_save_admission_complete") {
		t.Fatalf("changed stage inherited completion: %+v", r)
	}
}
