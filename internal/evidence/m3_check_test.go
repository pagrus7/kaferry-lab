package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

// Literal synthetic histories calibrate evidence-version3 for M2, not milestone
// M3 or the released application. No production admission helper builds inputs
// or expected verdicts, routes, readback ends or record bytes.
type phaseControl struct {
	m       PhaseManifest
	a       ArtifactMetadata
	e       []PhaseEvent
	full    Ledger
	warm    Ledger
	n       identity.Int64
	workers map[string]M2WorkerIdentity
}

func phaseTestHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newPhaseControl() *phaseControl {
	c := &phaseControl{workers: map[string]M2WorkerIdentity{}}
	subject := Subject{Kind: "synthetic-history", ExecutableSHA256: strings.Repeat("c", 64), ContractSHA256: ContractSHA256, Platform: "linux/amd64", VersionOutput: "CALIBRATION ONLY two-phase history"}
	c.m = PhaseManifest{SchemaVersion: 3, CheckerVersion: "evidence-v3", Namespace: "calibration", RunID: "phase-literal-control", ScenarioID: "delivery-threshold", Scope: "kafka", Group: "explicit-group", Given: "exactly three independently copied/saved warmup records", When: "owned stopped primary brackets additive publication and independent full readback", Then: "full96 membership and safe saved progress; mechanism remains unsupported", BudgetNS: 300_000_000_000, Subject: subject, LabSource: LabSource{Commit: strings.Repeat("1", 40), Proof: "literal calibration source"}, Environment: Environment{OrchestratorPlatform: "linux/amd64", ExecutionPlatform: "linux/amd64", Runtime: "literal OS observations", Storage: "retained synthetic broker history", Topology: "two owned independent clusters", Limits: "finite96 known records"}, SourceEndpoint: "127.0.0.1:19092", DestinationEndpoint: "127.0.0.1:29092", FinalAuditID: "final"}
	c.a = ArtifactMetadata{SchemaVersion: 1, Subject: subject, VerificationDetail: "synthetic attachment, not downloaded release", CalibrationLabel: "M2 phase checker controls"}
	c.full = Ledger{Partitions: []PartitionRange{}, Destinations: []identity.SourcePosition{}, Entries: []LedgerEntry{}}
	c.warm = Ledger{Partitions: []PartitionRange{}, Destinations: []identity.SourcePosition{}, Entries: []LedgerEntry{}}
	for p := 0; p < 3; p++ {
		source := identity.SourcePosition{Cluster: "source-cluster", Topic: "input", TopicID: strings.Repeat("1", 32), Partition: int32(p), Offset: 0}
		dest := identity.SourcePosition{Cluster: "destination-cluster", Topic: "output", TopicID: strings.Repeat("2", 32), Partition: int32(p), Offset: 0}
		c.full.Partitions = append(c.full.Partitions, PartitionRange{Source: source, End: 32, Gaps: []Gap{}})
		c.warm.Partitions = append(c.warm.Partitions, PartitionRange{Source: source, End: 1, Gaps: []Gap{}})
		c.full.Destinations = append(c.full.Destinations, dest)
		c.warm.Destinations = append(c.warm.Destinations, dest)
		for offset := 0; offset < 32; offset++ {
			position := source
			position.Offset = identity.Int64(offset)
			record := identity.Record{Key: identity.NullableBytes{Null: true}, Value: identity.NullableBytes{Base64: base64.StdEncoding.EncodeToString([]byte{byte(0xa0 + p), byte(offset), 0xff, 0})}, Headers: []identity.Header{}, TimestampKind: "unknown"}
			entry := LedgerEntry{ID: fmt.Sprintf("p%d-%02d", p, offset), Source: position, Record: record, Disposition: "required", Reason: "literal finite nontransactional record", DestinationTopic: "output", AllowedPartitions: []int32{int32(p)}}
			c.full.Entries = append(c.full.Entries, entry)
			if offset == 0 {
				c.warm.Entries = append(c.warm.Entries, entry)
			}
		}
	}
	unlimitedSQL := "WITH CONNECTION source AS ('bootstrap.servers'='127.0.0.1:19092','session.timeout.ms'='6000','heartbeat.interval.ms'='1000','socket.timeout.ms'='500'), CONNECTION destination AS ('bootstrap.servers'='127.0.0.1:29092','client.id'='lab-m2','linger.ms'='1500','request.timeout.ms'='1000','socket.timeout.ms'='500') INSERT INTO TOPIC 'output@destination' WITH (PARTITIONING = PRESERVE) SELECT * FROM TOPIC 'input@source' WITH (GROUP='explicit-group') WHERE PARTITION IN (0,1,2);\n"
	config := "[worker]\nrecord_cap=1024\npartition_record_cap=1024\nbyte_cap=16777216\npartition_byte_cap=8388608\ndelivery_timeout='4s'\nshutdown_timeout='10s'\nidle_exit='8s'\ntip_wait='8s'\nprogress_interval='1s'\n"
	for i, id := range []string{"primary-threshold4", "recovery-unlimited"} {
		sql, threshold := unlimitedSQL, identity.Int64(0)
		if i == 0 {
			sql, threshold = strings.TrimSuffix(unlimitedSQL, ";\n")+" OPTIONS (WORKER_STOP_AFTER_RECORDS=4);\n", 4
		}
		s := M2Settings{Routing: "PRESERVE", Args: []string{"run", "--file", "/synthetic/" + id + ".sql", "--config", "/synthetic/worker.toml"}, Environment: []string{}, SQL: sql, ConfigTOML: config, SQLSHA256: phaseTestHash([]byte(sql)), ConfigSHA256: phaseTestHash([]byte(config)), WorkBudgetNS: 200_000_000_000, CleanupBudgetNS: 100_000_000_000, DeliveryTimeoutNS: 4_000_000_000, ShutdownTimeoutNS: 10_000_000_000, RecordThreshold: threshold}
		c.m.Profiles = append(c.m.Profiles, PhaseSettings{ID: id, Settings: s})
	}
	c.add(PhaseEvent{Kind: "input_declared", Declaration: &c.full})
	return c
}

func (c *phaseControl) interval() M2Interval {
	c.n += 1_000_000
	start := c.n
	c.n += 1_000_000
	return M2Interval{StartNS: start, EndNS: c.n}
}
func (c *phaseControl) add(e PhaseEvent) {
	e.Seq, e.RunID, e.ElapsedNS = identity.Int64(len(c.e)+1), c.m.RunID, c.n
	c.e = append(c.e, e)
}
func (c *phaseControl) publish(phase, worker string) {
	ledger := c.warm
	if phase == "full" {
		ledger = c.full
	}
	raw, _ := json.Marshal(ledger)
	c.add(PhaseEvent{Kind: "input_published", Publication: &PhasePublication{PhaseID: phase, WorkerID: worker, Interval: c.interval(), LedgerSHA256: phaseTestHash(raw)}})
}
func phaseTestBind(v *PhaseVerification) {
	raw, _ := json.Marshal(PhaseSourceScan{Ledger: v.Ledger, Scans: v.Scans})
	v.RawObservationBase64, v.RawObservationBytes, v.RawObservationSHA256 = base64.StdEncoding.EncodeToString(raw), identity.Int64(len(raw)), phaseTestHash(raw)
}
func (c *phaseControl) verify(phase string) {
	ledger := c.warm
	if phase == "full" {
		ledger = c.full
	}
	v := &PhaseVerification{PhaseID: phase, Interval: c.interval(), Ledger: ledger, Scans: []Scan{}, Method: "independent_source_scan", Complete: true}
	for _, partition := range ledger.Partitions {
		v.Scans = append(v.Scans, Scan{PartitionRange: partition, Reached: partition.End, StableEnd: partition.End, Complete: true, Proof: "literal complete fixed-end source readback"})
	}
	phaseTestBind(v)
	c.add(PhaseEvent{Kind: "input_phase_verified", Verified: v})
}
func (c *phaseControl) broker(role, action string) {
	endpoint, cluster, character := "127.0.0.1:19092", "source-cluster", "3"
	if role == "destination" {
		endpoint, cluster, character = "127.0.0.1:29092", "destination-cluster", "4"
	}
	i := c.interval()
	b := &M2Broker{Identity: M2BrokerIdentity{RunID: c.m.RunID, Role: role, ContainerID: strings.Repeat(character, 64), Name: "lab-owned-" + role, ImageID: "sha256:" + strings.Repeat("5", 64), ImageReference: "fixture@sha256:" + strings.Repeat("6", 64), Endpoint: endpoint, ClusterID: cluster}, Action: action, Interval: i, State: M2BrokerState{RunningPresent: true, PausedPresent: true, Running: true, LoopbackBound: true}, Probe: &M2Probe{Interval: M2Interval{StartNS: i.EndNS, EndNS: i.EndNS}, Endpoint: endpoint, Available: true, APIKeys: 1}}
	if action != "inspect" {
		b.Request = M2Interval{StartNS: i.StartNS, EndNS: i.StartNS}
	}
	if action == "pause" {
		b.State.Paused = true
		b.Probe.Available, b.Probe.Unavailable, b.Probe.APIKeys, b.Probe.Failure = false, true, 0, "timeout"
	}
	c.add(PhaseEvent{Kind: "broker", Broker: b})
}
func (c *phaseControl) worker(id, profile, action, signal string) {
	settings := c.m.Profiles[0].Settings
	if profile == "recovery-unlimited" {
		settings = c.m.Profiles[1].Settings
	}
	w, found := c.workers[id]
	if !found {
		args, _ := json.Marshal(settings.Args)
		env, _ := json.Marshal(settings.Environment)
		w = M2WorkerIdentity{WorkerID: id, PID: 500 + len(c.workers), StartTicks: "12345", ExecutableSHA256: c.m.Subject.ExecutableSHA256, ArgsSHA256: phaseTestHash(args), EnvironmentSHA256: phaseTestHash(env)}
		c.workers[id] = w
	}
	o := M2Worker{Identity: w, Action: action, Signal: signal, Interval: c.interval()}
	if signal == "SIGSTOP" {
		o.ObservedState = "T"
	}
	if action == "exit" || action == "cleanup" {
		o.Reaped = true
	}
	c.add(PhaseEvent{Kind: "worker", Worker: &PhaseWorker{SettingsID: profile, Observation: o}})
}
func (c *phaseControl) audit(id, phase string, records, saved int, settled, final bool) {
	c.n += 1_000_000
	scan := M2Interval{StartNS: c.n}
	for p := 0; p < 3; p++ {
		for offset := 0; offset < records; offset++ {
			c.n += 1_000_000
			entry := c.full.Entries[p*32+offset]
			destination := c.full.Destinations[p]
			destination.Offset = identity.Int64(offset)
			c.add(PhaseEvent{Kind: "output", Output: &PhaseOutput{PhaseID: phase, Observation: Output{AuditID: id, Destination: destination, Record: entry.Record}}})
		}
	}
	c.n += 1_000_000
	scan.EndNS = c.n
	a := M2Audit{ID: id, Mode: "snapshot", ScanInterval: scan, SavedInterval: c.interval(), GroupInterval: c.interval(), Scans: []Scan{}, Saved: []M2SavedPosition{}, Final: final, Group: M2Group{GroupID: c.m.Group, State: "Stable", ProtocolType: "consumer", Protocol: "cooperative-sticky", Members: []M2GroupMember{{ID: "literal-member", AssignmentBase64: "AAAAAAABAAVpbnB1dAAAAAMAAAAAAAAAAQAAAAL/////"}}}}
	if settled {
		a.Mode, a.Group = "settled", M2Group{GroupID: c.m.Group, State: "Empty", Members: []M2GroupMember{}}
	}
	for p := 0; p < 3; p++ {
		a.Scans = append(a.Scans, Scan{PartitionRange: PartitionRange{Source: c.full.Destinations[p], End: identity.Int64(records), Gaps: []Gap{}}, Reached: identity.Int64(records), StableEnd: identity.Int64(records), Complete: true, Proof: "literal complete destination scan"})
		position := c.full.Partitions[p].Source
		position.Offset = identity.Int64(saved)
		a.Saved = append(a.Saved, M2SavedPosition{Source: position, Present: true, Group: c.m.Group})
	}
	worker := ""
	if phase == "warmup" {
		worker = "primary"
	}
	c.add(PhaseEvent{Kind: "audit", Audit: &PhaseAudit{PhaseID: phase, WorkerID: worker, Observation: a}})
}
func preparedPhaseControl() *phaseControl {
	c := newPhaseControl()
	c.publish("warmup", "")
	c.verify("warmup")
	c.broker("source", "inspect")
	c.broker("destination", "inspect")
	return c
}
func phasePrimarySafetyControl(c *phaseControl) {
	c.worker("primary", "primary-threshold4", "signal", "SIGSTOP")
	c.publish("full", "primary")
	c.verify("full")
	c.worker("primary", "primary-threshold4", "signal", "SIGCONT")
	c.worker("primary", "primary-threshold4", "exit", "")
	c.worker("primary", "primary-threshold4", "cleanup", "")
	c.broker("destination", "restart")
	c.verify("full")
	c.audit("stopped-safety", "full", 1, 1, true, false)
}
func phaseRecoveryControl(c *phaseControl) {
	c.worker("recovery", "recovery-unlimited", "start", "")
	c.worker("recovery", "recovery-unlimited", "exit", "")
	c.worker("recovery", "recovery-unlimited", "cleanup", "")
	c.broker("destination", "restart")
	c.verify("full")
	c.audit("final", "full", 32, 32, true, true)
	c.n += 1_000_000
	c.add(PhaseEvent{Kind: "run_finished", Finished: &RunFinished{CleanupComplete: true, Proof: "literal synthetic restoration/wait/cleanup observations complete"}})
}
func completePhaseControl() *phaseControl {
	c := preparedPhaseControl()
	c.worker("primary", "primary-threshold4", "start", "")
	c.audit("warmup-progress", "warmup", 1, 1, false, false)
	phasePrimarySafetyControl(c)
	phaseRecoveryControl(c)
	return c
}
func phaseFinding(r Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
func firstPhaseVerification(c *phaseControl, phase string) *PhaseVerification {
	for _, e := range c.e {
		if e.Verified != nil && e.Verified.PhaseID == phase {
			return e.Verified
		}
	}
	panic("literal control phase missing")
}

func TestVersion3PhaseAdmissionDoesNotClaimMechanism(t *testing.T) {
	// Given declared96, observed warmup3, STOP-bracketed additive publication,
	// full readback and settled recovery, when checked, then admission succeeds
	// but neither threshold count nor this history can create mechanism PASS.
	for _, scenario := range []string{"delivery-stop", "delivery-threshold"} {
		c := completePhaseControl()
		c.m.ScenarioID = scenario
		if c.m.Profiles[0].Settings.Args[2] == c.m.Profiles[1].Settings.Args[2] || c.m.Profiles[0].Settings.Args[4] != c.m.Profiles[1].Settings.Args[4] {
			t.Fatal("literal profiles lost their sole permitted SQL path difference")
		}
		r := CheckPhaseHistory(c.m, c.a, c.e)
		if r.Verdict != Unsupported || !phaseFinding(r, "phase_admission_complete") || !phaseFinding(r, "mechanism_unobserved") || r.ReleaseQualified || len(r.Findings) != 2 {
			t.Fatalf("valid two-phase data admission changed: %+v", r)
		}
	}
}

func TestVersion3PhaseAdmissionRejectsIndependentMutations(t *testing.T) {
	for _, control := range []struct {
		name string
		code string
		edit func(*phaseControl)
	}{
		{"omitted-source-partition-scan", "phase_scan", func(c *phaseControl) { v := firstPhaseVerification(c, "full"); v.Scans = v.Scans[:2]; phaseTestBind(v) }},
		{"source-scan-extra-unpublished-tail", "phase_scan", func(c *phaseControl) {
			v := firstPhaseVerification(c, "warmup")
			v.Scans[0].StableEnd = 32
			phaseTestBind(v)
		}},
		{"replaced-original-prefix", "phase_scan", func(c *phaseControl) {
			v := firstPhaseVerification(c, "full")
			v.Ledger.Entries = append([]LedgerEntry(nil), v.Ledger.Entries...)
			v.Ledger.Entries[0].Record.Value.Base64 = "Y2hhbmdlZA=="
			phaseTestBind(v)
		}},
		{"nonadditive-full-ledger", "phase_scan", func(c *phaseControl) {
			v := firstPhaseVerification(c, "full")
			v.Ledger.Entries = v.Ledger.Entries[1:]
			phaseTestBind(v)
		}},
		{"changed-published-route", "phase_scan", func(c *phaseControl) {
			v := firstPhaseVerification(c, "full")
			v.Ledger.Entries = append([]LedgerEntry(nil), v.Ledger.Entries...)
			v.Ledger.Entries[0].AllowedPartitions = []int32{1}
			phaseTestBind(v)
		}},
		{"wrong-source-topic-incarnation", "phase_scan", func(c *phaseControl) {
			v := firstPhaseVerification(c, "full")
			v.Ledger.Partitions = append([]PartitionRange(nil), v.Ledger.Partitions...)
			v.Ledger.Partitions[0].Source.TopicID = strings.Repeat("9", 32)
			phaseTestBind(v)
		}},
		{"missing-independent-readback", "phase_scan", func(c *phaseControl) { firstPhaseVerification(c, "full").Complete = false }},
		{"publication-is-not-readback", "phase_scan", func(c *phaseControl) { firstPhaseVerification(c, "full").Method = "producer_success" }},
		{"raw-readback-binding-corrupt", "phase_scan", func(c *phaseControl) { firstPhaseVerification(c, "full").RawObservationBase64 = "e30=" }},
		{"stale-publication-before-stop", "phase_stop", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Publication != nil && e.Publication.PhaseID == "full" {
					e.Publication.Interval = M2Interval{StartNS: 1, EndNS: 2}
				}
			}
		}},
		{"wrong-stopped-worker-handle", "phase_stop", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Publication != nil && e.Publication.PhaseID == "full" {
					e.Publication.WorkerID = "not-the-owned-primary"
				}
			}
		}},
		{"not-actually-stopped", "phase_stop", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.Observation.Signal == "SIGSTOP" {
					e.Worker.Observation.ObservedState = "S"
				}
			}
		}},
		{"early-CONT-before-readback", "phase_early_cont", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.Observation.Signal == "SIGCONT" {
					e.Worker.Observation.Interval.StartNS = firstPhaseVerification(c, "full").Interval.StartNS
				}
			}
		}},
		{"full-audit-bound-to-old-warmup", "phase_audit", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Audit != nil && e.Audit.Observation.ID == "stopped-safety" {
					e.Audit.PhaseID = "warmup"
				}
			}
		}},
		{"threshold-record-cap-substitution", "phase_profiles", func(c *phaseControl) { c.m.Profiles[0].Settings.RecordThreshold = 1024 }},
		{"missing-threshold-SQL", "phase_profiles", func(c *phaseControl) {
			s := &c.m.Profiles[0].Settings
			s.SQL = c.m.Profiles[1].Settings.SQL
			s.SQLSHA256 = phaseTestHash([]byte(s.SQL))
		}},
		{"changed-recovery-routing", "phase_profiles", func(c *phaseControl) { c.m.Profiles[1].Settings.Routing = "KEY" }},
		{"changed-config-path-with-rebound-worker-hashes", "phase_profiles", func(c *phaseControl) {
			s := &c.m.Profiles[1].Settings
			s.Args = append([]string(nil), s.Args...)
			s.Args[4] = "/synthetic/other-worker.toml"
			args, _ := json.Marshal(s.Args)
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.SettingsID == "recovery-unlimited" {
					e.Worker.Observation.Identity.ArgsSHA256 = phaseTestHash(args)
				}
			}
		}},
		{"unknown-settings-ID", "phase_worker", func(c *phaseControl) { c.e[5].Worker.SettingsID = "arbitrary-profile" }},
		{"warmup-only-final-completion", "phase_final", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Audit != nil && e.Audit.Observation.ID == "warmup-progress" {
					e.Audit.Observation.Final = true
				}
			}
		}},
	} {
		t.Run(control.name, func(t *testing.T) {
			// Given a literal admitted history, when one independent admission
			// fact is falsified, then it must fail at that boundary, not merely
			// inherit the valid history's generic unsupported-mechanism result.
			c := completePhaseControl()
			control.edit(c)
			r := CheckPhaseHistory(c.m, c.a, c.e)
			if r.Verdict != HarnessError || !phaseFinding(r, control.code) || phaseFinding(r, "phase_admission_complete") || r.ReleaseQualified {
				t.Fatalf("mutation escaped its admission boundary: %+v", r)
			}
		})
	}
}

func TestVersion3SavedBeyondPublishedWarmupIsViolation(t *testing.T) {
	// Given future93 declared but not yet published, when warmup OffsetFetch
	// already saves next2, then later recovery cannot erase that violation.
	c := completePhaseControl()
	for _, e := range c.e {
		if e.Audit != nil && e.Audit.Observation.ID == "warmup-progress" {
			e.Audit.Observation.Saved[0].Source.Offset = 2
		}
	}
	r := CheckPhaseHistory(c.m, c.a, c.e)
	if r.Verdict != Violation || !phaseFinding(r, "saved_beyond_published") || r.ReleaseQualified {
		t.Fatalf("unpublished saved progress not detected: %+v", r)
	}
}

func TestVersion3FinalMissingRecordIsViolationDespiteMechanismGap(t *testing.T) {
	c := completePhaseControl()
	// Given a complete final scan, replace one unique final value with an
	// allowed replay. Physical count stays96; one required value is absent.
	for _, e := range c.e {
		if e.Output != nil && e.Output.Observation.AuditID == "final" && e.Output.Observation.Destination.Partition == 2 && e.Output.Observation.Destination.Offset == 31 {
			e.Output.Observation.Record = c.full.Entries[94].Record
		}
	}
	r := CheckPhaseHistory(c.m, c.a, c.e)
	if r.Verdict != Violation || !phaseFinding(r, "required_record_missing") || !phaseFinding(r, "unsafe_saved_prefix") {
		t.Fatalf("aggregate96 concealed required membership loss: %+v", r)
	}
}

func TestVersion3FixedBundleDispatchPreservesVersion2(t *testing.T) {
	// Given independent four-file version3 evidence, when loaded without a
	// subject/runtime, then the actual public loader reaches phase admission.
	c := completePhaseControl()
	var stream bytes.Buffer
	for _, e := range c.e {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	artifact, _ := json.Marshal(c.a)
	c.m.Artifact = FileHash{Path: "artifact.json", SHA256: phaseTestHash(artifact), Bytes: identity.Int64(len(artifact))}
	c.m.Events = FileHash{Path: "events.jsonl", SHA256: phaseTestHash(stream.Bytes()), Bytes: identity.Int64(stream.Len())}
	c.m.EventCount = identity.Int64(len(c.e))
	manifest, _ := json.Marshal(c.m)
	completion, _ := json.Marshal(M2Completion{SchemaVersion: 3, RunID: c.m.RunID, ManifestSHA256: phaseTestHash(manifest), EventsSHA256: phaseTestHash(stream.Bytes()), EventCount: c.m.EventCount})
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"manifest.json": manifest, "artifact.json": artifact, "events.jsonl": stream.Bytes(), "complete.json": completion} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := LoadAndCheck(dir)
	if r.Verdict != Unsupported || !phaseFinding(r, "phase_admission_complete") {
		t.Fatalf("version3 dispatch failed: %+v", r)
	}
	// Historical v2 still verifies the entire prepared ledger before work.
	v2 := healthyM2Control()
	if r := CheckM2(v2.m, v2.a, v2.e); r.Verdict != Pass {
		t.Fatalf("version2 meaning changed: %+v", r)
	}
}

func TestVersion3WarmupProgressRequiresThisLaunchedLivePrimary(t *testing.T) {
	for _, name := range []string{"prelaunch-progress", "backdated-progress-scan", "wrong-primary-witness", "post-exit-progress"} {
		t.Run(name, func(t *testing.T) {
			// Given the same literal warmup data and group, when its progress
			// belongs before launch, spans launch, names another invocation or
			// follows the owned wait, then it cannot authorize this primary's STOP.
			var c *phaseControl
			if name == "prelaunch-progress" {
				c = preparedPhaseControl()
				c.audit("warmup-progress", "warmup", 1, 1, false, false)
				c.worker("primary", "primary-threshold4", "start", "")
				phasePrimarySafetyControl(c)
				phaseRecoveryControl(c)
			} else if name == "post-exit-progress" {
				c = preparedPhaseControl()
				c.worker("primary", "primary-threshold4", "start", "")
				c.worker("primary", "primary-threshold4", "exit", "")
				c.worker("primary", "primary-threshold4", "cleanup", "")
				c.audit("warmup-progress", "warmup", 1, 1, false, false)
			} else {
				c = completePhaseControl()
				for _, e := range c.e {
					if e.Audit != nil && e.Audit.Observation.ID == "warmup-progress" {
						if name == "wrong-primary-witness" {
							e.Audit.WorkerID = "foreign-primary"
						} else {
							// Outputs and all sequence/completion times remain valid;
							// only the scan request straddles completed launch.
							e.Audit.Observation.ScanInterval.StartNS = c.e[5].Worker.Observation.Interval.StartNS
						}
					}
				}
			}
			r := CheckPhaseHistory(c.m, c.a, c.e)
			if r.Verdict != HarnessError || !phaseFinding(r, "phase_warmup_progress") || phaseFinding(r, "phase_admission_complete") {
				t.Fatalf("foreign/stale warmup authorized the primary transition: %+v", r)
			}
		})
	}
}

func TestVersion3RecoveryNeedsCompletedRestorationAndFreshSettledSafety(t *testing.T) {
	for _, name := range []string{"restore-overlaps-launch", "restoration-after-old-settled-audit", "settled-scan-overlaps-restore", "restored-then-fresh-safety"} {
		t.Run(name, func(t *testing.T) {
			// Given a valid primary safety audit, when another owned pause and
			// restore occur, then a future healthy completion cannot backdate
			// availability and the old audit cannot stand in for post-restore safety.
			c := preparedPhaseControl()
			c.worker("primary", "primary-threshold4", "start", "")
			c.audit("warmup-progress", "warmup", 1, 1, false, false)
			phasePrimarySafetyControl(c)
			c.broker("destination", "pause")
			c.broker("destination", "restore")
			restore := c.e[len(c.e)-1].Broker.Interval
			if name == "restored-then-fresh-safety" || name == "settled-scan-overlaps-restore" {
				c.verify("full")
				c.audit("restored-safety", "full", 1, 1, true, false)
				if name == "settled-scan-overlaps-restore" {
					// Backdate source verification and the scan start together;
					// output/saved/group completions and identities remain valid.
					for _, e := range c.e {
						if e.Verified != nil && e.Verified.PhaseID == "full" && e.Verified.Interval.StartNS > restore.EndNS {
							e.Verified.Interval.StartNS = restore.StartNS
							e.Verified.Interval.EndNS = restore.StartNS
						}
						if e.Audit != nil && e.Audit.Observation.ID == "restored-safety" {
							e.Audit.Observation.ScanInterval.StartNS = restore.StartNS
						}
					}
				}
			}
			phaseRecoveryControl(c)
			if name == "restore-overlaps-launch" {
				for _, e := range c.e {
					if e.Worker != nil && e.Worker.SettingsID == "recovery-unlimited" && e.Worker.Observation.Action == "start" {
						e.Worker.Observation.Interval.StartNS = restore.StartNS
					}
				}
			}
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.SettingsID == "recovery-unlimited" && e.Worker.Observation.Action == "start" {
					launch := e.Worker.Observation.Interval
					if name == "restore-overlaps-launch" && !(restore.StartNS <= launch.StartNS && launch.StartNS < restore.EndNS && launch.EndNS > restore.EndNS && e.ElapsedNS >= restore.EndNS) {
						t.Fatal("literal overlap no longer isolates a launch beginning before completed restoration")
					}
					if name != "restore-overlaps-launch" && launch.StartNS < restore.EndNS {
						t.Fatal("literal nonoverlap control lost completed restoration before launch")
					}
				}
			}
			r := CheckPhaseHistory(c.m, c.a, c.e)
			if name == "restored-then-fresh-safety" {
				if r.Verdict != Unsupported || !phaseFinding(r, "phase_admission_complete") || !phaseFinding(r, "mechanism_unobserved") || len(r.Findings) != 2 {
					t.Fatalf("fresh post-restoration safety was not admitted: %+v", r)
				}
				return
			}
			code := "phase_recovery"
			if name == "restore-overlaps-launch" {
				code = "phase_worker_order"
			} else if name == "settled-scan-overlaps-restore" {
				code = "phase_scan" // its source interval now fails before the overlapping settled scan
			}
			if r.Verdict != HarnessError || !phaseFinding(r, code) || phaseFinding(r, "phase_admission_complete") {
				t.Fatalf("late health/stale settlement authorized recovery: %+v", r)
			}
		})
	}
}

func TestVersion3SourceReadbackStartCannotOverlapRestoration(t *testing.T) {
	// Given the valid restored-then-fresh-safety history, when ONLY its first
	// post-restore full-source readback START moves inside restore, then the
	// unchanged later end/readback bytes/audits/launch/completion cannot make
	// the complete readback interval fresh.
	c := preparedPhaseControl()
	c.worker("primary", "primary-threshold4", "start", "")
	c.audit("warmup-progress", "warmup", 1, 1, false, false)
	phasePrimarySafetyControl(c)
	c.broker("destination", "pause")
	c.broker("destination", "restore")
	restore := c.e[len(c.e)-1].Broker.Interval
	c.verify("full")
	readback := c.e[len(c.e)-1].Verified
	c.audit("restored-safety", "full", 1, 1, true, false)
	phaseRecoveryControl(c)
	positive := CheckPhaseHistory(c.m, c.a, c.e)
	if positive.Verdict != Unsupported || !phaseFinding(positive, "phase_admission_complete") || !phaseFinding(positive, "mechanism_unobserved") || len(positive.Findings) != 2 || positive.ReleaseQualified {
		t.Fatalf("unchanged fresh history did not establish the positive admission control: %+v", positive)
	}
	before, err := json.Marshal(c.e)
	if err != nil {
		t.Fatal(err)
	}
	originalStart := readback.Interval.StartNS
	if originalStart < restore.EndNS || readback.Interval.EndNS <= restore.EndNS {
		t.Fatal("literal positive history lost fresh post-restoration readback")
	}
	readback.Interval.StartNS = restore.StartNS
	mutated, err := json.Marshal(c.e)
	if err != nil {
		t.Fatal(err)
	}
	// Restore precisely that one scalar to independently verify the entire
	// recorded history (including raw bytes/hash/end and later facts) is equal.
	readback.Interval.StartNS = originalStart
	normalized, err := json.Marshal(c.e)
	if err != nil || !bytes.Equal(before, normalized) || bytes.Equal(before, mutated) {
		t.Fatal("start-only control changed other history facts or changed nothing")
	}
	readback.Interval.StartNS = restore.StartNS
	r := CheckPhaseHistory(c.m, c.a, c.e)
	if r.Verdict != HarnessError || !phaseFinding(r, "phase_scan") || phaseFinding(r, "phase_admission_complete") || r.ReleaseQualified {
		t.Fatalf("overlapping source readback start was treated as fresh: %+v", r)
	}
}

func phaseTestMutationWindow(b *M2Broker, start, end identity.Int64) {
	// Preserve exact owned identity/state/probe result; change only the
	// retained controller action/probe window, not its later event envelope.
	b.Interval = M2Interval{StartNS: start, EndNS: end}
	b.Request = M2Interval{StartNS: start, EndNS: start}
	b.Probe.Interval = M2Interval{StartNS: end, EndNS: end}
}

func TestVersion3SerialMutationReceiptsCannotBackdateWitnesses(t *testing.T) {
	for _, stage := range []string{"after-readback", "after-recovery-launch", "after-settled-safety", "future-fault-after-readback"} {
		t.Run(stage, func(t *testing.T) {
			// Given an already recorded witness, when valid owned broker
			// mutation receipts are appended later with overlapping older
			// intervals and monotonic envelopes, then serial admission rejects
			// them. A genuine later fault remains a valid data-only history.
			c := preparedPhaseControl()
			c.worker("primary", "primary-threshold4", "start", "")
			c.audit("warmup-progress", "warmup", 1, 1, false, false)
			var witness M2Interval
			if stage == "after-readback" || stage == "future-fault-after-readback" {
				c.worker("primary", "primary-threshold4", "signal", "SIGSTOP")
				c.publish("full", "primary")
				c.verify("full")
				witness = c.e[len(c.e)-1].Verified.Interval
			} else {
				phasePrimarySafetyControl(c)
				for _, e := range c.e {
					if e.Verified != nil && e.Verified.PhaseID == "full" {
						witness = e.Verified.Interval
					}
				}
				if stage == "after-recovery-launch" {
					c.worker("recovery", "recovery-unlimited", "start", "")
					witness = c.e[len(c.e)-1].Worker.Observation.Interval
				}
			}
			previousEnvelope := c.e[len(c.e)-1].ElapsedNS
			c.broker("destination", "pause")
			pauseIndex := len(c.e) - 1
			pause := c.e[pauseIndex].Broker
			c.broker("destination", "restore")
			restoreIndex := len(c.e) - 1
			restore := c.e[restoreIndex].Broker
			if stage == "after-recovery-launch" {
				phaseTestMutationWindow(pause, witness.StartNS-2, witness.StartNS-1)
				phaseTestMutationWindow(restore, witness.StartNS-1, witness.StartNS+1)
			} else if stage != "future-fault-after-readback" {
				phaseTestMutationWindow(pause, witness.StartNS+1, witness.StartNS+2)
				phaseTestMutationWindow(restore, witness.StartNS+2, witness.StartNS+3)
			}
			if c.e[pauseIndex].ElapsedNS < previousEnvelope || c.e[restoreIndex].ElapsedNS < c.e[pauseIndex].ElapsedNS || restore.Interval.EndNS > c.e[restoreIndex].ElapsedNS || (pause.Interval.EndNS != restore.Interval.StartNS && stage != "future-fault-after-readback") {
				t.Fatal("literal late receipts lost valid monotonic envelopes/action order")
			}
			if stage == "after-readback" || stage == "after-settled-safety" {
				if !(witness.StartNS < pause.Interval.StartNS && pause.Interval.StartNS < pause.Interval.EndNS && pause.Interval.EndNS < restore.Interval.EndNS && restore.Interval.EndNS < witness.EndNS) {
					t.Fatal("literal pause/restore no longer lies strictly inside the earlier complete readback")
				}
			}
			if stage == "future-fault-after-readback" {
				if pause.Interval.StartNS <= witness.EndNS {
					t.Fatal("positive future fault no longer follows completed readback")
				}
			} else if pause.Interval.StartNS >= previousEnvelope {
				t.Fatal("negative receipt no longer backdates its broker action")
			}
			if stage == "after-readback" || stage == "future-fault-after-readback" {
				c.worker("primary", "primary-threshold4", "signal", "SIGCONT")
				c.worker("primary", "primary-threshold4", "exit", "")
				c.worker("primary", "primary-threshold4", "cleanup", "")
				c.broker("destination", "restart")
				c.verify("full")
				c.audit("stopped-safety", "full", 1, 1, true, false)
				phaseRecoveryControl(c)
			} else if stage == "after-settled-safety" {
				phaseRecoveryControl(c)
			} else {
				c.worker("recovery", "recovery-unlimited", "exit", "")
				c.worker("recovery", "recovery-unlimited", "cleanup", "")
				c.broker("destination", "restart")
				c.verify("full")
				c.audit("final", "full", 32, 32, true, true)
				c.n += 1_000_000
				c.add(PhaseEvent{Kind: "run_finished", Finished: &RunFinished{CleanupComplete: true, Proof: "literal synthetic restoration/wait/cleanup observations complete"}})
			}
			r := CheckPhaseHistory(c.m, c.a, c.e)
			if stage == "future-fault-after-readback" {
				if r.Verdict != Unsupported || !phaseFinding(r, "phase_admission_complete") || !phaseFinding(r, "mechanism_unobserved") || len(r.Findings) != 2 || r.ReleaseQualified {
					t.Fatalf("legitimate future fault lost data-only admission: %+v", r)
				}
				return
			}
			if r.Verdict != HarnessError || !phaseFinding(r, "phase_broker_order") || phaseFinding(r, "phase_admission_complete") || r.ReleaseQualified {
				t.Fatalf("late mutation backdated an accepted witness: %+v", r)
			}
		})
	}
}

// The profile ID is an explicit variant, not a relabeling of threshold4 work.
// This literal history records a live primary TERM after the same full readback;
// it still supplies no independently observed delivery-timeout mechanism.
func unlimitedPhaseControl() *phaseControl {
	c := preparedPhaseControl()
	c.m.ScenarioID = "delivery-stop"
	p := &c.m.Profiles[0]
	p.ID = "primary-unlimited"
	p.Settings.Args = []string{"run", "--file", "/synthetic/primary-unlimited.sql", "--config", "/synthetic/worker.toml"}
	p.Settings.RecordThreshold = 0
	p.Settings.SQL = c.m.Profiles[1].Settings.SQL
	p.Settings.SQLSHA256 = phaseTestHash([]byte(p.Settings.SQL))
	c.worker("primary", "primary-unlimited", "start", "")
	c.audit("warmup-progress", "warmup", 1, 1, false, false)
	c.worker("primary", "primary-unlimited", "signal", "SIGSTOP")
	c.publish("full", "primary")
	c.verify("full")
	c.worker("primary", "primary-unlimited", "signal", "SIGCONT")
	c.worker("primary", "primary-unlimited", "signal", "SIGTERM")
	c.worker("primary", "primary-unlimited", "exit", "")
	c.worker("primary", "primary-unlimited", "cleanup", "")
	c.broker("destination", "restart")
	c.verify("full")
	c.audit("stopped-safety", "full", 1, 1, true, false)
	phaseRecoveryControl(c)
	return c
}

func TestVersion3ExplicitUnlimitedPrimaryStillNeedsMechanism(t *testing.T) {
	// Given an explicitly unlimited primary and recovery with a recorded live
	// TERM, when data admission completes, then neither TERM nor zero threshold
	// supplies an actual reached delivery-timeout predicate or qualification.
	c := unlimitedPhaseControl()
	r := CheckPhaseHistory(c.m, c.a, c.e)
	if r.Verdict != Unsupported || !phaseFinding(r, "phase_admission_complete") || !phaseFinding(r, "mechanism_unobserved") || len(r.Findings) != 2 || r.ReleaseQualified {
		t.Fatalf("explicit unlimited preparation changed mechanism admission: %+v", r)
	}
}

func TestVersion3UnlimitedPrimaryRejectsMixedProfilesAndSQLNormalization(t *testing.T) {
	for _, control := range []struct {
		name string
		code string
		edit func(*phaseControl)
	}{
		{"threshold-settings-under-unlimited-ID", "phase_profiles", func(c *phaseControl) {
			p := &c.m.Profiles[0].Settings
			p.RecordThreshold = 4
			p.SQL = strings.TrimSuffix(c.m.Profiles[1].Settings.SQL, ";\n") + " OPTIONS (WORKER_STOP_AFTER_RECORDS=4);\n"
			p.SQLSHA256 = phaseTestHash([]byte(p.SQL))
		}},
		{"unlimited-settings-under-threshold-ID", "phase_profiles", func(c *phaseControl) { c.m.Profiles[0].ID = "primary-threshold4" }},
		{"unlimited-primary-for-threshold-scenario", "phase_profiles", func(c *phaseControl) { c.m.ScenarioID = "delivery-threshold" }},
		{"rebound-SQL-option-with-zero-count", "phase_profiles", func(c *phaseControl) {
			p := &c.m.Profiles[0].Settings
			p.SQL = strings.TrimSuffix(p.SQL, ";\n") + " OPTIONS (WORKER_STOP_AFTER_RECORDS=4);\n"
			p.SQLSHA256 = phaseTestHash([]byte(p.SQL))
		}},
		{"rebound-primary-config-path", "phase_profiles", func(c *phaseControl) {
			p := &c.m.Profiles[0].Settings
			p.Args = append([]string(nil), p.Args...)
			p.Args[4] = "/synthetic/another-worker.toml"
			args, _ := json.Marshal(p.Args)
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.SettingsID == "primary-unlimited" {
					e.Worker.Observation.Identity.ArgsSHA256 = phaseTestHash(args)
				}
			}
		}},
		{"threshold-worker-in-unlimited-history", "phase_worker", func(c *phaseControl) {
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.Observation.Action == "start" && e.Worker.SettingsID == "primary-unlimited" {
					e.Worker.SettingsID = "primary-threshold4"
				}
			}
		}},
		{"rebound-recovery-using-primary-profile", "phase_recovery", func(c *phaseControl) {
			args, _ := json.Marshal(c.m.Profiles[0].Settings.Args)
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.SettingsID == "recovery-unlimited" {
					e.Worker.SettingsID = "primary-unlimited"
					e.Worker.Observation.Identity.ArgsSHA256 = phaseTestHash(args)
				}
			}
		}},
	} {
		t.Run(control.name, func(t *testing.T) {
			// Given independently literal valid unlimited work, when profile or
			// SQL/settings identity is mixed (including fresh hashes), then the
			// specific boundary must reject it before generic mechanism limits.
			c := unlimitedPhaseControl()
			control.edit(c)
			r := CheckPhaseHistory(c.m, c.a, c.e)
			if r.Verdict != HarnessError || !phaseFinding(r, control.code) || phaseFinding(r, "phase_admission_complete") || r.ReleaseQualified {
				t.Fatalf("mixed unlimited/threshold profile escaped admission: %+v", r)
			}
		})
	}
}
