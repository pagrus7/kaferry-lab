package evidence

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

//go:embed testdata/m2-configuration.sql
var m2ControlSQL string

// These controls contain three distinct literal records and independently
// specified source/output positions. No checker function creates expectations.
type m2Control struct {
	m       M2Manifest
	a       ArtifactMetadata
	e       []M2Event
	l       Ledger
	n       identity.Int64
	workers map[string]M2WorkerIdentity
	brokers map[string]M2BrokerIdentity
}

func newM2Control(scenario string) *m2Control {
	c := &m2Control{workers: map[string]M2WorkerIdentity{}, brokers: map[string]M2BrokerIdentity{}}
	s := Subject{Kind: "synthetic-history", ExecutableSHA256: strings.Repeat("c", 64), ContractSHA256: ContractSHA256, Platform: "linux/amd64", VersionOutput: "synthetic M2 control"}
	c.m = M2Manifest{SchemaVersion: 2, CheckerVersion: "evidence-v2", Namespace: "calibration", RunID: "m2-literal-control", ScenarioID: scenario, Scope: "kafka", Group: "explicit-group", Given: "three verified records in three partitions", When: "the compiled case executes", Then: "all required records survive with safe saved offsets", BudgetNS: 300_000_000_000, Subject: s, LabSource: LabSource{Commit: strings.Repeat("1", 40), Proof: "literal source control"}, Environment: Environment{OrchestratorPlatform: "linux/amd64", ExecutionPlatform: "linux/amd64", Runtime: "literal OS observations", Storage: "durable retained broker-volume assumption", Topology: "two independent single-broker clusters", Limits: "finite three-record control"}, Settings: M2Settings{Routing: "PRESERVE", Args: []string{"--synthetic-config"}, Environment: []string{}, DeliveryTimeoutNS: 2_000_000, ShutdownTimeoutNS: 10_000_000}, FinalAuditID: "final"}
	c.a = ArtifactMetadata{SchemaVersion: 1, Subject: s, VerificationDetail: "literal calibration attachment", CalibrationLabel: "synthetic M2 checker controls"}
	c.l = Ledger{Partitions: []PartitionRange{}, Destinations: []identity.SourcePosition{}, Entries: []LedgerEntry{}}
	for p, value := range []string{"QQ==", "Qg==", "Qw=="} {
		source := identity.SourcePosition{Cluster: "source-cluster", Topic: "input", TopicID: strings.Repeat("1", 32), Partition: int32(p), Offset: 0}
		dest := identity.SourcePosition{Cluster: "destination-cluster", Topic: "output", TopicID: strings.Repeat("2", 32), Partition: int32(p), Offset: 0}
		record := identity.Record{Key: identity.NullableBytes{Null: true}, Value: identity.NullableBytes{Base64: value}, Headers: []identity.Header{}, TimestampKind: "unknown"}
		c.l.Partitions = append(c.l.Partitions, PartitionRange{Source: source, End: 1, Gaps: []Gap{}})
		c.l.Destinations = append(c.l.Destinations, dest)
		c.l.Entries = append(c.l.Entries, LedgerEntry{ID: []string{"A", "B", "C"}[p], Source: source, Record: record, Disposition: "required", Reason: "finite acknowledged nontransactional input", DestinationTopic: "output", AllowedPartitions: []int32{int32(p)}})
	}
	c.m.Settings.Args = []string{"run", "--file", "/synthetic/copy.sql", "--config", "/synthetic/worker.toml"}
	c.m.Settings.WorkBudgetNS, c.m.Settings.CleanupBudgetNS = 200_000_000_000, 100_000_000_000
	c.m.Settings.SQL = m2ControlSQL
	c.m.Settings.ConfigTOML = "[worker]\nrecord_cap=1024\npartition_record_cap=1024\nbyte_cap=16777216\npartition_byte_cap=8388608\ndelivery_timeout='2ms'\nshutdown_timeout='10ms'\nidle_exit='8s'\ntip_wait='8s'\nprogress_interval='1s'\n"
	c.m.Settings.SQLSHA256, c.m.Settings.ConfigSHA256 = digest([]byte(c.m.Settings.SQL)), digest([]byte(c.m.Settings.ConfigTOML))
	c.add(M2Event{Kind: "ledger", Ledger: &c.l})
	c.verify()
	c.broker("source", "inspect")
	c.broker("destination", "inspect")
	return c
}

func (c *m2Control) interval() M2Interval {
	c.n += 1_000_000
	start := c.n
	c.n += 1_000_000
	return M2Interval{StartNS: start, EndNS: c.n}
}
func (c *m2Control) add(e M2Event) {
	e.Seq = identity.Int64(len(c.e) + 1)
	e.RunID = c.m.RunID
	e.ElapsedNS = c.n
	c.e = append(c.e, e)
}
func (c *m2Control) verify() {
	i := c.interval()
	c.add(M2Event{Kind: "inputs_verified", Inputs: &M2InputsVerified{Interval: i, Ledger: c.l, Method: "independent_source_scan", Complete: true}})
}

func (c *m2Control) broker(role, action string) {
	id, exists := c.brokers[role]
	if !exists {
		ch, port, cluster := "a", "19092", "source-cluster"
		if role == "destination" {
			ch, port, cluster = "b", "29092", "destination-cluster"
		}
		id = M2BrokerIdentity{RunID: c.m.RunID, Role: role, ContainerID: strings.Repeat(ch, 64), Name: "owned-" + role, ImageID: "sha256:" + strings.Repeat("d", 64), ImageReference: "broker@sha256:" + strings.Repeat("e", 64), Endpoint: "127.0.0.1:" + port, ClusterID: cluster}
		c.brokers[role] = id
	}
	i := c.interval()
	r := M2Interval{StartNS: i.StartNS, EndNS: i.StartNS}
	if action == "inspect" {
		r = M2Interval{}
	}
	p := &M2Probe{Interval: M2Interval{StartNS: i.EndNS, EndNS: i.EndNS}, Endpoint: id.Endpoint, Available: true, APIKeys: 10}
	state := M2BrokerState{RunningPresent: true, PausedPresent: true, Running: true, LoopbackBound: true}
	if action == "pause" {
		state.Paused = true
		p.Available = false
		p.APIKeys = 0
		p.Unavailable = true
		p.Failure = "timeout"
	}
	c.add(M2Event{Kind: "broker", Broker: &M2Broker{Identity: id, Action: action, Interval: i, Request: r, State: state, Probe: p}})
}

func (c *m2Control) worker(id, action, signal string) {
	w, exists := c.workers[id]
	if !exists {
		args, _ := json.Marshal(c.m.Settings.Args)
		env, _ := json.Marshal(c.m.Settings.Environment)
		w = M2WorkerIdentity{WorkerID: id, PID: 100 + len(c.workers), StartTicks: "1234", ExecutableSHA256: c.m.Subject.ExecutableSHA256, ArgsSHA256: digest(args), EnvironmentSHA256: digest(env)}
		c.workers[id] = w
	}
	i := c.interval()
	o := &M2Worker{Identity: w, Action: action, Interval: i, LocalElapsedNS: i.EndNS, Signal: signal}
	if action == "exit" || action == "cleanup" {
		o.Reaped = true
	}
	if action == "exit" && signal == "SIGKILL" {
		o.ExitCode = -1
	}
	c.add(M2Event{Kind: "worker", Worker: o})
}

func (c *m2Control) audit(id string, records []int, saved []identity.Int64, settled, final bool) {
	scan := c.interval()
	counts := []identity.Int64{0, 0, 0}
	for _, index := range records {
		entry := c.l.Entries[index]
		position := c.l.Destinations[index]
		position.Offset = counts[index]
		counts[index]++
		c.add(M2Event{Kind: "output", Output: &Output{AuditID: id, Destination: position, Record: entry.Record}})
	}
	a := &M2Audit{ID: id, Mode: "snapshot", ScanInterval: scan, SavedInterval: c.interval(), Scans: []Scan{}, Saved: []M2SavedPosition{}, Final: final}
	a.GroupInterval = a.SavedInterval
	a.Group = M2Group{GroupID: c.m.Group, State: "Empty", Members: []M2GroupMember{}}
	if !settled {
		a.Group = M2Group{GroupID: c.m.Group, State: "Stable", ProtocolType: "consumer", Protocol: "cooperative-sticky", Members: []M2GroupMember{{ID: "literal-member", ClientID: "literal-client", ClientHost: "/127.0.0.1", AssignmentBase64: "AAAAAAABAAVpbnB1dAAAAAMAAAAAAAAAAQAAAAL/////"}}}
	}
	if settled {
		a.Mode = "settled"
	}
	for p := 0; p < 3; p++ {
		a.Scans = append(a.Scans, Scan{PartitionRange: PartitionRange{Source: c.l.Destinations[p], End: counts[p], Gaps: []Gap{}}, Reached: counts[p], StableEnd: counts[p], Complete: true, Proof: "complete independent fixed-end scan"})
		source := c.l.Partitions[p].Source
		source.Offset = saved[p]
		a.Saved = append(a.Saved, M2SavedPosition{Source: source, Present: saved[p] >= 0, Group: c.m.Group})
	}
	c.add(M2Event{Kind: "audit", Audit: a})
}

func (c *m2Control) settle(id string, records []int, saved []identity.Int64, final bool, sourceRestart bool) {
	c.broker("destination", "restart")
	if sourceRestart {
		c.broker("source", "restart")
	}
	c.verify()
	c.audit(id, records, saved, true, final)
}
func (c *m2Control) finish() {
	c.n += 1_000_000
	c.add(M2Event{Kind: "run_finished", Finished: &RunFinished{CleanupComplete: true, Proof: "all owned workers waited and faults restored"}})
}

func healthyM2Control() *m2Control {
	c := newM2Control("healthy")
	c.worker("w1", "start", "")
	c.worker("w1", "exit", "")
	c.worker("w1", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.finish()
	return c
}

func repeatedM2Control() *m2Control {
	c := newM2Control("repeated-kill")
	c.worker("w1", "start", "")
	c.audit("lag1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w1", "signal", "SIGKILL")
	c.worker("w1", "exit", "SIGKILL")
	c.worker("w1", "cleanup", "")
	c.settle("stop1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w2", "start", "")
	c.audit("lag2", []int{0}, []identity.Int64{0, -1, -1}, false, false)
	c.worker("w2", "signal", "SIGKILL")
	c.worker("w2", "exit", "SIGKILL")
	c.worker("w2", "cleanup", "")
	c.settle("stop2", []int{0}, []identity.Int64{0, -1, -1}, false, false)
	c.worker("w3", "start", "")
	c.worker("w3", "exit", "")
	c.worker("w3", "cleanup", "")
	c.settle("final", []int{0, 0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill1", Kind: "unresolved-kill", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag1", StoppedAuditID: "stop1"}})
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill2", Kind: "visible-unsaved-kill", WorkerID: "w2", RecoveryWorkerID: "w3", TriggerAuditID: "lag2", VisibleAuditID: "lag2", StoppedAuditID: "stop2"}})
	c.finish()
	return c
}

func TestM2LiteralHealthyAndRepeatedCrashControls(t *testing.T) {
	for _, c := range []*m2Control{healthyM2Control(), repeatedM2Control()} {
		r := CheckM2(c.m, c.a, c.e)
		if r.Verdict != Pass || r.ReleaseQualified {
			t.Fatalf("%s: %+v", c.m.ScenarioID, r)
		}
		if !reflect.DeepEqual(r, CheckM2(c.m, c.a, c.e)) {
			t.Fatal("recheck is nondeterministic")
		}
	}
}

func TestM2IncompleteIndependentFactsCannotPass(t *testing.T) {
	tests := []struct {
		name, code string
		mutate     func(*m2Control)
	}{
		{"missing restart", "pending_output", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Broker != nil && c.e[i].Broker.Action == "restart" {
					c.e[i].Broker.Action = "restore"
				}
			}
		}},
		{"no independent broker probe", "broker_unavailable", func(c *m2Control) { c.e[2].Broker.Probe = nil }},
		{"missing worker cleanup", "cleanup_missing", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Worker != nil && c.e[i].Worker.Action == "cleanup" {
					c.e = append(c.e[:i], c.e[i+1:]...)
					break
				}
			}
			for i := range c.e {
				c.e[i].Seq = identity.Int64(i + 1)
			}
		}},
		{"missing input availability after restart", "pending_output", func(c *m2Control) {
			for i := len(c.e) - 1; i >= 0; i-- {
				if c.e[i].Inputs != nil {
					c.e[i].Inputs.Complete = false
					break
				}
			}
		}},
		{"unreaped process", "worker_unreaped", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Worker != nil && c.e[i].Worker.Action == "exit" {
					c.e[i].Worker.Reaped = false
				}
			}
		}},
		{"cleanup failure", "run_cleanup", func(c *m2Control) { c.e[len(c.e)-1].Finished.CleanupComplete = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := healthyM2Control()
			test.mutate(c)
			r := CheckM2(c.m, c.a, c.e)
			if r.Verdict == Pass || !m2HasCode(r, test.code) {
				t.Fatalf("want non-PASS/%s, got %+v", test.code, r)
			}
		})
	}
}

func TestM2VisibleUnsavedRequiresLaterMatchingSavedSample(t *testing.T) {
	c := repeatedM2Control()
	for i := range c.e {
		if c.e[i].Audit != nil && c.e[i].Audit.ID == "lag2" {
			c.e[i].Audit.Saved[0].Source.Offset = 1
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "visible_unsaved") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2DefiniteSafetyAuditDetectsMissingBytesAndUnsafeProgress(t *testing.T) {
	c := newM2Control("healthy")
	c.worker("w1", "start", "")
	c.worker("w1", "exit", "")
	c.worker("w1", "cleanup", "")
	c.settle("final", []int{0, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.finish()
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Violation || !m2HasCode(r, "required_record_missing") || !m2HasCode(r, "unsafe_saved_prefix") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2SnapshotDoesNotAccuseUnresolvedSavedPrefix(t *testing.T) {
	c := newM2Control("healthy")
	c.worker("w1", "start", "")
	c.audit("live", []int{}, []identity.Int64{1, 1, 1}, false, false)
	c.worker("w1", "exit", "")
	c.worker("w1", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.finish()
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Pass || m2HasCode(r, "unsafe_saved_prefix") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2IdentityOrderAndUnsupportedScopeControls(t *testing.T) {
	tests := []struct {
		name   string
		want   Verdict
		code   string
		mutate func(*m2Control)
	}{
		{"changed run", HarnessError, "event_identity", func(c *m2Control) { c.e[1].RunID = "different-run" }},
		{"changed worker start identity", HarnessError, "worker_identity", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Worker != nil && c.e[i].Worker.Action == "exit" {
					c.e[i].Worker.Identity.StartTicks = "9999"
				}
			}
		}},
		{"changed broker identity", HarnessError, "broker_identity", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Broker != nil && c.e[i].Broker.Action == "restart" {
					c.e[i].Broker.Identity.ContainerID = strings.Repeat("f", 64)
				}
			}
		}},
		{"saved before scan", HarnessError, "audit_interval", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Audit != nil {
					c.e[i].Audit.SavedInterval.StartNS = 0
				}
			}
		}},
		{"unsupported threshold observer", Unsupported, "threshold_observer", func(c *m2Control) { c.m.ScenarioID = "delivery-threshold"; c.m.Settings.RecordThreshold = 2 }},
		{"unknown scenario", Unsupported, "scenario", func(c *m2Control) { c.m.ScenarioID = "future-case" }},
		{"unknown event kind", Unsupported, "event_kind", func(c *m2Control) { c.e[1].Kind = "future-observer" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := healthyM2Control()
			test.mutate(c)
			r := CheckM2(c.m, c.a, c.e)
			if r.Verdict != test.want || !m2HasCode(r, test.code) || r.ReleaseQualified {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestM2BundleRoundTripAndStrictStreamControls(t *testing.T) {
	c := healthyM2Control()
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := WriteM2Bundle(dir, c.m, c.a, c.e); err != nil {
		t.Fatal(err)
	}
	want := LoadAndCheck(dir)
	if want.Verdict != Pass || !reflect.DeepEqual(want, LoadAndCheck(dir)) {
		t.Fatalf("got %+v", want)
	}
	if _, err := WriteM2Bundle(dir, c.m, c.a, c.e); err == nil {
		t.Fatal("writer overwrote existing evidence")
	}
	eventsPath := filepath.Join(dir, EventsName)
	raw, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventsPath, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if r := LoadAndCheck(dir); r.Verdict != HarnessError || !m2HasCode(r, "events_hash") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2StrictRequiredScalarAndDuplicateFields(t *testing.T) {
	var event M2Event
	for _, raw := range []string{
		`{"seq":"1","run_id":"run","elapsed_ns":"0","kind":"run_finished","finished":{"cleanup_complete":true,"proof":"known"}}`,
		`{"seq":"1","run_id":"run","elapsed_ns":"0","kind":"run_finished","kind":"ledger","finished":{"timed_out":false,"cleanup_complete":true,"proof":"known"}}`,
		`{"seq":"1","run_id":"run","elapsed_ns":"0","kind":"run_finished","finished":{"timed_out":false,"cleanup_complete":true,"proof":"known","unknown":false}}`,
	} {
		if err := strictJSON([]byte(raw), &event); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func m2HasCode(r Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func startupM2Control() *m2Control {
	c := newM2Control("source-startup")
	c.broker("source", "pause")
	c.worker("w1", "start", "")
	c.n += 5_000_000_000
	c.worker("w1", "signal", "SIGTERM")
	c.worker("w1", "exit", "")
	c.e[len(c.e)-1].Worker.ExitCode = 1
	c.worker("w1", "cleanup", "")
	c.e[len(c.e)-1].Worker.ExitCode = 1
	c.broker("source", "restore")
	c.settle("startup-stopped", []int{}, []identity.Int64{-1, -1, -1}, false, true)
	c.worker("w2", "start", "")
	c.worker("w2", "exit", "")
	c.worker("w2", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, true)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "startup1", Kind: "source-startup", WorkerID: "w1", RecoveryWorkerID: "w2", StoppedAuditID: "startup-stopped"}})
	c.finish()
	return c
}

func deliveryM2Control() *m2Control {
	c := newM2Control("delivery-stop")
	c.worker("w1", "start", "")
	c.audit("lag", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.broker("destination", "pause")
	c.n += 3_000_000
	i := c.interval()
	c.add(M2Event{Kind: "diagnostic", Diagnostic: &M2Diagnostic{WorkerID: "w1", Kind: "delivery-timeout", Interval: i, Proof: "literal timeout diagnostic corroborating actual outage and exit"}})
	c.worker("w1", "signal", "SIGTERM")
	c.worker("w1", "exit", "")
	c.worker("w1", "cleanup", "")
	c.broker("destination", "restore")
	c.settle("stopped", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w2", "start", "")
	c.worker("w2", "exit", "")
	c.worker("w2", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "outage1", Kind: "delivery-stop", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag", StoppedAuditID: "stopped"}})
	c.finish()
	return c
}

func TestM2LiteralStartupAndDeliveryRecoveryControls(t *testing.T) {
	for _, c := range []*m2Control{startupM2Control(), deliveryM2Control()} {
		r := CheckM2(c.m, c.a, c.e)
		if r.Verdict != Pass || r.ReleaseQualified {
			t.Fatalf("%s: %+v", c.m.ScenarioID, r)
		}
	}
}

func TestM2OutageAndDiagnosticCannotReplaceIndependentFacts(t *testing.T) {
	c := deliveryM2Control()
	for i := range c.e {
		if c.e[i].Broker != nil && c.e[i].Broker.Action == "pause" {
			c.e[i].Broker.Probe = nil
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "pause_unreached") {
		t.Fatalf("got %+v", r)
	}
	c = startupM2Control()
	for i := range c.e {
		if c.e[i].Broker != nil && c.e[i].Broker.Action == "pause" {
			c.e[i].Broker.Action = "inspect"
			c.e[i].Broker.State.Paused = false
			c.e[i].Broker.Probe.Available = true
			c.e[i].Broker.Probe.Unavailable = false
			c.e[i].Broker.Probe.APIKeys = 10
			c.e[i].Broker.Probe.Failure = ""
		}
	}
	r = CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "startup_unreached") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2UnscannedObservedTailCannotProveOutputLag(t *testing.T) {
	c := repeatedM2Control()
	for i := range c.e {
		if c.e[i].Audit != nil && c.e[i].Audit.ID == "lag1" {
			c.e[i].Audit.Scans[0].StableEnd = 1
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "kill_trigger") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2OneDeathCannotSatisfyRepeatedCrashRequirement(t *testing.T) {
	c := repeatedM2Control()
	for i := range c.e {
		if c.e[i].Episode != nil && c.e[i].Episode.ID == "kill2" {
			c.e[i].Episode.WorkerID = "w1"
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != HarnessError || !m2HasCode(r, "episode_duplicate") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2ConfigurationAndAssignmentEvidenceIsBound(t *testing.T) {
	c := healthyM2Control()
	c.m.Settings.DeliveryTimeoutNS = 1
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != HarnessError || !m2HasCode(r, "settings_binding") {
		t.Fatalf("got %+v", r)
	}
	c = repeatedM2Control()
	for i := range c.e {
		if c.e[i].Audit != nil && c.e[i].Audit.ID == "lag1" {
			c.e[i].Audit.Group.Members[0].AssignmentBase64 = "AA=="
		}
	}
	r = CheckM2(c.m, c.a, c.e)
	if r.Verdict != HarnessError || !m2HasCode(r, "group_observation") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2LiteralCorruptionAndRoutingControls(t *testing.T) {
	// Given a complete independent final scan, when recorded bytes or routing
	// are wrong, then the checker must identify the specific violation.
	c := healthyM2Control()
	for i := range c.e {
		if c.e[i].Output != nil {
			c.e[i].Output.Record.Value.Base64 = "RA=="
			break
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Violation || !m2HasCode(r, "corrupt_or_unexpected_output") {
		t.Fatalf("got %+v", r)
	}
	c = healthyM2Control()
	var first, second *Output
	for i := range c.e {
		if c.e[i].Output != nil {
			if first == nil {
				first = c.e[i].Output
			} else {
				second = c.e[i].Output
				break
			}
		}
	}
	first.Record, second.Record = second.Record, first.Record
	r = CheckM2(c.m, c.a, c.e)
	if r.Verdict != Violation || !m2HasCode(r, "wrong_partition") {
		t.Fatalf("got %+v", r)
	}
}

func TestM2StartupRequiresFailedExitAndOrderedSafeRecovery(t *testing.T) {
	// Given a reached source outage, when startup exits for another reason or
	// recovery lacks independent lifecycle evidence, then it cannot pass.
	tests := []struct {
		name, code string
		mutate     func(*m2Control)
	}{
		{"unreaped startup exit", "worker_unreaped", func(c *m2Control) {
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "exit" {
					w.Reaped = false
				}
			}
		}},
		{"recovery before restoration", "startup_recovery", func(c *m2Control) {
			var before identity.Int64
			for i := range c.e {
				b := c.e[i].Broker
				if b != nil && b.Identity.Role == "source" && b.Action == "restore" {
					before = b.Request.StartNS - 1
				}
			}
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w2" && w.Action == "start" {
					w.Interval.StartNS = before
				}
			}
		}},
		{"recovery before settled offset read", "startup_audit", func(c *m2Control) {
			var before identity.Int64
			for i := range c.e {
				a := c.e[i].Audit
				if a != nil && a.ID == "startup-stopped" {
					before = a.ScanInterval.EndNS + 1
				}
			}
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w2" && w.Action == "start" {
					w.Interval.StartNS = before
				}
			}
		}},
		{"successful startup exit", "startup_exit", func(c *m2Control) {
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "exit" {
					w.ExitCode = 0
				}
			}
		}},
		{"configuration failure", "startup_exit", func(c *m2Control) {
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "exit" {
					w.ExitCode = 2
				}
			}
		}},
		{"missing TERM request", "startup_termination", func(c *m2Control) {
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "signal" {
					c.e = append(c.e[:i], c.e[i+1:]...)
					break
				}
			}
			for i := range c.e {
				c.e[i].Seq = identity.Int64(i + 1)
			}
		}},
		{"exit precedes TERM request", "startup_termination", func(c *m2Control) {
			var start identity.Int64
			for i := range c.e {
				w := c.e[i].Worker
				if w == nil || w.Identity.WorkerID != "w1" {
					continue
				}
				if w.Action == "start" {
					start = w.Interval.EndNS
				}
				if w.Action == "exit" {
					w.Interval = M2Interval{StartNS: start + 1, EndNS: start + 1}
				}
			}
		}},
		{"shutdown exceeds configured bound", "startup_termination", func(c *m2Control) {
			var start identity.Int64
			for i := range c.e {
				w := c.e[i].Worker
				if w == nil || w.Identity.WorkerID != "w1" {
					continue
				}
				if w.Action == "start" {
					start = w.Interval.EndNS
				}
				if w.Action == "signal" {
					w.Interval = M2Interval{StartNS: start + 1, EndNS: start + 1}
				}
			}
		}},
		{"exit follows restoration", "startup_exit", func(c *m2Control) {
			var after identity.Int64
			for i := range c.e {
				b := c.e[i].Broker
				if b != nil && b.Action == "restore" && b.Identity.Role == "source" {
					after = b.Interval.EndNS
				}
			}
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "exit" {
					w.Interval = M2Interval{StartNS: after, EndNS: after}
					c.e[i].ElapsedNS = after
				}
			}
			for i := 1; i < len(c.e); i++ {
				c.e[i].ElapsedNS = max(c.e[i].ElapsedNS, c.e[i-1].ElapsedNS)
			}
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w1" && w.Action == "cleanup" {
					w.Interval = M2Interval{StartNS: after, EndNS: after}
				}
			}
		}},
		{"missing recovery worker", "startup_recovery", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Episode != nil {
					c.e[i].Episode.RecoveryWorkerID = ""
				}
			}
		}},
		{"failed recovery worker", "startup_recovery", func(c *m2Control) {
			for i := range c.e {
				w := c.e[i].Worker
				if w != nil && w.Identity.WorkerID == "w2" && w.Action == "exit" {
					w.ExitCode = 1
				}
			}
		}},
		{"missing settled audit", "startup_audit", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Episode != nil {
					c.e[i].Episode.StoppedAuditID = ""
				}
			}
		}},
		{"final audit used after recovery", "startup_audit", func(c *m2Control) {
			for i := range c.e {
				if c.e[i].Episode != nil {
					c.e[i].Episode.StoppedAuditID = "final"
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := startupM2Control()
			test.mutate(c)
			r := CheckM2(c.m, c.a, c.e)
			if r.Verdict != Inconclusive || !m2HasCode(r, test.code) || r.ReleaseQualified {
				t.Fatalf("want INCONCLUSIVE/%s, got %+v", test.code, r)
			}
		})
	}
}

func TestM2StartupFailureDiagnosticCorroboratesAnActualFailedExit(t *testing.T) {
	c := startupM2Control()
	for i := range c.e {
		w := c.e[i].Worker
		if w != nil && w.Identity.WorkerID == "w1" && w.Action == "signal" {
			c.e[i].Kind = "diagnostic"
			c.e[i].Diagnostic = &M2Diagnostic{WorkerID: "w1", Kind: "startup-failure", Interval: w.Interval, Proof: "literal retained startup failure during independently observed source impairment"}
			c.e[i].Worker = nil
		}
	}
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
		t.Fatalf("got %+v", r)
	}
	for i := range c.e {
		w := c.e[i].Worker
		if w != nil && w.Identity.WorkerID == "w1" && w.Action == "exit" {
			w.ExitCode = 2
		}
	}
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Inconclusive || !m2HasCode(r, "startup_exit") {
		t.Fatalf("startup diagnostic concealed configuration failure: %+v", r)
	}
}

func TestM2NewSavedObservationClosesVisibleUnsavedCrashWindow(t *testing.T) {
	// Given A visible with saved-next zero, when a later pre-kill audit proves
	// A saved-next one while B/C still lag, then the earlier window is closed.
	c := newM2Control("repeated-kill")
	c.worker("w1", "start", "")
	c.audit("lag1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w1", "signal", "SIGKILL")
	c.worker("w1", "exit", "SIGKILL")
	c.worker("w1", "cleanup", "")
	c.settle("stop1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w2", "start", "")
	c.audit("visible-old", []int{0}, []identity.Int64{0, -1, -1}, false, false)
	c.audit("lag-new", []int{0}, []identity.Int64{1, -1, -1}, false, false)
	c.worker("w2", "signal", "SIGKILL")
	c.worker("w2", "exit", "SIGKILL")
	c.worker("w2", "cleanup", "")
	c.settle("stop2", []int{0}, []identity.Int64{1, -1, -1}, false, false)
	c.worker("w3", "start", "")
	c.worker("w3", "exit", "")
	c.worker("w3", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill1", Kind: "unresolved-kill", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag1", StoppedAuditID: "stop1"}})
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill2", Kind: "visible-unsaved-kill", WorkerID: "w2", RecoveryWorkerID: "w3", TriggerAuditID: "lag-new", VisibleAuditID: "visible-old", StoppedAuditID: "stop2"}})
	c.finish()
	for _, visible := range []string{"visible-old", "lag-new"} {
		c.e[len(c.e)-2].Episode.VisibleAuditID = visible
		r := CheckM2(c.m, c.a, c.e)
		if r.Verdict != Inconclusive || !m2HasCode(r, "visible_unsaved") || m2HasCode(r, "kill_trigger") {
			t.Fatalf("%s: got %+v", visible, r)
		}
	}
}

func TestM2AuthoredSQLFixtureBindsObservedConfiguration(t *testing.T) {
	// The same authored SQL fixture is compared against the actual campaign
	// generator in campaign tests; this side checks independent literal records.
	c := healthyM2Control()
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
		t.Fatalf("authored configuration rejected: %+v", r)
	}
	for _, change := range []struct{ name, old, new string }{
		{"source endpoint", "127.0.0.1:19092", "127.0.0.1:19093"},
		{"destination endpoint", "127.0.0.1:29092", "127.0.0.1:29093"},
		{"source topic", "input@source", "other@source"},
		{"destination topic", "output@destination", "other@destination"},
		{"group", "explicit-group", "different-group"},
		{"routing", "PARTITIONING = PRESERVE", "PARTITIONING = KEY"},
		{"client attribution", "'client.id'='lab-m2'", "'client.id'='other'"},
		{"linger", "'linger.ms'='1500'", "'linger.ms'='2000'"},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := healthyM2Control()
			c.m.Settings.SQL = strings.Replace(c.m.Settings.SQL, change.old, change.new, 1)
			c.m.Settings.SQLSHA256 = digest([]byte(c.m.Settings.SQL))
			r := CheckM2(c.m, c.a, c.e)
			if r.Verdict != Unsupported || !m2HasCode(r, "sql_scope") {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestM2WriterReservationPreservesExistingEvidence(t *testing.T) {
	c := healthyM2Control()
	dir := filepath.Join(t.TempDir(), "bundle")
	owned, err := WriteM2Bundle(dir, c.m, c.a, c.e)
	if err != nil || !owned {
		t.Fatalf("exclusive writer ownership=%v error=%v", owned, err)
	}
	beforeComplete, err := os.ReadFile(filepath.Join(dir, CompleteName))
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents, err := os.ReadFile(filepath.Join(dir, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	owned, err = WriteM2Bundle(dir, c.m, c.a, c.e)
	if err == nil || owned {
		t.Fatalf("collision ownership=%v error=%v", owned, err)
	}
	afterComplete, err := os.ReadFile(filepath.Join(dir, CompleteName))
	if err != nil {
		t.Fatal(err)
	}
	afterEvents, err := os.ReadFile(filepath.Join(dir, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeComplete) != string(afterComplete) || string(beforeEvents) != string(afterEvents) {
		t.Fatal("colliding writer changed prior evidence")
	}
	if r := LoadAndCheck(dir); r.Verdict != Pass {
		t.Fatalf("prior bundle no longer rechecks: %+v", r)
	}
}

// Only the output scan completes before the fault. OffsetFetch/DescribeGroups
// finish later, so the raw observations must not disappear behind that delay.
func (c *m2Control) pendingAudit(id string, records []int, saved []identity.Int64) *M2Audit {
	c.audit(id, records, saved, false, false)
	a := c.e[len(c.e)-1].Audit
	c.e = c.e[:len(c.e)-1]
	return a
}
func (c *m2Control) finalizePendingAudit(a *M2Audit) {
	a.SavedInterval = c.interval()
	a.GroupInterval = a.SavedInterval
	c.add(M2Event{Kind: "audit", Audit: a})
}

func pendingOutputCrashM2Control(records []int) *m2Control {
	c := newM2Control("repeated-kill")
	c.worker("w1", "start", "")
	c.audit("lag1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w1", "signal", "SIGKILL")
	c.worker("w1", "exit", "SIGKILL")
	c.worker("w1", "cleanup", "")
	c.settle("stop1", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	c.worker("w2", "start", "")
	c.audit("lag2", []int{0}, []identity.Int64{0, -1, -1}, false, false)
	pending := c.pendingAudit("pending", records, []identity.Int64{0, -1, -1})
	c.worker("w2", "signal", "SIGKILL")
	c.worker("w2", "exit", "SIGKILL")
	c.worker("w2", "cleanup", "")
	c.finalizePendingAudit(pending)
	c.settle("stop2", []int{0, 1, 2}, []identity.Int64{0, -1, -1}, false, false)
	c.worker("w3", "start", "")
	c.worker("w3", "exit", "")
	c.worker("w3", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill1", Kind: "unresolved-kill", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag1", StoppedAuditID: "stop1"}})
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill2", Kind: "visible-unsaved-kill", WorkerID: "w2", RecoveryWorkerID: "w3", TriggerAuditID: "lag2", VisibleAuditID: "lag2", StoppedAuditID: "stop2"}})
	c.finish()
	return c
}

func TestM2PendingOutputObservationsInvalidateCrashTrigger(t *testing.T) {
	// Given a valid lag/visible-unsaved sample, when newer full or partial
	// output is known before the kill, then delayed group reads cannot hide it.
	for _, records := range [][]int{{0, 1, 2}, {0, 1}} {
		c := pendingOutputCrashM2Control(records)
		r := CheckM2(c.m, c.a, c.e)
		if r.Verdict != Inconclusive || !m2HasCode(r, "trigger_changed") || !m2HasCode(r, "visible_unsaved") || m2HasCode(r, "kill_trigger") {
			t.Fatalf("records %v: %+v", records, r)
		}
	}
	c := repeatedM2Control()
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
		t.Fatalf("no intervening observations: %+v", r)
	}
}

func TestM2PendingOutputObservationsInvalidatePauseTrigger(t *testing.T) {
	c := newM2Control("delivery-stop")
	c.worker("w1", "start", "")
	c.audit("lag", []int{}, []identity.Int64{-1, -1, -1}, false, false)
	pending := c.pendingAudit("pending", []int{0, 1, 2}, []identity.Int64{1, 1, 1})
	c.broker("destination", "pause")
	c.finalizePendingAudit(pending)
	c.n += 3_000_000
	i := c.interval()
	c.add(M2Event{Kind: "diagnostic", Diagnostic: &M2Diagnostic{WorkerID: "w1", Kind: "delivery-timeout", Interval: i, Proof: "literal corroborating diagnostic while independently paused"}})
	c.worker("w1", "signal", "SIGTERM")
	c.worker("w1", "exit", "")
	c.worker("w1", "cleanup", "")
	c.broker("destination", "restore")
	c.settle("stopped", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, false, false)
	c.worker("w2", "start", "")
	c.worker("w2", "exit", "")
	c.worker("w2", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "outage1", Kind: "delivery-stop", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag", StoppedAuditID: "stopped"}})
	c.finish()
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "trigger_changed") || m2HasCode(r, "outage_trigger") {
		t.Fatalf("got %+v", r)
	}
	c = deliveryM2Control()
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
		t.Fatalf("no intervening observations: %+v", r)
	}
}

func TestM2PreKillScanInvalidatesTriggerEvenWithLateOutputJournal(t *testing.T) {
	c := pendingOutputCrashM2Control([]int{0, 1, 2})
	lateOutputs := []M2Event{}
	retained := []M2Event{}
	for _, e := range c.e {
		if e.Output != nil && e.Output.AuditID == "pending" {
			lateOutputs = append(lateOutputs, e)
		} else {
			retained = append(retained, e)
		}
	}
	c.e = nil
	for _, e := range retained {
		if e.Audit != nil && e.Audit.ID == "pending" {
			for _, output := range lateOutputs {
				output.ElapsedNS = e.ElapsedNS
				c.e = append(c.e, output)
			}
		}
		c.e = append(c.e, e)
	}
	for i := range c.e {
		c.e[i].Seq = identity.Int64(i + 1)
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "trigger_changed") {
		t.Fatalf("late journal hid pre-kill scan: %+v", r)
	}
}

func TestM2OutputAfterActualKillRequestDoesNotInvalidateEarlierTrigger(t *testing.T) {
	c := pendingOutputCrashM2Control([]int{0, 1, 2})
	var afterRequest identity.Int64
	for _, e := range c.e {
		if e.Worker != nil && e.Worker.Identity.WorkerID == "w2" && e.Worker.Action == "signal" {
			afterRequest = e.Worker.Interval.StartNS + 1
		}
	}
	// The concurrent scan and output observations happen after the actual
	// signal request starts, but before its enclosing receipt finishes. Keep
	// the real request interval intact; receipt completion is not fault time.
	for i := range c.e {
		if c.e[i].Output != nil && c.e[i].Output.AuditID == "pending" {
			c.e[i].ElapsedNS = afterRequest
		}
		if c.e[i].Audit != nil && c.e[i].Audit.ID == "pending" {
			c.e[i].Audit.ScanInterval = M2Interval{StartNS: afterRequest, EndNS: afterRequest}
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Pass {
		t.Fatalf("post-request observations invalidated prior trigger: %+v", r)
	}
}

func TestVisibleCrashTailCandidateCannotReplaceDecodedKnownOutput(t *testing.T) {
	// Given a later destination tail but no decoded record in the claimed
	// visible-unsaved audit; full known output appears only after the crash.
	c := repeatedM2Control()
	kept := c.e[:0]
	for _, e := range c.e {
		if e.Output != nil && e.Output.AuditID == "lag2" {
			continue
		}
		if e.Audit != nil && e.Audit.ID == "lag2" {
			scan := &e.Audit.Scans[0]
			scan.End, scan.Reached, scan.StableEnd = 0, 0, 1
		}
		kept = append(kept, e)
	}
	c.e = kept
	for i := range c.e {
		c.e[i].Seq = identity.Int64(i + 1)
	}
	// When checking the history, Then a possible suspension candidate never
	// satisfies the required known-visible/unsaved crash observation.
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "visible_unsaved") {
		t.Fatalf("unscanned tail became a visible known write: %+v", r)
	}
}

func fullVisibleCrashM2Control() *m2Control {
	c := newM2Control("repeated-kill")
	for _, name := range []string{"1", "2"} {
		worker := "w" + name
		c.worker(worker, "start", "")
		c.audit("lag"+name, []int{}, []identity.Int64{-1, -1, -1}, false, false)
		c.worker(worker, "signal", "SIGKILL")
		c.worker(worker, "exit", "SIGKILL")
		c.worker(worker, "cleanup", "")
		c.settle("stop"+name, []int{}, []identity.Int64{-1, -1, -1}, false, false)
	}
	c.worker("w3", "start", "")
	c.audit("visible", []int{0, 1, 2}, []identity.Int64{0, 0, 0}, false, false)
	c.worker("w3", "signal", "SIGKILL")
	c.worker("w3", "exit", "SIGKILL")
	c.worker("w3", "cleanup", "")
	c.settle("stop3", []int{0, 1, 2}, []identity.Int64{0, 0, 0}, false, false)
	c.worker("w4", "start", "")
	c.worker("w4", "exit", "")
	c.worker("w4", "cleanup", "")
	c.settle("final", []int{0, 0, 1, 1, 2, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill1", Kind: "unresolved-kill", WorkerID: "w1", RecoveryWorkerID: "w2", TriggerAuditID: "lag1", StoppedAuditID: "stop1"}})
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "kill2", Kind: "unresolved-kill", WorkerID: "w2", RecoveryWorkerID: "w3", TriggerAuditID: "lag2", StoppedAuditID: "stop2"}})
	c.add(M2Event{Kind: "episode", Episode: &M2Episode{ID: "visible", Kind: "visible-unsaved-kill", WorkerID: "w3", RecoveryWorkerID: "w4", TriggerAuditID: "visible", VisibleAuditID: "visible", StoppedAuditID: "stop3"}})
	c.finish()
	return c
}

func TestM2CompleteVisibleOutputWithUnsavedPositionsIsASeparateCrash(t *testing.T) {
	// Given two independently observed lag crashes, then all known output
	// visible with a later saved-next0 sample, followed by a third actual crash.
	c := fullVisibleCrashM2Control()
	// When recovery replays all inputs, Then complete visibility does not
	// invalidate that separate unsaved crash or turn permitted copies into loss.
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Pass || r.ReleaseQualified {
		t.Fatal(r)
	}
	// The same full-output audit cannot establish an unresolved-output crash.
	wrongKind := fullVisibleCrashM2Control()
	for _, e := range wrongKind.e {
		if e.Episode != nil && e.Episode.ID == "visible" {
			e.Episode.Kind = "unresolved-kill"
		}
	}
	if got := CheckM2(wrongKind.m, wrongKind.a, wrongKind.e); got.Verdict != Inconclusive || !m2HasCode(got, "kill_trigger") {
		t.Fatalf("complete output was admitted as unresolved output: %+v", got)
	}
	// Removing one prior lag observation cannot be repaired by the complete
	// visible-unsaved crash and complete final output.
	for i := range c.e {
		if c.e[i].Episode != nil && c.e[i].Episode.ID == "kill2" {
			c.e = append(c.e[:i], c.e[i+1:]...)
			break
		}
	}
	for i := range c.e {
		c.e[i].Seq = identity.Int64(i + 1)
	}
	r = CheckM2(c.m, c.a, c.e)
	if r.Verdict != Inconclusive || !m2HasCode(r, "repeated_kill") || m2HasCode(r, "visible_unsaved") {
		t.Fatalf("complete output erased a missing lag crash: %+v", r)
	}
}

func TestM2TransientEmptyAssignmentRetainsUnknownOwnership(t *testing.T) {
	// Given complete final data and an earlier live group observation, When
	// Kafka omits assignments during rebalance, Then ownership remains unknown.
	for _, state := range []string{"PreparingRebalance", "CompletingRebalance"} {
		c := newM2Control("healthy")
		c.worker("w1", "start", "")
		c.audit("transition", []int{}, []identity.Int64{0, 0, 0}, false, false)
		g := &c.e[len(c.e)-1].Audit.Group
		g.State, g.Protocol = state, ""
		g.Members[0].AssignmentBase64 = ""
		c.worker("w1", "exit", "")
		c.worker("w1", "cleanup", "")
		c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
		c.finish()
		if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
			t.Fatal(r)
		}
		assigned, err := m2GroupAssigned(*g, c.m.Group, "input")
		if assigned || err != nil {
			t.Fatalf("unknown became ownership: %v / %v", assigned, err)
		}
		for _, fault := range []string{"truncated", "stable", "unknown state", "protocol", "base64", "duplicate member"} {
			original := *g
			original.Members = append([]M2GroupMember(nil), g.Members...)
			switch fault {
			case "truncated":
				g.Members[0].AssignmentBase64 = "AA=="
			case "stable":
				g.State = "Stable"
			case "unknown state":
				g.State = "other"
			case "protocol":
				g.ProtocolType = "other"
			case "base64":
				g.Members[0].AssignmentBase64 = "AA==\n"
			case "duplicate member":
				g.Members = append(g.Members, g.Members[0])
			}
			if r := CheckM2(c.m, c.a, c.e); r.Verdict != HarnessError || !m2HasCode(r, "group_observation") {
				t.Fatalf("%s concealed %s: %+v", state, fault, r)
			}
			*g = original
		}
	}
	// An unknown assignment also cannot supply the crash trigger's ownership.
	c := repeatedM2Control()
	for _, e := range c.e {
		if e.Audit != nil && e.Audit.ID == "lag1" {
			e.Audit.Group.State = "PreparingRebalance"
			e.Audit.Group.Members[0].AssignmentBase64 = ""
		}
	}
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Inconclusive || !m2HasCode(r, "kill_trigger") {
		t.Fatal(r)
	}
}

func TestM2ExistingVisibleOutputDoesNotProveRecoveryCompletion(t *testing.T) {
	// Given all output visible before the third kill and a started/reaped fourth
	// worker, When final progress stays unsaved, Then recovery is inconclusive.
	for _, offset := range []identity.Int64{-1, 0} {
		c := fullVisibleCrashM2Control()
		for _, e := range c.e {
			if e.Audit != nil && e.Audit.Final {
				e.Audit.Saved[1].Present = offset >= 0
				e.Audit.Saved[1].Source.Offset = offset
			}
		}
		if r := CheckM2(c.m, c.a, c.e); r.Verdict != Inconclusive || !m2HasCode(r, "completion_progress") {
			t.Fatal(r)
		}
	}
	// Complete group-wide saved progress plus complete membership permits
	// replay; no duplicate count or availability deadline is imposed.
	c := fullVisibleCrashM2Control()
	if r := CheckM2(c.m, c.a, c.e); r.Verdict != Pass {
		t.Fatal(r)
	}
}

func TestM2UnfinishedProgressCannotHideIndependentlyProvedViolation(t *testing.T) {
	// Given unfinished safe progress in partition0 and an independently proved
	// data violation elsewhere, When checking the final complete settled audit,
	// Then missing completion cannot demote that violation to INCONCLUSIVE.
	for _, fault := range []string{"unsafe saved prefix", "corruption"} {
		c := newM2Control("healthy")
		c.worker("w1", "start", "")
		c.worker("w1", "exit", "")
		c.worker("w1", "cleanup", "")
		records := []int{0, 1, 2}
		if fault == "unsafe saved prefix" {
			records = []int{0, 2}
		}
		c.settle("final", records, []identity.Int64{0, 1, 1}, true, false)
		if fault == "corruption" {
			for _, e := range c.e {
				if e.Output != nil && e.Output.Destination.Partition == 1 {
					e.Output.Record.Value = identity.NullableBytes{Base64: "WA=="}
				}
			}
		}
		c.finish()
		r := CheckM2(c.m, c.a, c.e)
		code := "unsafe_saved_prefix"
		if fault == "corruption" {
			code = "corrupt_or_unexpected_output"
		}
		if r.Verdict != Violation || !m2HasCode(r, code) || !m2HasCode(r, "completion_progress") {
			t.Fatalf("%s: %+v", fault, r)
		}
	}
}
