package campaign

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

func scenarioTestPlan(t *testing.T) ScenarioPlan {
	t.Helper()
	subject := evidence.Subject{Kind: "published-release", Tag: evidence.ReleaseTag, Commit: evidence.ReleaseCommit, ExecutableSHA256: evidence.ReleaseExecutableSHA256, ContractSHA256: evidence.ContractSHA256, Platform: "linux/amd64", VersionOutput: "kaferry " + evidence.ReleaseTag}
	return ScenarioPlan{ID: "healthy", Routing: "PRESERVE", Directory: t.TempDir(), Executable: filepath.Join(t.TempDir(), "kaferry"), Subject: subject, Artifact: evidence.ArtifactMetadata{Subject: subject, ProvenanceStatus: "verified", ArchiveSHA256: evidence.ReleaseArchiveSHA256}}
}
func TestScenarioRejectsUnreviewedOrUnboundedPlans(t *testing.T) {
	// Given a targeted release plan and individually invalid identity/budget inputs.
	cases := []struct {
		name   string
		change func(*ScenarioPlan)
	}{
		{"unknown case", func(p *ScenarioPlan) { p.ID = "generic-script" }},
		{"unknown route", func(p *ScenarioPlan) { p.Routing = "ANY" }},
		{"relative directory", func(p *ScenarioPlan) { p.Directory = "out" }},
		{"missing release", func(p *ScenarioPlan) { p.Executable = "release" }},
		{"short input", func(p *ScenarioPlan) { p.Records = 7 }},
		{"too much input", func(p *ScenarioPlan) { p.Records = 1025 }},
		{"short budget", func(p *ScenarioPlan) { p.Budget = time.Second }},
		{"cleanup exceeds total budget", func(p *ScenarioPlan) { p.Budget = 8 * time.Minute }},
		{"main drift", func(p *ScenarioPlan) { p.Subject.Commit = strings.Repeat("a", 40) }},
		{"wrong bytes", func(p *ScenarioPlan) { p.Subject.ExecutableSHA256 = strings.Repeat("a", 64) }},
		{"unverified provenance", func(p *ScenarioPlan) { p.Artifact.ProvenanceStatus = "unavailable" }},
		{"unrelated artifact", func(p *ScenarioPlan) { p.Artifact.Subject.Tag = "v999" }},
		{"foreign architecture", func(p *ScenarioPlan) { p.Subject.Platform = "linux/arm64" }},
		{"wire calibration only", func(p *ScenarioPlan) { p.ID = "source-save"; p.WireToolReceipt = "/tmp/receipt.json" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := scenarioTestPlan(t)
			tc.change(&p)
			// When the entry plan is admitted, Then no invalid plan can start resources.
			if _, err := normalizeScenarioPlan(p); err == nil {
				t.Fatal("invalid scenario admitted")
			}
		})
	}
	p, err := normalizeScenarioPlan(scenarioTestPlan(t))
	if err != nil || p.Records != 96 || p.Budget != 5*time.Minute {
		t.Fatalf("bounded defaults: %+v / %v", p, err)
	}
}

func scenarioSyntheticOutput(t *testing.T) (evidence.Ledger, kafkaScanSnapshot) {
	t.Helper()
	source, destination, inputs, attempts, sourceScans := syntheticKafkaSource(t)
	ledger, err := kafkaSourceLedger(source, destination, "PRESERVE", inputs, attempts, sourceScans)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := kafkaScanSnapshot{Topic: destination, Before: make([]observer.Boundary, destination.Partitions), After: make([]observer.Boundary, destination.Partitions), Scans: make([]observer.Scan, destination.Partitions)}
	for p := range destination.Partitions {
		snapshot.Scans[p] = observer.Scan{Cluster: destination.ClusterID, Topic: destination.Topic, TopicID: destination.TopicID, Partition: p, Records: []observer.Observed{}}
	}
	for _, entry := range ledger.Entries {
		scan := &snapshot.Scans[entry.Source.Partition]
		offset := identity.Int64(len(scan.Records))
		scan.Records = append(scan.Records, observer.Observed{Partition: scan.Partition, Offset: offset, Position: kafkaPosition(destination, scan.Partition, int64(offset)), Record: entry.Record})
	}
	scenarioSyntheticBounds(&snapshot)
	return ledger, snapshot
}
func scenarioSyntheticBounds(snapshot *kafkaScanSnapshot) {
	for p := range snapshot.Scans {
		scan := &snapshot.Scans[p]
		for i := range scan.Records {
			scan.Records[i].Offset = identity.Int64(i)
			scan.Records[i].Position = kafkaPosition(snapshot.Topic, int32(p), int64(i))
		}
		scan.End = int64(len(scan.Records))
		scan.Next = scan.End
		scan.Boundary = observer.Boundary{HighWatermark: scan.End, LastStable: scan.End}
		snapshot.Before[p] = scan.Boundary
		snapshot.After[p] = scan.Boundary
	}
}
func TestScenarioMembershipDoesNotLetReplayReplaceLostStressRecord(t *testing.T) {
	// Given complete independent synthetic scans and a unique stress obligation.
	ledger, output := scenarioSyntheticOutput(t)
	complete, err := scenarioMembership(ledger, output)
	if err != nil || len(complete.Missing) != 0 {
		t.Fatal(complete, err)
	}
	var lostID string
	for _, entry := range ledger.Entries {
		if entry.ID == "input-0009" {
			lostID = entry.ID
		}
	}
	if lostID == "" {
		t.Fatal("missing test obligation")
	}
	scan := &output.Scans[0]
	// When one distinct input is lost and a replay of another keeps counts equal.
	scan.Records[len(scan.Records)-1] = scan.Records[0]
	scenarioSyntheticBounds(&output)
	got, err := scenarioMembership(ledger, output)
	// Then equal record totals cannot conceal that missing logical input.
	if err != nil || !reflect.DeepEqual(got.Missing, []string{lostID}) {
		t.Fatalf("loss hidden by replay: %+v / %v", got, err)
	}
	scan.Records = append(scan.Records, scan.Records[0])
	scenarioSyntheticBounds(&output)
	got, err = scenarioMembership(ledger, output)
	if err != nil || !reflect.DeepEqual(got.Missing, []string{lostID}) {
		t.Fatalf("duplicate changed obligations: %+v / %v", got, err)
	}
}
func TestScenarioMembershipRejectsCorruptionRoutesAndPartialScans(t *testing.T) {
	// Given complete output, independently corrupt one byte, route or scan end.
	for _, change := range []string{"null-empty", "route", "incomplete"} {
		t.Run(change, func(t *testing.T) {
			ledger, output := scenarioSyntheticOutput(t)
			switch change {
			case "null-empty":
				output.Scans[0].Records[0].Record.Value = identity.NewNullableBytes(nil)
			case "route":
				r := output.Scans[0].Records[0]
				output.Scans[0].Records = output.Scans[0].Records[1:]
				r.Partition = 3
				output.Scans[3].Records = append(output.Scans[3].Records, r)
				scenarioSyntheticBounds(&output)
			case "incomplete":
				output.Scans[0].Next--
			}
			// When matching the observations, Then they cannot establish safe membership.
			if _, err := scenarioMembership(ledger, output); err == nil {
				t.Fatal("corrupt, misrouted or incomplete output accepted")
			}
		})
	}
}
func TestVisibleUnsavedUsesNextOffsetAndExactSourceIdentity(t *testing.T) {
	// Given one positively observed stress record at source offset zero.
	ledger, output := scenarioSyntheticOutput(t)
	entry := ledger.Entries[0]
	visible := scenarioMembershipResult{Visible: map[string]bool{entry.ID: true}}
	group := kafkaGroupSnapshot{Offsets: kafkaOffsetSnapshot{Offsets: []kafkaSavedOffset{{Source: entry.Source, Saved: true}}}}
	if !scenarioVisibleUnsaved(ledger, visible, group) {
		t.Fatal("saved next zero wrongly covers offset zero")
	}
	// When the saved next offset advances, Then the earlier visible record is saved.
	group.Offsets.Offsets[0].Source.Offset++
	if scenarioVisibleUnsaved(ledger, visible, group) {
		t.Fatal("saved record claimed as unsaved")
	}
	group.Offsets.Offsets[0] = kafkaSavedOffset{Source: entry.Source, Saved: false}
	group.Offsets.Offsets[0].Source.Offset = -1
	if !scenarioVisibleUnsaved(ledger, visible, group) {
		t.Fatal("absence -1 not distinguished from saved zero")
	}
	group.Offsets.Offsets[0].Source.TopicID = "foreign"
	if scenarioVisibleUnsaved(ledger, visible, group) {
		t.Fatal("foreign topic established unsaved window")
	}
	group.Error = "OffsetFetch failed"
	if scenarioVisibleUnsaved(ledger, visible, group) {
		t.Fatal("failed offsets established unsaved window")
	}
	// Output itself is independently complete; the function does not inspect process logs.
	if _, err := output.Outputs("proof"); err != nil {
		t.Fatal(err)
	}
}
func TestEarlyOwnershipReceiptsRetainCampaignClockAfterLedger(t *testing.T) {
	// Given ownership observations before finite source verification.
	c := &scenarioController{origin: time.Now(), report: &ScenarioReport{RunID: "clock-test"}}
	broker := evidence.M2Broker{Action: "inspect", Interval: evidence.M2Interval{StartNS: 0, EndNS: 0}}
	c.appendEvent(evidence.M2Event{Kind: "broker", Broker: &broker})
	if len(c.events) != 0 {
		t.Fatal("setup receipt preceded ledger")
	}
	ledger := evidence.Ledger{}
	// When the verified ledger is recorded, Then setup facts keep their own intervals.
	c.appendEvent(evidence.M2Event{Kind: "ledger", Ledger: &ledger})
	if len(c.events) != 2 || c.events[0].Kind != "ledger" || c.events[1].Broker.Interval != broker.Interval || c.events[1].ElapsedNS < c.events[0].ElapsedNS || c.events[1].Seq != 2 {
		t.Fatal(c.events)
	}
}
func TestAuditAdapterRetainsAssignmentAndUnsampledDestinationTail(t *testing.T) {
	// Given a complete scan to sampled end, followed by a separately observed newer tail.
	ledger, output := scenarioSyntheticOutput(t)
	output.After[0].HighWatermark++
	output.After[0].LastStable++
	group := kafkaGroupSnapshot{GroupID: "synthetic-group", Description: kafkaGroupDescription{GroupID: "synthetic-group", State: "Stable", Members: []kafkaMemberSnapshot{{ID: "member-a", ClientID: "kaferry-synthetic-group", AssignmentBase64: base64.StdEncoding.EncodeToString([]byte{0, 1})}}}}
	c := &scenarioController{origin: time.Now(), report: &ScenarioReport{RunID: "adapter-test"}, events: []evidence.M2Event{{Kind: "ledger", Ledger: &ledger}}}
	if err := c.auditEvent("sample", output, group, scenarioInterval{}, scenarioInterval{}, false, false); err != nil {
		t.Fatal(err)
	}
	audit := c.events[len(c.events)-1].Audit
	if audit.Scans[0].StableEnd <= audit.Scans[0].End {
		t.Fatal("unscanned observed tail silently normalized")
	}
	if audit.Group.GroupID != group.GroupID || audit.Group.Members[0].AssignmentBase64 != group.Description.Members[0].AssignmentBase64 {
		t.Fatal("independent group receipt discarded")
	}
	// Then the retained event is ordinary strict JSON, without embedding raw SQL in diagnostics.
	if _, err := json.Marshal(audit); err != nil {
		t.Fatal(err)
	}
}

func TestLateScenarioPersistenceFailureInvalidatesOnlyCompletion(t *testing.T) {
	// Given a new closed bundle and retained raw receipt, force the final report
	// write to fail through exclusive-file collision, without process hooks.
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{evidence.CompleteName, evidence.EventsName} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "scenario.json"), []byte("existing report"), 0600); err != nil {
		t.Fatal(err)
	}
	// When final report persistence fails, Then this run cannot recheck as a
	// complete bundle, and the events and earlier report are retained unchanged.
	if err := persistProcessJSON(root, "scenario.json", ScenarioReport{}); err == nil {
		t.Fatal("exclusive report replacement unexpectedly allowed")
	}
	if err := invalidateScenarioCompletion(bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bundle, evidence.CompleteName)); !os.IsNotExist(err) {
		t.Fatalf("completion marker survives: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(bundle, evidence.EventsName)); err != nil || string(raw) != evidence.EventsName {
		t.Fatal("failed evidence discarded", err)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "scenario.json")); err != nil || string(raw) != "existing report" {
		t.Fatal("earlier report replaced", err)
	}
	if err := invalidateScenarioCompletion(bundle); err != nil {
		t.Fatal("missing marker invalidation is not idempotent", err)
	}
}
