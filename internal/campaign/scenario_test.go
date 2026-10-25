package campaign

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
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
	if err := invalidateScenarioCompletion(bundle, true); err != nil {
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
	if err := invalidateScenarioCompletion(bundle, true); err != nil {
		t.Fatal("missing marker invalidation is not idempotent", err)
	}
}

func TestScenarioWorkDeadlineIsLatchedBeforeIndependentCleanup(t *testing.T) {
	cases := []struct {
		name                                   string
		work, cleanup                          time.Duration
		cancelWork, wantTimedOut, wantComplete bool
	}{
		{name: "cleanup crosses completed work deadline", work: 59 * time.Second, cleanup: 2 * time.Second, wantComplete: true},
		{name: "work really expired", work: 61 * time.Second, cleanup: 2 * time.Second, wantTimedOut: true},
		{name: "cleanup really expired", work: 59 * time.Second, cleanup: 21 * time.Second},
		{name: "work cancelled", work: 59 * time.Second, cleanup: 2 * time.Second, cancelWork: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given independently bounded work and cleanup phases under the fake clock.
				work, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				time.Sleep(tc.work)
				if tc.cancelWork {
					cancel()
				}
				synctest.Wait()
				workErr, timedOut := scenarioWorkEnd(work)
				cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
				defer done()
				// When only cleanup crosses the old deadline, its own allowance still applies.
				time.Sleep(tc.cleanup)
				synctest.Wait()
				cleanupErr := cleanup.Err()
				c := &scenarioController{origin: time.Now(), report: &ScenarioReport{RunID: "phase-control"}}
				c.finishEvent(timedOut, errors.Join(workErr, cleanupErr) == nil)
				finished := c.preledger[len(c.preledger)-1].Finished
				// Then the finished receipt preserves the work result captured before cleanup.
				if finished.TimedOut != tc.wantTimedOut || finished.CleanupComplete != tc.wantComplete {
					t.Fatalf("phase result %+v; latched work %v; cleanup %v", finished, workErr, cleanupErr)
				}
				if work.Err() == nil {
					t.Fatal("control did not actually cross the old work deadline")
				}
				if tc.name == "cleanup really expired" && !errors.Is(cleanupErr, context.DeadlineExceeded) {
					t.Fatal("cleanup timeout not reached")
				}
			})
		})
	}
}

func TestScenarioPriorBundleCollisionPreservesEveryPriorByte(t *testing.T) {
	// Given evidence that belongs to an earlier run in a caller-supplied directory.
	directory := t.TempDir()
	bundle := filepath.Join(directory, "bundle")
	if err := os.Mkdir(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	prior := map[string]string{evidence.CompleteName: "original completion", evidence.EventsName: "original events"}
	for name, body := range prior {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// When admission sees the collision, Then it refuses before reserving runtime
	// or operating a broker. A later exclusive-writer collision owns no marker.
	if err := reserveScenarioRuntime(directory); !errors.Is(err, os.ErrExist) {
		t.Fatalf("prior bundle was admitted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "runtime")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime reserved before collision refusal: %v", err)
	}
	c := &scenarioController{
		plan:   ScenarioPlan{Directory: directory},
		report: &ScenarioReport{},
		manifest: evidence.M2Manifest{
			SchemaVersion:  evidence.M2SchemaVersion,
			CheckerVersion: evidence.M2CheckerVersion,
			Settings:       evidence.M2Settings{Args: []string{}, Environment: []string{}},
		},
		events: []evidence.M2Event{{Kind: "run_finished", Finished: &evidence.RunFinished{}}},
	}
	reserved, err := c.writeBundle()
	if !errors.Is(err, os.ErrExist) || reserved {
		t.Fatalf("collision did not preserve reservation ownership: reserved=%v error=%v", reserved, err)
	}
	if err := invalidateScenarioCompletion(bundle, reserved); err != nil {
		t.Fatal(err)
	}
	for name, body := range prior {
		if raw, err := os.ReadFile(filepath.Join(bundle, name)); err != nil || string(raw) != body {
			t.Fatalf("prior %s changed: %q / %v", name, raw, err)
		}
	}
}

func TestScenarioRejectsOutputSymlinksBeforeRuntimeReservation(t *testing.T) {
	// Given a bundle symlink that refers to another retained evidence directory.
	directory := t.TempDir()
	prior := t.TempDir()
	if err := os.WriteFile(filepath.Join(prior, evidence.CompleteName), []byte("prior"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(prior, filepath.Join(directory, "bundle")); err != nil {
		t.Fatal(err)
	}
	// When reserving this scenario's outputs, Then no linked prior bytes change.
	if err := reserveScenarioRuntime(directory); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(prior, evidence.CompleteName)); err != nil || string(raw) != "prior" {
		t.Fatal("linked marker changed", err)
	}
}

func TestScenarioRawJournalRetainsFailedAndCompleteAttempts(t *testing.T) {
	// Given a mandatory append-only journal without a second memory history.
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	c := &scenarioController{log: file}
	observations := []scenarioObservation{{Kind: "readiness", Error: "not ready"}, {Kind: "output_scan", Output: &kafkaScanSnapshot{Scans: []observer.Scan{}}}}
	// When each attempt is retained, Then every original fact can be read back.
	for _, observation := range observations {
		if err := c.retain(observation); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != len(observations) {
		t.Fatalf("journal lost attempts: %s", raw)
	}
	for i, line := range lines {
		var got scenarioObservation
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, observations[i]) {
			t.Fatalf("attempt %d changed: %+v", i, got)
		}
	}
}

func TestScenarioGeneratedSQLMatchesIndependentlyReviewedCheckerFixture(t *testing.T) {
	// Given an independently authored literal also admitted by the checker history.
	expected, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "m2-configuration.sql"))
	if err != nil {
		t.Fatal(err)
	}
	preparation := kafkaPreparation{Source: kafkaTopic{Topic: "input"}, Destination: kafkaTopic{Topic: "output"}}
	// When the actual controller generates its invocation, Then endpoint, topic,
	// group, route and explicit wire-client settings match that reviewed contract.
	sql, _ := scenarioConfiguration(fixture.State{Source: "127.0.0.1:19092", Destination: "127.0.0.1:29092"}, preparation, "explicit-group", "PRESERVE")
	if sql != string(expected) {
		t.Fatalf("generated SQL differs from independent checker fixture\ngot: %q\nwant: %q", sql, expected)
	}
}

func TestScenarioJournalFailureCannotBecomeSuccessfulReadinessRetry(t *testing.T) {
	// Given a failed mandatory journal followed by an available new file.
	directory := t.TempDir()
	failed, err := os.Create(filepath.Join(directory, "failed.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	c := &scenarioController{log: failed}
	first := c.retain(scenarioObservation{Kind: "readiness"})
	if first == nil {
		t.Fatal("closed journal accepted")
	}
	recovered, err := os.Create(filepath.Join(directory, "later.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	c.log = recovered
	// When readiness would otherwise retry successfully, Then the original
	// missing evidence remains fatal and no replacement history is written.
	if next := c.retain(scenarioObservation{Kind: "readiness"}); next != first {
		t.Fatalf("journal failure was forgotten: %v / %v", first, next)
	}
	if info, err := recovered.Stat(); err != nil || info.Size() != 0 {
		t.Fatal("replacement journal concealed missing facts", err)
	}
	calls := 0
	_, err = scenarioReadyGroup(context.Background(), func(context.Context) (kafkaGroupSnapshot, error) {
		calls++
		return kafkaGroupSnapshot{}, errors.Join(io.EOF, c.retain(scenarioObservation{Kind: "group_preparation"}))
	})
	if err == nil || calls != 1 {
		t.Fatalf("failed journal retried beside transport error: calls=%d error=%v", calls, err)
	}
}

func TestScenarioCleanupCannotIgnoreExpiredBudgetWithoutResources(t *testing.T) {
	// Given cleanup's own already-expired numerical budget and no live resource.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	// When cleanup finishes without a resource operation, Then expiration still
	// prevents a claim that cleanup completed within its configured allowance.
	if err := (&scenarioController{}).cleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired cleanup passed", err)
	}
}

func TestScenarioPreparationRetriesOnlyAvailabilityFailures(t *testing.T) {
	// Given transport failures, broker availability codes, and permanent failures.
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EOF", io.EOF, true},
		{"wrapped reset", fmt.Errorf("metadata: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"leader unavailable", sarama.ErrLeaderNotAvailable, true},
		{"coordinator loading", sarama.ErrOffsetsLoadInProgress, true},
		{"coordinator unavailable", sarama.ErrConsumerCoordinatorNotAvailable, true},
		{"wrong coordinator", sarama.ErrNotCoordinatorForConsumer, true},
		{"joined availability", errors.Join(io.EOF, sarama.ErrNotCoordinatorForConsumer), true},
		{"authorization", sarama.ErrGroupAuthorizationFailed, false},
		{"CRC", sarama.ErrInvalidMessage, false},
		{"identity", errors.New("Kafka topic or cluster identity changed"), false},
		{"layout", errors.New("Kafka topic partition layout changed or missing"), false},
		{"retention", errors.New("snapshot exceeds finite retained nontransactional topic bounds"), false},
		{"malformed plus transport", errors.Join(io.EOF, errors.New("missing partition")), false},
		{"receipt plus transport", errors.Join(io.EOF, errors.New("scenario journal persistence failed")), false},
		{"cancellation", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When preparation decides whether another probe is permitted,
			// Then an availability error cannot conceal a permanent failure.
			if got := scenarioTransientPreparation(tc.err); got != tc.want {
				t.Fatalf("retry=%v, want %v: %v", got, tc.want, tc.err)
			}
		})
	}
}

func TestScenarioScanPreparationNeverRetriesStartedScans(t *testing.T) {
	cases := []struct {
		name      string
		scans     []observer.Scan
		err       error
		wantCalls int
	}{
		{"preread EOF", nil, io.EOF, 2},
		{"partial first partition EOF", []observer.Scan{{Partition: 0, Start: 0, End: 2, Next: 1}}, io.EOF, 1},
		{"first scan empty EOF", []observer.Scan{{Partition: 0}}, io.EOF, 1},
		{"finished scan then metadata EOF", []observer.Scan{{Partition: 0, End: 1, Next: 1}}, io.EOF, 1},
		{"CRC after scan starts", []observer.Scan{{Partition: 0}}, sarama.ErrInvalidMessage, 1},
		{"fidelity mismatch", []observer.Scan{{Partition: 0}}, errors.New("unknown, corrupt or misrouted bytes"), 1},
		{"identity before scan", nil, errors.New("Kafka topic or cluster identity changed"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given a failed snapshot followed by an available successful snapshot.
				failed := kafkaScanSnapshot{Scans: tc.scans, Error: tc.err.Error()}
				calls := 0
				read := func(context.Context) (kafkaScanSnapshot, error) {
					calls++
					if calls == 1 {
						return failed, tc.err
					}
					return kafkaScanSnapshot{}, nil
				}
				// When destination readiness is sampled, Then only a preread
				// availability failure may be followed by another snapshot.
				got, err := scenarioReadyOutput(context.Background(), read)
				if calls != tc.wantCalls || (err == nil) != (tc.wantCalls == 2) {
					t.Fatalf("output calls=%d error=%v", calls, err)
				}
				if err != nil && !reflect.DeepEqual(got, failed) {
					t.Fatal("failed destination snapshot was discarded")
				}
				// The same restriction applies to retained source verification.
				calls = 0
				v, err := scenarioReadyInputs(context.Background(), func(ctx context.Context) (kafkaInputVerification, error) {
					s, e := read(ctx)
					return kafkaInputVerification{Snapshot: s, Complete: e == nil}, e
				})
				if calls != tc.wantCalls || (err == nil) != (tc.wantCalls == 2) || (err != nil && !reflect.DeepEqual(v.Snapshot, failed)) {
					t.Fatalf("input calls=%d verification=%+v error=%v", calls, v, err)
				}
			})
		})
	}
}

func TestScenarioGroupPreparationRetainsEachFailedProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	synctest.Test(t, func(t *testing.T) {
		// Given literal unavailable and moved-coordinator responses for one
		// named group, followed by a successful readiness response.
		c := &scenarioController{log: file, origin: time.Now()}
		failures := []error{sarama.ErrConsumerCoordinatorNotAvailable, sarama.ErrNotCoordinatorForConsumer, nil}
		calls := 0
		group, err := scenarioReadyGroup(context.Background(), func(context.Context) (kafkaGroupSnapshot, error) {
			e := failures[calls]
			calls++
			g := kafkaGroupSnapshot{GroupID: "named-group", Error: scenarioError(e), Description: kafkaGroupDescription{GroupID: "named-group", State: "Dead"}}
			if e != nil {
				g.Description.ErrorCode = int16(e.(sarama.KError))
			}
			return g, errors.Join(e, c.retain(scenarioObservation{Kind: "group_preparation", Group: &g, Error: scenarioError(e)}))
		})
		// When readiness succeeds, Then all previous failed probes still exist.
		if err != nil || calls != 3 || group.Error != "" || group.GroupID != "named-group" {
			t.Fatalf("calls=%d group=%+v error=%v", calls, group, err)
		}
	})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lost group attempts: %s", raw)
	}
	for i, line := range lines {
		var receipt scenarioObservation
		if err := json.Unmarshal([]byte(line), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Group == nil || receipt.Group.GroupID != "named-group" || (receipt.Error != "") != (i < 2) {
			t.Fatalf("changed probe %d: %+v", i, receipt)
		}
	}
}

func TestScenarioPreparationStopsAtAttemptAndContextBounds(t *testing.T) {
	cases := []struct {
		name         string
		deadline     time.Duration
		cancelInRead bool
		delayRead    time.Duration
		wantCalls    int
		wantError    error
	}{
		{"already expired", -time.Second, false, 0, 0, context.DeadlineExceeded},
		{"attempt limit", time.Minute, false, 0, 12, io.EOF},
		{"deadline during poll", 100 * time.Millisecond, false, 0, 1, context.DeadlineExceeded},
		{"cancel before next probe", time.Minute, true, 0, 1, context.Canceled},
		{"late successful probe", time.Minute, false, 16 * time.Second, 1, context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given an unavailable coordinator or a probe completing after its deadline.
				ctx, cancel := context.WithTimeout(context.Background(), tc.deadline)
				defer cancel()
				calls := 0
				_, err := scenarioReadyGroup(ctx, func(context.Context) (kafkaGroupSnapshot, error) {
					calls++
					if tc.cancelInRead {
						cancel()
						return kafkaGroupSnapshot{}, nil
					}
					if tc.delayRead > 0 {
						time.Sleep(tc.delayRead)
						return kafkaGroupSnapshot{}, nil
					}
					return kafkaGroupSnapshot{}, io.EOF
				})
				// When bounded readiness ends, Then it cannot run extra probes
				// or accept a response after cancellation/deadline expiry.
				if calls != tc.wantCalls || !errors.Is(err, tc.wantError) {
					t.Fatalf("calls=%d error=%v, want %d / %v", calls, err, tc.wantCalls, tc.wantError)
				}
			})
		})
	}
}

func TestVisibleCrashCandidateNeedsKnownBytesAfterSuspension(t *testing.T) {
	// Given full input but no decoded destination records, with one later tail.
	ledger, output := scenarioSyntheticOutput(t)
	for p := range output.Scans {
		output.Scans[p].Records = nil
	}
	scenarioSyntheticBounds(&output)
	if scenarioObservedNewTail(output) {
		t.Fatal("unchanged empty output became a candidate")
	}
	output.After[0].HighWatermark = 1
	output.After[0].LastStable = 1
	// When the tail advances beyond the sampled scan, Then it can prompt STOP
	// and a fresh full audit, but cannot satisfy visible-known-byte evidence.
	if !scenarioObservedNewTail(output) {
		t.Fatal("observed unscanned tail was ignored")
	}
	membership, err := scenarioMembership(ledger, output)
	if err != nil || len(membership.Visible) != 0 || scenarioVisibleUnsaved(ledger, membership, kafkaGroupSnapshot{}) {
		t.Fatal("tail alone was promoted to known visible output", membership, err)
	}
	output.Error = "incomplete transport observation"
	if scenarioObservedNewTail(output) {
		t.Fatal("failed observation prompted a candidate")
	}
	output.Error = ""
	output.After = nil
	if scenarioObservedNewTail(output) {
		t.Fatal("missing boundary observation prompted a candidate")
	}
}
