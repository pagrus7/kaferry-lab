package campaign

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func liveCampaignState(t *testing.T) fixture.State {
	t.Helper()
	id, source, destination := os.Getenv("LAB_RUN_ID"), os.Getenv("LAB_SOURCE_ADDR"), os.Getenv("LAB_DEST_ADDR")
	if id == "" && source == "" && destination == "" {
		t.Skip("owned live fixture opt-in absent")
	}
	if _, err := fixture.StatePath(id); err != nil || source == "" || destination == "" {
		t.Fatalf("incomplete owned fixture opt-in: %v", err)
	}
	// Go runs this test from its package directory; fixture state belongs to
	// the repository root where the fixture command created it.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	state, err := fixture.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Source != source || state.Destination != destination {
		t.Fatal("live endpoints differ from the owned fixture manifest")
	}
	return state
}

func logLiveCampaign(t *testing.T, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(name + " " + string(raw))
}

func TestLiveM2ControllerCalibration(t *testing.T) {
	// Given only this run's two disposable brokers and independently known input.
	state := liveCampaignState(t)
	t.Log("CONTROLLER CALIBRATION ONLY: no Kaferry subject or qualification")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	k, preparation, err := openKafka(ctx, state, kafkaPlan{Routing: "PRESERVE", Records: 16}, fixture.Docker)
	logLiveCampaign(t, "preparation", preparation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := k.Close(); err != nil {
			t.Errorf("close calibration clients: %v", err)
		}
	})
	source, _, err := openOwnedBroker(ctx, state, "source", fixture.Docker)
	if err != nil {
		t.Fatal(err)
	}
	destination, _, err := openOwnedBroker(ctx, state, "destination", fixture.Docker)
	if err != nil {
		t.Fatal(err)
	}
	// Register restoration before the first fault. The fixture owner retains
	// broker logs/state and removes the exact labeled resources after this test.
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 90*time.Second)
		defer done()
		for _, broker := range []*ownedBroker{source, destination} {
			restored, err := broker.Restore(cleanup)
			logLiveCampaign(t, "cleanup_restore", restored)
			if err != nil || !restored.Reached {
				t.Errorf("restore calibration broker: %v", err)
			}
		}
	})
	for _, warmup := range []bool{true, false} {
		attempts, err := k.Publish(ctx, warmup)
		logLiveCampaign(t, "publication", attempts)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := k.VerifyInputs(ctx, warmup)
		logLiveCampaign(t, "input_verification", verified)
		want := 16
		if warmup {
			want = 3
		}
		if err != nil || !verified.Complete || len(verified.Ledger.Entries) != want {
			t.Fatalf("finite input readback: %d entries, complete=%t, error=%v", len(verified.Ledger.Entries), verified.Complete, err)
		}
	}
	output, err := k.SnapshotOutput(ctx)
	logLiveCampaign(t, "empty_destination", output)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := output.Outputs("initial")
	if err != nil || len(observed) != 0 {
		t.Fatalf("unused destination is not independently empty: %d / %v", len(observed), err)
	}
	group, err := k.SnapshotGroup(ctx, k.Preparation.Source.Topic+"-not-started")
	logLiveCampaign(t, "absent_group", group)
	if err != nil {
		t.Fatal(err)
	}
	if len(group.Offsets.Offsets) != 3 {
		t.Fatal("missing explicit absent offset observations")
	}
	for _, offset := range group.Offsets.Offsets {
		if offset.Saved || offset.Source.Offset != -1 {
			t.Fatal("absent progress was changed into a saved position")
		}
	}
	// When an owned destination pauses, both Docker and a fresh Kafka request
	// must observe the impairment; restoration must independently reach Kafka.
	paused, err := destination.Pause(ctx)
	logLiveCampaign(t, "pause", paused)
	if err != nil || !paused.Reached || !paused.RecoveryNeeded {
		t.Fatalf("pause not reached: %v", err)
	}
	restored, err := destination.Restore(ctx)
	logLiveCampaign(t, "restore", restored)
	if err != nil || !restored.Reached || restored.RecoveryNeeded {
		t.Fatalf("recovery not reached: %v", err)
	}
	for _, broker := range []*ownedBroker{destination, source} {
		restarted, err := broker.Restart(ctx)
		logLiveCampaign(t, "restart", restarted)
		if err != nil || !restarted.Reached || restarted.RecoveryNeeded {
			t.Fatalf("restart not reached: %v", err)
		}
	}
	// Then retained source bytes/identities survive these process restarts.
	recovery, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	for {
		verified, err := k.VerifyInputs(recovery, false)
		logLiveCampaign(t, "recovered_input", verified)
		if err == nil && verified.Complete && len(verified.Ledger.Entries) == 16 {
			break
		}
		// An API response can precede topic metadata readiness. Retain those
		// preread failures, but never retry a scan or byte-verification failure.
		if len(verified.Snapshot.Scans) != 0 {
			t.Fatalf("recovered input scan cannot be checked: %v", err)
		}
		select {
		case <-recovery.Done():
			t.Fatalf("recovered input unavailable within budget: %v / %v", err, recovery.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
