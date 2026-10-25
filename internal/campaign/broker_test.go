package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

// All Docker and Kafka observations here are synthetic controller calibration.
// These mocks neither execute containers nor establish release fault coverage.
type brokerCalibration struct {
	state                                        fixture.State
	id, name                                     string
	running, paused                              bool
	started                                      string
	calls                                        [][]string
	probes                                       int
	inspectErr, pauseErr, unpauseErr, restartErr error
	pauseUnchanged, restartUnchanged             bool
	mutate                                       func(map[string]any)
	probeResult                                  func(context.Context, string) (brokerProbeResult, error)
}

func newBrokerCalibration() *brokerCalibration {
	id := "synthetic-broker"
	prefix := "kaferry-lab-" + id
	return &brokerCalibration{
		state: fixture.State{RunID: id, Image: fixture.Image, Network: prefix, Containers: []string{prefix + "-source", prefix + "-dest"}, Source: "127.0.0.1:21092", Destination: "127.0.0.1:22092"},
		id:    strings.Repeat("a", 64), name: prefix + "-dest", running: true, started: "2026-10-24T01:00:00Z",
	}
}

func (f *brokerCalibration) execute(ctx context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) >= 3 && args[0] == "container" && args[1] == "inspect" {
		if args[2] != f.name && args[2] != f.id {
			return nil, errors.New("synthetic inspect of unrelated target")
		}
		if f.inspectErr != nil {
			return []byte("synthetic missing resource"), f.inspectErr
		}
		hostPort := "22092"
		if strings.HasSuffix(f.name, "-source") {
			hostPort = "21092"
		}
		port := []map[string]string{{"HostIp": "127.0.0.1", "HostPort": hostPort}}
		info := map[string]any{
			"Id": f.id, "Name": "/" + f.name, "Image": "sha256:" + strings.Repeat("b", 64),
			"Config":          map[string]any{"Image": fixture.Image, "Labels": map[string]string{brokerOwnerLabel: f.state.RunID}},
			"State":           map[string]any{"Running": f.running, "Paused": f.paused, "StartedAt": f.started},
			"HostConfig":      map[string]any{"PortBindings": map[string]any{"19092/tcp": port}},
			"NetworkSettings": map[string]any{"Ports": map[string]any{"19092/tcp": port}},
		}
		if f.mutate != nil {
			f.mutate(info)
		}
		return json.Marshal(info)
	}
	if len(args) < 2 || args[len(args)-1] != f.id {
		return nil, errors.New("synthetic mutation did not target retained container ID")
	}
	switch args[0] {
	case "pause":
		if f.pauseErr != nil {
			return []byte("synthetic pause failure"), f.pauseErr
		}
		if !f.pauseUnchanged {
			f.paused = true
		}
	case "unpause":
		if f.unpauseErr != nil {
			return []byte("synthetic unpause failure"), f.unpauseErr
		}
		f.paused = false
	case "restart":
		if f.restartErr != nil {
			return []byte("synthetic restart failure"), f.restartErr
		}
		if !f.restartUnchanged {
			f.started = "2026-10-24T01:01:00Z"
		}
		f.running = true
	default:
		return nil, errors.New("unrequested synthetic Docker operation")
	}
	return []byte(f.id + "\n"), nil
}

func (f *brokerCalibration) probe(ctx context.Context, endpoint string) (brokerProbeResult, error) {
	f.probes++
	expectedEndpoint := f.state.Destination
	if strings.HasSuffix(f.name, "-source") {
		expectedEndpoint = f.state.Source
	}
	if endpoint != expectedEndpoint {
		return brokerProbeResult{}, errors.New("synthetic probe targeted unrelated endpoint")
	}
	if f.probeResult != nil {
		return f.probeResult(ctx, endpoint)
	}
	if f.paused || !f.running {
		return brokerProbeResult{Unavailable: true, Failure: "timeout", TransportError: "synthetic Kafka request timeout"}, nil
	}
	return brokerProbeResult{Available: true, APIKeys: 1}, nil
}

func (f *brokerCalibration) mutations() int {
	count := 0
	for _, args := range f.calls {
		if args[0] != "container" {
			count++
		}
	}
	return count
}

func openCalibrationBroker(t *testing.T, f *brokerCalibration) *ownedBroker {
	t.Helper()
	b, snapshot, err := openBrokerWithProbe(context.Background(), f.state, "destination", f.execute, f.probe, true)
	if err != nil {
		t.Fatalf("open synthetic broker: %+v %v", snapshot, err)
	}
	return b
}

func TestBrokerCalibrationNormalLifecycleRetainsReachedAndRecoveredEvidence(t *testing.T) {
	// Given a uniquely identified, running synthetic destination and fixed binding.
	f := newBrokerCalibration()
	b := openCalibrationBroker(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// When paused, restored, then restarted at an audit boundary.
	pause, err := b.Pause(ctx)
	if err != nil || !pause.Reached || !pause.RecoveryNeeded {
		t.Fatalf("pause: %+v %v", pause, err)
	}
	restore, err := b.Restore(ctx)
	if err != nil || !restore.Reached || restore.RecoveryNeeded {
		t.Fatalf("restore: %+v %v", restore, err)
	}
	restart, err := b.Restart(ctx)
	if err != nil || !restart.Reached || restart.RecoveryNeeded {
		t.Fatalf("restart: %+v %v", restart, err)
	}
	// Then every mutation targets the immutable ID and every state has API evidence.
	if f.mutations() != 3 || f.probes != 3 {
		t.Fatalf("operations=%v probes=%d", f.calls, f.probes)
	}
	previousEnd := int64(0)
	for _, observation := range []brokerObservation{pause, restore, restart} {
		if !observation.Calibration || observation.Request == nil || observation.Request.ContainerID != f.id || observation.Request.Output != f.id+"\n" {
			t.Fatalf("missing request evidence: %+v", observation)
		}
		if observation.Interval.StartElapsedNanoseconds < 0 || observation.Interval.EndElapsedNanoseconds < observation.Interval.StartElapsedNanoseconds {
			t.Fatalf("invalid monotonic interval: %+v", observation.Interval)
		}
		if observation.Interval.StartElapsedNanoseconds < previousEnd {
			t.Fatal("lifecycle intervals overlap")
		}
		previousEnd = observation.Interval.EndElapsedNanoseconds
		check := observation.Checks[len(observation.Checks)-1]
		if check.Probe == nil || check.Snapshot.Facts == nil || !check.Snapshot.Facts.RunningPresent || !check.Snapshot.Facts.PausedPresent || len(check.Snapshot.Facts.PublishedExternalBindings) != 1 {
			t.Fatalf("incomplete state/probe evidence: %+v", check)
		}
		if check.Snapshot.Interval.StartElapsedNanoseconds < observation.Interval.StartElapsedNanoseconds || check.Snapshot.Interval.EndElapsedNanoseconds < check.Snapshot.Interval.StartElapsedNanoseconds || check.Probe.Interval.StartElapsedNanoseconds < check.Snapshot.Interval.EndElapsedNanoseconds || check.Probe.Interval.EndElapsedNanoseconds < check.Probe.Interval.StartElapsedNanoseconds || check.Probe.Interval.EndElapsedNanoseconds > observation.Interval.EndElapsedNanoseconds {
			t.Fatalf("state/probe interval order invalid: %+v", check)
		}
	}
	if restart.Before.Facts.StartedAt.Equal(restart.Checks[0].Snapshot.Facts.StartedAt) {
		t.Fatal("restart did not retain changed start identity")
	}
	for _, args := range f.calls {
		if args[0] != "container" && args[len(args)-1] != f.id {
			t.Fatalf("mutation by discovered name: %v", args)
		}
	}
}

func TestBrokerCalibrationRefusesChangedOwnershipBeforeMutationOrProbe(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"label", func(info map[string]any) {
			info["Config"].(map[string]any)["Labels"] = map[string]string{brokerOwnerLabel: "unrelated-run"}
		}},
		{"name", func(info map[string]any) { info["Name"] = "/unrelated-broker" }},
		{"container ID", func(info map[string]any) { info["Id"] = strings.Repeat("c", 64) }},
		{"short ID", func(info map[string]any) { info["Id"] = "abc" }},
		{"image", func(info map[string]any) { info["Config"].(map[string]any)["Image"] = "unrelated:latest" }},
		{"host binding", func(info map[string]any) {
			info["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"19092/tcp": []map[string]string{{"HostIp": "0.0.0.0", "HostPort": "22092"}}}
		}},
		{"published port", func(info map[string]any) {
			info["NetworkSettings"].(map[string]any)["Ports"] = map[string]any{"19092/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "22093"}}}
		}},
		{"missing binding", func(info map[string]any) { delete(info, "NetworkSettings") }},
		{"missing paused", func(info map[string]any) { delete(info["State"].(map[string]any), "Paused") }},
		{"missing running", func(info map[string]any) { delete(info["State"].(map[string]any), "Running") }},
		{"missing start", func(info map[string]any) { delete(info["State"].(map[string]any), "StartedAt") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given an admitted handle, then changed or missing ownership evidence.
			f := newBrokerCalibration()
			b := openCalibrationBroker(t, f)
			f.mutate = tc.mutate
			// When a fault is requested, re-inspection must reject it first.
			observation, err := b.Pause(context.Background())
			// Then neither a mutation nor any address probe is permitted.
			if err == nil || observation.Reached || f.mutations() != 0 || f.probes != 0 {
				t.Fatalf("ownership guard failed: %+v calls=%v probes=%d error=%v", observation, f.calls, f.probes, err)
			}
		})
	}
}

func TestBrokerCalibrationRejectsInitialMismatchAndUnrelatedManifest(t *testing.T) {
	// Given unrelated addresses or resource names in a fixture-shaped manifest.
	for _, change := range []func(*fixture.State){
		func(s *fixture.State) { s.RunID = "../other" },
		func(s *fixture.State) { s.Containers[1] = "real-broker" },
		func(s *fixture.State) { s.Destination = "192.0.2.10:9092" },
		func(s *fixture.State) { s.Destination = "localhost:22092" },
		func(s *fixture.State) { s.Destination = s.Source },
	} {
		f := newBrokerCalibration()
		change(&f.state)
		// When opening, no discovery, mutation, or probe may run.
		if _, _, err := openBrokerWithProbe(context.Background(), f.state, "destination", f.execute, f.probe, true); err == nil {
			t.Fatal("unrelated fixture admitted")
		}
		if len(f.calls) != 0 || f.probes != 0 {
			t.Fatalf("manifest reached resources: %v %d", f.calls, f.probes)
		}
	}
	f := newBrokerCalibration()
	f.mutate = func(info map[string]any) { info["Name"] = "/other" }
	if _, snapshot, err := openBrokerWithProbe(context.Background(), f.state, "destination", f.execute, f.probe, true); err == nil || snapshot.Facts == nil {
		t.Fatalf("initial mismatch admitted or evidence lost: %+v %v", snapshot, err)
	}
	if f.mutations() != 0 || f.probes != 0 {
		t.Fatal("initial mismatch reached mutation/probe")
	}
}

func TestBrokerCalibrationPauseRequiresStateAndIndependentUnavailability(t *testing.T) {
	for _, mode := range []string{"false paused", "API still available", "probe error", "missing probe evidence", "missing transport cause", "unknown transport cause", "Kafka API error"} {
		t.Run(mode, func(t *testing.T) {
			// Given Docker request success with one deliberately absent reached predicate.
			f := newBrokerCalibration()
			b := openCalibrationBroker(t, f)
			switch mode {
			case "false paused":
				f.pauseUnchanged = true
			case "API still available":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
					return brokerProbeResult{Available: true, APIKeys: 1}, nil
				}
			case "probe error":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
					return brokerProbeResult{}, errors.New("synthetic observer failure")
				}
			case "missing probe evidence":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) { return brokerProbeResult{}, nil }
			case "missing transport cause":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
					return brokerProbeResult{Unavailable: true}, nil
				}
			case "unknown transport cause":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
					return brokerProbeResult{Unavailable: true, Failure: "guessed_outage", TransportError: "synthetic unknown error"}, nil
				}
			case "Kafka API error":
				f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
					return brokerProbeResult{Available: true, APIKeys: 1, ErrorCode: 42}, nil
				}
			}
			// When Pause attempts the fault, the missing predicate must block success.
			observation, err := b.Pause(context.Background())
			// Then evidence stays unreached and the retained handle can restore safely.
			if err == nil || observation.Reached || !observation.RecoveryNeeded {
				t.Fatalf("missing fault evidence passed: %+v %v", observation, err)
			}
			f.probeResult = nil
			restore, err := b.Restore(context.Background())
			if err != nil || !restore.Reached || restore.RecoveryNeeded {
				t.Fatalf("bounded restoration failed: %+v %v", restore, err)
			}
		})
	}
}

func TestBrokerCalibrationMissingResourceAndCommandFailureCannotPass(t *testing.T) {
	// Given a retained broker that Docker cannot inspect anymore.
	f := newBrokerCalibration()
	b := openCalibrationBroker(t, f)
	f.inspectErr = errors.New("synthetic No such container")
	observation, err := b.Restore(context.Background())
	// When restoration lacks a resource, it remains an error rather than cleanup success.
	if err == nil || observation.Reached || !observation.RecoveryNeeded || f.mutations() != 0 {
		t.Fatalf("absent recovery passed: %+v %v", observation, err)
	}
	f.inspectErr = nil
	f.pauseErr = errors.New("synthetic ambiguous command failure")
	observation, err = b.Pause(context.Background())
	// Then an ambiguous mutation retains its result and pending restoration duty.
	if err == nil || observation.Reached || !observation.RecoveryNeeded || observation.Request == nil || observation.Request.Error == "" || observation.Request.Output == "" {
		t.Fatalf("command failure hidden: %+v %v", observation, err)
	}
}

func TestBrokerCalibrationRecoveryRequiresReadinessAndCanRetryByOwnedID(t *testing.T) {
	// Given a reached synthetic pause and an unpause command that fails.
	f := newBrokerCalibration()
	b := openCalibrationBroker(t, f)
	if _, err := b.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.unpauseErr = errors.New("synthetic unpause failure")
	restore, err := b.Restore(context.Background())
	if err == nil || restore.Reached || !restore.RecoveryNeeded {
		t.Fatalf("failed unpause passed: %+v %v", restore, err)
	}
	f.unpauseErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	f.probeResult = func(context.Context, string) (brokerProbeResult, error) {
		cancel()
		return brokerProbeResult{Unavailable: true, Failure: "timeout", TransportError: "synthetic Kafka request timeout"}, nil
	}
	// When Docker unpauses but readiness is unavailable through the bounded probe.
	restore, err = b.Restore(ctx)
	if err == nil || restore.Reached || !restore.RecoveryNeeded || len(restore.Checks) != 1 || restore.Checks[0].Probe == nil {
		t.Fatalf("missing readiness passed: %+v %v", restore, err)
	}
	// Then a fresh cleanup context can independently confirm full recovery.
	f.probeResult = nil
	restore, err = b.Restore(context.Background())
	if err != nil || !restore.Reached || restore.RecoveryNeeded {
		t.Fatalf("recovery retry failed: %+v %v", restore, err)
	}
}

func TestBrokerCalibrationRestartRequiresNewStartAndRestoresStoppedContainer(t *testing.T) {
	// Given restart request success with unchanged Docker start identity.
	f := newBrokerCalibration()
	b := openCalibrationBroker(t, f)
	f.restartUnchanged = true
	restart, err := b.Restart(context.Background())
	// When no new start is observed, readiness alone cannot establish the audit boundary.
	if err == nil || restart.Reached || f.probes != 0 {
		t.Fatalf("unchanged start passed: %+v %v", restart, err)
	}
	// Then restoration can restart only this same stopped container, preserving storage.
	f.restartUnchanged, f.running = false, false
	restore, err := b.Restore(context.Background())
	if err != nil || !restore.Reached || restore.Request == nil || restore.Request.Operation != "restart" || restore.Request.ContainerID != f.id {
		t.Fatalf("stopped owned container not recovered: %+v %v", restore, err)
	}
}

func TestBrokerProbeCalibrationDistinguishesTransportFailureFromObserverError(t *testing.T) {
	// Given known transport failures, only those can support API unavailability.
	for _, cause := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}} {
		result, err := brokerTransportFailure(cause)
		if err != nil || !result.Unavailable || result.Available || result.Failure == "" || result.TransportError == "" {
			t.Fatalf("transport evidence lost: %+v %v", result, err)
		}
	}
	result, err := brokerTransportFailure(errors.New("synthetic decoder failure"))
	if err == nil || result.Unavailable {
		t.Fatalf("observer failure became outage: %+v %v", result, err)
	}
	// When a probe is already cancelled, it returns without attempting a network call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = kafkaBrokerProbe(ctx, "127.0.0.1:22092")
	if !errors.Is(err, context.Canceled) || result.Available || result.Unavailable {
		t.Fatalf("cancelled probe evidence: %+v %v", result, err)
	}
	// Then unrelated addresses are rejected even with a syntactically usable port.
	if _, err := ownedBrokerPort("198.51.100.1:9092"); err == nil {
		t.Fatal("unrelated probe address admitted")
	}
}

func TestBrokerCalibrationSourceHasSeparateOwnedEndpoint(t *testing.T) {
	// Given the source role, its derived name and mapping differ from destination.
	f := newBrokerCalibration()
	f.name = f.state.Containers[0]
	b, snapshot, err := openBrokerWithProbe(context.Background(), f.state, "source", f.execute, f.probe, true)
	if err != nil || snapshot.Facts == nil || snapshot.Facts.Endpoint != f.state.Source {
		t.Fatalf("source admission: %+v %v", snapshot, err)
	}
	// When a source fault is requested and then recovered.
	pause, err := b.Pause(context.Background())
	if err != nil || !pause.Reached {
		t.Fatalf("source pause: %+v %v", pause, err)
	}
	restore, err := b.Restore(context.Background())
	// Then both probes use only the independently verified source binding.
	if err != nil || !restore.Reached || f.probes != 2 {
		t.Fatalf("source recovery: %+v %v", restore, err)
	}
}

func TestBrokerCalibrationInspectRetainsFactsWithoutContainerEnvironment(t *testing.T) {
	// Given an owned container whose full inspect includes environment contents.
	f := newBrokerCalibration()
	f.mutate = func(info map[string]any) {
		info["Config"].(map[string]any)["Env"] = []string{"SYNTHETIC_SECRET=do-not-retain"}
	}
	// When the handle returns its selected ownership/port facts.
	_, snapshot, err := openBrokerWithProbe(context.Background(), f.state, "destination", f.execute, f.probe, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Then raw inspect environment is not part of the retained receipt.
	if strings.Contains(string(data), "SYNTHETIC_SECRET") || strings.Contains(string(data), "do-not-retain") {
		t.Fatal("container environment leaked into broker receipt")
	}
}
