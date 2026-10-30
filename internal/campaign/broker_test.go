package campaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

func reserveDirectBrokerCalibration(t *testing.T, f *brokerCalibration) fixture.State {
	t.Helper()
	// Literal plan/receipt fields are calibration data; no Docker image, broker,
	// private original or native execution is asserted by this helper.
	s := f.state
	s.DockerPlatform = "linux/amd64"
	s.ClusterIDs = []string{"AAAAAAAAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEBAQEBAQ"}
	s.Created = "2026-10-29T01:02:03Z"
	plan, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path, err := fixture.StatePath(s.RunID)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(".cache", "fixtures-private", s.RunID+"-brokers")
	for _, directory := range []string{filepath.Dir(path), root} {
		if err = os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(path, plan, 0600); err != nil {
		t.Fatal(err)
	}
	marker, err := json.Marshal(struct{ RunID, Classification, Publication string }{s.RunID, "PRIVATE RAW EVIDENCE", "withhold pending explicit redaction review"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "PRIVATE.json"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	s.Direct = &fixture.DirectIdentity{RunID: s.RunID, ManifestSHA256: fmt.Sprintf("%x", sha256.Sum256(plan)), NetworkID: strings.Repeat("d", 64), BrokerIDs: []string{strings.Repeat("c", 64), f.id}, Image: fixture.LinkImageIdentity{Mode: "exact-config-v1", RuntimeImageID: "sha256:41abbd7d7f05d1ea7918ce2539d04a334c597943a53dbc1812a572af136c6df1", ConfigDigest: "sha256:41abbd7d7f05d1ea7918ce2539d04a334c597943a53dbc1812a572af136c6df1"}}
	writeDirectBrokerCalibrationIdentity(t, s)
	f.state = s
	f.mutate = func(row map[string]any) {
		row["Image"] = s.Direct.Image.RuntimeImageID
		config := row["Config"].(map[string]any)
		config["Labels"] = map[string]string{brokerOwnerLabel: s.RunID, "io.kaferry-lab.role": "destination"}
		config["Env"] = []string{"CLUSTER_ID=" + s.ClusterIDs[1], "KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092", "KAFKA_ADVERTISED_LISTENERS=INTERNAL://" + f.name + ":9092,EXTERNAL://" + s.Destination, "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT", "SYNTHETIC_PRIVATE_ENV=private-candidate"}
		host := row["HostConfig"].(map[string]any)
		host["NetworkMode"], host["Memory"], host["NanoCpus"], host["PidsLimit"] = s.Network, 768<<20, 1500000000, 256
		host["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1m", "max-file": "1"}}
		row["NetworkSettings"].(map[string]any)["Networks"] = map[string]any{s.Network: map[string]string{"NetworkID": s.Direct.NetworkID}}
	}
	return s
}

func writeDirectBrokerCalibrationIdentity(t *testing.T, s fixture.State) {
	t.Helper()
	body, err := json.Marshal(s.Direct)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(".cache", "fixtures-private", s.RunID+"-brokers", "identity.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectBrokerRequiresModernSelectedProofBeforeDiscoveryOrProbe(t *testing.T) {
	// Given a modern runtime target and literal typed fields, When its selected
	// proof is missing/foreign, Then real admission issues no discovery, probe,
	// pause or restart even though the sha256 runtime string looks valid.
	for _, kind := range []string{"no-identity", "no-proof", "wrong-manifest"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newBrokerCalibration()
			s := reserveDirectBrokerCalibration(t, f)
			// Update the exclusive literal plan before reserving these separate
			// negative calibration facts; no existing production plan is changed.
			s.DockerPlatform = "linux/arm64"
			image := &s.Direct.Image
			image.Mode = "native-arm64-manifest-v1"
			image.RuntimeImageID = "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02"
			image.ConfigDigest = "sha256:5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f"
			image.ProofSHA256 = strings.Repeat("e", 64)
			image.Manifest = &fixture.ImageManifestIdentity{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", Size: 2201}
			image.Manifest.Platform.OS, image.Manifest.Platform.Architecture = "linux", "arm64"
			if kind == "wrong-manifest" {
				image.Manifest.Digest = image.RuntimeImageID
			}
			copy := s
			copy.Direct = nil
			body, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			path, _ := fixture.StatePath(s.RunID)
			if err = os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			s.Direct.ManifestSHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
			writeDirectBrokerCalibrationIdentity(t, s)
			if kind == "no-identity" {
				s.Direct = nil
			}
			if b, _, err := openOwnedBroker(context.Background(), s, "destination", f.execute); err == nil || b != nil {
				t.Fatal("missing modern authority admitted", kind, err)
			}
			if len(f.calls) != 0 || f.probes != 0 {
				t.Fatal("modern authority failure reached discovery/probe", kind)
			}
		})
	}
}

func TestDirectBrokerUsesSameIdentityBeforeMutationAndRetainsForeignCandidate(t *testing.T) {
	// Given a plan-bound direct classic identity and one private fixture executor,
	// When candidate ownership/image/network changes after admission, Then each
	// requested mutation refuses before probe/request and retains the raw row.
	for _, kind := range []string{"owner", "runtime", "manifest", "network", "role", "port"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newBrokerCalibration()
			s := reserveDirectBrokerCalibration(t, f)
			run, err := fixture.FixtureExecutor(s, f.execute)
			if err != nil {
				t.Fatal(err)
			}
			b, snapshot, err := openBrokerWithProbe(context.Background(), s, "destination", run, f.probe, true)
			if err != nil {
				t.Fatal(err)
			}
			public, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(public), "SYNTHETIC_PRIVATE_ENV") || strings.Contains(string(public), `"Config"`) || strings.Contains(string(public), `"Env"`) {
				t.Fatal("public ownership leaked private config")
			}
			valid := f.mutate
			var refused []byte
			f.mutate = func(row map[string]any) {
				valid(row)
				switch kind {
				case "owner":
					row["Config"].(map[string]any)["Labels"].(map[string]string)[brokerOwnerLabel] = "foreign"
				case "role":
					row["Config"].(map[string]any)["Labels"].(map[string]string)["io.kaferry-lab.role"] = "source"
				case "runtime":
					row["Image"] = "sha256:" + strings.Repeat("e", 64)
				case "manifest":
					row["ImageManifestDescriptor"] = &fixture.ImageManifestIdentity{Digest: "foreign"}
				case "network":
					row["HostConfig"].(map[string]any)["NetworkMode"] = "foreign"
				case "port":
					row["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{}
				}
				refused, _ = json.Marshal(row)
			}
			observation, err := b.Pause(context.Background())
			if err == nil || observation.Request != nil || observation.Reached || f.probes != 0 || f.mutations() != 0 {
				t.Fatal("changed direct candidate reached mutation/probe", kind, err)
			}
			// STOP is shared by a newly requested executor as well as this handle.
			before := len(f.calls)
			if _, err = fixture.FixtureExecutor(s, f.execute); err == nil || len(f.calls) != before {
				t.Fatal("semantic refusal did not latch direct facility")
			}
			found := false
			root := filepath.Join(".cache", "fixtures-private", s.RunID+"-brokers")
			err = filepath.WalkDir(root, func(path string, entry os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if entry.IsDir() {
					return nil
				}
				body, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				var row struct {
					Combined            []byte
					PrivateReadbackKind string
				}
				_ = json.Unmarshal(body, &row)
				if strings.Contains(row.PrivateReadbackKind, "candidate") && len(refused) > 0 && bytes.Equal(row.Combined, refused) && strings.Contains(string(row.Combined), "SYNTHETIC_PRIVATE_ENV") {
					found = true
				}
				return nil
			})
			if err != nil || !found {
				t.Fatal("private candidate original missing", err)
			}
		})
	}
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

// This exposes the same numeric exit information as exec.ExitError without
// starting a subprocess. Its outer wrapper includes full inspect stdout, just
// as fixture.Docker does on command failure.
type brokerCalibrationExitFailure struct{ code int }

func (e brokerCalibrationExitFailure) Error() string { return "synthetic Docker exit failure" }
func (e brokerCalibrationExitFailure) ExitCode() int { return e.code }

func TestBrokerCalibrationFailedInspectNeverRetainsFullOutputOrWrappedError(t *testing.T) {
	const secretName = "SYNTHETIC_INSPECT_SECRET"
	const secretValue = "must-not-retain-inspect-value"
	for _, tc := range []struct {
		name  string
		cause error
		class string
	}{
		{"executor", errors.New("synthetic executor failure"), "executor failure"},
		{"exit", brokerCalibrationExitFailure{code: 7}, "exit code 7"},
		{"cancelled", context.Canceled, "context canceled"},
		{"deadline", context.DeadlineExceeded, "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given complete inspect stdout containing an environment secret and the
			// exact output-embedding error shape returned by fixture.Docker.
			f := newBrokerCalibration()
			f.mutate = func(info map[string]any) {
				info["Config"].(map[string]any)["Env"] = []string{secretName + "=" + secretValue}
			}
			failedInspect := func(ctx context.Context, args ...string) ([]byte, error) {
				out, err := f.execute(ctx, args...)
				if err != nil {
					return out, err
				}
				return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), tc.cause, out)
			}
			assertSafe := func(diagnostic error, retained any, target string) {
				t.Helper()
				if diagnostic == nil {
					t.Fatal("inspect failure was accepted")
				}
				data, err := json.Marshal(retained)
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{diagnostic.Error(), string(data)} {
					for _, forbidden := range []string{secretName, secretValue, `"Config"`, `"Env"`, "Config.Env"} {
						if strings.Contains(text, forbidden) {
							t.Fatal("full inspect environment leaked through failure diagnostic or retained receipt")
						}
					}
				}
				for _, text := range []string{diagnostic.Error(), string(data)} {
					if !strings.Contains(text, "docker container inspect "+target) || !strings.Contains(text, tc.class) {
						t.Fatal("safe operation/target/failure class missing from diagnostic or retained receipt")
					}
				}
				if (tc.cause == context.Canceled || tc.cause == context.DeadlineExceeded) && !errors.Is(diagnostic, tc.cause) {
					t.Fatalf("safe context cause lost: %v", diagnostic)
				}
			}
			// When ownership admission fails, neither facts nor a handle may be admitted.
			b, snapshot, err := openBrokerWithProbe(context.Background(), f.state, "destination", failedInspect, f.probe, true)
			if b != nil || snapshot.Facts != nil {
				t.Fatal("failed inspection admitted broker ownership")
			}
			assertSafe(err, snapshot, f.name)
			if f.mutations() != 0 || f.probes != 0 {
				t.Fatal("failed ownership inspection reached mutation/probe")
			}
			// Then an already owned handle also retains only the sanitized pre-mutation
			// failure when its subsequent full inspect fails.
			b = openCalibrationBroker(t, f)
			b.run = failedInspect
			observation, err := b.Pause(context.Background())
			assertSafe(err, observation, f.id)
			if observation.Reached || observation.Before.Facts != nil || observation.Request != nil || f.mutations() != 0 || f.probes != 0 {
				t.Fatal("failed re-inspection reached mutation/probe")
			}
		})
	}
}
