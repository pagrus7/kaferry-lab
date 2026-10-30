package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanupRefusesWrongOwnerAndRetainsDaemonFailures(t *testing.T) {
	// Given an admitted direct fixture, When fresh cleanup ownership/daemon
	// evidence refuses, Then no resource is removed and the original is private.
	for _, tc := range []struct {
		name, output string
		err          error
	}{
		{"wrong owner", `{"Config":{"Labels":{"io.kaferry-lab.run":"someone-else"}}}`, nil},
		{"daemon unavailable", "Cannot connect to Docker daemon", errors.New("daemon unavailable")},
		{"malformed evidence", `{`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newDirectDockerControl(t)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if len(args) < 2 || args[1] != "inspect" {
					t.Fatal("attempted destructive command", args)
				}
				return []byte(tc.output), tc.err
			}
			if err := Down(context.Background(), s, run); err == nil {
				t.Fatal("unsafe cleanup reported success")
			}
			if calls != 1 {
				t.Fatal(calls)
			}
			found := false
			for _, body := range privateDirectBodies(t, s.RunID) {
				var row struct{ Combined []byte }
				_ = json.Unmarshal(body, &row)
				found = found || bytes.Equal(row.Combined, []byte(tc.output))
			}
			if !found {
				t.Fatal("refused cleanup original missing")
			}
		})
	}
}
func TestCleanupExplicitAbsenceIsIdempotent(t *testing.T) {
	// Given actual cleanup through the inert backend, When exact retained IDs
	// are absent on repeat cleanup, Then retained daemon absence is idempotent.
	t.Chdir(t.TempDir())
	f := newDirectDockerControl(t)
	s, err := upDirectControl(context.Background(), f.execute)
	if err != nil {
		t.Fatal(err)
	}
	if err = Down(context.Background(), s, f.execute); err != nil {
		t.Fatal(err)
	}
	if err = Down(context.Background(), s, f.execute); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupRequiresExactNamesBeforeInspect(t *testing.T) {
	run := func(_ context.Context, args ...string) ([]byte, error) {
		t.Fatal("must reject foreign names before Docker", args)
		return nil, nil
	}
	err := Down(context.Background(), State{RunID: "test", Network: "production", Containers: []string{"real-broker"}}, run)
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatal(err)
	}
}
func TestRunIDRejectsTraversalAndShellText(t *testing.T) {
	for _, id := range []string{"../other", "a;rm", "", strings.Repeat("a", 50), "UPPER"} {
		if _, err := StatePath(id); err == nil {
			t.Fatal(id)
		}
	}
}

func TestCleanupCapturesEvidenceBeforeRemovingOwnedContainer(t *testing.T) {
	// Given exact retained IDs, When Down reaches rm, Then bounded logs and
	// their selected-fact receipt have already survived private persistence.
	t.Chdir(t.TempDir())
	f := newDirectDockerControl(t)
	s, err := upDirectControl(context.Background(), f.execute)
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 1 && args[0] == "container" && args[1] == "rm" {
			removed++
			target := args[len(args)-1]
			logs, receipt := false, false
			for _, body := range privateDirectBodies(t, s.RunID) {
				var row struct {
					ContainerID         string
					Bytes               []byte
					Facts               linkFacts
					PrivateLogReference string
				}
				_ = json.Unmarshal(body, &row)
				logs = logs || row.ContainerID == target && bytes.Equal(row.Bytes, []byte("SYNTHETIC-PRIVATE-LOG\x00\xff"))
				receipt = receipt || row.Facts.ID == target && row.PrivateLogReference != ""
			}
			if !logs || !receipt {
				t.Fatal("removal preceded required private log/fact evidence", target)
			}
		}
		return f.execute(ctx, args...)
	}
	if err := Down(context.Background(), s, run); err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatal("missing exact removals", removed)
	}
}

func TestUpUsesDistinctRecordedClusterIdentities(t *testing.T) {
	// Given inert owned broker candidates, When direct setup creates its fixed
	// native brokers, Then independent cluster IDs match the exclusive plan.
	t.Chdir(t.TempDir())
	var ids []string
	f := newDirectDockerControl(t)
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "WORKER") || strings.Contains(strings.Join(args, " "), ProxyImage) {
			t.Fatal("legacy Up added proxy behavior", args)
		}
		if args[0] == "pull" || args[0] == "run" {
			if !strings.Contains(strings.Join(args, " "), "--platform linux/amd64") {
				t.Fatal("legacy broker missing native platform", args)
			}
		}
		if args[0] == "run" {
			for _, arg := range args {
				if strings.HasPrefix(arg, "CLUSTER_ID=") {
					ids = append(ids, strings.TrimPrefix(arg, "CLUSTER_ID="))
				}
			}
		}
		return f.execute(ctx, args...)
	}
	state, err := upDirectControl(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if state.Proxy != nil || state.WorkerSource != "" || state.WorkerDestination != "" {
		t.Fatal("legacy Up returned proxy endpoints")
	}
	if len(ids) != 2 || ids[0] == "" || ids[0] == ids[1] || len(state.ClusterIDs) != 2 || ids[0] != state.ClusterIDs[0] || ids[1] != state.ClusterIDs[1] {
		t.Fatalf("cluster identity ambiguity: actual=%v state=%v", ids, state.ClusterIDs)
	}
}

func TestFailedSecondDirectStartRetainsStoppedPartialSetupWithoutCleanup(t *testing.T) {
	// Given an admitted image and one started direct broker, When the second
	// start refuses/cancels, Then the primary original and STOP survive without
	// guessed-ID cleanup, another executor, or destructive command.
	t.Chdir(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newDirectDockerControl(t)
	var calls []string
	run := func(c context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "run" && strings.Contains(strings.Join(args, " "), "kaferry-lab-test-dest") {
			cancel()
			return []byte("injected start failure"), errors.New("start failed")
		}
		if c.Err() != nil {
			t.Fatal("new command after cancelled startup", args)
		}
		return f.execute(c, args...)
	}
	if _, err := upDirectControl(ctx, run); err == nil {
		t.Fatal("failed start reported success")
	}
	if len(calls) != 6 || !strings.HasPrefix(calls[5], "run ") || !strings.Contains(calls[5], "kaferry-lab-test-dest") {
		t.Fatal("unexpected startup command sequence", calls)
	}
	loaded, err := Load("test")
	if err != nil {
		t.Fatal("partial plan unavailable", err)
	}
	if loaded.Direct != nil {
		t.Fatal("failed partial setup asserted complete resource identity")
	}
	if err = Down(context.Background(), loaded, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("partial startup authorized cleanup")
		return nil, nil
	}); err == nil {
		t.Fatal("partial startup cleanup passed")
	}
	found := false
	for _, body := range privateDirectBodies(t, "test") {
		var row struct {
			Combined  []byte
			CauseText []byte
		}
		_ = json.Unmarshal(body, &row)
		found = found || string(row.Combined) == "injected start failure" && strings.Contains(string(row.CauseText), "start failed")
	}
	if !found {
		t.Fatal("original second-start failure lost")
	}
	if _, err = os.Stat(filepath.Join(directPrivateDirectory("test"), "STOPPED.json")); err != nil {
		t.Fatal("failed startup has no durable stop", err)
	}
}

func TestFixtureRefusesUnsupportedEngineBeforePullOrCreation(t *testing.T) {
	// Given an unreviewed engine platform, When fixture setup starts, Then it
	// refuses before any pull, network or container mutation is requested.
	for _, platform := range []string{"linux/386", "darwin/arm64", "linux/ARM64", "linux/arm64/v8", "linux/riscv64", ""} {
		t.Run(platform, func(t *testing.T) {
			t.Chdir(t.TempDir())
			calls := 0
			_, err := Up(context.Background(), "test", func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if args[0] != "info" {
					t.Fatal("unsupported engine mutation", args)
				}
				return []byte(platform), nil
			})
			if err == nil || calls != 1 {
				t.Fatalf("unsupported engine admitted: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestLinkedFixtureRejectsBackendMismatchBeforeResourceCreation(t *testing.T) {
	// Given an ARM64 engine reporting an AMD64 broker image, When setup admits
	// pulled images, Then it retains a failed attempt and creates no resource.
	t.Chdir(t.TempDir())
	calls := 0
	s, err := up(context.Background(), "test", func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		switch args[0] {
		case "info":
			return []byte("linux/aarch64"), nil
		case "pull":
			return nil, nil
		case "image":
			return []byte(`{"Id":"sha256:41abbd7d7f05d1ea7918ce2539d04a334c597943a53dbc1812a572af136c6df1","Os":"linux","Architecture":"amd64"}`), nil
		default:
			t.Fatal("resource mutation after backend mismatch", args)
			return nil, nil
		}
	}, true, func(context.Context, string, string, string, []byte) (int, []byte, error) {
		t.Fatal("proxy API after backend mismatch")
		return 0, nil, nil
	}, func(context.Context, string) (linkBrokerProbeResult, error) {
		t.Fatal("broker probe after backend mismatch")
		return linkBrokerProbeResult{}, nil
	})
	if err == nil || calls != 4 || s.DockerPlatform != "linux/aarch64" || s.Proxy == nil || s.Proxy.Image != "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87" {
		t.Fatalf("backend admission: calls=%d state=%+v err=%v", calls, s, err)
	}
	if _, err = Load("test"); err != nil {
		t.Fatal("failed plan not retained", err)
	}
}
