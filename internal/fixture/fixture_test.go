package fixture

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCleanupRefusesWrongOwnerAndRetainsDaemonFailures(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		err          error
	}{
		{"wrong owner", `{"Config":{"Labels":{"io.kaferry-lab.run":"someone-else"}}}`, nil},
		{"daemon unavailable", "Cannot connect to Docker daemon", errors.New("daemon unavailable")},
		{"malformed evidence", `{`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if len(args) < 2 || args[1] != "inspect" {
					t.Fatal("attempted destructive command", args)
				}
				return []byte(tc.output), tc.err
			}
			if err := remove(context.Background(), "container", "kaferry-lab-test-source", "test", run); err == nil {
				t.Fatal("unsafe cleanup reported success")
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}
func TestCleanupExplicitAbsenceIsIdempotent(t *testing.T) {
	run := func(_ context.Context, args ...string) ([]byte, error) {
		return []byte("Error response from daemon: No such container: x"), errors.New("exit 1")
	}
	if err := remove(context.Background(), "container", "x", "test", run); err != nil {
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
	t.Chdir(t.TempDir())
	var calls []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[1] == "inspect" {
			return []byte(`{"Config":{"Labels":{"io.kaferry-lab.run":"test"}}}`), nil
		}
		if args[0] == "logs" {
			return []byte("retained broker evidence"), nil
		}
		return nil, nil
	}
	if err := remove(context.Background(), "container", "kaferry-lab-test-source", "test", run); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[1] != "logs kaferry-lab-test-source" || calls[2] != "container rm -f kaferry-lab-test-source" {
		t.Fatal(calls)
	}
}

func TestUpUsesDistinctRecordedClusterIdentities(t *testing.T) {
	t.Chdir(t.TempDir())
	var ids []string
	run := func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "info" {
			return []byte("linux/amd64"), nil
		}
		if args[0] == "run" {
			for _, arg := range args {
				if strings.HasPrefix(arg, "CLUSTER_ID=") {
					ids = append(ids, strings.TrimPrefix(arg, "CLUSTER_ID="))
				}
			}
		}
		return nil, nil
	}
	state, err := Up(context.Background(), "test", run)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] == "" || ids[0] == ids[1] || len(state.ClusterIDs) != 2 || ids[0] != state.ClusterIDs[0] || ids[1] != state.ClusterIDs[1] {
		t.Fatalf("cluster identity ambiguity: actual=%v state=%v", ids, state.ClusterIDs)
	}
}

func TestFailedSecondStartCleansFirstEvenAfterCancellation(t *testing.T) {
	t.Chdir(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	var removed []string
	run := func(c context.Context, args ...string) ([]byte, error) {
		if args[0] == "info" {
			return []byte("linux/amd64"), nil
		}
		if args[0] == "run" && strings.Contains(strings.Join(args, " "), "kaferry-lab-test-dest") {
			cancel()
			return []byte("injected start failure"), errors.New("start failed")
		}
		if len(args) > 1 && args[1] == "inspect" {
			if c.Err() != nil {
				t.Fatal("cleanup inherited canceled context")
			}
			if strings.HasSuffix(args[2], "-dest") {
				return []byte("No such container"), errors.New("absent")
			}
			return []byte(`{"Config":{"Labels":{"io.kaferry-lab.run":"test"}},"Labels":{"io.kaferry-lab.run":"test"}}`), nil
		}
		if len(args) > 1 && args[1] == "rm" {
			removed = append(removed, strings.Join(args, " "))
		}
		return nil, nil
	}
	if _, err := Up(ctx, "test", run); err == nil {
		t.Fatal("failed start reported success")
	}
	if len(removed) != 2 || removed[0] != "container rm -f kaferry-lab-test-source" || removed[1] != "network rm kaferry-lab-test" {
		t.Fatalf("owned partial start leaked: %v", removed)
	}
}
