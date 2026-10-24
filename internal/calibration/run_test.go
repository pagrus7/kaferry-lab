package calibration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

// The controller starts this executable as a separate stand-in process. Fault
// controls change only that child's behavior, never the controller or checker.
func TestMain(m *testing.M) {
	if len(os.Args) == 6 && os.Args[1] == "_standin" {
		if err := testChild(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testChild(args []string) error {
	f, err := os.OpenFile(os.Getenv("LAB_TEST_CHILDREN"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, os.Getpid())
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	switch os.Getenv("LAB_TEST_CONTROL") {
	case "missing-barrier":
		_, err = io.Copy(io.Discard, os.Stdin)
		return err
	case "wrong-mode":
		return json.NewEncoder(os.Stdout).Encode(Barrier{Saved: 1, Mode: "wrong"})
	case "wrong-boundary":
		return json.NewEncoder(os.Stdout).Encode(Barrier{Saved: 2, Mode: args[3]})
	case "dead-child":
		return fmt.Errorf("deliberate child exit before barrier")
	case "blocked-recovery":
		if args[3] == "healthy" {
			// The recovery child has no stdin pipe. Keep it alive until the
			// parent context kills it, independently of the stand-in files.
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	return Standin(args[0], args[1], args[2], args[3], os.Stdin, os.Stdout)
}

func TestControllerDetectsActualStandinFault(t *testing.T) {
	// Given finite synthetic input and real healthy/faulty child processes.
	pids := childLog(t, "")
	dir := filepath.Join(t.TempDir(), "calibration")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// When the controller kills each child at its observed barrier and resumes.
	got, err := Run(context.Background(), dir, exe)
	if err != nil {
		t.Fatal(err)
	}
	// Then the healthy control passes and the deliberate loss is detected.
	if len(got) != 2 || got[0].Result.Verdict != evidence.Pass || got[1].Result.Verdict != evidence.Violation {
		t.Fatalf("unexpected sensitivity results: %+v", got)
	}
	if got[0].Result.RunID == got[1].Result.RunID {
		t.Fatal("separate calibration histories reused a run ID")
	}
	for _, outcome := range got {
		if outcome.Result.ReleaseQualified {
			t.Fatal("stand-in calibration qualified a release")
		}
		if !reflect.DeepEqual(outcome.Result, evidence.LoadAndCheck(outcome.Bundle)) {
			t.Fatal("offline recheck changed the observed verdict")
		}
		if runID := assertOwnership(t, filepath.Dir(outcome.Bundle), 2); runID != outcome.Result.RunID {
			t.Fatalf("bundle run ID differs from observed ownership: %q / %q", outcome.Result.RunID, runID)
		}
	}
	found := map[string]bool{}
	for _, finding := range got[1].Result.Findings {
		found[finding.Code] = true
	}
	if !found["required_record_missing"] || !found["unsafe_saved_prefix"] {
		t.Fatalf("fault escaped membership or prefix detection: %+v", got[1].Result.Findings)
	}
	assertReaped(t, pids, 4)
}

func TestControllerRejectsUnreachedFaultAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		control     string
		cancelAfter int
		wantError   string
	}{
		{"missing-barrier", "missing-barrier", 0, "context deadline exceeded"},
		{"wrong-mode", "wrong-mode", 0, "standin barrier not reached"},
		{"wrong-boundary", "wrong-boundary", 0, "standin barrier not reached"},
		{"dead-child", "dead-child", 0, "standin barrier not reached"},
		{"cancel-controller", "missing-barrier", 1, "context canceled"},
		{"cancel-recovery", "blocked-recovery", 2, "standin recovery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given an owned child that cannot complete the required control.
			pids := childLog(t, tc.control)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if tc.cancelAfter != 0 {
				done := make(chan struct{})
				defer func() { <-done }()
				go func() {
					defer close(done)
					for {
						if len(readPIDs(pids)) >= tc.cancelAfter {
							cancel()
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(5 * time.Millisecond):
						}
					}
				}()
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "calibration")
			// When calibration encounters that condition.
			got, err := Run(ctx, dir, exe)
			// Then it fails without finalizing a successful history and reaps
			// every started child, including a canceled recovery process.
			if err == nil || !strings.Contains(err.Error(), tc.wantError) || len(got) != 0 {
				t.Fatalf("unreached fault accepted: outcomes=%+v error=%v", got, err)
			}
			t.Logf("expected controller failure: %v", err)
			bundle := filepath.Join(dir, "healthy-pause", "bundle")
			if _, err := os.Stat(filepath.Join(bundle, evidence.CompleteName)); !os.IsNotExist(err) {
				t.Fatalf("failed control finalized completion: %v", err)
			}
			if result := evidence.LoadAndCheck(bundle); result.Verdict == evidence.Pass {
				t.Fatal("failed controller left a passing bundle")
			}
			wantChildren := 1
			if tc.cancelAfter == 2 {
				wantChildren = 2
			}
			assertReaped(t, pids, wantChildren)
			assertOwnership(t, filepath.Join(dir, "healthy-pause"), wantChildren)
		})
	}
}

func childLog(t *testing.T, control string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "children")
	t.Setenv("LAB_TEST_CHILDREN", path)
	t.Setenv("LAB_TEST_CONTROL", control)
	return path
}

func assertOwnership(t *testing.T, dir string, wantChildren int) string {
	t.Helper()
	work := filepath.Join(dir, "work")
	raw, err := os.ReadFile(filepath.Join(work, "ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ownership struct {
		RunID     string            `json:"run_id"`
		Owner     string            `json:"owner"`
		Resources map[string]string `json:"resources"`
	}
	if err := json.Unmarshal(raw, &ownership); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(ownership.RunID) == "" || ownership.Owner != "kaferry-lab" || ownership.Resources["checkpoint"] != filepath.Join(work, "saved.json") {
		t.Fatalf("missing run-scoped ownership: %s", raw)
	}
	f, err := os.Open(filepath.Join(work, "processes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	for i := 0; i < wantChildren; i++ {
		var child struct {
			RunID string `json:"run_id"`
			Owner string `json:"owner"`
			Role  string `json:"role"`
			PID   int    `json:"pid"`
		}
		if err := d.Decode(&child); err != nil {
			t.Fatal(err)
		}
		role := "initial"
		if i == 1 {
			role = "recovery"
		}
		if child.RunID != ownership.RunID || child.Owner != ownership.Owner || child.Role != role || child.PID <= 0 {
			t.Fatalf("missing owned child identity: %+v", child)
		}
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected extra process ownership evidence: %v/%v", extra, err)
	}
	return ownership.RunID
}

func readPIDs(path string) []string {
	raw, _ := os.ReadFile(path)
	return strings.Fields(string(raw))
}

func assertReaped(t *testing.T, path string, want int) {
	t.Helper()
	pids := readPIDs(path)
	if len(pids) != want {
		t.Fatalf("started %d children, want %d: %v", len(pids), want, pids)
	}
	for _, raw := range pids {
		pid, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("owned child %d remains: %v", pid, err)
		}
		var status syscall.WaitStatus
		if got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); got != -1 || !errors.Is(err, syscall.ECHILD) {
			t.Errorf("owned child %d was not reaped: wait=%d error=%v", pid, got, err)
		}
	}
}
