package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/calibration"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

// Run the real command dispatcher in a child, so exit codes, stdout, and the
// nested stand-in invocation are exercised without replacing command handlers.
func TestMain(m *testing.M) {
	if os.Getenv("LAB_TEST_CLI") == "1" {
		os.Exit(execute(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func TestOfflineCheckCLIStatuses(t *testing.T) {
	// Given authored complete, violating, unsupported, and incomplete histories.
	for _, tc := range []struct {
		name    string
		status  int
		verdict evidence.Verdict
	}{
		{"valid", 0, evidence.Pass},
		{"required-loss", 1, evidence.Violation},
		{"archive-unsupported", 3, evidence.Unsupported},
		{"missing-trigger", 4, evidence.Inconclusive},
		{"truncated-stream", 2, evidence.HarnessError},
		{"absent-bundle", 2, evidence.HarnessError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := filepath.Join("..", "..", "internal", "evidence", "testdata", tc.name)
			// When the offline command checks each bundle in a separate process.
			first := runCLI(t, tc.status, "check", bundle)
			var got evidence.Result
			if err := json.Unmarshal(first, &got); err != nil {
				t.Fatal(err)
			}
			// Then both machine-readable verdict and process status agree, and
			// identical rechecks produce identical command output.
			if got.Verdict != tc.verdict || got.ReleaseQualified {
				t.Fatalf("unexpected command result: %+v", got)
			}
			if second := runCLI(t, tc.status, "check", bundle); !bytes.Equal(first, second) {
				t.Fatalf("offline command output changed:\n%s\n%s", first, second)
			}
		})
	}
}

func TestCalibrationCLIAndOfflineRecheck(t *testing.T) {
	// Given a fresh destination containing only lab-owned synthetic files.
	dir := filepath.Join(t.TempDir(), "calibration")
	// When the CLI drives actual stand-in children through kill and recovery.
	raw := runCLI(t, 0, "calibrate", dir)
	var outcomes []calibration.Outcome
	if err := json.Unmarshal(raw, &outcomes); err != nil {
		t.Fatal(err)
	}
	// Then command wiring preserves the healthy/faulty sensitivity and keeps
	// both histories offline-checkable in the calibration namespace.
	if len(outcomes) != 2 {
		t.Fatalf("missing controls: %s", raw)
	}
	for i, outcome := range outcomes {
		status, verdict := 0, evidence.Pass
		if i == 1 {
			status, verdict = 1, evidence.Violation
		}
		if outcome.Result.Verdict != verdict || outcome.Result.ReleaseQualified {
			t.Fatalf("unexpected calibration result: %+v", outcome)
		}
		var rechecked evidence.Result
		if err := json.Unmarshal(runCLI(t, status, "check", outcome.Bundle), &rechecked); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(outcome.Result, rechecked) {
			t.Fatalf("CLI offline recheck differs: %+v / %+v", outcome.Result, rechecked)
		}
	}
	// An existing run destination is an execution error, never a fresh success.
	runCLI(t, 2, "calibrate", dir)
}

func TestQualificationCLIRefusesPartialEvidence(t *testing.T) {
	// Given an incomplete required release campaign, when qualification is requested,
	// then the command reports unsupported and cannot qualify the release.
	var got struct {
		Verdict          evidence.Verdict `json:"verdict"`
		ReleaseQualified bool             `json:"release_qualified"`
	}
	if err := json.Unmarshal(runCLI(t, 3, "qualify"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != evidence.Unsupported || got.ReleaseQualified {
		t.Fatalf("partial harness qualified a release: %+v", got)
	}
}

func runCLI(t *testing.T, want int, args ...string) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = append(os.Environ(), "LAB_TEST_CLI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	status := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		status = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || status != want {
		t.Fatalf("lab %v: status=%d want=%d deadline=%v stderr=%s stdout=%s", args, status, want, ctx.Err(), stderr.Bytes(), stdout)
	}
	return stdout
}
