//go:build linux

package campaign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// These helper processes calibrate controller lifecycle handling. They are not
// release artifacts and cannot establish any Kaferry qualification property.
func TestProcessCalibrationHelper(t *testing.T) {
	if os.Getenv("KAFERRY_LAB_PROCESS_CALIBRATION") != "1" {
		return
	}
	if _, err := os.Stat("ownership.json"); err != nil {
		os.Exit(21)
	}
	mode := os.Getenv("KAFERRY_LAB_PROCESS_MODE")
	if mode == "wait" {
		signal.Ignore(syscall.SIGTERM)
	}
	if err := os.WriteFile("ready", []byte("synthetic controller calibration\n"), 0600); err != nil {
		os.Exit(22)
	}
	switch mode {
	case "wait":
		fmt.Fprint(os.Stdout, "synthetic stdout\n")
		fmt.Fprint(os.Stderr, "synthetic stderr\n")
		for {
			time.Sleep(time.Second)
		}
	case "logs":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 8192))
		fmt.Fprint(os.Stderr, strings.Repeat("y", 8192))
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

func calibrationProcess(t *testing.T, mode string, limit int64) (*ownedProcess, context.CancelFunc) {
	t.Helper()
	if err := nativeProcessPlatform(); err != nil {
		t.Skip(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	runDirectory := t.TempDir()
	coverageDirectory := filepath.Join(runDirectory, "coverage")
	if err := os.Mkdir(coverageDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	// Instrumented helpers write counters to their owned directory instead of
	// adding coverage-runtime diagnostics to the calibrated stdout/stderr.
	plan := processPlan{
		RunID: "synthetic-calibration-" + rand.Text(), WorkerID: mode,
		Directory: filepath.Join(runDirectory, "worker"), Executable: executable,
		Args:           []string{"-test.run=^TestProcessCalibrationHelper$"},
		Env:            []string{"KAFERRY_LAB_PROCESS_CALIBRATION=1", "KAFERRY_LAB_PROCESS_MODE=" + mode, "GOCOVERDIR=" + coverageDirectory},
		CleanupTimeout: 2 * time.Second, TermGrace: 50 * time.Millisecond, LogLimit: limit,
	}
	p, err := startOwnedProcess(ctx, plan, processDigest(data), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Cleanup(context.Background()); err != nil && mode != "logs" {
			t.Errorf("calibration cleanup: %v", err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(plan.Directory, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("calibration helper did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return p, cancel
}

func TestProcessCalibrationSuspendResumeKillAndReap(t *testing.T) {
	// Given a synthetic direct child with persisted ownership/start identity.
	p, _ := calibrationProcess(t, "wait", 1024)
	if p.Identity().PID <= 0 || p.Identity().StartTicks == "" {
		t.Fatal("missing process identity")
	}
	for _, name := range []string{"ownership.json", "started.json"} {
		if _, err := os.Stat(filepath.Join(p.plan.Directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// When the controller suspends it, /proc must independently confirm T/t.
	if err := p.Suspend(ctx); err != nil {
		t.Fatal(err)
	}
	state, start, err := readProcessState(p.Identity().PID)
	if err != nil || (state != 'T' && state != 't') || start != p.Identity().StartTicks {
		t.Fatalf("suspension not reached: %c %q %v", state, start, err)
	}
	if err := p.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(ctx, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	// Then the one Wait owner records an actual signaled exit and reaps the child.
	result, err := p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reaped || result.ExitCode != -1 || result.Signal != "SIGKILL" {
		t.Fatalf("unexpected exit: %+v", result)
	}
	again, err := p.Wait(ctx)
	if err != nil || again != result {
		t.Fatalf("repeat wait changed: %+v %v", again, err)
	}
	if err := p.Signal(ctx, syscall.SIGCONT); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("signal after reap: %v", err)
	}
	if _, _, err := readProcessState(p.Identity().PID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child remains after reap: %v", err)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertCalibrationElapsedEvidence(t, p, result, "request_SIGKILL")
}

func TestProcessCalibrationCancellationReapsSuspendedChild(t *testing.T) {
	// Given a stopped helper that ignores TERM, with no caller cleanup yet.
	p, cancel := calibrationProcess(t, "wait", 1024)
	ctx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer waitCancel()
	if err := p.Suspend(ctx); err != nil {
		t.Fatal(err)
	}
	// When the campaign context cancels, automatic cleanup resumes then kills it.
	cancel()
	result, err := p.Wait(ctx)
	// Then cancellation is bounded and the child has actually been reaped.
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reaped || result.Signal != "SIGKILL" {
		t.Fatalf("cancelled helper not killed/reaped: %+v", result)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertCalibrationElapsedEvidence(t, p, result, "cleanup_request_SIGKILL")
	actions, err := os.ReadFile(filepath.Join(p.plan.Directory, "actions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(actions), "context_cancelled") || !strings.Contains(string(actions), "cleanup_request_SIGCONT") {
		t.Fatal("missing cancellation/recovery evidence")
	}
}

func TestProcessCalibrationLogOverflowIsEvidenceFailure(t *testing.T) {
	// Given a synthetic helper emitting beyond both retained log limits.
	p, _ := calibrationProcess(t, "logs", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// When it exits, the complete byte counts remain separate from retained bytes.
	result, err := p.Wait(ctx)
	// Then a clean helper exit cannot hide truncated evidence or block reaping.
	if err == nil || !result.LogsTruncated || !result.Reaped || result.StdoutBytes != 8192 || result.StderrBytes != 8192 {
		stdout, stdoutErr := os.ReadFile(filepath.Join(p.plan.Directory, "stdout.log"))
		stderr, stderrErr := os.ReadFile(filepath.Join(p.plan.Directory, "stderr.log"))
		t.Fatalf("overflow control mismatch: %+v %v; retained stdout=%q (%v), stderr=%q (%v)", result, err, stdout, stdoutErr, stderr, stderrErr)
	}
	for _, name := range []string{"stdout.log", "stderr.log"} {
		info, err := os.Stat(filepath.Join(p.plan.Directory, name))
		if err != nil || info.Size() != 32 {
			t.Fatalf("retained %s: %v %v", name, info, err)
		}
	}
}

func TestProcessReleaseRejectsMissingAndWrongExecutable(t *testing.T) {
	if err := nativeProcessPlatform(); err != nil {
		t.Skip(err)
	}
	// Given a missing executable or this visibly synthetic test executable.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	directory := filepath.Join(t.TempDir(), "reserved")
	plan := processPlan{RunID: "calibration", WorkerID: "invalid", Directory: directory, Executable: filepath.Join(t.TempDir(), "missing")}
	// When the fixed release entry validates them, neither can launch.
	if _, err := startReleaseProcess(ctx, plan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	plan.Executable = executable
	if _, err := startReleaseProcess(ctx, plan); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("synthetic executable accepted by release entry: %v", err)
	}
	// Then rejection occurs before ownership reservation or child creation.
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ownership created for rejected executable: %v", err)
	}
}

func TestProcessCalibrationOwnershipCannotBeReused(t *testing.T) {
	// Given a live synthetic worker's exclusively reserved directory.
	p, _ := calibrationProcess(t, "wait", 1024)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// When a second invocation uses that ownership reservation, launch fails.
	_, err := startOwnedProcess(ctx, p.plan, p.Identity().ExecutableSHA256, true)
	if err == nil {
		t.Fatal("duplicate ownership launched")
	}
	// Then the original child remains independently controllable.
	if err := p.Suspend(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestProcessStatCalibrationParsesParenthesesAndRejectsMissingStart(t *testing.T) {
	stat := "123 (synthetic (worker)) T 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0"
	state, start, err := parseProcessStat(stat, 123)
	if err != nil || state != 'T' || start != "98765" {
		t.Fatalf("stat identity: %c %q %v", state, start, err)
	}
	for _, bad := range []string{"", "123 (worker) T 0", strings.Replace(stat, "98765", "secret", 1)} {
		if _, _, err := parseProcessStat(bad, 123); err == nil {
			t.Fatalf("invalid stat accepted: %q", bad)
		}
	}
	if _, _, err := parseProcessStat(stat, 124); err == nil {
		t.Fatal("different PID accepted")
	}
}

func TestProcessCalibrationNaturalExitAndMissingProcess(t *testing.T) {
	// Given a synthetic child that exits normally.
	p, _ := calibrationProcess(t, "exit", 1024)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// When it completes, waiting obtains the retained result without signalling.
	result, err := p.Wait(ctx)
	// Then absence is distinct from a requested kill or a successful signal.
	if err != nil || !result.Reaped || result.ExitCode != 0 || result.Signal != "" {
		t.Fatalf("normal calibration exit: %+v %v", result, err)
	}
	if err := p.Suspend(ctx); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("missing child suspension accepted: %v", err)
	}
	if _, _, err := readProcessState(-1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing process state: %v", err)
	}
}

func TestProcessCalibrationWaitDeadlinePreservesOwnership(t *testing.T) {
	// Given a live synthetic child and a shorter observation context.
	p, _ := calibrationProcess(t, "wait", 1024)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// When only the caller's Wait context expires, it cannot consume Wait ownership.
	if _, err := p.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("observation cancellation: %v", err)
	}
	// Then the retained handle can still terminate and reap the same invocation.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
	defer cleanupCancel()
	if err := p.Signal(cleanupCtx, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	result, err := p.Wait(cleanupCtx)
	if err != nil || !result.Reaped || result.Signal != "SIGKILL" {
		t.Fatalf("ownership lost after observation cancellation: %+v %v", result, err)
	}
}

// Inspect retained elapsed observations rather than deriving durations from UTC.
func assertCalibrationElapsedEvidence(t *testing.T, p *ownedProcess, result processExit, signalRequest string) {
	t.Helper()
	identity := p.Identity()
	if identity.LaunchRequestedAt.IsZero() || identity.StartedElapsedNanoseconds < 0 || result.ElapsedNanoseconds < identity.StartedElapsedNanoseconds {
		t.Fatalf("invalid launch/start/exit elapsed evidence: %+v %+v", identity, result)
	}
	f, err := os.Open(filepath.Join(p.plan.Directory, "actions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	previous := identity.StartedElapsedNanoseconds
	reached := false
	for {
		var action processAction
		err := decoder.Decode(&action)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if action.ElapsedNanoseconds < previous || action.Identity.RunID != identity.RunID || action.Identity.WorkerID != identity.WorkerID || action.Identity.PID != identity.PID || action.Identity.StartTicks != identity.StartTicks {
			t.Fatalf("invalid action elapsed/identity: %+v", action)
		}
		previous = action.ElapsedNanoseconds
		if action.Action == signalRequest {
			reached = true
			if result.ElapsedNanoseconds < action.ElapsedNanoseconds {
				t.Fatalf("wait observation precedes signal request: %+v %+v", result, action)
			}
		}
	}
	if !reached {
		t.Fatalf("missing elapsed signal request %q", signalRequest)
	}
	data, err := os.ReadFile(filepath.Join(p.plan.Directory, "exit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var retained processExit
	if err := json.Unmarshal(data, &retained); err != nil {
		t.Fatal(err)
	}
	if retained.ElapsedNanoseconds != result.ElapsedNanoseconds || retained.Identity.StartedElapsedNanoseconds != identity.StartedElapsedNanoseconds {
		t.Fatalf("persisted elapsed evidence differs from observations: %+v %+v", retained, result)
	}
}

func TestProcessCalibrationInvocationsHaveSeparateRunIdentity(t *testing.T) {
	// Given two independent synthetic invocations of the same helper role.
	first, _ := calibrationProcess(t, "wait", 1024)
	second, _ := calibrationProcess(t, "wait", 1024)
	// When their ownership receipts are retained, each identifies its own run.
	if first.Identity().RunID == second.Identity().RunID {
		t.Fatal("independent calibration invocations share run identity")
	}
	for _, p := range []*ownedProcess{first, second} {
		if err := p.Cleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(p.plan.Directory, "ownership.json"))
		if err != nil {
			t.Fatal(err)
		}
		var ownership struct {
			Identity    processIdentity
			Calibration bool
		}
		if err := json.Unmarshal(data, &ownership); err != nil {
			t.Fatal(err)
		}
		// Then calibration stays explicit and agrees with the started invocation.
		if !ownership.Calibration || ownership.Identity.RunID != p.Identity().RunID || ownership.Identity.WorkerID != p.Identity().WorkerID {
			t.Fatalf("ownership history mismatch: %+v %+v", ownership, p.Identity())
		}
	}
}

// heldProcessCancellation pauses this synthetic monitor after it has selected
// cancellation, before its record or cleanup can enter the controller locks.
// The real process controller uses ordinary context.Context without test hooks.
type heldProcessCancellation struct {
	context.Context
	done, entered, release chan struct{}
	once                   sync.Once
}

func (c *heldProcessCancellation) Done() <-chan struct{} { return c.done }
func (c *heldProcessCancellation) Err() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return context.Canceled
}

func TestProcessCalibrationCleanupJoinsLateCancellationMonitor(t *testing.T) {
	for _, missingActions := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing-actions-%t", missingActions), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given a synthetic reaped worker whose cancellation monitor has not yet
				// entered record/cleanup, the same gap can occur after Cmd.Wait completes.
				directory := t.TempDir()
				actionsPath := filepath.Join(directory, "actions.jsonl")
				if !missingActions {
					if err := os.WriteFile(actionsPath, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				p := &ownedProcess{
					plan:              processPlan{Directory: directory, CleanupTimeout: time.Second},
					identity:          processIdentity{RunID: "synthetic-monitor-" + rand.Text(), WorkerID: "already-reaped"},
					launchRequestedAt: time.Now(), done: make(chan struct{}), monitorDone: make(chan struct{}), cleanupLock: make(chan struct{}, 1),
					result: processExit{Reaped: true, ExitCode: 0},
				}
				ctx := &heldProcessCancellation{Context: context.Background(), done: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
				var releaseOnce sync.Once
				releaseMonitor := func() { releaseOnce.Do(func() { close(ctx.release) }) }
				defer releaseMonitor()
				close(ctx.done)
				go p.monitorContext(ctx)
				<-ctx.entered
				close(p.done)
				retained, err := p.Wait(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				// When public Cleanup runs after Wait, lock serialization alone would let
				// it return while the monitor can still append a cancellation action.
				cleanupResult := make(chan error, 1)
				go func() { cleanupResult <- p.Cleanup(context.Background()) }()
				synctest.Wait() // both goroutines have reached their deterministic gates
				select {
				case err := <-cleanupResult:
					t.Fatalf("cleanup returned before monitor completed: %v", err)
				default:
				}
				releaseMonitor()
				synctest.Wait()
				err = <-cleanupResult
				// Then Cleanup joins the monitor and reports any action failure that arose
				// after the immutable Wait result was already available.
				if missingActions {
					if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("late action evidence failure lost: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				select {
				case <-p.monitorDone:
				default:
					t.Fatal("cleanup did not join monitor completion")
				}
				again, waitErr := p.Wait(context.Background())
				if waitErr != nil || again != retained {
					t.Fatalf("late cleanup changed retained Wait result: %+v %v", again, waitErr)
				}
				if !missingActions {
					before, err := os.ReadFile(actionsPath)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(string(before), "context_cancelled") != 1 {
						t.Fatalf("missing or repeated cancellation receipt: %s", before)
					}
					if err := p.Cleanup(context.Background()); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					after, err := os.ReadFile(actionsPath)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatalf("finalized receipts changed: %v", err)
					}
				}
			})
		})
	}
}
