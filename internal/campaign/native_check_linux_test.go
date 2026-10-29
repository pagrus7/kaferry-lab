//go:build linux

package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeCheckUnitAnchorSpecimen(t *testing.T) {
	if os.Getenv("NATIVE_CHECK_UNIT_ANCHOR") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	// This unit anchor has no descendants/output and independently expires well
	// inside the unchanged20s close bound, even after identity/signal admission
	// closes. It is not the390s production anchor or a changed production route.
	time.Sleep(12 * time.Second)
	os.Exit(0)
}

type nativeCheckControlFacts struct {
	Status, SyntheticMechanism            string
	Wait                                  LinkCalibrationWait
	Tree                                  LinkCalibrationTree
	GroupClosureStarted                   bool
	ExplicitCloseCalls, GroupSignalCalls  int
	InjectedFalseDirectWaitGate           bool
	OwnFinalCloseProven, ReleaseQualified bool
	RequiresExternalWaitAndMacReadback    bool
}

func TestNativeCheckPipeHolderSpecimen(t *testing.T) {
	if os.Getenv("NATIVE_CHECK_HOLDER") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	if err := os.WriteFile(os.Getenv("NATIVE_CHECK_READY"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(23)
	}
	fmt.Fprint(os.Stdout, "synthetic descendant holds the output pipe\n")
	time.Sleep(8 * time.Second) // independently finite if the selected signal route fails
	os.Exit(0)
}

func TestNativeCheckCommandSpecimen(t *testing.T) {
	mode := os.Getenv("NATIVE_CHECK_CASE")
	if mode == "" {
		return
	}
	go func() { time.Sleep(12 * time.Second); os.Exit(24) }()
	switch mode {
	case "healthy":
		// Exceeds the unchanged link profile; exact binary bytes must survive.
		if _, err := os.Stdout.Write(bytes.Repeat([]byte{0, 255}, 48<<10)); err != nil {
			os.Exit(25)
		}
	case "nonzero":
		fmt.Fprint(os.Stdout, "PASS\nHARNESS_CHECKS_PASSED_EXTERNAL_CUSTODY_REQUIRED\n")
		os.Exit(7)
	case "orphan":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(26)
		}
		leaf := exec.Command(exe, "-test.run=^TestNativeCheckPipeHolderSpecimen$")
		leaf.Env = []string{"NATIVE_CHECK_HOLDER=1", "NATIVE_CHECK_READY=" + os.Getenv("NATIVE_CHECK_READY"), "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
		leaf.Stdout, leaf.Stderr = os.Stdout, os.Stderr
		if err := leaf.Start(); err != nil {
			os.Exit(27)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(os.Getenv("NATIVE_CHECK_READY")); err == nil {
				os.Exit(0) // deliberately no leaf.Wait: driver must adopt and actually reap
			}
			if time.Now().After(deadline) {
				os.Exit(28)
			}
			time.Sleep(5 * time.Millisecond)
		}
	case "cancel-exit0":
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("NATIVE_CHECK_READY"), []byte("ready"), 0600); err != nil {
			os.Exit(29)
		}
		time.Sleep(400 * time.Millisecond)
		os.Exit(0)
	default:
		os.Exit(30)
	}
}

func TestNativeCheckControllerSpecimen(t *testing.T) {
	mode := os.Getenv("NATIVE_CHECK_CONTROLLER")
	if mode == "" {
		return
	}
	go func() { time.Sleep(32 * time.Second); os.Exit(31) }()
	directory := os.Getenv("NATIVE_CHECK_DIRECTORY")
	f, err := os.OpenFile(filepath.Join(directory, "errors.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("native check control first private error sink unavailable")
	}
	sink, err := newLinkCalibrationSink(f, "native-controller-control")
	if err != nil {
		t.Fatal("native check control primary error prefix incomplete")
	}
	defer func() {
		if !sink.finalized {
			closeLinkCalibrationSink(sink)
		}
	}()
	var group *linkCalibrationGroup
	var tree LinkCalibrationTree
	var wait LinkCalibrationWait
	var stdout, stderr []byte
	var explicitCloseCalls, groupSignalCalls int
	var syntheticMechanism string
	injectedGate, factsStaged := false, false
	stage := func() error {
		if factsStaged {
			return nil // one original snapshot/one attempt per selected file
		}
		factsStaged = true
		closureStarted := false
		if group != nil {
			tree, closureStarted = group.result, group.closureStarted
		}
		// Retain actually obtained facts and prefixes even when a subsequent
		// assertion must fail. This original snapshot grants no completion claim.
		return errors.Join(
			nativeCheckWrite(directory, "stdout.bin", stdout, nativeCheckOutputLimit),
			nativeCheckWrite(directory, "stderr.bin", stderr, nativeCheckOutputLimit),
			nativeCheckJSON(directory, "control-facts.json", nativeCheckControlFacts{
				Status: "INCOMPLETE", SyntheticMechanism: syntheticMechanism, Wait: wait, Tree: tree,
				GroupClosureStarted: closureStarted, ExplicitCloseCalls: explicitCloseCalls, GroupSignalCalls: groupSignalCalls,
				InjectedFalseDirectWaitGate: injectedGate, RequiresExternalWaitAndMacReadback: true,
			}))
	}
	closeGroup := func(testStopped bool) error {
		stopErr := group.beginStop()
		if stopErr == nil {
			stopErr = group.lastSignal()
		}
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer closeCancel()
		explicitCloseCalls++
		_, closeErr := group.close(closeCtx, testStopped)
		return errors.Join(stopErr, closeErr)
	}
	fail := func(cause error) {
		retainLinkCalibrationError(sink, []string{"native_controller_control"}, cause)
		if group != nil && !group.closureStarted {
			// Preserve the only stop/signal/Wait route. A post-start identity
			// failure can already have SignalsClosed=true; no alternate signal
			// is attempted, but the same owner still performs its bounded Wait.
			closed := !wait.Started || (wait.WaitReturned && wait.Reaped && wait.StreamCopiesJoined)
			if cleanupErr := closeGroup(closed); cleanupErr != nil {
				retainLinkCalibrationError(sink, []string{"native_control_failure_cleanup"}, cleanupErr)
			}
		}
		if stageErr := stage(); stageErr != nil {
			retainLinkCalibrationError(sink, []string{"native_control_failure_facts"}, stageErr)
		}
		t.Fatal("native check control failed; exact private notice retained if available")
	}
	tree, err = prepareLinkCalibrationTree()
	if err != nil {
		fail(err)
	}
	exe, err := os.Executable()
	if err != nil {
		fail(err)
	}
	anchor := exec.Command(exe, "-test.run=^TestNativeCheckUnitAnchorSpecimen$")
	anchor.Env = []string{"NATIVE_CHECK_UNIT_ANCHOR=1", "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	group, err = startLinkCalibrationGroup(anchor, tree)
	if group != nil {
		originalSignal := group.killGroup
		group.killGroup = func(pid int, signal syscall.Signal) error {
			groupSignalCalls++
			return originalSignal(pid, signal) // same selected syscall; observation only
		}
	}
	if err == nil && mode == "post-start-membership" {
		syntheticMechanism = "synthetic wrong owned controller PID supplied to membership admission; not a platform denial"
		// Supply a known owned NONmember instead of a command PID, after the
		// actual anchor start. This reaches the existing real mismatch branch.
		err = group.checkMember(os.Getpid())
		if err == nil {
			fail(errors.New("synthetic post-start membership failure was not reached"))
		}
	}
	if err != nil {
		fail(err)
	}
	if mode == "injected-wait-gate" {
		syntheticMechanism = "synthetic false direct-wait evidence-admission gate; no timed-out or unreaped child is simulated"
		injectedGate = true
		// Exercise the existing rejection AFTER the actual sole anchor Wait.
		// No command is launched. The failed original Tree lacks ECHILD/Closed
		// and is retained as such; never retry close or invent a command Wait.
		gateErr := closeGroup(false)
		if gateErr == nil {
			fail(errors.New("synthetic false direct-wait gate was not rejected"))
		}
		fail(gateErr)
	}
	ready := filepath.Join(directory, "specimen-ready")
	command := exec.Command(exe, "-test.run=^TestNativeCheckCommandSpecimen$")
	command.Env = []string{"NATIVE_CHECK_CASE=" + mode, "NATIVE_CHECK_READY=" + ready, "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reached := make(chan struct{})
	if mode == "cancel-exit0" {
		go func() {
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(ready); err == nil {
					close(reached)
					cancel()
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
		}()
	}
	var waitErr error
	wait, stdout, stderr, _, waitErr = waitOwnedHarnessCommand(ctx, command, group, nativeCheckOutputLimit)
	if waitErr != nil && !retainLinkCalibrationError(sink, []string{"fixed_native_profile_command"}, waitErr) {
		fail(errors.New("control original command notice incomplete"))
	}
	r := nativeCheckStoppedFixture()
	r.Wait, r.Tree = wait, group.result
	r.CommandReturnedSuccessfully = waitErr == nil
	r.StdoutEOF = waitErr == nil && wait.OutputComplete && wait.StreamCopiesJoined
	r.StderrEOF = r.StdoutEOF
	r.CommandWritersStopped = nativeCheckStopped(wait, r.Tree)
	if !r.CommandWritersStopped {
		fail(errors.New("control did not actually wait and close its owned tree"))
	}
	if stageErr := stage(); stageErr != nil {
		fail(stageErr)
	}
	if mode == "healthy" && (waitErr != nil || len(stdout) <= linkCalibrationOutputLimit || !bytes.Contains(stdout, bytes.Repeat([]byte{0, 255}, 48<<10))) {
		fail(errors.New("healthy native profile failed or lost binary bytes beyond old link bound"))
	}
	if mode == "nonzero" && (waitErr == nil || wait.ExitCode != 7 || !bytes.Contains(stdout, []byte("PASS\n"))) {
		fail(errors.New("nonzero fake-pass control was not reached"))
	}
	if mode == "orphan" && (waitErr == nil || wait.ExitCode != 0 || wait.OutputComplete || len(r.Tree.Adopted) != 1 || !r.Tree.Adopted[0].Terminal) {
		fail(errors.New("descendant-held pipe did not retain incomplete capture and actual adopted wait"))
	}
	if mode == "cancel-exit0" {
		select {
		case <-reached:
		default:
			fail(errors.New("cancellation readiness trigger was not reached"))
		}
		if !errors.Is(waitErr, context.Canceled) || wait.ExitCode != 0 {
			fail(errors.New("cancellation control did not preserve actual exit0 and cancellation failure"))
		}
	}
	got, finishErr := finishNativeCheck(directory, sink, r, true)
	if (finishErr == nil) != (mode == "healthy") || got.NativeHarnessChecksPassed != (mode == "healthy") || got.OwnFinalCloseProven || got.ReleaseQualified {
		t.Fatal("native check verdict confused process success, capture, cancellation or qualification")
	}
}

func TestNativeCheckOwnedCommandControls(t *testing.T) {
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		t.Skip("native owned process controls require a reviewed Linux architecture")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("native control executable unavailable")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("native control repository unavailable")
	}
	module, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil || !strings.HasPrefix(string(module), "module github.com/pagrus7/kaferry-lab\n") {
		t.Fatal("native control requires package working directory")
	}
	parent := filepath.Join(repo, ".cache", "native-check-controller-controls")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal("native control private storage unavailable")
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !nativeCheckOwned(info) {
		t.Fatal("native control private storage identity mismatch")
	}
	for _, mode := range []string{"healthy", "nonzero", "orphan", "cancel-exit0", "post-start-membership", "injected-wait-gate"} {
		t.Run(mode, func(t *testing.T) {
			directory, err := os.MkdirTemp(parent, mode+"-")
			if err != nil {
				t.Fatal("native control exclusive attempt unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 38*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, exe, "-test.run=^TestNativeCheckControllerSpecimen$")
			command.Env = []string{"NATIVE_CHECK_CONTROLLER=" + mode, "NATIVE_CHECK_DIRECTORY=" + directory, "GOCOVERDIR=" + t.TempDir()}
			out, diagnostic := &linkCalibrationOutput{overflow: make(chan struct{})}, &linkCalibrationOutput{overflow: make(chan struct{})}
			command.Stdout, command.Stderr, command.WaitDelay = out, diagnostic, time.Second
			runErr := command.Run() // actual sole foreground controller Wait
			stdout, outCount := out.snapshot()
			stderr, errCount := diagnostic.snapshot()
			var cause []byte
			if runErr != nil {
				cause = []byte(runErr.Error())
			}
			pid := 0
			if command.Process != nil {
				pid = command.Process.Pid
			}
			if err := nativeCheckJSON(directory, "controller-wait.json", struct {
				PID                        int
				WaitReturned, Reaped       bool
				Stdout, Stderr, ExactCause []byte
				StdoutBytes, StderrBytes   int64
				OwnFinalCloseProven        bool
			}{pid, true, command.ProcessState != nil, stdout, stderr, cause, outCount, errCount, false}); err != nil {
				t.Fatal("native control foreground wait retention incomplete")
			}
			negative := mode == "post-start-membership" || mode == "injected-wait-gate"
			if negative {
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
					t.Fatal("synthetic failed-controller path was not reached; private originals retained")
				}
				factsRaw, factsErr := os.ReadFile(filepath.Join(directory, "control-facts.json"))
				errorRaw, errorErr := os.ReadFile(filepath.Join(directory, "errors.json"))
				var facts nativeCheckControlFacts
				var original struct{ Errors []struct{ Cause []byte } }
				if factsErr != nil || errorErr != nil || json.Unmarshal(factsRaw, &facts) != nil || json.Unmarshal(errorRaw, &original) != nil || len(original.Errors) == 0 {
					t.Fatal("failed-controller original facts/error retention incomplete")
				}
				if facts.Status != "INCOMPLETE" || facts.SyntheticMechanism == "" || facts.Wait.Started || facts.Wait.WaitReturned ||
					!facts.GroupClosureStarted || facts.ExplicitCloseCalls != 1 || !facts.Tree.AnchorStarted || facts.Tree.AnchorPID <= 0 || facts.Tree.AnchorStartTicks == "" ||
					!facts.Tree.AnchorWaitReturned || !facts.Tree.AnchorReaped || facts.OwnFinalCloseProven || facts.ReleaseQualified || !facts.RequiresExternalWaitAndMacReadback {
					t.Fatal("failed-controller snapshot invented closure, lost actual waits or retried close")
				}
				if mode == "post-start-membership" && (string(original.Errors[0].Cause) != "test did not join the owned anchor group" || !facts.Tree.ControlFailed ||
					!facts.Tree.SignalsClosed || facts.GroupSignalCalls != 0 || len(facts.Tree.Signals) != 0 || !facts.Tree.Closed || !facts.Tree.NoChildren || !syscall.WaitStatus(facts.Tree.AnchorStatus).Exited()) {
					t.Fatal("post-start mismatch did not retain original failure and actual natural-expiry wait without signals")
				}
				if mode == "injected-wait-gate" && (string(original.Errors[0].Cause) != "direct wait ownership not closed" || !facts.InjectedFalseDirectWaitGate ||
					facts.Tree.Closed || facts.Tree.NoChildren || facts.GroupSignalCalls != 3 || !syscall.WaitStatus(facts.Tree.AnchorStatus).Signaled()) {
					t.Fatal("injected wait gate did not preserve the original incomplete tree separately from actual terminal anchor wait")
				}
				if _, err := os.Stat(filepath.Join(directory, "result.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed helper path published a completed native result")
				}
			}
			if (!negative && runErr != nil) || outCount > linkCalibrationOutputLimit || errCount > linkCalibrationOutputLimit {
				t.Fatal("native check owned control failed; private originals retained")
			}
		})
	}
}
