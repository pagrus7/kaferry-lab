//go:build linux

package campaign

import (
	"bytes"
	"context"
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
	fail := func(cause error) {
		retainLinkCalibrationError(sink, []string{"native_controller_control"}, cause)
		t.Fatal("native check control failed; exact private notice retained if available")
	}
	seed, err := prepareLinkCalibrationTree()
	if err != nil {
		fail(err)
	}
	exe, err := os.Executable()
	if err != nil {
		fail(err)
	}
	anchor := exec.Command(exe, "-test.run=^TestLinkCalibrationTreeAnchorSpecimen$")
	anchor.Env = []string{"LINK_TREE_ANCHOR=normal", "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	group, err := startLinkCalibrationGroup(anchor, seed)
	if err != nil {
		fail(err)
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
	wait, stdout, stderr, _, waitErr := waitOwnedHarnessCommand(ctx, command, group, nativeCheckOutputLimit)
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
	for _, item := range []struct {
		name string
		body []byte
	}{{"stdout.bin", stdout}, {"stderr.bin", stderr}} {
		if err := nativeCheckWrite(directory, item.name, item.body, nativeCheckOutputLimit); err != nil {
			fail(err)
		}
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
	for _, mode := range []string{"healthy", "nonzero", "orphan", "cancel-exit0"} {
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
			if runErr != nil || outCount > linkCalibrationOutputLimit || errCount > linkCalibrationOutputLimit {
				t.Fatal("native check owned control failed; private originals retained")
			}
		})
	}
}
