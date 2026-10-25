//go:build linux

package campaign

import (
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

// Every stand-in has a finite self-exit, including when a literal denial stops
// all controller escalation. These specimens never invoke Docker or Kaferry.
func TestLinkCalibrationTreeAnchorSpecimen(t *testing.T) {
	if os.Getenv("LINK_TREE_ANCHOR") == "" {
		return
	}
	lifetime := 12 * time.Second
	if os.Getenv("LINK_TREE_ANCHOR") == "early" {
		lifetime = 200 * time.Millisecond
	}
	signal.Ignore(syscall.SIGTERM)
	time.Sleep(lifetime)
	os.Exit(0)
}
func TestLinkCalibrationTreeLeafSpecimen(t *testing.T) {
	if os.Getenv("LINK_TREE_LEAF") == "" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	if e := os.WriteFile(os.Getenv("LINK_TREE_READY"), []byte(strconv.Itoa(os.Getpid())), 0600); e != nil {
		os.Exit(23)
	}
	fmt.Fprintln(os.Stdout, "PRIVATE orphan still owns output; WRITERS_QUIESCENT")
	lifetime := 12 * time.Second
	if os.Getenv("LINK_TREE_ESCAPED") == "1" {
		lifetime = 3 * time.Second
	}
	time.Sleep(lifetime)
	os.Exit(0)
}
func TestLinkCalibrationTreeParentSpecimen(t *testing.T) {
	mode := os.Getenv("LINK_TREE_PARENT")
	if mode == "" {
		return
	}
	// Independent hard exit bounds the specimen even if process signaling fails.
	go func() { time.Sleep(14 * time.Second); os.Exit(24) }()
	signal.Ignore(syscall.SIGTERM)
	if mode == "exit" {
		fmt.Fprintln(os.Stdout, "PRIVATE fake PASS; WRITERS_QUIESCENT")
		return
	}
	exe, e := os.Executable()
	if e != nil {
		os.Exit(25)
	}
	leaf := exec.Command(exe, "-test.run=^TestLinkCalibrationTreeLeafSpecimen$")
	leaf.Env = []string{"LINK_TREE_ESCAPED=" + map[bool]string{true: "1", false: "0"}[mode == "escaped"], "LINK_TREE_LEAF=1", "LINK_TREE_READY=" + os.Getenv("LINK_TREE_READY"), "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	if mode == "escaped" {
		leaf.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	leaf.Stdout, leaf.Stderr = os.Stdout, os.Stderr
	if e = leaf.Start(); e != nil {
		os.Exit(26)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, e = os.Stat(os.Getenv("LINK_TREE_READY")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(27)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mode == "orphan" || mode == "early-anchor" || mode == "escaped" {
		os.Exit(0)
	} // deliberately do NOT Wait
	if mode == "overflow" {
		fmt.Fprint(os.Stdout, strings.Repeat("x", 2*linkCalibrationOutputLimit))
	}
	time.Sleep(12 * time.Second)
	os.Exit(0)
}

// Subreaper is set only inside this isolated owned controller subprocess, never
// on the ordinary shared go-test process or alongside unrelated Cmd.Wait calls.
func TestLinkCalibrationTreeControllerSpecimen(t *testing.T) {
	mode := os.Getenv("LINK_TREE_CONTROLLER")
	if mode == "" {
		return
	}
	go func() { time.Sleep(32 * time.Second); os.Exit(28) }()
	// Keep actual native syscall failures private; public control output is fixed.
	privateFile, e := os.OpenFile(filepath.Join(os.Getenv("LINK_TREE_DIRECTORY"), "native-control-errors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal("native control private sink unavailable")
	}
	privateSink, e := newLinkCalibrationSink(privateFile, "driver-native-control")
	if e != nil {
		t.Fatal("native control private prefix incomplete")
	}
	defer func() {
		if !privateSink.finalized {
			closeLinkCalibrationSink(privateSink)
		}
	}()
	fail := func(cause error) {
		retainLinkCalibrationError(privateSink, []string{"owned_native_tree_control"}, cause)
		t.Fatal("owned native lifecycle operation failed; private notice retained if available")
	}

	if e := nativeProcessPlatform(); e != nil {
		fail(e)
	}
	seed, e := prepareLinkCalibrationTree()
	if e != nil {
		fail(e)
	}
	if mode == "initial-failure" {
		// No anchor/test/cleanup is launched. The actual kernel must attest the
		// prepared controller's empty subtree before a writer-only marker.
		cause := errors.Join(syscall.EPERM, errors.New("PRIVATE synthetic initial facility failure"))
		if !retainLinkCalibrationError(privateSink, []string{"fixture.UpLinks", "docker", "info"}, cause) {
			t.Fatal("initial failure retention incomplete")
		}
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		tree, err := drainLinkCalibrationChildren(ctx, seed)
		stop()
		if err != nil || !tree.NoChildren || !tree.Closed {
			fail(errors.Join(err, errors.New("empty controller child closure unavailable")))
		}
		r := LinkCalibrationResult{Version: "1", RunID: "driver-native-control", Synthetic: true, Status: "INCOMPLETE", SetupReturned: true, Tree: tree}
		publicDir := filepath.Join(os.Getenv("LINK_TREE_DIRECTORY"), "initial-failure-public")
		if e := os.Mkdir(publicDir, 0700); e != nil {
			fail(e)
		}
		got, err := finishLinkCalibration(publicDir, privateSink, r, true)
		if err == nil || !got.WritersQuiescent || !got.PrivateCaptureComplete || got.CleanupAttempted || got.CleanupReturned || got.ResourcesCleaned || got.Status != "INCOMPLETE" || got.SealingReady || got.PublicationAuthorized {
			t.Fatal("empty-tree initial failure invented cleanup or qualification")
		}
		return
	}
	exe, e := os.Executable()
	if e != nil {
		fail(e)
	}
	anchor := exec.Command(exe, "-test.run=^TestLinkCalibrationTreeAnchorSpecimen$")
	anchorMode := "normal"
	if mode == "early-anchor" {
		anchorMode = "early"
	}
	anchor.Env = []string{"LINK_TREE_ANCHOR=" + anchorMode, "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	g, e := startLinkCalibrationGroup(anchor, seed)
	if e != nil {
		fail(e)
	}
	if mode == "denied" {
		calls := 0
		g.killGroup = func(int, syscall.Signal) error {
			calls++
			return errors.Join(syscall.EPERM, errors.New("PRIVATE signal refusal"))
		}
		_, sink := driverProofFiles(t)
		if e = g.beginStop(); e == nil {
			t.Fatal("literal denial accepted")
		}
		original := e.Error()
		if !retainLinkCalibrationError(sink, []string{"group_signal", "SIGCONT"}, e) {
			t.Fatal("literal original signal failure not retained")
		}
		g.lastSignal() // must not issue an escalation after refusal
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		defer cancel()
		tree, e := g.close(ctx, true)
		if e == nil || calls != 1 || !tree.ControlFailed || !tree.Closed || !tree.NoChildren || !tree.AnchorReaped {
			t.Fatal("denial escalated, lost actual finite wait, or fabricated success")
		}
		if err := closeLinkCalibrationSink(sink); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(sink.Name())
		if err != nil {
			t.Fatal(err)
		}
		var saved struct{ Errors []struct{ Cause []byte } }
		if json.Unmarshal(body, &saved) != nil || len(saved.Errors) != 1 || string(saved.Errors[0].Cause) != original {
			t.Fatal("original denial cause lost before public conversion")
		}
		if e = g.signal(syscall.SIGKILL); e == nil || calls != 1 {
			t.Fatal("group signalled after anchor reap")
		}
		return
	}
	ready := filepath.Join(os.Getenv("LINK_TREE_DIRECTORY"), "leaf-ready")
	parent := exec.Command(exe, "-test.run=^TestLinkCalibrationTreeParentSpecimen$")
	parent.Env = []string{"LINK_TREE_PARENT=" + mode, "LINK_TREE_READY=" + ready, "GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	if mode == "early-anchor" {
		time.Sleep(300 * time.Millisecond)
	} // anchor remains unreaped
	if mode == "escaped" {
		if e = g.attach(parent); e != nil {
			fail(e)
		}
		if e = parent.Start(); e != nil {
			fail(e)
		}
		if e = parent.Wait(); e != nil {
			fail(e)
		} // the sole direct owner is closed
		if e = g.beginStop(); e != nil {
			fail(e)
		}
		if e = g.lastSignal(); e != nil {
			fail(e)
		}
		short, stop := context.WithTimeout(context.Background(), time.Second)
		tree, err := g.close(short, true)
		stop()
		if err != nil && !retainLinkCalibrationError(privateSink, []string{"escaped_live_observation"}, err) {
			t.Fatal("original escaped-wait failure not retained")
		}
		if err == nil || tree.Closed || tree.NoChildren || !tree.AnchorReaped {
			t.Fatal("escaped live descendant fabricated closed tree")
		}
		// The negative observation stays failed. Only wait for the bounded
		// stand-in's own expiry; never signal a guessed PID or another PGID.
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		final, err := drainLinkCalibrationChildren(cleanup, tree)
		stop()
		if err != nil || !final.Closed || !final.NoChildren || len(final.Adopted) != 1 || !final.Adopted[0].Terminal {
			t.Fatal("finite escaped stand-in was not actually reaped")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if mode == "cancel" {
		go func() {
			deadline := time.Now().Add(4 * time.Second)
			for {
				if _, e := os.Stat(ready); e == nil {
					cancel()
					return
				}
				if time.Now().After(deadline) {
					cancel()
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	wait, out, _, _, runErr := waitLinkCalibrationCommand(ctx, parent, g)
	tree := g.result
	if runErr != nil && !retainLinkCalibrationError(privateSink, []string{"actual_owned_tree_wait"}, runErr) {
		t.Fatal("original owned tree failure not retained")
	}
	if runErr == nil || !wait.WaitReturned || !wait.Reaped || !wait.StreamCopiesJoined || !tree.AnchorWaitReturned || !tree.AnchorReaped || !tree.Closed || !tree.NoChildren || !tree.SignalsClosed {
		t.Fatal("owned waits/closed subtree were replaced by exit text or timeout")
	}
	if mode != "exit" {
		raw, e := os.ReadFile(ready)
		if e != nil {
			fail(e)
		}
		leafPID, e := strconv.Atoi(string(raw))
		if e != nil {
			fail(e)
		}
		found := false
		for _, reap := range tree.Adopted {
			if reap.PID == leafPID && reap.Terminal && syscall.WaitStatus(reap.Status).Signaled() {
				found = true
			}
		}
		if !found {
			t.Fatal("actual orphan terminal wait missing")
		}
	}
	if mode == "orphan" && wait.OutputComplete {
		t.Fatal("descendant-held pipe wrongly complete")
	}
	if mode == "overflow" && (wait.OutputComplete || len(out) != linkCalibrationOutputLimit || wait.CapturedStdoutBytes != linkCalibrationOutputLimit || wait.DroppedObservedStdoutBytes <= 0) {
		t.Fatal("overflow falsely complete or exact prefix lost")
	}
	if mode == "exit" || mode == "overflow" {
		if e := closeLinkCalibrationSink(privateSink); e != nil {
			t.Fatal("control primary terminal close incomplete")
		}
		dir, sink := driverProofFiles(t)
		if !retainLinkCalibrationError(sink, []string{"owned_tree_control"}, runErr) {
			t.Fatal("original controller failure not retained")
		}
		if err := persistLinkCalibrationJSON(dir, "child-output.json", struct {
			RunID  string
			Output []byte
		}{"driver-test", out}); err != nil {
			t.Fatal(err)
		}
		r := driverStoppedResult()
		r.Wait = wait
		r.Tree = tree
		got, err := finishLinkCalibration(dir, sink, r, wait.OutputComplete)
		if err == nil || got.WritersQuiescent != (mode == "exit") {
			t.Fatal("real closure/capture facts did not control final marker")
		}
		if mode == "overflow" {
			if _, err = os.Stat(filepath.Join(dir, "WRITERS_QUIESCENT.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("overflow laundered complete writer evidence")
			}
		}
	}
	before := len(tree.Signals)
	if e = g.signal(syscall.SIGKILL); e == nil || len(g.result.Signals) != before {
		t.Fatal("signal phase reopened after anchor wait")
	}
	raw, e := json.Marshal(tree)
	if e != nil || strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("raw private cause entered public tree facts")
	}
}
func TestLinkCalibrationOwnedOrphanTreeLifecycle(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("owned lifecycle control requires native Linux AMD64")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal("native control executable unavailable; exact first prerequisite notice unavailable")
	}
	// Ordinary go test runs this package from internal/campaign. Keep bounded
	// raw native-control notices in ignored owner-only storage, not t.TempDir
	// (which would delete a failure) or the public unit artifact directory.
	repo, e := filepath.Abs(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal("native control repository unavailable")
	}
	module, e := os.ReadFile(filepath.Join(repo, "go.mod"))
	if e != nil || !strings.HasPrefix(string(module), "module github.com/pagrus7/kaferry-lab\n") {
		t.Fatal("native control requires package working directory")
	}
	parentDir := filepath.Join(repo, ".cache", "link-driver-native-controls")
	if e = os.MkdirAll(parentDir, 0700); e != nil {
		t.Fatal("native control private storage unavailable")
	}
	if info, e := os.Lstat(parentDir); e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("native control private storage not owner-only")
	}
	for _, mode := range []string{"exit", "orphan", "cancel", "overflow", "early-anchor", "denied", "escaped", "initial-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 38*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestLinkCalibrationTreeControllerSpecimen$", "-test.v")
			directory, e := os.MkdirTemp(parentDir, mode+"-")
			if e != nil {
				t.Fatal("native control private attempt unavailable")
			}
			cmd.Env = []string{"LINK_TREE_CONTROLLER=" + mode, "LINK_TREE_DIRECTORY=" + directory, "GOCOVERDIR=" + t.TempDir()}
			out, diagnostic := &linkCalibrationOutput{overflow: make(chan struct{})}, &linkCalibrationOutput{overflow: make(chan struct{})}
			cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, diagnostic, time.Second
			err := cmd.Run()
			stdout, stdoutCount := out.snapshot()
			stderr, stderrCount := diagnostic.snapshot()
			var cause []byte
			if err != nil {
				cause = []byte(err.Error())
			}
			causeBytes := len(cause)
			causeComplete := causeBytes <= 64<<10
			if !causeComplete {
				cause = cause[:64<<10]
			}
			stdout = stdout[:min(len(stdout), 32<<10)]
			stderr = stderr[:min(len(stderr), 32<<10)]
			if e := persistLinkCalibrationJSON(directory, "controller-output.json", struct {
				RunID                                 string
				Argv                                  []string
				Cause, Stdout, Stderr                 []byte
				StdoutObserved, StderrObserved        int64
				Reaped, OutputComplete, CauseComplete bool
				CauseBytes                            int
			}{"driver-native-control", cmd.Args, cause, stdout, stderr, stdoutCount, stderrCount, cmd.ProcessState != nil, stdoutCount <= linkCalibrationOutputLimit && stderrCount <= linkCalibrationOutputLimit && !errors.Is(err, exec.ErrWaitDelay) && stdoutCount == int64(len(stdout)) && stderrCount == int64(len(stderr)), causeComplete, causeBytes}); e != nil {
				t.Fatal("native control output retention incomplete")
			}
			if stdoutCount > int64(len(stdout)) || stderrCount > int64(len(stderr)) || !causeComplete {
				t.Fatal("native control output exceeded capture bound")
			}
			if err != nil {
				t.Fatal("owned lifecycle control failed; retain its private ignored notices")
			}
		})
	}
}
func TestLinkCalibrationClosedTreeRequiresActualECHILD(t *testing.T) {
	// A missing wait fact cannot make an anchored owner perform a broad drain.
	// Production requires this predicate before the serial -1 syscall phase.
	g := &linkCalibrationGroup{result: LinkCalibrationTree{SubreaperEnabled: true, SignalsClosed: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tree, err := g.close(ctx, false)
	if err == nil || tree.Closed || tree.NoChildren {
		t.Fatal("missing direct wait fabricated ECHILD")
	}
}
