package campaign

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func nativeCheckSourceFixture(t *testing.T) (string, []NativeCheckSourceFile) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "scripts"), 0700); err != nil {
		t.Fatal(err)
	}
	var rows []NativeCheckSourceFile
	for _, item := range []struct{ path, body string }{
		{"go.mod", "module synthetic/native-source\ngo 1.26.0\n"},
		{"go.sum", "synthetic data only\n"},
		{"scripts/check.sh", "#!/bin/sh\nexit 0\n"},
	} {
		if err := os.WriteFile(filepath.Join(root, item.path), []byte(item.body), 0600); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, NativeCheckSourceFile{Path: item.path, Bytes: int64(len(item.body)), SHA256: processDigest([]byte(item.body)), Mode: 0600})
	}
	return root, rows
}

func TestNativeCheckCompleteSourceRejectsChangedMissingAndExtraWork(t *testing.T) {
	// Given a complete externally bound source catalog, a plausible check script
	// cannot cover a missing dependency or an additional executable source file.
	for _, fault := range []string{"healthy", "changed", "missing", "extra", "hardlink", "symlink", "public_mode", "duplicate", "escape", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			root, rows := nativeCheckSourceFixture(t)
			if err := checkNativeSource(root, rows); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "changed":
				if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("different known bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(root, "go.sum")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(root, "scripts", "extra.go"), []byte("package extra\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink", "symlink":
				path := filepath.Join(root, "go.sum")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				var err error
				if fault == "hardlink" {
					err = os.Link(filepath.Join(root, "go.mod"), path)
				} else {
					err = os.Symlink("go.mod", path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "public_mode":
				if err := os.Chmod(filepath.Join(root, "go.sum"), 0644); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				rows = append(rows[:1], append([]NativeCheckSourceFile{rows[0]}, rows[1:]...)...)
			case "escape":
				rows[0].Path = "../outside"
			case "oversized":
				rows[0].Bytes = nativeCheckSourceLimit + 1
			}
			err := checkNativeSource(root, rows)
			if (err == nil) != (fault == "healthy") {
				t.Fatalf("source admission did not detect %s", fault)
			}
		})
	}
}

func nativeCheckStoppedFixture() NativeCheckResult {
	return NativeCheckResult{Version: "1", Namespace: "harness/native-unit-check", RunID: "native-test", Status: "INCOMPLETE",
		SourceAdmitted: true, SourceUnchanged: true, StdoutEOF: true, StderrEOF: true, PriorPayloadFilesClosed: true,
		CommandReturnedSuccessfully: true, CommandWritersStopped: true,
		Wait: LinkCalibrationWait{Started: true, WaitReturned: true, Reaped: true, StreamCopiesJoined: true,
			PID: 123, StartTicks: "456", OutputComplete: true},
		Tree: LinkCalibrationTree{SubreaperEnabled: true, AnchorStarted: true, AnchorPID: 122, AnchorStartTicks: "455",
			AnchorWaitReturned: true, AnchorReaped: true, AnchorStatus: int(syscall.SIGTERM), SignalsClosed: true, Closed: true, NoChildren: true}}
}

func TestNativeCheckFinalizationRejectsMissingProducerFacts(t *testing.T) {
	// Given an exit0 and plausible success flags, the real finalizer still needs
	// every actual producer/EOF/source/close fact before exposing result.json.
	for _, missing := range []string{"wait", "reap", "copies", "pid", "start", "stdout_eof", "stderr_eof", "anchor_wait", "anchor_reap", "anchor_identity", "anchor_status", "adopted_live", "tree", "children", "refusal", "postcheck", "source", "payload_close", "capture", "command_error", "overflow", "nonzero", "retained_error"} {
		t.Run(missing, func(t *testing.T) {
			directory, sink := driverProofFiles(t)
			r, capture := nativeCheckStoppedFixture(), true
			switch missing {
			case "wait":
				r.Wait.WaitReturned = false
			case "reap":
				r.Wait.Reaped = false
			case "copies":
				r.Wait.StreamCopiesJoined = false
			case "pid":
				r.Wait.PID = 0 // an Orb client result cannot supply the guest child PID
			case "start":
				r.Wait.StartTicks = ""
			case "stdout_eof":
				r.StdoutEOF = false
			case "stderr_eof":
				r.StderrEOF = false
			case "anchor_wait":
				r.Tree.AnchorWaitReturned = false
			case "anchor_reap":
				r.Tree.AnchorReaped = false
			case "anchor_identity":
				r.Tree.AnchorStartTicks = ""
			case "anchor_status":
				r.Tree.AnchorStatus = 0
			case "adopted_live":
				r.Tree.Adopted = []LinkCalibrationAdoptedWait{{PID: 124, Terminal: false}}
			case "tree":
				r.Tree.Closed = false
			case "children":
				r.Tree.NoChildren = false
			case "refusal":
				r.Tree.ControlFailed = true
			case "postcheck":
				r.SourceUnchanged = false
			case "source":
				r.SourceAdmitted = false
			case "payload_close":
				r.PriorPayloadFilesClosed = false
			case "capture":
				capture = false
			case "command_error":
				r.CommandReturnedSuccessfully = false // canceled command can still exit0
			case "overflow":
				r.Wait.StdoutBytes, r.Wait.CapturedStdoutBytes, r.Wait.DroppedObservedStdoutBytes = nativeCheckOutputLimit+1, nativeCheckOutputLimit, 1
			case "nonzero":
				r.Wait.ExitCode = 7
			case "retained_error":
				if !retainLinkCalibrationError(sink, []string{"synthetic"}, errors.New("original failure")) {
					t.Fatal("failure control could not reach primary sink")
				}
			}
			got, err := finishNativeCheck(directory, sink, r, capture)
			if err == nil || got.NativeHarnessChecksPassed || got.ReleaseQualified || got.OwnFinalCloseProven || !got.RequiresExternalWaitAndMacReadback {
				t.Fatal("missing producer fact promoted to completed native custody")
			}
		})
	}
}

func TestNativeCheckFinalCloseFailureKeepsOriginalPending(t *testing.T) {
	directory, sink := driverProofFiles(t)
	if err := sink.File.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := finishNativeCheck(directory, sink, nativeCheckStoppedFixture(), true)
	if err == nil || got.NativeHarnessChecksPassed {
		t.Fatal("failed last sink close produced passing result")
	}
	if _, err := os.Stat(filepath.Join(directory, "result.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed final close published terminal receipt")
	}
	if _, err := os.Stat(filepath.Join(directory, "result.pending.json")); err != nil {
		t.Fatal("original pending result was discarded")
	}
}

func TestNativeCheckSuccessStillRequiresExternalParentAndMac(t *testing.T) {
	directory, sink := driverProofFiles(t)
	r := nativeCheckStoppedFixture()
	r.OwnFinalCloseProven, r.ReleaseQualified = true, true // cannot be serialized even if a caller supplies them
	got, err := finishNativeCheck(directory, sink, r, true)
	if err != nil || !got.NativeHarnessChecksPassed || got.OwnFinalCloseProven || got.ReleaseQualified || !got.RequiresExternalWaitAndMacReadback {
		t.Fatal("harness verdict incorrectly claimed external custody or qualification")
	}
	if _, err := sink.Write([]byte("late synthetic write")); err == nil {
		t.Fatal("primary error writer remained open")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored NativeCheckResult
	if json.Unmarshal(raw, &stored) != nil || !stored.NativeHarnessChecksPassed || stored.OwnFinalCloseProven || stored.ReleaseQualified || !stored.RequiresExternalWaitAndMacReadback {
		t.Fatal("stored receipt changed the boundary")
	}
}

func TestNativeCheckEnvironmentHasNoOptinsOrCacheRedirect(t *testing.T) {
	for _, value := range []string{"LAB_LINKS=1", "LAB_INTEGRATION=1", "LAB_HARDWARE_GDB=1", "GOCACHE=/synthetic", "LD_PRELOAD=synthetic", "GITHUB_TOKEN=synthetic"} {
		parts := strings.SplitN(value, "=", 2)
		t.Setenv(parts[0], parts[1])
	}
	if !slices.Equal(nativeCheckEnvironment(), []string{"PATH=/usr/local/go/bin:/usr/bin:/bin", "HOME=/home/labrunner", "LC_ALL=C"}) {
		t.Fatal("ambient credentials, opt-ins or cache overrides entered fixed child environment")
	}
}

func TestNativeCheckCaptureProfileDoesNotWidenLinkCalibration(t *testing.T) {
	for _, limit := range []int{0, nativeCheckOutputLimit} {
		out := &linkCalibrationOutput{overflow: make(chan struct{}), limit: limit}
		body := bytes.Repeat([]byte{0, 255}, 48<<10)
		if _, err := out.Write(body); err != nil {
			t.Fatal(err)
		}
		actual, observed := out.snapshot()
		want := len(body)
		if limit == 0 {
			want = linkCalibrationOutputLimit
		}
		if len(actual) != want || observed != int64(len(body)) || !bytes.Equal(actual, body[:want]) {
			t.Fatal("fixed capture profile lost exact binary prefix or widened old link bound")
		}
	}
	// Reach the NEW bound using finite chunks: a prefix-only snapshot without
	// the overflow event must never be admitted as a complete native stream.
	out := &linkCalibrationOutput{overflow: make(chan struct{}), limit: nativeCheckOutputLimit}
	chunk := bytes.Repeat([]byte{7}, 64<<10)
	for copied := 0; copied < nativeCheckOutputLimit; copied += len(chunk) {
		if _, err := out.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := out.Write([]byte{0, 255}); err != nil {
		t.Fatal(err)
	}
	prefix, observed := out.snapshot()
	if len(prefix) != nativeCheckOutputLimit || observed != nativeCheckOutputLimit+2 || prefix[len(prefix)-1] != 7 {
		t.Fatal("native overflow did not preserve exact bounded prefix/count")
	}
	select {
	case <-out.overflow:
	default:
		t.Fatal("native output overflow did not reach the stop trigger")
	}
}

func TestNativeCheckReservationCannotAdoptOrOverwriteAttempt(t *testing.T) {
	root, _ := nativeCheckSourceFixture(t)
	p := NativeCheckPlan{Repository: root, RunID: "native-test", ReviewedHead: strings.Repeat("a", 40), InputSHA256: strings.Repeat("b", 64)}
	directory, sink, err := reserveNativeCheck(p)
	if err != nil {
		t.Fatal(err)
	}
	if !retainLinkCalibrationError(sink, []string{"synthetic"}, errors.New("EXACT synthetic first refusal")) {
		t.Fatal("first cause unavailable")
	}
	if err := closeLinkCalibrationSink(sink); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "errors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reserveNativeCheck(p); err == nil {
		t.Fatal("existing attempt adopted")
	}
	after, err := os.ReadFile(filepath.Join(directory, "errors.json"))
	var original struct{ Errors []struct{ Cause []byte } }
	if err != nil || !bytes.Equal(before, after) || json.Unmarshal(after, &original) != nil || len(original.Errors) != 1 || string(original.Errors[0].Cause) != "EXACT synthetic first refusal" {
		t.Fatal("original exact first refusal changed")
	}
}
