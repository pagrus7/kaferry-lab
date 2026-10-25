package campaign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func driverProofFiles(t *testing.T) (string, *linkCalibrationSink) {
	t.Helper()
	dir := t.TempDir()
	f, e := os.OpenFile(filepath.Join(dir, "driver-errors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	sink, e := newLinkCalibrationSink(f, "driver-test")
	if e != nil {
		t.Fatal(e)
	}
	return dir, sink
}
func driverStoppedResult() LinkCalibrationResult {
	return LinkCalibrationResult{Version: "1", RunID: "driver-test", Synthetic: true, Status: "INCOMPLETE", SetupReturned: true, CleanupAttempted: true, CleanupReturned: true, Tree: LinkCalibrationTree{SubreaperEnabled: true, Closed: true, NoChildren: true}, Wait: LinkCalibrationWait{Started: true, WaitReturned: true, Reaped: true, StreamCopiesJoined: true, PID: 123, StartTicks: "456"}}
}

func TestLinkCalibrationWriterProofRejectsMissingTerminalWaitAndActiveCalls(t *testing.T) {
	// Given plausible exit0/test-pass text, none may replace the actual sole Wait
	// or a returned synchronous fixture call on the production finalization path.
	for _, missing := range []string{"wait", "reap", "copies", "identity", "setup", "cleanup", "capture", "subreaper", "tree", "adopted_live", "control_denied"} {
		t.Run(missing, func(t *testing.T) {
			dir, sink := driverProofFiles(t)
			r := driverStoppedResult()
			capture := true
			r.Status = "CALIBRATION_PASSED_NOT_QUALIFICATION"
			r.Wait.TestsPassed = true
			r.Wait.ExitCode = 0
			switch missing {
			case "wait":
				r.Wait.WaitReturned = false
			case "reap":
				r.Wait.Reaped = false
			case "copies":
				r.Wait.StreamCopiesJoined = false
			case "identity":
				r.Wait.StartTicks = ""
			case "subreaper":
				r.Tree.SubreaperEnabled = false
			case "tree":
				r.Tree.Closed = false
			case "adopted_live":
				r.Tree.NoChildren = false
			case "control_denied":
				r.Tree.ControlFailed = true
			case "setup":
				r.SetupReturned = false
			case "cleanup":
				r.CleanupReturned = false
			case "capture":
				capture = false
			}
			result, err := finishLinkCalibration(dir, sink, r, capture)
			if err == nil || result.WritersQuiescent {
				t.Fatal("missing actual lifecycle fact admitted writer proof")
			}
			if _, e := os.Stat(filepath.Join(dir, "WRITERS_QUIESCENT.json")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("false final writer marker")
			}
		})
	}
}
func TestLinkCalibrationQuiescenceDoesNotClaimResourceCleanupOrDurability(t *testing.T) {
	// Given stopped writers and unresolved Docker state, the dedicated proof can
	// be true while the calibration, resources and current sealing gate stay false.
	dir, sink := driverProofFiles(t)
	r := driverStoppedResult()
	r.ResourcesCleaned = false
	got, err := finishLinkCalibration(dir, sink, r, true)
	if err == nil || !got.WritersQuiescent || got.ResourcesCleaned || got.SealingReady || got.PublicationAuthorized || got.ReleaseQualified {
		t.Fatal("independent facts collapsed")
	}
	if _, e := sink.Write([]byte("PRIVATE late writer")); e == nil {
		t.Fatal("private sink remained live after marker")
	}
	body, e := os.ReadFile(filepath.Join(dir, "WRITERS_QUIESCENT.json"))
	if e != nil {
		t.Fatal(e)
	}
	var stored LinkCalibrationResult
	if e = json.Unmarshal(body, &stored); e != nil || !stored.WritersQuiescent {
		t.Fatal("terminal marker missing truthful writer proof")
	}
}
func TestLinkCalibrationTerminalSinkAndPublicationFailureCannotMarkStopped(t *testing.T) {
	for _, failure := range []string{"sink_closed", "pending_exists", "rename_target"} {
		t.Run(failure, func(t *testing.T) {
			dir, sink := driverProofFiles(t)
			switch failure {
			case "sink_closed":
				sink.Close()
			case "pending_exists":
				os.WriteFile(filepath.Join(dir, "result.pending.json"), []byte("prior"), 0600)
			case "rename_target":
				os.Mkdir(filepath.Join(dir, "WRITERS_QUIESCENT.json"), 0700)
			}
			got, err := finishLinkCalibration(dir, sink, driverStoppedResult(), true)
			if err == nil || got.WritersQuiescent {
				t.Fatal("failed terminal boundary published writer proof")
			}
			info, e := os.Lstat(filepath.Join(dir, "WRITERS_QUIESCENT.json"))
			if e == nil && info.Mode().IsRegular() {
				t.Fatal("false regular completion marker")
			}
		})
	}
}
func TestLinkCalibrationExactPrivateErrorsNeverEnterPublicProof(t *testing.T) {
	dir, sink := driverProofFiles(t)
	cause := errors.Join(errors.New("unknown-PRIVATE-sentinel"), syscall.EPERM)
	if !retainLinkCalibrationError(sink, []string{"literal_action", "PRIVATE-action"}, cause) {
		t.Fatal("exact bounded original cause not retained")
	}
	got, err := finishLinkCalibration(dir, sink, driverStoppedResult(), true)
	body, e := os.ReadFile(sink.Name())
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct {
		RunID  string
		Errors []struct {
			Action   []string
			Cause    []byte
			Complete bool
		}
	}
	if e = json.Unmarshal(body, &receipt); e != nil || receipt.RunID != "driver-test" || len(receipt.Errors) != 1 || string(receipt.Errors[0].Cause) != cause.Error() || !receipt.Errors[0].Complete || len(receipt.Errors[0].Action) != 2 {
		t.Fatal("original joined failure or complete JSON object lost")
	}
	public, _ := json.Marshal(got)
	if err == nil || bytes.Contains(public, []byte("PRIVATE")) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("private action/cause leaked to public result")
	}
}
func TestLinkCalibrationRetentionOverflowAndClosedSinkAreFatal(t *testing.T) {
	for _, kind := range []string{"cause_overflow", "closed_sink", "file_cap"} {
		t.Run(kind, func(t *testing.T) {
			_, sink := driverProofFiles(t)
			defer sink.Close()
			cause := errors.New("PRIVATE")
			switch kind {
			case "cause_overflow":
				cause = errors.New(strings.Repeat("x", (64<<10)+1))
			case "closed_sink":
				sink.Close()
			case "file_cap":
				if e := sink.Truncate(256 << 10); e != nil {
					t.Fatal(e)
				}
			}
			if retainLinkCalibrationError(sink, []string{"literal"}, cause) {
				t.Fatal("incomplete exact retention accepted")
			}
		})
	}
}
func TestLinkCalibrationRequiresBothActualTestCompletions(t *testing.T) {
	healthy := "=== RUN   TestLiveOwnedWorkerLinkTopology\n--- PASS: TestLiveOwnedWorkerLinkTopology (0.01s)\n=== RUN   TestLiveOwnedLinkDirectionalLatency\n--- PASS: TestLiveOwnedLinkDirectionalLatency (0.02s)\nPASS\n"
	for _, text := range []string{"PASS\n", strings.ReplaceAll(healthy, "--- PASS: TestLiveOwnedLinkDirectionalLatency", "--- SKIP: TestLiveOwnedLinkDirectionalLatency"), healthy + healthy, strings.ReplaceAll(healthy, "=== RUN   TestLiveOwnedWorkerLinkTopology", "forged log prefix === RUN   TestLiveOwnedWorkerLinkTopology")} {
		if linkCalibrationPassed([]byte(text)) {
			t.Fatal("generic/duplicate/skipped/log-prefixed completion accepted")
		}
	}
	if !linkCalibrationPassed([]byte(healthy)) {
		t.Fatal("literal complete two-test history rejected")
	}
}

func TestLinkCalibrationFreshReservationCannotBeReused(t *testing.T) {
	// Given a real reserved first sink, another attempt must not replace it or
	// choose another path after refusal, even before any Docker operation.
	p := LinkCalibrationPlan{Repository: t.TempDir(), RunID: "driver-reservation"}
	public, private, sink, err := reserveLinkCalibration(p)
	if err != nil {
		t.Fatal(err)
	}
	literal := []byte("PRIVATE original first sink")
	if _, err = sink.Write(literal); err != nil {
		t.Fatal(err)
	}
	if err = sink.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, next, err := reserveLinkCalibration(p)
	if err == nil || next != nil {
		t.Fatal("existing ownership reused")
	}
	got, err := os.ReadFile(filepath.Join(private, "driver-errors.json"))
	if err != nil || !bytes.Contains(got, literal) {
		t.Fatal("first private evidence replaced")
	}
	if _, err = os.Stat(filepath.Join(public, "WRITERS_QUIESCENT.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reservation alone became writer proof")
	}
}

func TestLinkCalibrationPrimaryObjectIncompleteUntilFinalization(t *testing.T) {
	dir, sink := driverProofFiles(t)
	if !retainLinkCalibrationError(sink, []string{"PRIVATE literal"}, errors.New("unknown-PRIVATE")) {
		t.Fatal("original failure not appended")
	}
	before, err := os.ReadFile(sink.Name())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(before, &object) == nil {
		t.Fatal("unfinished primary sink looked complete")
	}
	result, err := finishLinkCalibration(dir, sink, driverStoppedResult(), true)
	if err == nil || !result.WritersQuiescent {
		t.Fatal("bounded finalization failed writer-only proof")
	}
	after, err := os.ReadFile(sink.Name())
	if err != nil || json.Unmarshal(after, &object) != nil || len(after) > 256<<10 {
		t.Fatal("final sink is not a bounded JSON object")
	}
	if retainLinkCalibrationError(sink, []string{"late"}, errors.New("PRIVATE")) {
		t.Fatal("finalized primary accepted a late notice")
	}
}
func TestLinkCalibrationPrivateMarkerExactAndHomeExcluded(t *testing.T) {
	p := LinkCalibrationPlan{Repository: t.TempDir(), RunID: "driver-marker"}
	_, private, sink, err := reserveLinkCalibration(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = closeLinkCalibrationSink(sink); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(private, "PRIVATE.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err = json.Unmarshal(raw, &got); err != nil || len(got) != 3 || got["RunID"] != p.RunID || got["Classification"] != "PRIVATE RAW EVIDENCE" || got["Publication"] != "withhold pending explicit redaction review" {
		t.Fatal("private marker identity/schema mismatch")
	}
	for _, name := range []string{"child-home", ".docker"} {
		if _, err = os.Stat(filepath.Join(private, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("nonreceipt home entered sealed root")
		}
	}
}

func TestLinkCalibrationPrimaryCompleteByteCapIncludesFooter(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			_, sink := driverProofFiles(t)
			info, err := sink.Stat()
			if err != nil {
				t.Fatal(err)
			}
			empty, err := json.Marshal(struct {
				Action   []string
				Cause    []byte
				Complete bool
			}{[]string{""}, []byte("literal"), true})
			if err != nil {
				t.Fatal(err)
			}
			padding := (256 << 10) - int(info.Size()) - len(empty) - 3 + extra
			admitted := retainLinkCalibrationError(sink, []string{strings.Repeat("x", padding)}, errors.New("literal"))
			if admitted != (extra == 0) {
				t.Fatal("complete-byte bound ignored JSON envelope/footer")
			}
			if err = closeLinkCalibrationSink(sink); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(sink.Name())
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > 256<<10 || (extra == 0 && len(raw) != 256<<10) {
				t.Fatal("producer file disagrees with sealer byte cap")
			}
		})
	}
}

func TestLinkCalibrationInitialFailureNoCleanupStillRetainsWriterProof(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprint(attempted), func(t *testing.T) {
			// Given a returned initial facility failure with no started test and an
			// already proved empty owned subtree, run actual receipt finalization.
			// An attempted but unreturned cleanup remains an active writer boundary.
			dir, sink := driverProofFiles(t)
			cause := errors.Join(syscall.EPERM, errors.New("PRIVATE synthetic initial Docker info failure"))
			action := []string{"fixture.UpLinks", "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"}
			if !retainLinkCalibrationError(sink, action, cause) {
				t.Fatal("initial exact synthetic failure not retained")
			}
			r := LinkCalibrationResult{Version: "1", RunID: "driver-test", Synthetic: true, Status: "INCOMPLETE", SetupReturned: true, CleanupAttempted: attempted, CleanupReturned: false, Tree: LinkCalibrationTree{SubreaperEnabled: true, Closed: true, NoChildren: true}}
			got, err := finishLinkCalibration(dir, sink, r, true)
			if err == nil || got.Status != "INCOMPLETE" || got.WritersQuiescent == attempted || !got.PrivateCaptureComplete || got.ResourcesCleaned || got.FixtureCleanupSucceeded || got.SealingReady || got.PublicationAuthorized || got.ReleaseQualified || got.CleanupReturned {
				t.Fatal("writer quiescence collapsed into resource cleanup or calibration success")
			}
			marker, e := os.ReadFile(filepath.Join(dir, "WRITERS_QUIESCENT.json"))
			if attempted {
				if !errors.Is(e, os.ErrNotExist) {
					t.Fatal("unreturned attempted cleanup published marker")
				}
			} else {
				if e != nil || bytes.Contains(marker, []byte("PRIVATE")) {
					t.Fatal("initial-failure marker missing or leaked raw cause")
				}
				var stored LinkCalibrationResult
				if json.Unmarshal(marker, &stored) != nil || !stored.WritersQuiescent || stored.CleanupAttempted || stored.CleanupReturned || stored.ResourcesCleaned {
					t.Fatal("no-call receipt manufactured cleanup facts")
				}
			}
			body, e := os.ReadFile(sink.Name())
			if e != nil {
				t.Fatal(e)
			}
			var raw struct {
				RunID  string
				Errors []struct {
					Action   []string
					Cause    []byte
					Complete bool
				}
			}
			if json.Unmarshal(body, &raw) != nil || raw.RunID != "driver-test" || len(raw.Errors) != 1 || string(raw.Errors[0].Cause) != cause.Error() || !raw.Errors[0].Complete {
				t.Fatal("original initial failure lost during finalization")
			}
			if _, e = sink.Write([]byte("PRIVATE late writer")); e == nil {
				t.Fatal("primary error writer remained active after finalization")
			}
		})
	}
}
