package campaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

const linkCalibrationTests = "^(TestLiveOwnedWorkerLinkTopology|TestLiveOwnedLinkDirectionalLatency)$"
const linkCalibrationOutputLimit = 64 << 10

// LinkCalibrationPlan identifies a fresh lab specimen, never a Kaferry release.
// The caller's build identity is also checked against actual bytes and embedded VCS settings.
type LinkCalibrationPlan struct {
	Repository, RunID, TestBinary, TestSHA256, ReviewedHead string
	BuiltAfter                                              time.Time
}

type LinkCalibrationWait struct {
	Started, WaitReturned, Reaped, StreamCopiesJoined                                                bool
	PID                                                                                              int
	StartTicks                                                                                       string
	ExitCode, SignalNumber                                                                           int
	LaunchAt, WaitObservedAt                                                                         time.Time
	WaitElapsedNS                                                                                    int64
	StdoutBytes, StderrBytes                                                                         int64
	CapturedStdoutBytes, CapturedStderrBytes, DroppedObservedStdoutBytes, DroppedObservedStderrBytes int64
	OutputComplete, TestsPassed                                                                      bool
}

type LinkCalibrationAdoptedWait struct {
	PID, Status int
	Terminal    bool
}
type LinkCalibrationGroupSignal struct {
	SignalNumber, Errno int
	Succeeded, Absent   bool
}
type LinkCalibrationTree struct {
	SubreaperEnabled, AnchorStarted, AnchorWaitReturned, AnchorReaped bool
	AnchorPID, AnchorStatus                                           int
	AnchorStartTicks                                                  string
	ControlFailed, SignalsClosed, NoChildren, Closed                  bool
	Signals                                                           []LinkCalibrationGroupSignal
	Adopted                                                           []LinkCalibrationAdoptedWait
}

// Quiescence, resource cleanup and durable notice coverage are independent.
// SealingReady and PublicationAuthorized stay false: this driver alone
// neither validates an external courier nor grants publication authority.
type LinkCalibrationResult struct {
	Version, RunID, ReviewedHead, TestSHA256                           string
	Synthetic, ReleaseQualified                                        bool
	Status                                                             string
	PrivateReference, DriverPrivate, FixturePrivate                    string
	Wait                                                               LinkCalibrationWait
	Tree                                                               LinkCalibrationTree
	LatencyCleanup                                                     LinkCalibrationCleanup
	SetupReturned, CleanupReturned, CleanupAttempted, ResourcesCleaned bool
	FixtureCleanupSucceeded                                            bool
	WritersQuiescent, PrivateCaptureComplete                           bool
	SealingReady, PublicationAuthorized                                bool
}

var linkCalibrationIncomplete = errors.New("link calibration incomplete; private evidence required; publication disabled")

// RunLinkCalibration performs synchronous UpLinks/Down and waits one direct
// campaign test executable with one held process-group anchor. Fixture calls
// remain synchronous; this synthetic path does not use release-process admission.
func RunLinkCalibration(ctx context.Context, p LinkCalibrationPlan) (r LinkCalibrationResult, err error) {
	r = LinkCalibrationResult{Version: "1", RunID: p.RunID, ReviewedHead: p.ReviewedHead, TestSHA256: p.TestSHA256, Synthetic: true, Status: "INCOMPLETE"}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	public, private, sink, reserveErr := reserveLinkCalibration(p)
	r.DriverPrivate = private
	if reserveErr != nil {
		return r, linkCalibrationIncomplete
	} // first-sink exact notice may be unavailable
	r.PrivateReference = sink.Name()
	r.FixturePrivate = filepath.Join(p.Repository, ".cache", "fixtures-private", p.RunID+"-links")
	capture := true
	cleanupWritable := true
	retain := func(action []string, cause error) {
		if cause != nil && !retainLinkCalibrationError(sink, action, cause) {
			capture = false
			cleanupWritable = false
		}
	}
	finish := func() (LinkCalibrationResult, error) { return finishLinkCalibration(public, sink, r, capture) }
	image, validateErr := validateLinkCalibration(p)
	if validateErr != nil {
		retain([]string{"validate_native_build"}, validateErr)
		return finish()
	}
	if ctx.Err() != nil {
		retain([]string{"cancelled_before_setup"}, ctx.Err())
		if e := image.Close(); e != nil {
			capture = false
			retain([]string{"close_test_image"}, e)
		}
		return finish()
	}
	childHome := filepath.Join(p.Repository, ".cache", "link-calibration-home", p.RunID)
	homeParent := filepath.Dir(childHome)
	if e := os.Mkdir(homeParent, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		retain([]string{"reserve_child_home_parent"}, errors.Join(e, image.Close()))
		return finish()
	}
	if info, e := os.Lstat(homeParent); e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		retain([]string{"validate_child_home_parent"}, errors.Join(e, errors.New("owned home parent unavailable"), image.Close()))
		return finish()
	}
	for _, directory := range []string{childHome, filepath.Join(childHome, ".docker")} {
		if e := os.Mkdir(directory, 0700); e != nil {
			retain([]string{"reserve_child_home"}, errors.Join(e, image.Close()))
			return finish()
		}
	}
	if e := persistProcessJSON(public, "plan.json", struct {
		Plan                                      LinkCalibrationPlan
		Args                                      []string
		SetupSeconds, TestSeconds, CleanupSeconds int
		PublicationAuthorized, SealingReady       bool
	}{p, linkCalibrationArgs(), 240, 120, 150, false, false}); e != nil {
		retain([]string{"persist_plan"}, errors.Join(e, image.Close()))
		return finish()
	}
	r.Tree, err = prepareLinkCalibrationTree()
	if err != nil {
		retain([]string{"prepare_dedicated_subreaper"}, errors.Join(err, image.Close()))
		return finish()
	}
	setup, done := context.WithTimeout(ctx, 4*time.Minute)
	state, upErr := fixture.UpLinks(setup, p.RunID, fixture.Docker)
	done()
	r.SetupReturned = true
	retain([]string{"fixture.UpLinks", p.RunID}, upErr)
	var cleanupDeadline time.Time
	if upErr == nil && ctx.Err() == nil && capture {
		testCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
		cmd := exec.Command("/proc/self/fd/3", linkCalibrationArgs()...)
		cmd.Args[0] = p.TestBinary
		cmd.ExtraFiles = []*os.File{image}                            // only the immutable lab image, never a notice-writer FD
		cmd.Dir = filepath.Join(p.Repository, "internal", "campaign") // liveCampaignState expects this cwd
		cmd.Env = linkCalibrationEnvironment(state, childHome)
		var rawOut, rawErr []byte
		var childErr error
		anchor := exec.Command("/proc/self/exe", "--owned-link-group-anchor")
		anchor.Env = []string{"LC_ALL=C"}
		group, groupErr := startLinkCalibrationGroup(anchor, r.Tree)
		if group != nil {
			r.Wait, rawOut, rawErr, cleanupDeadline, childErr = waitLinkCalibrationCommand(testCtx, cmd, group)
			r.Tree = group.result
			if r.Tree.ControlFailed {
				cleanupWritable = false
			}
		} else {
			childErr = groupErr
		}
		childErr = errors.Join(groupErr, childErr)
		stop()
		if r.Wait.Started && !r.Wait.OutputComplete {
			capture = false
		}
		retain([]string{"campaign.test", "fixed_link_tests"}, childErr)
		if e := persistLinkCalibrationJSON(private, "child-output.json", struct {
			RunID          string
			Executable     string
			Argv, Env      []string
			Wait           LinkCalibrationWait
			Stdout, Stderr []byte
		}{p.RunID, cmd.Path, cmd.Args, cmd.Env, r.Wait, rawOut, rawErr}); e != nil {
			capture = false
			cleanupWritable = false
			retain([]string{"persist_child_output"}, e)
		}
	}
	if e := image.Close(); e != nil {
		capture = false
		cleanupWritable = false
		retain([]string{"close_test_image"}, e)
	}
	if cleanupDeadline.IsZero() {
		cleanupDeadline = time.Now().Add(150 * time.Second)
	}
	if !r.Tree.AnchorStarted && !r.Tree.Closed {
		treeCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		var treeErr error
		r.Tree, treeErr = drainLinkCalibrationChildren(treeCtx, r.Tree)
		stop()
		retain([]string{"close_empty_child_subtree"}, treeErr)
	}
	if e := persistLinkCalibrationJSON(private, "child-tree.json", struct {
		RunID string
		Tree  LinkCalibrationTree
	}{p.RunID, r.Tree}); e != nil {
		capture = false
		cleanupWritable = false
		retain([]string{"persist_child_tree"}, e)
	}
	// An unconfirmed test process can still issue fixture calls. Never overlap Down.
	if r.Tree.Closed && r.Tree.NoChildren && (!r.Wait.Started || (r.Wait.WaitReturned && r.Wait.Reaped && r.Wait.StreamCopiesJoined)) {
		if cleanupDeadline.IsZero() {
			cleanupDeadline = time.Now().Add(150 * time.Second)
		}
		cleanup, stop := context.WithDeadline(context.Background(), cleanupDeadline)
		// Never fall through to legacy M0 Down for an incomplete linked state.
		// Linked Down checks its durable STOPPED journal before any Docker command.
		if state.Proxy != nil && cleanupWritable {
			r.CleanupAttempted = true
			var cleanupErr error
			r.LatencyCleanup, cleanupErr = cleanupLinkCalibrationLatency(cleanup, state, fixture.Docker)
			var cleanupNotice *linkCalibrationCleanupError
			if errors.As(cleanupErr, &cleanupNotice) && !cleanupNotice.retentionComplete {
				capture = false
				cleanupWritable = false
			}
			retain([]string{"latency_resource_cleanup", p.RunID}, cleanupErr)
			if cleanupErr == nil && cleanupWritable {
				cleanupErr = fixture.Down(cleanup, state, fixture.Docker)
				r.FixtureCleanupSucceeded = cleanupErr == nil
				retain([]string{"fixture.Down", p.RunID}, cleanupErr)
			}
			r.CleanupReturned = true
			r.ResourcesCleaned = cleanupErr == nil && r.LatencyCleanup.Resolved && r.FixtureCleanupSucceeded
		}
		// If that branch was skipped, both cleanup flags remain false.
		stop()
	}
	// Parent-side cleanup Docker calls are synchronous too. Re-observe actual
	// ECHILD after their Cmd.Wait owners have returned; the earlier test-tree
	// proof is not reused across new child launches. No group signal is allowed
	// after anchor reap, including during this final observation-only drain.
	if r.CleanupAttempted && r.CleanupReturned && r.Tree.Closed {
		finalDeadline := time.Now().Add(20 * time.Second)
		if cleanupDeadline.Before(finalDeadline) {
			finalDeadline = cleanupDeadline
		}
		finalCtx, stop := context.WithDeadline(context.Background(), finalDeadline)
		var finalErr error
		r.Tree, finalErr = drainLinkCalibrationChildren(finalCtx, r.Tree)
		stop()
		retain([]string{"final_cleanup_child_drain"}, finalErr)
		if e := persistLinkCalibrationJSON(private, "cleanup-tree.json", struct {
			RunID string
			Tree  LinkCalibrationTree
		}{p.RunID, r.Tree}); e != nil {
			capture = false
			retain([]string{"persist_final_child_tree"}, e)
		}
	}
	r.ResourcesCleaned = r.ResourcesCleaned && r.Tree.Closed && r.Tree.NoChildren
	if ctx.Err() != nil {
		retain([]string{"driver_context"}, ctx.Err())
	}
	if upErr == nil && ctx.Err() == nil && capture && r.Wait.TestsPassed && r.ResourcesCleaned && r.LatencyCleanup.JournalComplete {
		r.Status = "CALIBRATION_PASSED_NOT_QUALIFICATION"
	}
	return finish()
}

func linkCalibrationArgs() []string {
	return []string{"-test.run=" + linkCalibrationTests, "-test.count=1", "-test.parallel=1", "-test.timeout=115s", "-test.v"}
}
func linkCalibrationEnvironment(s fixture.State, home string) []string {
	// No inherited LAB_*, loader settings, coverage hooks or credentials.
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "DOCKER_CONFIG=" + filepath.Join(home, ".docker"), "LC_ALL=C", "LAB_LINKS=1", "LAB_RUN_ID=" + s.RunID, "LAB_SOURCE_ADDR=" + s.Source, "LAB_DEST_ADDR=" + s.Destination, "LAB_WORKER_SOURCE_ADDR=" + s.WorkerSource, "LAB_WORKER_DEST_ADDR=" + s.WorkerDestination, "LAB_PROXY_API_ADDR=" + s.Proxy.API}
}

func reserveLinkCalibration(p LinkCalibrationPlan) (public, private string, sink *linkCalibrationSink, err error) {
	if _, err = fixture.StatePath(p.RunID); err != nil || !filepath.IsAbs(p.Repository) || filepath.Clean(p.Repository) != p.Repository {
		return "", "", nil, linkCalibrationIncomplete
	}
	if real, e := filepath.EvalSymlinks(p.Repository); e != nil || real != p.Repository {
		return "", "", nil, linkCalibrationIncomplete
	}
	public = filepath.Join(p.Repository, ".cache", "link-calibration", p.RunID)
	private = filepath.Join(p.Repository, ".cache", "link-calibration-private", p.RunID)
	// Build only these fixed parents, rejecting symlinks before descending.
	for _, parent := range []string{filepath.Join(p.Repository, ".cache"), filepath.Dir(public), filepath.Dir(private)} {
		if e := os.Mkdir(parent, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			err = e
			return
		}
		if info, e := os.Lstat(parent); e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			err = linkCalibrationIncomplete
			return
		}
	}
	if err = os.Mkdir(private, 0700); err != nil {
		return
	}
	f, e := os.OpenFile(filepath.Join(private, "driver-errors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		err = e
		return
	}
	sink, err = newLinkCalibrationSink(f, p.RunID)
	if err != nil {
		return
	}
	if err = persistLinkCalibrationJSON(private, "PRIVATE.json", struct{ RunID, Classification, Publication string }{p.RunID, "PRIVATE RAW EVIDENCE", "withhold pending explicit redaction review"}); err != nil {
		retainLinkCalibrationError(sink, []string{"reserve_private_marker"}, err)
		closeLinkCalibrationSink(sink)
		sink = nil
		return
	}
	if err = os.Mkdir(public, 0700); err != nil {
		retainLinkCalibrationError(sink, []string{"reserve_public"}, err)
		closeLinkCalibrationSink(sink)
		sink = nil
	}
	return
}

func validateLinkCalibration(p LinkCalibrationPlan) (f *os.File, err error) {
	if err = nativeProcessPlatform(); err != nil {
		return
	}
	self, ok := debug.ReadBuildInfo()
	if !ok || self.Path != "github.com/pagrus7/kaferry-lab/cmd/link-calibration" {
		return nil, errors.New("standalone reviewed link driver required")
	}
	selfSettings := map[string]string{}
	for _, setting := range self.Settings {
		selfSettings[setting.Key] = setting.Value
	}
	if selfSettings["vcs.revision"] != p.ReviewedHead || selfSettings["vcs.modified"] != "false" {
		return nil, errors.New("driver and test must share clean reviewed source")
	}
	wd, e := os.Getwd()
	if e != nil {
		return nil, e
	}
	if wd != p.Repository || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.ReviewedHead) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.TestSHA256) {
		return nil, errors.New("canonical current repository and reviewed hashes required")
	}
	if p.TestBinary != filepath.Join(p.Repository, ".cache", "link-calibration-build", p.RunID, "campaign.test") || p.BuiltAfter.IsZero() || p.BuiltAfter.After(time.Now()) || time.Since(p.BuiltAfter) > 30*time.Minute {
		return nil, errors.New("fresh fixed owned campaign build required")
	}
	if real, e := filepath.EvalSymlinks(p.TestBinary); e != nil || real != p.TestBinary {
		return nil, errors.Join(e, errors.New("owned build path must not contain symlinks"))
	}
	f, err = os.Open(p.TestBinary)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
			f = nil
		}
	}()
	info, e := f.Stat()
	if e != nil {
		return f, e
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Mode()&0222 != 0 || info.Size() <= 0 || info.Size() > 128<<20 || info.ModTime().Before(p.BuiltAfter) {
		return f, errors.New("bounded fresh regular executable required")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if e != nil {
		return f, e
	}
	if n != info.Size() || hex.EncodeToString(h.Sum(nil)) != p.TestSHA256 {
		return f, errors.New("owned test executable digest mismatch")
	}
	bi, e := buildinfo.Read(f)
	if e != nil {
		return f, e
	}
	settings := map[string]string{}
	for _, v := range bi.Settings {
		settings[v.Key] = v.Value
	}
	if bi.Path != "github.com/pagrus7/kaferry-lab/internal/campaign.test" || settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["vcs.revision"] != p.ReviewedHead || settings["vcs.modified"] != "false" || bi.Main.Path != "github.com/pagrus7/kaferry-lab" {
		return f, errors.New("clean reviewed native lab build metadata required")
	}
	_, err = f.Seek(0, io.SeekStart)
	return
}

// These nonblocking memory sinks keep bounded exact prefixes. Cmd.Wait joins
// exec's copy goroutines before their final snapshots; WaitDelay closes any
// descendant-held log pipes. Output/pipe incompleteness cannot pass calibration.
type linkCalibrationOutput struct {
	mu       sync.Mutex
	bytes    []byte
	observed int64
	overflow chan struct{}
	once     sync.Once
}

func (b *linkCalibrationOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observed += int64(len(p))
	keep := min(len(p), linkCalibrationOutputLimit-len(b.bytes))
	b.bytes = append(b.bytes, p[:keep]...)
	if b.observed > linkCalibrationOutputLimit {
		b.once.Do(func() { close(b.overflow) })
	}
	return len(p), nil
}
func (b *linkCalibrationOutput) snapshot() ([]byte, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.bytes...), b.observed
}

// The cmd parameter is a purpose-specific process seam for native owned-helper
// controls; production supplies only the pinned open image and fixed args/env.
func waitLinkCalibrationCommand(ctx context.Context, cmd *exec.Cmd, group *linkCalibrationGroup) (r LinkCalibrationWait, stdout, stderr []byte, cleanupDeadline time.Time, err error) {
	r.ExitCode = -1
	out, diagnostic := &linkCalibrationOutput{overflow: make(chan struct{})}, &linkCalibrationOutput{overflow: make(chan struct{})}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, diagnostic, time.Second
	launch := time.Now()
	r.LaunchAt = launch.UTC()
	var done chan error
	var waitErr error
	waited := false
	if err = group.attach(cmd); err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = cmd.Start()
	}
	if err == nil {
		r.Started, r.PID = true, cmd.Process.Pid
		_, r.StartTicks, err = readProcessState(r.PID)
		if err == nil {
			err = group.checkMember(r.PID)
		}
		done = make(chan error, 1)
		go func() { done <- cmd.Wait() }() // sole test Wait, even after identity failure
		if err == nil {
			select {
			case waitErr = <-done:
				waited = true
			case <-ctx.Done():
				err = ctx.Err()
			case <-out.overflow:
				err = errors.New("stdout capture bound exceeded")
			case <-diagnostic.overflow:
				err = errors.New("stderr capture bound exceeded")
			}
		}
	}
	cleanupDeadline = time.Now().Add(150 * time.Second)
	// All process termination uses this ONE anchored group route. A denied signal
	// latches the route; never try another signal/handle as a denial workaround.
	stopErr := group.beginStop()
	if stopErr == nil {
		grace := time.NewTimer(2 * time.Second)
		if r.Started && !waited {
			select {
			case waitErr = <-done:
				waited = true
			case <-grace.C:
			}
			if waited {
				<-grace.C
			}
		} else {
			<-grace.C
		}
		grace.Stop()
		stopErr = group.lastSignal()
	}
	err = errors.Join(err, stopErr)
	if r.Started && !waited {
		last := time.NewTimer(8 * time.Second)
		select {
		case waitErr = <-done:
			waited = true
		case <-last.C:
			err = errors.Join(err, errors.New("owned test terminal wait unavailable"))
		}
		last.Stop()
	}
	stdout, r.StdoutBytes = out.snapshot()
	stderr, r.StderrBytes = diagnostic.snapshot()
	r.CapturedStdoutBytes, r.CapturedStderrBytes = int64(len(stdout)), int64(len(stderr))
	r.DroppedObservedStdoutBytes = r.StdoutBytes - r.CapturedStdoutBytes
	r.DroppedObservedStderrBytes = r.StderrBytes - r.CapturedStderrBytes
	if waited {
		r.WaitReturned, r.StreamCopiesJoined = true, true
		r.WaitObservedAt, r.WaitElapsedNS = time.Now().UTC(), time.Since(launch).Nanoseconds()
		if state := cmd.ProcessState; state != nil {
			if status, ok := state.Sys().(syscall.WaitStatus); ok && (status.Exited() || status.Signaled()) {
				r.Reaped, r.ExitCode = true, state.ExitCode()
				if status.Signaled() {
					r.SignalNumber = int(status.Signal())
				}
			}
		}
		var exit *exec.ExitError
		r.OutputComplete = (waitErr == nil || errors.As(waitErr, &exit)) && r.StdoutBytes <= linkCalibrationOutputLimit && r.StderrBytes <= linkCalibrationOutputLimit && !errors.Is(waitErr, exec.ErrWaitDelay)
	}
	treeCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	_, treeErr := group.close(treeCtx, !r.Started || (r.WaitReturned && r.Reaped && r.StreamCopiesJoined))
	stop()
	err = errors.Join(err, waitErr, treeErr)
	r.TestsPassed = err == nil && r.Reaped && r.StartTicks != "" && r.ExitCode == 0 && r.OutputComplete && group.result.Closed && group.result.NoChildren && linkCalibrationPassed(stdout)
	if !r.TestsPassed {
		err = errors.Join(err, errors.New("fixed tests did not both complete successfully"))
	}
	return
}

func linkCalibrationPassed(output []byte) bool {
	lines := bytes.Split(output, []byte{'\n'})
	for _, name := range []string{"TestLiveOwnedWorkerLinkTopology", "TestLiveOwnedLinkDirectionalLatency"} {
		runs, passes := 0, 0
		for _, line := range lines {
			s := string(line)
			if s == "=== RUN   "+name {
				runs++
			}
			if strings.HasPrefix(s, "--- PASS: "+name+" (") {
				passes++
			}
			if strings.HasPrefix(s, "--- FAIL: "+name) || strings.HasPrefix(s, "--- SKIP: "+name) {
				return false
			}
		}
		if runs != 1 || passes != 1 {
			return false
		}
	}
	return true
}

// The primary FD is reserved before work. Its JSON prefix and each exact
// original error are synced in place; only finalization closes the error array.
// A crash/partial write leaves an invalid/incomplete input, never repaired.
type linkCalibrationSink struct {
	*os.File
	records           int
	finalized, broken bool
}

func newLinkCalibrationSink(f *os.File, run string) (*linkCalibrationSink, error) {
	encoded, err := json.Marshal(run)
	if err != nil {
		f.Close()
		return nil, err
	}
	header := append(append([]byte("{\"RunID\":"), encoded...), []byte(",\"Errors\":[")...)
	n, err := f.Write(header)
	if err != nil || n != len(header) {
		f.Close()
		return nil, errors.New("primary JSON prefix incomplete")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return &linkCalibrationSink{File: f}, nil
}
func retainLinkCalibrationError(sink *linkCalibrationSink, action []string, cause error) bool {
	if sink.finalized || sink.broken {
		return false
	}
	raw := []byte(cause.Error())
	complete := len(raw) <= 64<<10
	if !complete {
		raw = raw[:64<<10]
	}
	body, err := json.Marshal(struct {
		Action   []string
		Cause    []byte
		Complete bool
	}{action, raw, complete})
	if err != nil {
		sink.broken = true
		return false
	}
	if sink.records > 0 {
		body = append([]byte{','}, body...)
	}
	info, err := sink.Stat()
	// Reserve the final ]} plus newline inside the complete256KiB file bound.
	if err != nil || info.Size()+int64(len(body))+3 > 256<<10 {
		sink.broken = true
		return false
	}
	n, err := sink.Write(body)
	if err != nil || n != len(body) {
		sink.broken = true
		return false
	}
	if err = sink.Sync(); err != nil {
		sink.broken = true
		return false
	}
	sink.records++
	if !complete {
		sink.broken = true
	}
	return complete
}
func closeLinkCalibrationSink(sink *linkCalibrationSink) error {
	if sink.finalized {
		return errors.New("primary JSON sink already finalized")
	}
	sink.finalized = true
	n, err := sink.Write([]byte("]}\n"))
	if err != nil || n != 3 {
		return errors.Join(errors.New("primary JSON finalization incomplete"), err, sink.Close())
	}
	if err = sink.Sync(); err != nil {
		return errors.Join(err, sink.Close())
	}
	return sink.Close()
}
func persistLinkCalibrationJSON(dir, name string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if len(body)+1 > 256<<10 {
		return errors.New("complete driver JSON receipt exceeds256KiB")
	}
	return persistProcessJSON(dir, name, value)
}

func finishLinkCalibration(public string, sink *linkCalibrationSink, r LinkCalibrationResult, capture bool) (LinkCalibrationResult, error) {
	capture = capture && !sink.broken && !sink.finalized
	childStopped := !r.Wait.Started || (r.Wait.WaitReturned && r.Wait.Reaped && r.Wait.StreamCopiesJoined && r.Wait.PID > 0 && r.Wait.StartTicks != "")
	cleanupStopped := !r.CleanupAttempted || r.CleanupReturned
	proof := capture && r.SetupReturned && cleanupStopped && childStopped && r.Tree.SubreaperEnabled && r.Tree.Closed && r.Tree.NoChildren && !r.Tree.ControlFailed
	r.WritersQuiescent, r.PrivateCaptureComplete = proof, capture
	if !proof {
		r.Status = "INCOMPLETE"
	}
	name := "INCOMPLETE.json"
	if proof {
		name = "WRITERS_QUIESCENT.json"
	}
	// Stage+close selected facts while the primary raw sink is alive. Close that
	// sink exactly once, then final rename only. No private writes after marker.
	if e := persistProcessJSON(public, "result.pending.json", r); e != nil {
		r.PrivateCaptureComplete = retainLinkCalibrationError(sink, []string{"stage_public_result"}, e)
		if closeLinkCalibrationSink(sink) != nil {
			r.PrivateCaptureComplete = false
		}
		r.WritersQuiescent = false
		r.Status = "INCOMPLETE"
		return r, linkCalibrationIncomplete
	}
	if e := closeLinkCalibrationSink(sink); e != nil {
		r.WritersQuiescent, r.PrivateCaptureComplete = false, false
		r.Status = "INCOMPLETE"
		return r, linkCalibrationIncomplete // exact terminal-finalization notice unavailable; no replacement sink
	}
	if e := os.Rename(filepath.Join(public, "result.pending.json"), filepath.Join(public, name)); e != nil {
		r.WritersQuiescent, r.PrivateCaptureComplete = false, false
		r.Status = "INCOMPLETE"
		return r, linkCalibrationIncomplete
	} // no replacement sink
	if !proof || r.Status != "CALIBRATION_PASSED_NOT_QUALIFICATION" {
		return r, linkCalibrationIncomplete
	}
	return r, nil
}
