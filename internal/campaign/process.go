package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
)

// processPlan names one invocation, including each restart. Directory must not
// exist: creation reserves this run/worker ownership before any child starts.
// Args and Env contain only the campaign's synthetic configuration. Their hashes
// are retained here; the caller retains the sanitized configuration separately.
// Env replaces the inherited environment.
type processPlan struct {
	RunID, WorkerID, Directory, Executable string
	Args, Env                              []string
	CleanupTimeout, TermGrace              time.Duration
	LogLimit                               int64
}

// Elapsed fields share the monotonic sample taken immediately before Cmd.Start.
// UTC fields give human context and are not used to calculate durations.
type processIdentity struct {
	RunID, WorkerID, ExecutableSHA256 string
	PID                               int
	StartTicks                        string // field 22 of Linux /proc/PID/stat
	StartedAt                         time.Time
	LaunchRequestedAt                 time.Time
	StartedElapsedNanoseconds         int64
}

// Exit times observe Cmd.Wait completion, including bounded log draining; they
// do not identify the exact instant of kernel process exit.
type processExit struct {
	Identity                 processIdentity
	ExitedAt                 time.Time
	ElapsedNanoseconds       int64
	ExitCode                 int
	Signal                   string
	SignalNumber             int
	Reaped                   bool
	StdoutBytes, StderrBytes int64
	LogsTruncated            bool
	WaitError, EvidenceError string
	ResourceUsage            processResourceUsage
}

type processAction struct {
	Identity           processIdentity
	Action             string
	At                 time.Time
	ElapsedNanoseconds int64
	Error              string `json:",omitempty"`
}

type ownedProcess struct {
	plan     processPlan
	identity processIdentity
	// Retain time.Now's monotonic reading; serialized UTC times are context only.
	launchRequestedAt time.Time
	cmd               *exec.Cmd
	done              chan struct{}
	monitorDone       chan struct{}
	monitorErr        error       // written before monitorDone closes
	result            processExit // written by the sole Wait owner before closing done
	stdout, stderr    *processLog
	actionMu          sync.Mutex
	cleanupLock       chan struct{}
	actionErr         error
}

// startReleaseProcess never builds or substitutes an executable. Provenance and
// version verification are campaign prerequisites; this boundary independently
// checks the exact reviewed executable bytes and actual execution platform.
func startReleaseProcess(ctx context.Context, plan processPlan) (*ownedProcess, error) {
	profile, supported := artifact.ReviewedPlatform(runtime.GOOS + "/" + runtime.GOARCH)
	if !supported {
		return nil, errors.New("release campaign requires a reviewed native Linux platform")
	}
	return startOwnedProcess(ctx, plan, profile.BinarySHA256, false)
}

// startOwnedProcess admits a different digest only for visibly synthetic helper
// calibration. Campaign code uses startReleaseProcess exclusively.
func startOwnedProcess(ctx context.Context, plan processPlan, expectedDigest string, calibration bool) (*ownedProcess, error) {
	if err := nativeProcessPlatform(); err != nil {
		return nil, err
	}
	if !calibration {
		profile, supported := artifact.ReviewedPlatform(runtime.GOOS + "/" + runtime.GOARCH)
		if !supported || expectedDigest != profile.BinarySHA256 {
			return nil, errors.New("unreviewed release executable digest")
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("worker requires a bounded context")
	}
	if plan.RunID == "" || plan.WorkerID == "" || !filepath.IsAbs(plan.Directory) || !filepath.IsAbs(plan.Executable) {
		return nil, errors.New("worker requires run/worker identity and absolute paths")
	}
	if plan.CleanupTimeout == 0 {
		plan.CleanupTimeout = 10 * time.Second
	}
	if plan.TermGrace == 0 {
		plan.TermGrace = 2 * time.Second
	}
	if plan.LogLimit == 0 {
		plan.LogLimit = 1 << 20
	}
	if plan.CleanupTimeout <= 0 || plan.CleanupTimeout > 30*time.Second || plan.TermGrace <= 0 || plan.TermGrace >= plan.CleanupTimeout || plan.LogLimit < 1 || plan.LogLimit > 4<<20 {
		return nil, errors.New("invalid worker cleanup or log bound")
	}
	f, err := os.Open(plan.Executable)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Size() > 64<<20 {
		return nil, errors.New("worker executable is not a bounded executable file")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (64<<20)+1)); err != nil {
		return nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if digest != expectedDigest {
		return nil, errors.New("worker executable digest mismatch")
	}
	if err = os.Mkdir(plan.Directory, 0700); err != nil {
		return nil, fmt.Errorf("reserve worker ownership: %w", err)
	}
	identity := processIdentity{RunID: plan.RunID, WorkerID: plan.WorkerID, ExecutableSHA256: digest}
	args, _ := json.Marshal(plan.Args)
	env, _ := json.Marshal(plan.Env)
	receipt := struct {
		Identity                                    processIdentity
		Executable, Platform, ArgsSHA256, EnvSHA256 string
		Calibration                                 bool
		CleanupTimeout, TermGrace                   time.Duration
		LogLimit                                    int64
	}{identity, plan.Executable, runtime.GOOS + "-" + runtime.GOARCH, processDigest(args), processDigest(env), calibration, plan.CleanupTimeout, plan.TermGrace, plan.LogLimit}
	if err = persistProcessJSON(plan.Directory, "ownership.json", receipt); err != nil {
		return nil, err
	}
	if err = syncProcessDirectory(filepath.Dir(plan.Directory)); err != nil {
		return nil, err
	}
	p := &ownedProcess{plan: plan, identity: identity, done: make(chan struct{}), monitorDone: make(chan struct{}), cleanupLock: make(chan struct{}, 1)}
	actions, err := os.OpenFile(filepath.Join(plan.Directory, "actions.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if err = errors.Join(actions.Sync(), actions.Close()); err != nil {
		return nil, err
	}
	if p.stdout, err = newProcessLog(filepath.Join(plan.Directory, "stdout.log"), plan.LogLimit); err != nil {
		return nil, err
	}
	if p.stderr, err = newProcessLog(filepath.Join(plan.Directory, "stderr.log"), plan.LogLimit); err != nil {
		p.stdout.close()
		return nil, err
	}
	// The inherited descriptor pins the opened inode: replacing the path after
	// hashing cannot substitute another executable at launch.
	p.cmd = exec.Command("/proc/self/fd/3", plan.Args...)
	p.cmd.Args[0] = plan.Executable
	p.cmd.ExtraFiles = []*os.File{f}
	p.cmd.Env = append([]string{}, plan.Env...)
	p.cmd.Dir = plan.Directory
	p.cmd.Stdout, p.cmd.Stderr = p.stdout, p.stderr
	// A descendant retaining a log pipe cannot indefinitely delay the reaper.
	p.cmd.WaitDelay = time.Second
	p.launchRequestedAt = time.Now()
	if err = p.cmd.Start(); err != nil {
		p.stdout.close()
		p.stderr.close()
		return nil, err
	}
	p.identity.PID = p.cmd.Process.Pid
	startedAt := time.Now()
	p.identity.StartedAt = startedAt.UTC()
	p.identity.LaunchRequestedAt = p.launchRequestedAt.UTC()
	p.identity.StartedElapsedNanoseconds = startedAt.Sub(p.launchRequestedAt).Nanoseconds()
	_, p.identity.StartTicks, err = readProcessState(p.identity.PID)
	if err == nil {
		err = persistProcessJSON(plan.Directory, "started.json", p.identity)
	}
	// Exactly this goroutine calls Cmd.Wait, even when initial persistence fails.
	go p.reap()
	if err != nil {
		close(p.monitorDone) // no cancellation monitor was started
		cleanupErr := p.cleanupProcess(context.Background())
		return nil, errors.Join(fmt.Errorf("persist started worker: %w", err), cleanupErr)
	}
	go p.monitorContext(ctx)
	return p, nil
}

func (p *ownedProcess) monitorContext(ctx context.Context) {
	defer close(p.monitorDone)
	select {
	case <-ctx.Done():
		p.monitorErr = errors.Join(p.record("context_cancelled", ctx.Err()), p.cleanupProcess(context.Background()))
	case <-p.done:
	}
}

func (p *ownedProcess) Identity() processIdentity { return p.identity }

// Signal targets only the retained direct-child handle. PID/start observations
// are evidence, never a way to discover or attach to another process.
func (p *ownedProcess) Signal(ctx context.Context, signal syscall.Signal) error {
	switch signal {
	case syscall.SIGSTOP:
		return p.Suspend(ctx)
	case syscall.SIGCONT:
		return p.Resume(ctx)
	default:
		return p.requestSignal(ctx, signal)
	}
}

func (p *ownedProcess) requestSignal(ctx context.Context, signal syscall.Signal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if signal != syscall.SIGTERM && signal != syscall.SIGKILL && signal != syscall.SIGSTOP && signal != syscall.SIGCONT {
		return errors.New("unsupported worker signal")
	}
	select {
	case <-p.done:
		return os.ErrProcessDone
	default:
	}
	if err := p.record("request_"+processSignalName(signal), nil); err != nil {
		return err
	}
	err := p.cmd.Process.Signal(signal)
	return errors.Join(err, p.record("result_"+processSignalName(signal), err))
}

// Suspend returns only after /proc independently reports this process stopped.
// A requested SIGSTOP alone is not a reached suspension.
func (p *ownedProcess) Suspend(ctx context.Context) error {
	if err := p.requestSignal(ctx, syscall.SIGSTOP); err != nil {
		return err
	}
	return p.observeState(ctx, true)
}

func (p *ownedProcess) Resume(ctx context.Context) error {
	if err := p.requestSignal(ctx, syscall.SIGCONT); err != nil {
		return err
	}
	return p.observeState(ctx, false)
}

func (p *ownedProcess) observeState(ctx context.Context, stopped bool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, start, err := readProcessState(p.identity.PID)
		if err != nil {
			return err
		}
		if start != p.identity.StartTicks {
			return errors.New("worker start identity changed")
		}
		if state == 'Z' || state == 'X' {
			return os.ErrProcessDone
		}
		if (state == 'T' || state == 't') == stopped {
			action := "observed_running"
			if stopped {
				action = "observed_stopped"
			}
			return p.record(action, nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return os.ErrProcessDone
		case <-ticker.C:
		}
	}
}

// Wait is repeatable; the internal reaper owns Cmd.Wait. A caller's wait timeout
// does not replace the campaign context or release ownership.
func (p *ownedProcess) Wait(ctx context.Context) (processExit, error) {
	select {
	case <-p.done:
		var err error
		if p.result.EvidenceError != "" {
			err = errors.New(p.result.EvidenceError)
		}
		return p.result, err
	case <-ctx.Done():
		return processExit{}, ctx.Err()
	}
}

// Cleanup resumes a suspended child before TERM, escalates to KILL and waits
// for the sole reaper. Successful cleanup also joins the cancellation monitor;
// callers can then freeze receipts. A timeout or evidence error blocks that claim.
// Wait's retained exit result stays unchanged; Cleanup returns later action errors.
// Callers finish signal and suspension operations before cleanup.
func (p *ownedProcess) Cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.plan.CleanupTimeout)
	defer cancel()
	cleanupErr := p.cleanupProcess(ctx)
	select {
	case <-p.monitorDone:
		p.actionMu.Lock()
		actionErr := p.actionErr
		p.actionMu.Unlock()
		return errors.Join(cleanupErr, p.monitorErr, actionErr)
	case <-ctx.Done():
		return errors.Join(cleanupErr, fmt.Errorf("join worker cancellation monitor: %w", ctx.Err()))
	}
}

// The monitor and startup-error path use this bounded cleanup without joining
// themselves. Only the public Cleanup establishes completion of final receipts.
func (p *ownedProcess) cleanupProcess(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.plan.CleanupTimeout)
	defer cancel()
	select {
	case p.cleanupLock <- struct{}{}:
		defer func() { <-p.cleanupLock }()
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-p.done:
		_, err := p.Wait(context.Background())
		return err
	default:
	}
	// Receipt failures must not strand a child. Normal Signal is fail-closed;
	// cleanup still sends through the retained handle and returns receipt errors.
	signal := func(s syscall.Signal) error {
		err := p.record("cleanup_request_"+processSignalName(s), nil)
		signalErr := p.cmd.Process.Signal(s)
		if errors.Is(signalErr, os.ErrProcessDone) {
			signalErr = nil
		}
		return errors.Join(err, signalErr, p.record("cleanup_result_"+processSignalName(s), signalErr))
	}
	err := errors.Join(signal(syscall.SIGCONT), signal(syscall.SIGTERM))
	grace := time.NewTimer(p.plan.TermGrace)
	defer grace.Stop()
	select {
	case <-p.done:
		_, waitErr := p.Wait(context.Background())
		return errors.Join(err, waitErr)
	case <-ctx.Done():
		// Even an expired caller deadline still requires the final kill request.
		err = errors.Join(err, signal(syscall.SIGKILL))
		return errors.Join(err, ctx.Err())
	case <-grace.C:
	}
	err = errors.Join(err, signal(syscall.SIGKILL))
	_, waitErr := p.Wait(ctx)
	return errors.Join(err, waitErr)
}

func (p *ownedProcess) reap() {
	err := p.cmd.Wait()
	exitedAt := time.Now()
	r := processExit{Identity: p.identity, ExitedAt: exitedAt.UTC(), ElapsedNanoseconds: exitedAt.Sub(p.launchRequestedAt).Nanoseconds(), ExitCode: -1}
	var waitEvidenceErr error
	if err != nil {
		r.WaitError = err.Error()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			waitEvidenceErr = err
		}
	}
	if state := p.cmd.ProcessState; state != nil {
		r.Reaped = true
		r.ExitCode = state.ExitCode()
		r.ResourceUsage = processUsageFromState(state)
		if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			r.Signal = processSignalName(status.Signal())
			r.SignalNumber = int(status.Signal())
		}
	} else {
		r.ResourceUsage = processUsageFromState(nil)
		waitEvidenceErr = errors.Join(waitEvidenceErr, errors.New("worker was not reaped"))
	}
	r.StdoutBytes, r.StderrBytes = p.stdout.total, p.stderr.total
	r.LogsTruncated = p.stdout.total > p.plan.LogLimit || p.stderr.total > p.plan.LogLimit
	p.actionMu.Lock()
	actionErr := p.actionErr
	p.actionMu.Unlock()
	evidenceErr := errors.Join(waitEvidenceErr, actionErr, p.stdout.close(), p.stderr.close())
	if r.LogsTruncated {
		evidenceErr = errors.Join(evidenceErr, errors.New("worker log bound exceeded; retained logs are incomplete"))
	}
	if evidenceErr != nil {
		r.EvidenceError = evidenceErr.Error()
	}
	if err := persistProcessJSON(p.plan.Directory, "exit.json", r); err != nil {
		r.EvidenceError = errors.Join(evidenceErr, err).Error()
	}
	p.result = r
	close(p.done)
}

func (p *ownedProcess) record(action string, actionErr error) (err error) {
	p.actionMu.Lock()
	defer p.actionMu.Unlock()
	defer func() {
		if err != nil && p.actionErr == nil {
			p.actionErr = err
		}
	}()
	at := time.Now()
	r := processAction{Identity: p.identity, Action: action, At: at.UTC(), ElapsedNanoseconds: at.Sub(p.launchRequestedAt).Nanoseconds()}
	if actionErr != nil {
		r.Error = actionErr.Error()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(p.plan.Directory, "actions.jsonl"), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	return errors.Join(writeErr, f.Sync(), f.Close())
}

func persistProcessJSON(directory, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	return syncProcessDirectory(directory)
}

func syncProcessDirectory(directory string) error {
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

func processSignalName(signal syscall.Signal) string {
	switch signal {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGSTOP:
		return "SIGSTOP"
	case syscall.SIGCONT:
		return "SIGCONT"
	default:
		return fmt.Sprintf("signal_%d", signal)
	}
}

func processDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

type processLog struct {
	file         *os.File
	limit, total int64
	err          error
}

func newProcessLog(path string, limit int64) (*processLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &processLog{file: f, limit: limit}, nil
}

// Drain past the cap so the harness cannot block the child's log pipes.
func (l *processLog) Write(b []byte) (int, error) {
	n := len(b)
	keep := min(int64(n), max(int64(0), l.limit-l.total))
	l.total += int64(n)
	if keep > 0 && l.err == nil {
		_, l.err = l.file.Write(b[:keep])
	}
	return n, nil
}
func (l *processLog) close() error { return errors.Join(l.err, l.file.Sync(), l.file.Close()) }
