//go:build linux

package campaign

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PR_GET_CHILD_SUBREAPER writes a Linux C int through arg2; its syscall
// return value is only success/failure. Keep the pointer conversion directly
// in Syscall6 so Go retains the int32 storage for the duration of the call.
func readLinkCalibrationSubreaper() (int32, error) {
	var value int32
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(unix.PR_GET_CHILD_SUBREAPER), uintptr(unsafe.Pointer(&value)), 0, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return value, nil
}

// This attribute belongs only to the dedicated one-shot driver process. No
// concurrent fixture command or other Cmd.Wait may run during an adopted drain.
func prepareLinkCalibrationTree() (LinkCalibrationTree, error) {
	r := LinkCalibrationTree{}
	initial, err := readLinkCalibrationSubreaper()
	if err != nil {
		return r, err
	}
	if initial != 0 {
		return r, errors.New("link driver requires a fresh dedicated non-subreaper process")
	}
	var status syscall.WaitStatus
	pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
	if pid > 0 {
		r.Adopted = append(r.Adopted, LinkCalibrationAdoptedWait{PID: pid, Status: int(status), Terminal: status.Exited() || status.Signaled()})
		return r, errors.New("unexpected preexisting child wait in dedicated driver")
	}
	if !errors.Is(err, syscall.ECHILD) {
		return r, errors.Join(err, errors.New("dedicated driver already has child ownership"))
	}

	if err = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return r, err
	}
	observed, err := readLinkCalibrationSubreaper()
	if err != nil {
		return r, err
	}
	if observed != 1 {
		return r, errors.New("process-local subreaper readback failed")
	}
	r.SubreaperEnabled = true
	return r, nil
}

type linkCalibrationGroup struct {
	anchor         *exec.Cmd
	result         LinkCalibrationTree
	failure        error
	closureStarted bool
	// Purpose-specific syscall seam for literal denial controls; production uses
	// syscall.Kill only, never an alternate signal route.
	killGroup func(int, syscall.Signal) error
}

func startLinkCalibrationGroup(anchor *exec.Cmd, seed LinkCalibrationTree) (*linkCalibrationGroup, error) {
	g := &linkCalibrationGroup{anchor: anchor, result: seed, killGroup: syscall.Kill}
	if !seed.SubreaperEnabled {
		return g, errors.New("subreaper prerequisite missing")
	}
	if anchor.SysProcAttr != nil {
		return g, errors.New("anchor already has process attributes")
	}
	anchor.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := anchor.Start(); err != nil {
		g.failure = err
		g.result.ControlFailed = true
		return g, err
	}
	g.result.AnchorStarted = true
	g.result.AnchorPID = anchor.Process.Pid
	state, start, err := readProcessState(g.result.AnchorPID)
	g.result.AnchorStartTicks = start
	if err == nil {
		var group int
		group, err = syscall.Getpgid(g.result.AnchorPID)
		if err == nil && (group != g.result.AnchorPID || state == 'Z' || state == 'X') {
			err = errors.New("anchor is not the live newly owned process-group leader")
		}
	}
	g.failure = err
	if err != nil {
		g.result.ControlFailed = true
		g.result.SignalsClosed = true
	}
	return g, err
}
func (g *linkCalibrationGroup) attach(cmd *exec.Cmd) error {
	if g.failure != nil {
		return g.failure
	}
	if !g.result.AnchorStarted || g.result.SignalsClosed || cmd.SysProcAttr != nil {
		return errors.New("owned test group unavailable")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: g.result.AnchorPID}
	return nil
}
func (g *linkCalibrationGroup) checkMember(pid int) error {
	group, err := syscall.Getpgid(pid)
	if err != nil {
		g.result.SignalsClosed = true
		g.result.ControlFailed = true
		g.failure = errors.Join(g.failure, err)
		return err
	}
	if group != g.result.AnchorPID {
		g.result.SignalsClosed = true
		g.result.ControlFailed = true
		g.failure = errors.New("test did not join the owned anchor group")
		return g.failure
	}
	return nil
}
func (g *linkCalibrationGroup) signal(signal syscall.Signal) error {
	if !g.result.AnchorStarted || g.result.AnchorReaped || g.result.SignalsClosed {
		return errors.New("owned group signal phase closed")
	}
	err := g.killGroup(-g.result.AnchorPID, signal)
	action := LinkCalibrationGroupSignal{SignalNumber: int(signal), Succeeded: err == nil, Absent: errors.Is(err, syscall.ESRCH)}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		action.Errno = int(errno)
	}
	g.result.Signals = append(g.result.Signals, action)
	if errors.Is(err, syscall.ESRCH) {
		g.result.SignalsClosed = true
		return nil
	}
	if err != nil {
		g.result.SignalsClosed = true
		g.result.ControlFailed = true
		g.failure = errors.Join(g.failure, err)
		return err
	}
	if signal == syscall.SIGKILL {
		g.result.SignalsClosed = true
	}
	return nil
}
func (g *linkCalibrationGroup) beginStop() error {
	if !g.result.AnchorStarted {
		g.result.SignalsClosed = true
		return nil
	}
	if err := g.signal(syscall.SIGCONT); err != nil {
		return err
	}
	if g.result.SignalsClosed {
		return nil
	}
	return g.signal(syscall.SIGTERM)
}
func (g *linkCalibrationGroup) lastSignal() error {
	if g.result.SignalsClosed {
		return nil
	}
	return g.signal(syscall.SIGKILL)
}

// Both exact Cmd.Wait owners must finish before any -1 adopted wait. The last
// PGID operation is already over; anchor PID reuse cannot affect later signals.
func (g *linkCalibrationGroup) close(ctx context.Context, testStopped bool) (LinkCalibrationTree, error) {
	if !g.result.SignalsClosed {
		return g.result, errors.New("cannot reap anchor before final group signal")
	}
	if g.closureStarted {
		return g.result, errors.New("owned tree closure already attempted; original Wait owner retained")
	}
	g.closureStarted = true
	err := g.failure
	if g.result.AnchorStarted {
		done := make(chan error, 1)
		go func() { done <- g.anchor.Wait() }() // sole anchor Wait, never before final signal
		select {
		case waitErr := <-done:
			g.result.AnchorWaitReturned = true
			if state := g.anchor.ProcessState; state != nil {
				if status, ok := state.Sys().(syscall.WaitStatus); ok && (status.Exited() || status.Signaled()) {
					g.result.AnchorReaped = true
					g.result.AnchorStatus = int(status)
					// Natural early anchor exit remains a failed calibration, even if the
					// later genuine ECHILD still proves all writers stopped.
					if !status.Signaled() {
						err = errors.Join(err, errors.New("anchor exited outside owned stop protocol"))
					}
				}
			}
			var exit *exec.ExitError
			if waitErr != nil && !errors.As(waitErr, &exit) {
				err = errors.Join(err, waitErr)
			}
		case <-ctx.Done():
			return g.result, errors.Join(err, ctx.Err(), errors.New("anchor terminal wait unavailable"))
		}
	}
	if !testStopped || (g.result.AnchorStarted && !g.result.AnchorReaped) {
		return g.result, errors.Join(err, errors.New("direct wait ownership not closed"))
	}
	result, drainErr := drainLinkCalibrationChildren(ctx, g.result)
	g.result = result
	return result, errors.Join(err, drainErr)
}
func drainLinkCalibrationChildren(ctx context.Context, r LinkCalibrationTree) (LinkCalibrationTree, error) {
	r.NoChildren, r.Closed = false, false
	if !r.SubreaperEnabled {
		return r, errors.New("subreaper prerequisite missing")
	}
	for attempts := 0; attempts < 2000; attempts++ {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		var status syscall.WaitStatus
		var usage syscall.Rusage
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, &usage)
		if errors.Is(err, syscall.ECHILD) {
			r.NoChildren = true
			r.Closed = true
			return r, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return r, err
		}
		if pid > 0 {
			terminal := status.Exited() || status.Signaled()
			r.Adopted = append(r.Adopted, LinkCalibrationAdoptedWait{PID: pid, Status: int(status), Terminal: terminal})
			if len(r.Adopted) > 16 {
				return r, errors.New("adopted child count exceeds fixed bound; overflow wait witness retained")
			}
			if !terminal {
				return r, errors.New("adopted wait was not terminal")
			}
			continue
		}
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return r, errors.New("adopted terminal drain exceeded finite attempt bound")
}
