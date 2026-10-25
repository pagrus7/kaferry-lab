package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Wire capture is an experimental lower-bound observer. Its output cannot reach
// a threshold fault or prove absence of Produce responses until native capture
// completeness and sensitivity controls have been independently accepted.
type wirePlan struct {
	Directory, ToolReceipt string
	Duration               time.Duration
	MaxBytes               int64
}

type wireTool struct {
	Path, SHA256 string
}

const wireDependencyPinsSHA256 = "2d08a951936afac4817c16b3def40bf73864db5175ddf350c765f30dc9970939"

type wireTools struct {
	Schema     int
	PinsSHA256 string `json:"pins_sha256"`
	Version    string
	Tools      map[string]wireTool
}

type wireCaptureReceipt struct {
	Schema                               int
	RunID, Role, StartTicks              string
	PID                                  int
	InterruptElapsedNS, KillElapsedNS    int64
	InterruptError, KillError            string
	Endpoint, ContainerID, CaptureSHA256 string
	ToolReceiptSHA256                    string
	DependencyPinsSHA256                 string
	StartedAt, StoppedAt                 time.Time
	ElapsedNanoseconds                   int64
	ExitCode                             int
	WaitError                            string
	Args                                 []string
	Bytes                                int64
	Reaped, BoundReached, Supported      bool
	Error, Limitation                    string
}

type wireCapture struct {
	plan    wirePlan
	tools   wireTools
	cmd     *exec.Cmd
	stderr  *processLog
	done    chan struct{}
	waitErr error
	receipt wireCaptureReceipt
	stopped bool      // caller serializes Stop and Decode
	origin  time.Time // monotonic capture-controller duration
}

// startWireCapture targets only the freshly inspected source/destination port of an
// owned fixture. A port filter includes other clients to that disposable broker;
// PDML attribution must subsequently identify this worker's client and stream.
// The caller may start a separate disposable native calibration under sudo.
// This helper starts a direct child and never escalates or retries privileges.
func startWireCapture(ctx context.Context, plan wirePlan, broker *ownedBroker) (*wireCapture, error) {
	if err := nativeProcessPlatform(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return nil, errors.New("wire capture requires a live bounded context")
	}
	if broker == nil || (broker.role != "destination" && broker.role != "source") || broker.calibration || broker.id == "" {
		return nil, errors.New("wire capture requires the actual owned source/destination fixture")
	}
	if _, err := broker.inspect(ctx, broker.id); err != nil {
		return nil, err
	}
	port, err := ownedBrokerPort(broker.endpoint)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(plan.Directory) || !filepath.IsAbs(plan.ToolReceipt) || plan.Duration < time.Second || plan.Duration > 3*time.Minute || plan.MaxBytes < 1<<20 || plan.MaxBytes > 32<<20 || plan.MaxBytes%1024 != 0 {
		return nil, errors.New("invalid wire capture paths or duration/byte bounds")
	}
	body, err := wireReadReceipt(plan.ToolReceipt)
	if err != nil {
		return nil, errors.New("wire dependency receipt unavailable or oversized")
	}
	var tools wireTools
	if err = json.Unmarshal(body, &tools); err != nil || tools.Schema != 1 || tools.PinsSHA256 != wireDependencyPinsSHA256 || tools.Version != "4.6.6-1~ubuntu24.04.0~ppa1" {
		return nil, errors.New("wire dependency revision unsupported; Noble default 4.2.2 cannot decode Produce11")
	}
	for _, name := range []string{"dumpcap", "tshark"} {
		tool := tools.Tools[name]
		if tool.Path != "/usr/bin/"+name {
			return nil, errors.New("wire tool must be the fixed installed standard executable")
		}
		if err = wireVerifyTool(tool); err != nil {
			return nil, fmt.Errorf("wire %s identity: %w", name, err)
		}
	}
	if err = os.Mkdir(plan.Directory, 0700); err != nil {
		return nil, err
	}
	c := &wireCapture{plan: plan, tools: tools, done: make(chan struct{}), receipt: wireCaptureReceipt{Schema: 1, RunID: broker.runID, Role: broker.role, ExitCode: -1, Endpoint: broker.endpoint, ContainerID: broker.id, ToolReceiptSHA256: processDigest(body), DependencyPinsSHA256: wireDependencyPinsSHA256, Limitation: "native capture completeness, actual Produce11 and sensitivity controls have not been accepted; wire requests are neither output nor Kafka acknowledgments"}}
	c.stderr, err = newProcessLog(filepath.Join(plan.Directory, "capture.stderr"), 16384)
	if err != nil {
		return nil, err
	}
	args := []string{"-i", "lo", "-p", "-s", "0", "-f", "host 127.0.0.1 and tcp port " + port, "-a", "duration:" + strconv.Itoa(int(plan.Duration.Seconds())), "-a", "filesize:" + strconv.FormatInt(plan.MaxBytes/1024, 10), "-w", filepath.Join(plan.Directory, "broker.pcapng")}
	c.receipt.Args = args
	c.origin = time.Now()
	c.receipt.StartedAt = c.origin.UTC()
	toolFile, err := wireOpenTool(tools.Tools["dumpcap"])
	if err != nil {
		_ = c.stderr.close()
		return nil, err
	}
	defer toolFile.Close()
	c.cmd = exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	c.cmd.Args[0] = tools.Tools["dumpcap"].Path
	c.cmd.ExtraFiles = []*os.File{toolFile}
	c.cmd.Stdout, c.cmd.Stderr = io.Discard, c.stderr
	c.cmd.WaitDelay = 2 * time.Second
	if err = c.cmd.Start(); err != nil {
		_ = c.stderr.close()
		c.receipt.Error = "standard dumpcap did not start; capture permission/tool prerequisite unavailable"
		_ = persistProcessJSON(plan.Directory, "capture.json", c.receipt)
		return nil, errors.New(c.receipt.Error)
	}
	c.receipt.PID = c.cmd.Process.Pid
	_, c.receipt.StartTicks, err = readProcessState(c.receipt.PID)
	go func() {
		c.waitErr = c.cmd.Wait()
		close(c.done)
	}()
	if err == nil {
		err = persistProcessJSON(plan.Directory, "capture-started.json", c.receipt)
	}
	if err != nil {
		_, cleanupErr := c.Stop()
		return nil, errors.Join(err, cleanupErr)
	}
	// Do not start the worker merely because Cmd.Start succeeded. Dumpcap opens
	// its output after capture initialization; native warmup must still validate
	// that the complete initiating handshake was actually captured.
	ready := time.NewTimer(5 * time.Second)
	defer ready.Stop()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			_, stopErr := c.Stop()
			return nil, errors.Join(ctx.Err(), stopErr)
		case <-c.done:
			_, stopErr := c.Stop()
			return nil, errors.Join(errors.New("standard capture exited before readiness; retain exact diagnostics"), stopErr)
		case <-ready.C:
			_, stopErr := c.Stop()
			return nil, errors.Join(errors.New("standard capture did not initialize within five seconds"), stopErr)
		case <-poll.C:
			info, statErr := os.Stat(filepath.Join(plan.Directory, "broker.pcapng"))
			if statErr == nil && info.Mode().IsRegular() && info.Size() >= 28 {
				diagnostic, readErr := os.ReadFile(filepath.Join(plan.Directory, "capture.stderr"))
				if readErr == nil && strings.Contains(string(diagnostic), "Capturing on") {
					return c, nil
				}
			}
		}
	}
}

// Stop interrupts the retained child, waits three seconds, then kills and
// waits two more seconds. Reaped is false if that wait cannot be confirmed.
// An incomplete/bounded capture remains unsupported.
func (c *wireCapture) Stop() (wireCaptureReceipt, error) {
	if c.stopped {
		return c.receipt, errors.New("wire capture already stopped")
	}
	c.stopped = true
	select {
	case <-c.done:
	default:
		c.receipt.InterruptElapsedNS = time.Since(c.origin).Nanoseconds()
		if err := c.cmd.Process.Signal(syscall.SIGINT); err != nil {
			c.receipt.InterruptError = err.Error()
		}
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
			c.receipt.KillElapsedNS = time.Since(c.origin).Nanoseconds()
			if err := c.cmd.Process.Kill(); err != nil {
				c.receipt.KillError = err.Error()
			}
			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				c.receipt.Error = "capture child has not been reaped after kill; cleanup remains unconfirmed"
				writeErr := persistProcessJSON(c.plan.Directory, "capture.json", c.receipt)
				return c.receipt, errors.Join(errors.New(c.receipt.Error), writeErr)
			}
			c.receipt.Error = "capture did not stop within its cleanup budget"
		}
	}
	var waitEvidenceErr error
	c.receipt.ExitCode = -1
	if state := c.cmd.ProcessState; state != nil {
		c.receipt.Reaped = true
		c.receipt.ExitCode = state.ExitCode()
	} else {
		waitEvidenceErr = errors.New("capture child reaping was not confirmed")
	}
	if c.waitErr != nil {
		c.receipt.WaitError = c.waitErr.Error()
	}
	c.receipt.ElapsedNanoseconds = time.Since(c.origin).Nanoseconds()
	c.receipt.StoppedAt = time.Now().UTC()
	err := errors.Join(c.stderr.close(), waitEvidenceErr)
	if c.waitErr != nil {
		c.receipt.Error = "standard capture failed; retain stderr for the exact privilege/tool notice"
		err = errors.Join(err, errors.New(c.receipt.Error))
	}
	if c.stderr.total > c.stderr.limit {
		err = errors.Join(err, errors.New("capture diagnostics exceeded evidence limit"))
	}
	path := filepath.Join(c.plan.Directory, "broker.pcapng")
	f, openErr := os.Open(path)
	if openErr == nil {
		info, statErr := f.Stat()
		if statErr == nil {
			c.receipt.Bytes = info.Size()
			c.receipt.BoundReached = info.Size() >= c.plan.MaxBytes || time.Duration(c.receipt.ElapsedNanoseconds) >= c.plan.Duration
		}
		if statErr == nil && info.Size() <= c.plan.MaxBytes+(1<<16) {
			data, readErr := io.ReadAll(io.LimitReader(f, c.plan.MaxBytes+(1<<16)+1))
			if readErr == nil {
				c.receipt.CaptureSHA256 = processDigest(data)
			}
			err = errors.Join(err, readErr)
		} else {
			err = errors.Join(err, statErr, errors.New("capture exceeded byte bound"))
		}
		err = errors.Join(err, f.Close())
	}
	err = errors.Join(err, openErr)
	if c.receipt.BoundReached {
		err = errors.Join(err, errors.New("capture reached its time/byte evidence bound"))
	}
	err = errors.Join(err, persistProcessJSON(c.plan.Directory, "capture.json", c.receipt))
	return c.receipt, err
}

func wireVerifyTool(tool wireTool) error {
	f, err := wireOpenTool(tool)
	if err != nil {
		return err
	}
	return f.Close()
}

// Keep the verified inode open through Cmd.Start, even if its path is replaced.
func wireOpenTool(tool wireTool) (*os.File, error) {
	if !filepath.IsAbs(tool.Path) || len(tool.SHA256) != 64 {
		return nil, errors.New("missing absolute tool path or executable digest")
	}
	f, err := os.Open(tool.Path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) { _ = f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Mode().Perm()&0022 != 0 || info.Size() > 64<<20 {
		return fail(errors.New("tool is not a bounded executable"))
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return fail(errors.New("standard wire tool must be root owned"))
	}
	body, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil || processDigest(body) != tool.SHA256 {
		return fail(errors.New("tool executable digest mismatch"))
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return f, nil
}

type wireDecodeReceipt struct {
	Schema                                int
	CaptureSHA256, PDMLSHA256, ToolSHA256 string
	Bytes                                 int64
	Reaped, Supported                     bool
	Error                                 string
	Candidates                            wireSubmissionCandidates
}

// Decode invokes the pinned standard dissector on a stopped, bounded capture.
// It retains raw PDML; its candidate report deliberately remains unsupported.
func (c *wireCapture) Decode(ctx context.Context, clientID string, known []wireKnownValue) (wireSubmissionCandidates, error) {
	var candidates wireSubmissionCandidates
	if !c.stopped || !c.receipt.Reaped || c.receipt.CaptureSHA256 == "" || c.receipt.BoundReached || c.waitErr != nil {
		return candidates, errors.New("decode requires a stopped/reaped bounded capture")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return candidates, errors.New("decode requires a live bounded context")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tool, err := wireOpenTool(c.tools.Tools["tshark"])
	if err != nil {
		return candidates, err
	}
	defer tool.Close()
	out, err := newProcessLog(filepath.Join(c.plan.Directory, "capture.pdml"), 32<<20)
	if err != nil {
		return candidates, err
	}
	diagnostic, err := newProcessLog(filepath.Join(c.plan.Directory, "decode.stderr"), 16384)
	if err != nil {
		_ = out.close()
		return candidates, err
	}
	port, _ := ownedBrokerPort(c.receipt.Endpoint)
	args := []string{"-n", "-2", "-r", filepath.Join(c.plan.Directory, "broker.pcapng"), "-d", "tcp.port==" + port + ",kafka", "-o", "tcp.desegment_tcp_streams:TRUE", "-T", "pdml"}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = c.tools.Tools["tshark"].Path
	cmd.ExtraFiles = []*os.File{tool}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	cmd.WaitDelay = 2 * time.Second
	receipt := wireDecodeReceipt{Schema: 1, CaptureSHA256: c.receipt.CaptureSHA256, ToolSHA256: c.tools.Tools["tshark"].SHA256}
	err = cmd.Run()
	receipt.Reaped = cmd.ProcessState != nil
	err = errors.Join(err, out.close(), diagnostic.close())
	if out.total > out.limit || diagnostic.total > diagnostic.limit {
		err = errors.Join(err, errors.New("dissector output exceeded evidence bounds"))
	}
	receipt.Bytes = out.total
	if err == nil {
		body, readErr := os.ReadFile(filepath.Join(c.plan.Directory, "capture.pdml"))
		err = readErr
		if err == nil {
			receipt.PDMLSHA256 = processDigest(body)
			n, _ := strconv.Atoi(port)
			candidates, err = parseWirePDML(bytes.NewReader(body), clientID, n, known)
		}
	}
	receipt.Candidates = candidates
	if err != nil {
		receipt.Error = "standard dissection/candidate parse failed; retain raw diagnostics"
	}
	err = errors.Join(err, persistProcessJSON(c.plan.Directory, "decode.json", receipt))
	return candidates, err
}

func wireReadReceipt(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 16384 {
		return nil, errors.New("wire receipt must be a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("wire receipt changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(body) > 16384 || int64(len(body)) != opened.Size() {
		return nil, errors.New("wire receipt oversized or changed while reading")
	}
	return body, nil
}
