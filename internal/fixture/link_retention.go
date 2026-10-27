package fixture

// This file is the private evidence boundary for optional linked fixtures only.
// Raw Docker bytes are never public diagnostics or publishable link receipts.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const linkOutputLimit = 64 << 10

type linkCaptureKey struct{}
type linkOutputOverflow struct{ ObservedBytes int64 }

func (*linkOutputOverflow) Error() string { return "linked Docker output exceeded capture bound" }

type linkBoundedOutput struct {
	mu       sync.Mutex
	bytes    []byte
	observed int64
	overflow bool
	cancel   context.CancelFunc
}

func (w *linkBoundedOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observed += int64(len(p))
	available := linkOutputLimit - len(w.bytes)
	if available > len(p) {
		available = len(p)
	}
	w.bytes = append(w.bytes, p[:available]...)
	if available != len(p) {
		w.overflow = true
		w.cancel()
		return available, &linkOutputOverflow{ObservedBytes: w.observed}
	}
	return len(p), nil
}

// Both streams intentionally share a writer: retained bytes are truthfully
// labelled combined, never described as separate stdout and stderr. The child
// is canceled on overflow; observed is not a claim about all emitted bytes.
func boundedLinkDocker(ctx context.Context, args ...string) ([]byte, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &linkBoundedOutput{cancel: cancel}
	cmd := exec.CommandContext(child, "docker", args...)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if output.overflow {
		err = errors.Join(err, &linkOutputOverflow{ObservedBytes: output.observed})
	}
	return output.bytes, err
}

func linkPrivateDirectory(id string) string {
	return filepath.Join(".cache", "fixtures-private", id+"-links")
}

// Exclusive reservation precedes even docker info. This directory is private
// raw material, separate from the public selected-fact link receipts. It must
// never be uploaded by a public artifact allowlist without explicit review.
func reserveLinkEvidence(id string) error {
	if _, err := StatePath(id); err != nil {
		return err
	}
	root := linkPrivateDirectory(id)
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return errors.New("private link evidence parent unavailable; no Docker action permitted")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return errors.New("private link evidence reservation failed; no Docker action permitted")
	}
	_, err := writeLinkPrivate(root, "PRIVATE.json", struct{ RunID, Classification, Publication string }{id, "PRIVATE RAW EVIDENCE", "withhold pending explicit redaction review"})
	return err
}

func writeLinkPrivate(dir, name string, value any) (string, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", errors.New("private link receipt encoding failed")
	}
	if len(body)+1 > 256<<10 {
		return "", errors.New("private link receipt exceeds evidence bound")
	}
	var f *os.File
	if name == "" {
		f, err = os.CreateTemp(dir, "docker-*.json")
	} else {
		f, err = os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return "", errors.New("private link receipt reservation failed")
	}
	_, we := f.Write(append(body, '\n'))
	if errors.Join(we, f.Sync(), f.Close()) != nil {
		return "", errors.New("private link receipt persistence failed; evidence incomplete")
	}
	return f.Name(), nil
}

type linkDockerCause struct {
	ExitCode *int    `json:",omitempty"`
	Signal   string  `json:",omitempty"`
	Errno    *uint64 `json:",omitempty"`
	Context  string  `json:",omitempty"`
	Timeout  bool    `json:",omitempty"`
}

func safeLinkDockerCause(ctx context.Context, err error) linkDockerCause {
	var result linkDockerCause
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		result.ExitCode = &code
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			result.Signal = status.Signal().String()
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		code := uint64(errno)
		result.Errno = &code
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		result.Context = "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Context = "deadline exceeded"
	}
	var network net.Error
	if errors.As(err, &network) {
		result.Timeout = network.Timeout()
	}
	return result
}

type linkDockerFailure struct {
	Reference         string
	Cause             linkDockerCause
	PersistenceFailed bool
	ExactAbsence      bool
}

func (e *linkDockerFailure) Error() string {
	if e.ExactAbsence && !e.PersistenceFailed {
		return fmt.Sprintf("linked Docker reports exact target absence; private receipt %s", e.Reference)
	}
	if e.PersistenceFailed {
		return "linked Docker action failed; private evidence incomplete; Docker facility stopped"
	}
	return fmt.Sprintf("linked Docker action failed; private receipt %s; Docker facility stopped", e.Reference)
}

// LinkExecutor is also used by the opt-in topology control, so its inherited
// broker inspectors retain failures before they redact public diagnostics.
// The wrapper is sequential by contract, and latches unknown failure before
// returning. A persisted stop prevents later cleanup/observation from silently
// trying the same denied facility via another command, target or invocation.
func LinkExecutor(s State, run Executor) (Executor, error) {
	if err := validateLinkPlan(s); err != nil {
		return nil, err
	}
	return linkExecutor(s.RunID, run)
}
func linkExecutor(id string, run Executor) (Executor, error) {
	if run == nil {
		return nil, errors.New("linked Docker executor missing")
	}
	root := linkPrivateDirectory(id)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("private link evidence directory unavailable or not owner-only")
	}
	if _, err := os.Stat(filepath.Join(root, "PRIVATE.json")); err != nil {
		return nil, errors.New("private link evidence reservation missing; no Docker action permitted")
	}
	stop := filepath.Join(root, "STOPPED.json")
	if _, err := os.Stat(stop); err == nil {
		return nil, errors.New("retained Docker facility stop; no further Docker action permitted")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Docker facility stop state unavailable")
	}
	operation, err := os.MkdirTemp(root, "operation-")
	if err != nil {
		return nil, errors.New("private link operation reservation failed; no Docker action permitted")
	}
	var stopped error
	return func(ctx context.Context, args ...string) ([]byte, error) {
		if stopped != nil {
			return nil, stopped
		}
		argvBytes := 0
		for _, arg := range args {
			argvBytes += len(arg)
		}
		if len(args) > 128 || argvBytes > 32<<10 {
			stopped = errors.New("linked Docker action exceeds fixed evidence bound")
			return nil, stopped
		}
		if _, err := os.Stat(stop); err == nil {
			stopped = errors.New("retained Docker facility stop; no further Docker action permitted")
			return nil, stopped
		} else if !errors.Is(err, os.ErrNotExist) {
			stopped = errors.New("Docker facility stop state unavailable")
			return nil, stopped
		}
		// Reserve intent exclusively before each action, not just the first failure.
		started := time.Now()
		intent := struct {
			RunID          string
			Argv           []string
			StartedAt      time.Time
			Classification string
		}{id, append([]string{"docker"}, args...), started.UTC(), "PRIVATE RAW EVIDENCE"}
		// The durable stop is reserved before the intent write as well: a
		// denied/incomplete intent write cannot be followed through a fresh
		// operation directory. Only a complete permitted outcome removes it.
		_, e := writeLinkPrivate(root, "STOPPED.json", struct {
			RunID, Operation, Status string
			Argv                     []string
		}{id, operation, "action pending or unresolved; no further Docker action permitted", append([]string{"docker"}, args...)})
		if e != nil {
			stopped = e
			return nil, stopped
		}
		intentPath, e := writeLinkPrivate(operation, "", intent)
		if e != nil {
			stopped = e
			return nil, stopped
		}
		raw, cause := run(context.WithValue(ctx, linkCaptureKey{}, true), args...)
		if cause == nil && ctx.Err() != nil {
			cause = ctx.Err()
		}
		reportedCombinedBytes := len(raw)
		complete := len(raw) <= linkOutputLimit
		var overflow *linkOutputOverflow
		if errors.As(cause, &overflow) {
			complete = false
		}
		if !complete && len(raw) > linkOutputLimit {
			raw = raw[:linkOutputLimit]
		}
		if cause == nil && complete {
			_, e = writeLinkPrivate(operation, "", struct {
				Intent, Status, SHA256 string
				Bytes                  int
			}{intentPath, "successful bounded command; raw success output discarded", linkDigest(raw), len(raw)})
			if e != nil {
				stopped = e
				return nil, stopped
			}
			if e = os.Remove(stop); e != nil {
				stopped = errors.New("Docker completion marker persistence failed; facility stopped")
				return nil, stopped
			}
			return raw, nil
		}
		if cause == nil {
			cause = &linkOutputOverflow{}
		}
		// Exact target absence is the only reviewed nonfatal Docker outcome.
		// It is still retained, but never classified from arbitrary substrings.
		absent := complete && exactLinkAbsence(args, raw) && !errors.Is(cause, syscall.EACCES) && !errors.Is(cause, syscall.EPERM) && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) && ctx.Err() == nil
		causeBytes := []byte(cause.Error())
		reportedCauseBytes := len(causeBytes)
		causeComplete := len(causeBytes) <= linkOutputLimit
		if !causeComplete {
			causeBytes = causeBytes[:linkOutputLimit]
		}
		safeCause := safeLinkDockerCause(ctx, cause)
		observedCombinedBytes := int64(reportedCombinedBytes)
		if overflow != nil {
			observedCombinedBytes = overflow.ObservedBytes
		}
		receipt := struct {
			RunID, Intent, Stream, Classification                         string
			Argv                                                          []string
			StartedAt, EndedAt                                            time.Time
			ElapsedNanoseconds                                            int64
			Combined, CauseText                                           []byte
			CombinedSHA256, CauseSHA256                                   string
			CapturedCombinedBytes, CapturedCauseBytes, ReportedCauseBytes int
			ObservedCombinedBytes                                         int64
			CombinedComplete, CauseComplete, ExactAbsence                 bool
			Cause                                                         linkDockerCause
			Reason                                                        string
		}{id, intentPath, "combined stdout/stderr", "PRIVATE RAW EVIDENCE", append([]string{"docker"}, args...), started.UTC(), time.Now().UTC(), time.Since(started).Nanoseconds(), raw, causeBytes, linkDigest(raw), linkDigest(causeBytes), len(raw), len(causeBytes), reportedCauseBytes, observedCombinedBytes, complete, causeComplete, absent, safeCause, "exact reported reason retained in private CauseText/Combined; no separate policy reason inferred"}
		reference, persistErr := writeLinkPrivate(operation, "", receipt)
		failure := &linkDockerFailure{Reference: reference, Cause: safeCause, PersistenceFailed: persistErr != nil}
		// Public summaries contain only fixed classification, references, hashes,
		// lengths and typed codes. No raw action argv, Env, cause or log text.
		if persistErr == nil {
			persistErr = linkReceipt(State{RunID: id}, "docker-failure", struct {
				Classification, PrivateReference, CombinedSHA256, CauseSHA256 string
				CombinedBytes, CauseBytes                                     int
				CombinedComplete, CauseComplete, ExactAbsence                 bool
				Cause                                                         linkDockerCause
			}{"PRIVATE RAW BYTES WITHHELD; review before publication", reference, linkDigest(raw), linkDigest(causeBytes), len(raw), len(causeBytes), complete, causeComplete, absent, safeCause})
			if persistErr != nil {
				failure.PersistenceFailed = true
			}
		}
		if absent && causeComplete && persistErr == nil {
			if e = os.Remove(stop); e == nil {
				failure.ExactAbsence = true
				return raw, failure
			}
			failure.PersistenceFailed = true
		}
		stopped = failure
		return nil, stopped
	}, nil
}

func exactLinkAbsence(args []string, raw []byte) bool {
	if len(args) != 5 || args[1] != "inspect" || args[3] != "--format" || args[4] != "{{json .}}" {
		return false
	}
	// docker container inspect --format emits an empty stdout line before this
	// exact daemon stderr in the retained native failure. Admit that one framing
	// only; do not trim arbitrary warnings, policy text or additional lines.
	if args[0] == "container" && string(raw) == "\nError response from daemon: No such container: "+args[2]+"\n" {
		return true
	}
	for _, expected := range linkAbsenceMessages(args[0], args[2]) {
		if string(raw) == expected || string(raw) == expected+"\n" {
			return true
		}
	}
	return false
}
func linkAbsenceMessages(kind, target string) []string {
	if kind != "container" && kind != "network" {
		return nil
	}
	messages := []string{"Error: No such object: " + target, "Error response from daemon: No such object: " + target, "Error: No such " + kind + ": " + target, "Error response from daemon: No such " + kind + ": " + target}
	if kind == "network" {
		messages = append(messages, "Error response from daemon: network "+target+" not found")
	}
	return messages
}

func retainPrivateLinkLogs(s State, id string, logs []byte) (string, error) {
	return writeLinkPrivate(linkPrivateDirectory(s.RunID), "", struct {
		RunID, ContainerID, Classification, Stream string
		Bytes                                      []byte
	}{s.RunID, id, "PRIVATE RAW EVIDENCE", "combined stdout/stderr", logs})
}

// A mandatory non-command receipt failure is fatal too. Record only a safe
// operation status here; never retry the failed receipt through another path.
func stopLinkOperation(id, operation string) error {
	root := linkPrivateDirectory(id)
	stop := filepath.Join(root, "STOPPED.json")
	if _, err := os.Stat(stop); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("link stop evidence unavailable; no further Docker action permitted")
	}
	_, err := writeLinkPrivate(root, "STOPPED.json", struct{ RunID, Operation, Status string }{id, operation, "mandatory operation/evidence incomplete; no further Docker action permitted"})
	return err
}
