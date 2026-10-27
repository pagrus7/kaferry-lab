package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

type LinkCalibrationCleanup struct {
	PlannedName, ContainerID                                         string
	PlanFound, Attempted, Resolved, Removed, Absent, JournalComplete bool
}
type linkCalibrationLatencyPlan struct {
	RunID, Name, Role, Image, ExpectedImageID, Network, API, Endpoint, Upstream, ConfigPath string
	Command                                                                                 []string
	MemoryBytes, NanoCPUs, PIDs, LogBytes                                                   int64
}
type linkCalibrationCleanupError struct {
	reference         string
	retentionComplete bool
}

func (e *linkCalibrationCleanupError) Error() string {
	if !e.retentionComplete {
		return "latency cleanup incomplete; exact private notice unavailable"
	}
	return "latency cleanup incomplete; private reference " + e.reference
}

// The only discovery is a bounded read of this run's existing public directory.
// No Docker resource inventory or unrelated filesystem traversal is performed.
func cleanupLinkCalibrationLatency(ctx context.Context, s fixture.State, rawDocker fixture.Executor) (r LinkCalibrationCleanup, err error) {
	action := []string{"latency_owner_cleanup", "read_run_journal"}
	var notice []byte
	defer func() {
		if err != nil {
			ref, e := fixture.RetainLinkNetworkFailure(s, action, notice, err)
			if e != nil {
				err = &linkCalibrationCleanupError{retentionComplete: false}
			} else {
				err = &linkCalibrationCleanupError{reference: ref, retentionComplete: true}
			}
		}
	}()
	if s.Proxy == nil {
		return r, errors.New("genuine linked fixture required")
	}
	root := filepath.Join(".cache", "fixtures", s.RunID+"-links")
	action = append(action, root)
	rootInfo, e := os.Lstat(root)
	if e != nil {
		return r, e
	}
	if !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return r, errors.New("run journal root is not a real owner-only directory")
	}
	dir, e := os.Open(root)
	if e != nil {
		return r, e
	}
	opened, e := dir.Stat()
	if e != nil {
		return r, errors.Join(e, dir.Close())
	}
	if !os.SameFile(rootInfo, opened) {
		return r, errors.Join(errors.New("run journal root changed"), dir.Close())
	}
	entries, readErr := dir.ReadDir(513)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return r, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return r, closeErr
	}
	if len(entries) > 512 {
		return r, errors.New("run journal directory exceeds fixed bound")
	}
	prefix := s.Proxy.Container + "-latency-"
	var name string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), prefix)
		if len(suffix) != 16 || !calibrationHex(suffix) {
			return r, errors.New("unexpected latency journal name")
		}
		if name != "" {
			return r, errors.New("ambiguous latency journal ownership")
		}
		info, e := entry.Info()
		if e != nil {
			return r, e
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 || entry.Type()&os.ModeSymlink != 0 {
			return r, errors.New("latency journal is not an owner-only real directory")
		}
		name = entry.Name()
	}
	if name == "" {
		r.Resolved, r.JournalComplete = true, true
		return r, nil
	}
	r.PlannedName = name
	path := filepath.Join(root, name, "observations.jsonl")
	action = []string{"latency_owner_cleanup", "read_journal", path}
	body, e := readLinkCalibrationJournal(path)
	if e != nil {
		return r, e
	}
	plan, id, tail, e := readLinkCalibrationLatencyPlan(body, s, name)
	if e != nil {
		notice = body
		return r, e
	}
	r.PlanFound = true
	r.JournalComplete = len(tail) == 0
	if len(tail) > 0 {
		// The complete pre-create plan still permits exact-resource restoration;
		// malformed trailing observations can never qualify calibration. Retain
		// the literal incomplete row before any safe available cleanup attempt.
		_, e = fixture.RetainLinkNetworkFailure(s, []string{"latency_owner_cleanup", "incomplete_journal_tail", path}, tail, errors.New("latency journal has incomplete trailing observation"))
		if e != nil {
			return r, e
		}
	}
	run, e := fixture.LinkExecutor(s, rawDocker)
	if e != nil {
		return r, e
	}
	target := id
	if target == "" {
		target = plan.Name
	}
	action = []string{"latency_owner_cleanup", "container", "inspect", target, "--format", "{{json .}}"}
	raw, e := run(ctx, "container", "inspect", target, "--format", "{{json .}}")
	notice = raw
	r.Attempted = true
	if e != nil {
		// LinkExecutor returns raw failure bytes only for its reviewed exact
		// absence outcome, after retaining the original and clearing its stop.
		if exactCalibrationContainerAbsence(raw, target) {
			r.Resolved, r.Absent = true, true
			return r, nil
		}
		return r, e
	}
	actual, e := validateLinkCalibrationLatencyContainer(raw, s, plan, id)
	if e != nil {
		return r, e
	}
	r.ContainerID = actual
	// Keep selected immutable ownership facts before removal can destroy the
	// inspected resource. This fixed private receipt belongs to the same run.
	if e = persistLinkCalibrationJSON(filepath.Join(".cache", "fixtures-private", s.RunID+"-links"), "latency-cleanup-owner.json", struct {
		RunID, Name, ID, ImageID, Image, Role, Network, ConfigPath string
		Command                                                    []string
		JournalSHA256                                              string
	}{s.RunID, plan.Name, actual, s.Proxy.ImageID, fixture.ProxyImage, "latency-calibration", "host", plan.ConfigPath, plan.Command, processDigest(body)}); e != nil {
		return r, e
	}
	action = []string{"latency_owner_cleanup", "container", "rm", "-f", actual}
	notice = nil
	if _, e = run(ctx, "container", "rm", "-f", actual); e != nil {
		return r, e
	}
	r.Resolved, r.Removed = true, true
	return r, nil
}
func calibrationHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}
func readLinkCalibrationJournal(path string) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > 128<<10 {
		return nil, errors.New("latency journal is not a bounded owner-only regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	opened, e := f.Stat()
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return nil, errors.Join(errors.New("latency journal changed before bounded read"), f.Close())
	}
	body, re := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	after, se := f.Stat()
	ce := f.Close()
	if e = errors.Join(re, se, ce); e != nil {
		return nil, e
	}
	final, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if len(body) > 128<<10 || !os.SameFile(before, opened) || !os.SameFile(opened, after) || !os.SameFile(after, final) || before.Size() != int64(len(body)) || after.Size() != before.Size() || !before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(final.ModTime()) {
		return nil, errors.New("latency journal changed during stopped-writer read")
	}
	return body, nil
}
func readLinkCalibrationLatencyPlan(body []byte, s fixture.State, name string) (plan linkCalibrationLatencyPlan, id string, tail []byte, err error) {
	lines := bytes.Split(body, []byte{'\n'})
	if len(lines) > 129 {
		return plan, id, nil, errors.New("latency journal record count exceeds bound")
	}
	plans := 0
	for i, line := range lines {
		if len(line) == 0 && i == len(lines)-1 {
			continue
		}
		if len(line) > 16<<10 {
			return plan, id, nil, errors.New("latency journal row exceeds bound")
		}
		if i == len(lines)-1 {
			tail = append([]byte(nil), line...)
			break
		}
		var row struct {
			Kind      string
			ElapsedNS int64
			Facts     json.RawMessage
		}
		if decodeErr := json.Unmarshal(line, &row); decodeErr != nil {
			return plan, id, nil, errors.Join(decodeErr, errors.New("latency journal complete row malformed"))
		}
		switch row.Kind {
		case "resource_plan":
			plans++
			if plans != 1 {
				return plan, id, nil, errors.New("latency resource plan missing or ambiguous")
			}
			if decodeErr := json.Unmarshal(row.Facts, &plan); decodeErr != nil {
				return plan, id, nil, decodeErr
			}
		case "container_ownership":
			var fact struct{ ID, Name, ImageID string }
			if decodeErr := json.Unmarshal(row.Facts, &fact); decodeErr != nil {
				return plan, id, nil, decodeErr
			}
			if len(fact.ID) != 64 || !calibrationHex(fact.ID) || fact.Name != name || fact.ImageID != s.Proxy.ImageID || id != "" && fact.ID != id {
				return plan, id, nil, errors.New("latency immutable identity receipt inconsistent")
			}
			id = fact.ID
		}
	}
	configPath, e := filepath.Abs(filepath.Join(".cache", "fixtures", s.RunID+"-links", name, "startup.json"))
	if e != nil {
		return plan, id, tail, e
	}
	host, port, e := net.SplitHostPort(plan.API)
	imageBound := len(plan.ExpectedImageID) == 71 && strings.HasPrefix(plan.ExpectedImageID, "sha256:") && calibrationHex(strings.TrimPrefix(plan.ExpectedImageID, "sha256:"))
	if plans != 1 || !imageBound || e != nil || host != "127.0.0.1" || port == "" || plan.RunID != s.RunID || plan.Name != name || plan.Role != "latency-calibration" || plan.Image != fixture.ProxyImage || plan.ExpectedImageID != s.Proxy.ImageID || plan.Network != "host" || plan.ConfigPath != configPath || !reflect.DeepEqual(plan.Command, []string{"-host=127.0.0.1", "-port=" + port, "-config=/calibration.json"}) || plan.MemoryBytes != 128<<20 || plan.NanoCPUs != 500000000 || plan.PIDs != 64 || plan.LogBytes != 1<<20 {
		return plan, id, tail, errors.Join(e, errors.New("latency plan differs from this run's fixed ownership contract"))
	}
	return
}
func validateLinkCalibrationLatencyContainer(raw []byte, s fixture.State, p linkCalibrationLatencyPlan, retained string) (string, error) {
	var f struct {
		ID, Name, Image string
		Config          struct {
			Image           string
			Labels          map[string]string
			Cmd, Entrypoint []string
		}
		HostConfig struct {
			NetworkMode                 string
			Memory, NanoCPUs, PidsLimit int64
			Privileged, ReadonlyRootfs  bool
			PortBindings                map[string]json.RawMessage
			LogConfig                   struct {
				Type   string
				Config map[string]string
			}
		}
		State  struct{ Running, Paused *bool }
		Mounts []struct {
			Type, Source, Destination string
			RW                        bool
		}
	}
	if len(raw) > 64<<10 {
		return "", errors.New("latency cleanup inspect malformed or oversized")
	}
	if decodeErr := json.Unmarshal(raw, &f); decodeErr != nil {
		return "", decodeErr
	}
	if len(f.ID) != 64 || !calibrationHex(f.ID) || retained != "" && f.ID != retained || f.Name != "/"+p.Name || f.Image != s.Proxy.ImageID || f.Config.Image != fixture.ProxyImage || f.Config.Labels[brokerOwnerLabel] != s.RunID || f.Config.Labels["io.kaferry-lab.role"] != "latency-calibration" {
		return "", errors.New("latency cleanup immutable ownership mismatch")
	}
	if !reflect.DeepEqual(f.Config.Cmd, p.Command) || !reflect.DeepEqual(f.Config.Entrypoint, []string{"/toxiproxy"}) || f.State.Running == nil || f.State.Paused == nil || *f.State.Paused || f.HostConfig.NetworkMode != "host" || f.HostConfig.Memory != 128<<20 || f.HostConfig.NanoCPUs != 500000000 || f.HostConfig.PidsLimit != 64 || f.HostConfig.Privileged || !f.HostConfig.ReadonlyRootfs || len(f.HostConfig.PortBindings) != 0 {
		return "", errors.New("latency cleanup process/resource mismatch")
	}
	if f.HostConfig.LogConfig.Type != "json-file" || f.HostConfig.LogConfig.Config["max-size"] != "1m" || f.HostConfig.LogConfig.Config["max-file"] != "1" || len(f.Mounts) != 1 || f.Mounts[0].Type != "bind" || f.Mounts[0].Source != p.ConfigPath || f.Mounts[0].Destination != "/calibration.json" || f.Mounts[0].RW {
		return "", errors.New("latency cleanup exact configuration mismatch")
	}
	return f.ID, nil
}
func exactCalibrationContainerAbsence(raw []byte, target string) bool {
	// Same exact combined stdout/stderr framing admitted by LinkExecutor. Its
	// permission/context/persistence gates must succeed before raw reaches here.
	if string(raw) == "\nError response from daemon: No such container: "+target+"\n" {
		return true
	}
	for _, prefix := range []string{"Error: No such object: ", "Error response from daemon: No such object: ", "Error: No such container: ", "Error response from daemon: No such container: "} {
		expected := prefix + target
		if string(raw) == expected || string(raw) == expected+"\n" {
			return true
		}
	}
	return false
}

// Compile-time guard against accidentally formatting a raw inspect into public
// diagnostics: the only error with details above exposes a private reference.
var _ error = (*linkCalibrationCleanupError)(nil)
