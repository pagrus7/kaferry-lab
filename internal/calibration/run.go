package calibration

import (
	"bytes"
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
	"reflect"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/identity"
)

type Outcome struct {
	Mode   string          `json:"mode"`
	Bundle string          `json:"bundle"`
	Result evidence.Result `json:"result"`
}

func digest(raw []byte) string        { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func jsonBytes(v any) ([]byte, error) { b, e := json.Marshal(v); return append(b, '\n'), e }
func syncFile(path string, raw []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func fixtures() []identity.Record {
	records := make([]identity.Record, 3)
	for i := range records {
		ms := identity.Int64(1700000000123)
		records[i] = identity.Record{Key: identity.NewNullableBytes(nil), Value: identity.NewNullableBytes([]byte(fmt.Sprintf("calibration-record-%d", i))), Headers: []identity.Header{}, TimestampMS: &ms, TimestampKind: "create_time"}
	}
	return records
}
func readOutput(path string) ([]identity.Record, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	out := []identity.Record{}
	for {
		var r identity.Record
		e = d.Decode(&r)
		if errors.Is(e, io.EOF) {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		out = append(out, r)
		if len(out) > 16 {
			return nil, fmt.Errorf("standin exceeded finite output budget")
		}
	}
}

// Run creates two independent calibration histories. The healthy control must
// PASS; the deliberately faulty stand-in must produce VIOLATION. A controller
// error is returned separately and cannot count as successful sensitivity.
func Run(ctx context.Context, dir, executable string) ([]Outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if e := os.MkdirAll(filepath.Dir(dir), 0700); e != nil {
		return nil, e
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	dir, e := filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	binary, e := os.ReadFile(executable)
	if e != nil {
		return nil, e
	}
	sha := digest(binary)
	outcomes := []Outcome{}
	for _, mode := range []string{"healthy-pause", "faulty"} {
		outcome, e := one(ctx, filepath.Join(dir, mode), executable, sha, mode)
		if e != nil {
			return outcomes, e
		}
		outcomes = append(outcomes, outcome)
		expected := evidence.Pass
		if mode == "faulty" {
			expected = evidence.Violation
		}
		if outcome.Result.Verdict != expected {
			return outcomes, fmt.Errorf("calibration %s detected %s, required %s; preserve bundle %s", mode, outcome.Result.Verdict, expected, outcome.Bundle)
		}
	}
	return outcomes, nil
}

func one(ctx context.Context, dir, exe, exeSHA, mode string) (Outcome, error) {
	outcome := Outcome{Mode: mode, Bundle: filepath.Join(dir, "bundle")}
	work := filepath.Join(dir, "work")
	if e := os.MkdirAll(work, 0700); e != nil {
		return outcome, e
	}
	if e := os.Mkdir(outcome.Bundle, 0700); e != nil {
		return outcome, e
	}
	input, output, state := filepath.Join(work, "input.json"), filepath.Join(work, "output.jsonl"), filepath.Join(work, "saved.json")
	records := fixtures()
	sourceRaw, e := jsonBytes(records)
	if e != nil {
		return outcome, e
	}
	if e = syncFile(input, sourceRaw); e != nil {
		return outcome, e
	}
	actualSource, e := os.ReadFile(input)
	if e != nil {
		return outcome, e
	}
	var verified []identity.Record
	if e = json.Unmarshal(actualSource, &verified); e != nil || !reflect.DeepEqual(verified, records) {
		return outcome, fmt.Errorf("prepared ledger readback failed: %w", e)
	}
	runID := filepath.Base(filepath.Dir(dir)) + "-" + mode
	group := "calibration-" + runID
	ownership, e := jsonBytes(map[string]any{
		"schema_version": 1, "run_id": runID, "owner": "kaferry-lab", "namespace": "calibration", "mode": mode,
		"resources":         map[string]string{"input": input, "output": output, "checkpoint": state, "executable": exe},
		"executable_sha256": exeSHA, "process_records": "processes.jsonl",
		"scope": "only direct stand-in children started by this controller and these synthetic files",
	})
	if e != nil {
		return outcome, e
	}
	if e = syncFile(filepath.Join(work, "ownership.json"), ownership); e != nil {
		return outcome, e
	}
	processes, e := os.OpenFile(filepath.Join(work, "processes.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return outcome, e
	}
	defer processes.Close()
	recordProcess := func(process *os.Process, role string) error {
		if e := json.NewEncoder(processes).Encode(map[string]any{
			"run_id": runID, "owner": "kaferry-lab", "kind": "child_started", "role": role, "pid": process.Pid,
			"identity": "direct child returned by exec.Cmd.Start; controller retains its os.Process handle",
		}); e != nil {
			return e
		}
		return processes.Sync()
	}
	src := identity.SourcePosition{Cluster: "standin-source", Topic: "calibration-input", TopicID: "11111111111111111111111111111111", Partition: 0, Offset: 0}
	dst := identity.SourcePosition{Cluster: "standin-destination", Topic: "calibration-output", TopicID: "22222222222222222222222222222222", Partition: 0, Offset: 0}
	ledger := evidence.Ledger{Partitions: []evidence.PartitionRange{{Source: src, End: 3, Gaps: []evidence.Gap{}}}, Destinations: []identity.SourcePosition{dst}, Entries: []evidence.LedgerEntry{}}
	for i, r := range records {
		p := src
		p.Offset = identity.Int64(i)
		ledger.Entries = append(ledger.Entries, evidence.LedgerEntry{ID: fmt.Sprintf("record-%d", i), Source: p, Record: r, Disposition: "required", Reason: "finite prepared standin input", DestinationTopic: dst.Topic, AllowedPartitions: []int32{0}})
	}
	start := time.Now()
	events := []evidence.Event{}
	emit := func(event evidence.Event) {
		event.Seq = identity.Int64(len(events) + 1)
		event.RunID = runID
		event.ElapsedMS = identity.Int64(time.Since(start).Milliseconds())
		events = append(events, event)
	}
	emit(evidence.Event{Kind: "ledger", Ledger: &ledger})
	emit(evidence.Event{Kind: "inputs_verified", InputsVerified: &evidence.InputVerification{Method: "standin_fsynced_ledger", Complete: true, Proof: "fsynced finite input readback matched independently prepared records; sha256=" + digest(actualSource)}})
	stderr, e := os.OpenFile(filepath.Join(work, "child-stderr.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return outcome, e
	}
	defer stderr.Close()
	child := exec.CommandContext(ctx, exe, "_standin", input, output, state, mode)
	child.Stderr = stderr
	stdin, e := child.StdinPipe()
	if e != nil {
		return outcome, e
	}
	defer stdin.Close()
	stdout, e := child.StdoutPipe()
	if e != nil {
		return outcome, e
	}
	if e = child.Start(); e != nil {
		return outcome, e
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	if e = recordProcess(child.Process, "initial"); e != nil {
		return outcome, e
	}
	type barrierResult struct {
		value Barrier
		err   error
	}
	barrier := make(chan barrierResult, 1)
	go func() {
		var b Barrier
		e := json.NewDecoder(io.LimitReader(stdout, 4096)).Decode(&b)
		barrier <- barrierResult{b, e}
	}()
	select {
	case <-ctx.Done():
		return outcome, ctx.Err()
	case b := <-barrier:
		if b.err != nil || b.value.Saved != 1 || b.value.Mode != mode {
			return outcome, fmt.Errorf("standin barrier not reached: %+v", b)
		}
	}
	before, e := readOutput(output)
	if e != nil {
		return outcome, e
	}
	saved, e := readCheckpoint(state)
	if e != nil || saved != 1 {
		return outcome, fmt.Errorf("saved boundary not independently observed: %d/%v", saved, e)
	}
	audit := func(id, kind, proof string, outputs []identity.Record, next identity.Int64, final bool) {
		for i, r := range outputs {
			p := dst
			p.Offset = identity.Int64(i)
			emit(evidence.Event{Kind: "output", Output: &evidence.Output{AuditID: id, Destination: p, Record: r}})
		}
		scan := evidence.Scan{PartitionRange: evidence.PartitionRange{Source: dst, End: identity.Int64(len(outputs)), Gaps: []evidence.Gap{}}, Reached: identity.Int64(len(outputs)), StableEnd: identity.Int64(len(outputs)), Complete: true, Proof: "decoded every fsynced output JSONL record to explicit file EOF; " + proof}
		p := src
		p.Offset = next
		emit(evidence.Event{Kind: "audit", Audit: &evidence.Audit{ID: id, Kind: kind, Scans: []evidence.Scan{scan}, Saved: []evidence.SavedPosition{{Source: p, Group: group, Proof: "independent checkpoint file JSON readback"}}, PendingOutputResolved: true, QuiescenceMethod: func() string {
			if final {
				return "workers_stopped"
			}
			return "standin_barrier"
		}(), QuiescenceProof: proof, Final: final}})
	}
	audit("kill-window", "quiescent", "child emitted durable barrier and cannot proceed without parent stdin byte", before, saved, false)
	emit(evidence.Event{Kind: "trigger", Trigger: &evidence.Trigger{FaultID: "kill", AuditID: "kill-window", Predicate: "required_output_outstanding", Observer: "parent filesystem reader", Proof: "known finite source obligations exceed complete observed output at durable blocked child barrier"}})
	observation := evidence.FaultObservation{ID: "kill", PID: child.Process.Pid, Signal: "SIGKILL", Observer: "parent os.Process handle", Proof: "requested Kill on this started lab-owned standin only"}
	emit(evidence.Event{Kind: "fault_requested", Fault: &observation})
	if e = ctx.Err(); e != nil {
		return outcome, e
	}
	if e = child.Process.Kill(); e != nil {
		return outcome, e
	}
	waitErr := child.Wait()
	status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
	if waitErr == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		return outcome, fmt.Errorf("kill not confirmed: %v/%v", waitErr, child.ProcessState)
	}
	reached := observation
	exit := child.ProcessState.ExitCode()
	reached.ExitCode = &exit
	reached.Proof = child.ProcessState.String() + "; waited/reaped by parent"
	emit(evidence.Event{Kind: "fault_reached", Fault: &reached})
	recovery := exec.CommandContext(ctx, exe, "_standin", input, output, state, "healthy")
	recovery.Stderr = stderr
	if e = recovery.Start(); e != nil {
		return outcome, e
	}
	defer func() {
		if recovery.ProcessState == nil {
			_ = recovery.Process.Kill()
			_ = recovery.Wait()
		}
	}()
	if e = recordProcess(recovery.Process, "recovery"); e != nil {
		return outcome, e
	}
	newPID := recovery.Process.Pid
	if e = recovery.Wait(); e != nil {
		return outcome, fmt.Errorf("standin recovery: %w", e)
	}
	recovered := observation
	recovered.RecoveryPID = newPID
	recovered.Proof = "same progress/input/output paths; distinct child waited/reaped with exit 0"
	emit(evidence.Event{Kind: "fault_recovered", Fault: &recovered})
	finalOutput, e := readOutput(output)
	if e != nil {
		return outcome, e
	}
	saved, e = readCheckpoint(state)
	if e != nil {
		return outcome, e
	}
	audit("final", "quiescent", "both workers stopped and reaped; recovery exit 0; no output writer exists", finalOutput, saved, true)
	emit(evidence.Event{Kind: "run_finished", Finished: &evidence.RunFinished{TimedOut: ctx.Err() != nil, CleanupComplete: true, Proof: "first process signaled and reaped; replacement exited 0 and reaped; no children remain"}})
	subject := evidence.Subject{Kind: "standin", ExecutableSHA256: exeSHA, ContractSHA256: evidence.ContractSHA256, Platform: runtime.GOOS + "/" + runtime.GOARCH, VersionOutput: "lab calibration standin v1"}
	meta := evidence.ArtifactMetadata{SchemaVersion: 1, Subject: subject, CalibrationLabel: "CALIBRATION ONLY: " + mode, VerificationDetail: "sha256 of actual parent/standin executable; no Kaferry artifact or qualification"}
	manifest := evidence.Manifest{SchemaVersion: 1, CheckerVersion: evidence.CheckerVersion, Namespace: "calibration", RunID: runID, ScenarioID: "standin-" + mode, Scope: "standin", Group: group, Given: "finite independently verified input and durable standin files", When: "kill reached blocked save/output boundary then same-state restart", Then: "healthy retains every input; deliberately commit-before-produce specimen violates membership/prefix", BudgetMS: 20000, Subject: subject, LabSource: labSource(exeSHA), Environment: evidence.Environment{OrchestratorPlatform: runtime.GOOS + "/" + runtime.GOARCH, ExecutionPlatform: runtime.GOOS + "/" + runtime.GOARCH, Runtime: "actual Go standin child subprocesses; no Kaferry executable", Storage: "local filesystem; fsynced files; filesystem type unmeasured; process SIGKILL preserves kernel cache", Topology: "synthetic input/output/checkpoint files only; no Kafka, network, Docker or remote services", Limits: "20s overall calibration; three records; max16 observed output records; at most one child alive at a time; two per history"}, RequiredFaults: []evidence.FaultSpec{{ID: "kill", Kind: "process_kill", TriggerPredicate: "required_output_outstanding"}}, FinalAuditID: "final"}
	if e = finalize(outcome.Bundle, manifest, meta, events); e != nil {
		return outcome, e
	}
	outcome.Result = evidence.LoadAndCheck(outcome.Bundle)
	return outcome, nil
}

func finalize(dir string, m evidence.Manifest, a evidence.ArtifactMetadata, events []evidence.Event) error {
	var stream bytes.Buffer
	enc := json.NewEncoder(&stream)
	for _, event := range events {
		if e := enc.Encode(event); e != nil {
			return e
		}
	}
	rawArtifact, e := jsonBytes(a)
	if e != nil {
		return e
	}
	m.Artifact = evidence.FileHash{Path: evidence.ArtifactName, SHA256: digest(rawArtifact), Bytes: identity.Int64(len(rawArtifact))}
	m.Events = evidence.FileHash{Path: evidence.EventsName, SHA256: digest(stream.Bytes()), Bytes: identity.Int64(stream.Len())}
	m.EventCount = identity.Int64(len(events))
	manifest, e := jsonBytes(m)
	if e != nil {
		return e
	}
	complete, e := jsonBytes(evidence.Completion{SchemaVersion: 1, RunID: m.RunID, ManifestSHA256: digest(manifest), EventsSHA256: m.Events.SHA256, EventCount: m.EventCount})
	if e != nil {
		return e
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{evidence.ArtifactName, rawArtifact}, {evidence.EventsName, stream.Bytes()}, {evidence.ManifestName, manifest}, {evidence.CompleteName, complete}} {
		if e = syncFile(filepath.Join(dir, file.name), file.raw); e != nil {
			return e
		}
	}
	return nil
}

func labSource(exeSHA string) evidence.LabSource {
	s := evidence.LabSource{Commit: "unavailable", Dirty: true, Proof: "embedded VCS metadata unavailable; actual executable sha256=" + exeSHA}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return s
	}
	revision, modified := "", ""
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if len(revision) == 40 && (modified == "true" || modified == "false") {
		s.Commit = revision
		s.Dirty = modified == "true"
		s.Proof = "Go embedded VCS metadata; actual executable sha256=" + exeSHA
	}
	return s
}
