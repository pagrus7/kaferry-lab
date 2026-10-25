package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

func m2Result(m M2Manifest) Result {
	return Result{Verdict: HarnessError, RunID: m.RunID, ScenarioID: m.ScenarioID, Namespace: m.Namespace,
		Findings: []Finding{}, Limitations: []string{
			"Checks bounded recorded observations; hashes do not authenticate an untrusted author's observations.",
			"One M2 scenario cannot qualify a release or establish every historical acknowledgment/save ordering.",
			"SIGKILL is process failure; broker restart assumes the recorded retained input and durable broker storage.",
		}}
}

func loadM2(dir string, manifestRaw []byte) Result {
	var m M2Manifest
	r := m2Result(m)
	fail := func(code string, err error) Result {
		r.Findings = append(r.Findings, Finding{Code: code, Message: err.Error()})
		return r
	}
	if err := strictJSON(manifestRaw, &m); err != nil {
		return fail("manifest_json", err)
	}
	r = m2Result(m)
	if m.Events.Path != EventsName || m.Artifact.Path != ArtifactName {
		return fail("manifest_path", fmt.Errorf("v2 uses the exact fixed bundle filenames"))
	}
	if !digestValid(m.Events.SHA256) || !digestValid(m.Artifact.SHA256) || m.Events.Bytes <= 0 || m.Events.Bytes > maxEventsBytes || m.Artifact.Bytes <= 0 || m.Artifact.Bytes > 4<<20 || m.EventCount <= 0 || m.EventCount > maxEvents {
		return fail("manifest_integrity", fmt.Errorf("invalid bounded v2 attachment digest, length or event count"))
	}
	completionRaw, err := readRegular(dir, CompleteName, 1<<20)
	if err != nil {
		return fail("completion_read", err)
	}
	var completion M2Completion
	if err := strictJSON(completionRaw, &completion); err != nil {
		return fail("completion_json", err)
	}
	if completion.SchemaVersion != M2SchemaVersion {
		r.Verdict = Unsupported
		return fail("completion_version", fmt.Errorf("unsupported completion schema"))
	}
	if completion.RunID != m.RunID || completion.ManifestSHA256 != digest(manifestRaw) || completion.EventsSHA256 != m.Events.SHA256 || completion.EventCount != m.EventCount {
		return fail("completion_integrity", fmt.Errorf("completion marker does not bind this manifest, stream, count and run"))
	}
	artifactRaw, err := readRegular(dir, ArtifactName, 4<<20)
	if err != nil {
		return fail("artifact_read", err)
	}
	if !matchesFile(artifactRaw, m.Artifact) {
		return fail("artifact_hash", fmt.Errorf("artifact metadata hash or length differs from manifest"))
	}
	var artifact ArtifactMetadata
	if err := strictJSON(artifactRaw, &artifact); err != nil {
		return fail("artifact_json", err)
	}
	eventsRaw, err := readRegular(dir, EventsName, maxEventsBytes)
	if err != nil {
		return fail("events_read", err)
	}
	if !matchesFile(eventsRaw, m.Events) {
		return fail("events_hash", fmt.Errorf("event stream hash or length differs from manifest"))
	}
	if len(eventsRaw) == 0 || eventsRaw[len(eventsRaw)-1] != '\n' {
		return fail("events_truncated", fmt.Errorf("v2 JSONL must end with a complete newline-terminated record"))
	}
	lines := bytes.Split(eventsRaw[:len(eventsRaw)-1], []byte{'\n'})
	if int64(len(lines)) != int64(m.EventCount) {
		return fail("events_count", fmt.Errorf("event stream count differs from finalized manifest"))
	}
	events := make([]M2Event, 0, len(lines))
	for i, line := range lines {
		if len(line) == 0 || len(line) > maxEventBytes {
			return fail("event_size", fmt.Errorf("v2 event %d is empty or exceeds the line limit", i+1))
		}
		var e M2Event
		if err := strictJSON(line, &e); err != nil {
			return fail("event_json", fmt.Errorf("v2 event %d: %w", i+1, err))
		}
		events = append(events, e)
	}
	return CheckM2(m, artifact, events)
}

// WriteM2Bundle reserves a new flat directory and never replaces existing
// evidence. A failed write leaves the incomplete directory for inspection.
// Completion binds a closed stream, not a passing property verdict.
func WriteM2Bundle(dir string, m M2Manifest, artifact ArtifactMetadata, events []M2Event) error {
	if m.SchemaVersion != M2SchemaVersion || m.CheckerVersion != M2CheckerVersion || len(events) == 0 || len(events) > maxEvents || events[len(events)-1].Kind != "run_finished" {
		return fmt.Errorf("v2 writer requires a supported manifest and a bounded closed event stream")
	}
	artifactRaw, err := json.Marshal(artifact)
	if err != nil || len(artifactRaw) > (4<<20)-1 {
		return fmt.Errorf("artifact metadata cannot be encoded within its bound: %v", err)
	}
	artifactRaw = append(artifactRaw, '\n')
	var stream bytes.Buffer
	for i, e := range events {
		raw, err := json.Marshal(e)
		if err != nil || len(raw) > maxEventBytes {
			return fmt.Errorf("event %d cannot be encoded within its bound: %v", i+1, err)
		}
		if stream.Len()+len(raw)+1 > maxEventsBytes {
			return fmt.Errorf("v2 stream exceeds its byte bound")
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	m.Artifact = FileHash{Path: ArtifactName, SHA256: digest(artifactRaw), Bytes: identity.Int64(len(artifactRaw))}
	m.Events = FileHash{Path: EventsName, SHA256: digest(stream.Bytes()), Bytes: identity.Int64(stream.Len())}
	m.EventCount = identity.Int64(len(events))
	manifestRaw, err := json.Marshal(m)
	if err != nil || len(manifestRaw) > (1<<20)-1 {
		return fmt.Errorf("v2 manifest cannot be encoded within its bound: %v", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	// Apply the same required-field/duplicate-key discipline before reserving
	// the destination. Semantic INCONCLUSIVE/UNSUPPORTED results are retained.
	var decoded M2Manifest
	if err := strictJSON(manifestRaw, &decoded); err != nil {
		return err
	}
	for _, line := range bytes.Split(stream.Bytes()[:stream.Len()-1], []byte{'\n'}) {
		var decoded M2Event
		if err := strictJSON(line, &decoded); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("reserve evidence bundle: %w", err)
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{
		{ArtifactName, artifactRaw}, {EventsName, stream.Bytes()}, {ManifestName, manifestRaw},
	} {
		if err := writeM2File(dir, item.name, item.raw); err != nil {
			return err
		}
	}
	c := M2Completion{SchemaVersion: M2SchemaVersion, RunID: m.RunID, ManifestSHA256: digest(manifestRaw), EventsSHA256: m.Events.SHA256, EventCount: m.EventCount}
	completeRaw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeM2File(dir, CompleteName, append(completeRaw, '\n')); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func writeM2File(dir, name string, raw []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
