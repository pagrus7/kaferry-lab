package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
)

const maxEventsBytes = 64 << 20
const maxEventBytes = 4 << 20
const maxEvents = 200000

// LoadAndCheck checks a versioned bundle with four fixed flat files. Hashes
// establish recorded byte consistency, not that an untrusted author observed
// reality. The directory
// must remain stable during this read. No referenced executable is opened.
func LoadAndCheck(dir string) Result {
	r := Result{Verdict: HarnessError, Findings: []Finding{}, Limitations: []string{
		"Checks recorded evidence consistency; hashes do not authenticate an untrusted author's observations.",
		"One partial scenario history cannot qualify a release or establish all historical acknowledgment/save orderings.",
	}}
	fail := func(code, message string) Result {
		r.Findings = append(r.Findings, Finding{Code: code, Message: message})
		return r
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("bundle_directory", "bundle must be an existing real directory")
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return fail("bundle_directory", err.Error())
	}
	want := map[string]bool{ManifestName: true, EventsName: true, ArtifactName: true, CompleteName: true}
	if len(names) != len(want) {
		return fail("bundle_files", "v1 requires exactly manifest.json, events.jsonl, artifact.json and complete.json")
	}
	for _, name := range names {
		if !want[name.Name()] || name.Type()&os.ModeSymlink != 0 || name.IsDir() {
			return fail("bundle_files", "unexpected file, directory or symlink in flat v1 bundle")
		}
	}
	manifestRaw, err := readRegular(dir, ManifestName, 1<<20)
	if err != nil {
		return fail("manifest_read", err.Error())
	}
	var version struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := validateJSON(manifestRaw); err != nil {
		return fail("manifest_json", err.Error())
	}
	if err := json.Unmarshal(manifestRaw, &version); err != nil {
		return fail("manifest_json", err.Error())
	}
	if version.SchemaVersion == PhaseSchemaVersion {
		return loadPhaseBundle(dir, manifestRaw)
	}
	if version.SchemaVersion == M2SchemaVersion {
		return loadM2(dir, manifestRaw)
	}
	if version.SchemaVersion != SchemaVersion {
		r.Verdict = Unsupported
		return fail("manifest_version", "unsupported manifest schema version")
	}
	var m Manifest
	if err := strictJSON(manifestRaw, &m); err != nil {
		return fail("manifest_json", err.Error())
	}
	r.RunID, r.ScenarioID, r.Namespace = m.RunID, m.ScenarioID, m.Namespace
	if m.CheckerVersion != CheckerVersion {
		r.Verdict = Unsupported
		return fail("checker_version", "unsupported checker contract version")
	}
	if m.Events.Path != EventsName || m.Artifact.Path != ArtifactName {
		return fail("manifest_path", "manifest paths must use the exact fixed v1 filenames")
	}
	if !digestValid(m.Events.SHA256) || !digestValid(m.Artifact.SHA256) || m.Events.Bytes <= 0 || m.Artifact.Bytes <= 0 || m.EventCount <= 0 || m.EventCount > maxEvents {
		return fail("manifest_integrity", "invalid stream or artifact digest, size or event count")
	}
	if strings.TrimSpace(m.RunID) == "" || strings.TrimSpace(m.ScenarioID) == "" || strings.TrimSpace(m.Group) == "" || m.FinalAuditID == "" || strings.TrimSpace(m.Given) == "" || strings.TrimSpace(m.When) == "" || strings.TrimSpace(m.Then) == "" || m.BudgetMS <= 0 {
		return fail("manifest_required", "missing run/scenario/group, Given/When/Then, final audit, or time budget")
	}
	if err := validateExecutionMetadata(m); err != nil {
		return fail("execution_metadata", err.Error())
	}
	completeRaw, err := readRegular(dir, CompleteName, 1<<20)
	if err != nil {
		return fail("completion_read", err.Error())
	}
	var complete Completion
	if err := strictJSON(completeRaw, &complete); err != nil {
		return fail("completion_json", err.Error())
	}
	if complete.SchemaVersion != SchemaVersion {
		r.Verdict = Unsupported
		return fail("completion_version", "unsupported completion schema version")
	}
	if complete.RunID != m.RunID || complete.ManifestSHA256 != digest(manifestRaw) || complete.EventsSHA256 != m.Events.SHA256 || complete.EventCount != m.EventCount {
		return fail("completion_integrity", "completion marker does not bind this manifest, stream, count and run")
	}
	artifactRaw, err := readRegular(dir, ArtifactName, 4<<20)
	if err != nil {
		return fail("artifact_read", err.Error())
	}
	if !matchesFile(artifactRaw, m.Artifact) {
		return fail("artifact_hash", "artifact metadata hash or length differs from manifest")
	}
	var artifact ArtifactMetadata
	if err := strictJSON(artifactRaw, &artifact); err != nil {
		return fail("artifact_json", err.Error())
	}
	if verdict, code, err := validateArtifact(m, artifact); err != nil {
		r.Verdict = verdict
		return fail(code, err.Error())
	}
	eventsRaw, err := readRegular(dir, EventsName, maxEventsBytes)
	if err != nil {
		return fail("events_read", err.Error())
	}
	if !matchesFile(eventsRaw, m.Events) {
		return fail("events_hash", "event stream hash or length differs from manifest")
	}
	if len(eventsRaw) == 0 || eventsRaw[len(eventsRaw)-1] != '\n' {
		return fail("events_truncated", "JSONL must end with a complete newline-terminated record")
	}
	lines := bytes.Split(eventsRaw[:len(eventsRaw)-1], []byte{'\n'})
	if int64(len(lines)) != int64(m.EventCount) {
		return fail("events_count", "event stream count differs from finalized manifest")
	}
	events := make([]Event, 0, len(lines))
	var elapsed int64
	for i, line := range lines {
		if len(line) == 0 || len(line) > maxEventBytes {
			return fail("event_size", fmt.Sprintf("event %d is empty or exceeds the v1 line limit", i+1))
		}
		var event Event
		if err := strictJSON(line, &event); err != nil {
			return fail("event_json", fmt.Sprintf("event %d: %v", i+1, err))
		}
		if int64(event.Seq) != int64(i+1) || event.RunID != m.RunID || event.ElapsedMS < 0 || int64(event.ElapsedMS) < int64(elapsed) {
			return fail("event_identity", fmt.Sprintf("event %d has conflicting sequence/run/time identity", i+1))
		}
		elapsed = int64(event.ElapsedMS)
		if !validPayload(event) {
			return fail("event_payload", fmt.Sprintf("event %d has an unknown kind or conflicting/missing payload", i+1))
		}
		events = append(events, event)
	}
	return checkHistory(m, events, r)
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func digestValid(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s && s != strings.Repeat("0", 64)
}
func matchesFile(raw []byte, ref FileHash) bool {
	return int64(len(raw)) == int64(ref.Bytes) && digest(raw) == ref.SHA256
}

func readRegular(dir, name string, limit int64) ([]byte, error) {
	// name is a code-owned constant, never a manifest-controlled path.
	path := filepath.Join(dir, name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, fmt.Errorf("%s must be a bounded regular file, not a link or device", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while opening", name)
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit || int64(len(raw)) != opened.Size() {
		return nil, fmt.Errorf("%s exceeds limit or changed while reading", name)
	}
	return raw, nil
}

func strictJSON(raw []byte, target any) error {
	if err := validateJSON(raw); err != nil {
		return err
	}
	if err := requiredFields(raw, reflect.TypeOf(target), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

// Required scalar evidence must not silently default to zero/false when a
// field disappears. This walks only the fixed exported schema structs; it is not
// an extensible event or scenario system.
func requiredFields(raw json.RawMessage, typ reflect.Type, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds evidence limit")
	}
	nullable := typ.Kind() == reflect.Pointer
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if nullable {
			return nil
		}
		return fmt.Errorf("non-null evidence field is null")
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fmt.Errorf("expected evidence JSON object")
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			parts := strings.Split(field.Tag.Get("json"), ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if field.Anonymous && name == "" {
				if err := requiredFields(raw, field.Type, depth+1); err != nil {
					return err
				}
				continue
			}
			if name == "" {
				name = field.Name
			}
			optional := false
			for _, part := range parts[1:] {
				if part == "omitempty" {
					optional = true
				}
			}
			value, exists := object[name]
			if !exists {
				if optional {
					continue
				}
				return fmt.Errorf("required evidence JSON field %s is missing", name)
			}
			if err := requiredFields(value, field.Type, depth+1); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := requiredFields(value, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reject duplicate and case-folded keys before Go's struct decoder can
// resolve conflicts. Evidence field names are lowercase.
func validateJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("evidence JSON must be valid UTF-8; binary bytes belong in base64 fields")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := jsonValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds evidence limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || s != strings.ToLower(s) || seen[s] {
				return fmt.Errorf("duplicate or noncanonical JSON field")
			}
			seen[s] = true
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func validPayload(e Event) bool {
	n := 0
	for _, present := range []bool{e.Ledger != nil, e.InputsVerified != nil, e.Output != nil, e.Audit != nil, e.Trigger != nil, e.Fault != nil, e.Finished != nil} {
		if present {
			n++
		}
	}
	if n != 1 {
		return false
	}
	switch e.Kind {
	case "ledger":
		return e.Ledger != nil
	case "inputs_verified":
		return e.InputsVerified != nil
	case "output":
		return e.Output != nil
	case "audit":
		return e.Audit != nil
	case "trigger":
		return e.Trigger != nil
	case "fault_requested", "fault_reached", "fault_recovered":
		return e.Fault != nil
	case "run_finished":
		return e.Finished != nil
	}
	return false
}

func validateArtifact(m Manifest, a ArtifactMetadata) (Verdict, string, error) {
	bad := func(code, msg string) (Verdict, string, error) { return HarnessError, code, fmt.Errorf("%s", msg) }
	if a.SchemaVersion != SchemaVersion {
		return Unsupported, "artifact_version", fmt.Errorf("unsupported artifact metadata schema")
	}
	if a.Subject != m.Subject {
		return bad("subject_mismatch", "manifest and artifact attachment identify different subjects")
	}
	s := m.Subject
	if s.ContractSHA256 != ContractSHA256 {
		return Unsupported, "contract_identity", fmt.Errorf("unknown reviewed contract root")
	}
	if !digestValid(s.ExecutableSHA256) || s.Platform == "" || strings.TrimSpace(s.VersionOutput) == "" {
		return bad("subject_required", "subject executable digest, platform or version output missing")
	}
	if strings.TrimSpace(a.VerificationDetail) == "" {
		return bad("artifact_verification", "artifact verification detail is missing")
	}
	switch m.Namespace {
	case "release":
		if s.Kind != "published-release" || s.Tag != ReleaseTag || s.Commit != ReleaseCommit {
			return bad("release_identity", "release namespace requires exact pinned published tag and commit")
		}
		platform, ok := artifact.ReviewedPlatform(s.Platform)
		if !ok {
			return Unsupported, "release_platform", fmt.Errorf("release evidence requires an exact reviewed Linux platform")
		}
		if s.ExecutableSHA256 != platform.BinarySHA256 {
			return bad("release_binary_identity", "release metadata must identify the exact executable digest measured from the selected platform's pinned archive")
		}
		if !strings.Contains(s.VersionOutput, ReleaseTag) {
			return bad("release_version", "version output does not identify the pinned release")
		}
		if a.CalibrationLabel != "" {
			return bad("namespace_conflict", "release metadata contains a calibration label")
		}
		if len(a.ContractDocuments) != 3 {
			return bad("contract_documents", "release evidence must retain all three sorted tagged contract document hashes")
		}
		paths := []string{"design/archive.md", "design/client-compatibility.md", "design/decisions.md"}
		var contract strings.Builder
		for i, doc := range a.ContractDocuments {
			if doc.Path != paths[i] || !digestValid(doc.SHA256) {
				return bad("contract_documents", "invalid tagged contract document identities")
			}
			fmt.Fprintf(&contract, "%s  %s\n", doc.SHA256, doc.Path)
		}
		if digest([]byte(contract.String())) != ContractSHA256 {
			return bad("contract_documents", "tagged document hashes do not produce the pinned contract root")
		}
		if a.ArchiveName != platform.ArchiveName || a.ArchiveSHA256 != platform.ArchiveSHA256 {
			return bad("archive_identity", "release evidence must identify the exact pinned published archive for its platform")
		}
		if a.PublishedAssetURL != "https://github.com/pagrus7/kaferry/releases/download/"+ReleaseTag+"/"+a.ArchiveName {
			return bad("artifact_url", "asset URL does not bind pinned release and archive name")
		}
		found := 0
		for _, line := range strings.Split(a.ChecksumsText, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == a.ArchiveName {
				found++
				if fields[0] != a.ArchiveSHA256 {
					return bad("artifact_checksum", "recorded archive hash differs from published checksum text")
				}
			}
		}
		if found != 1 {
			return bad("artifact_checksum", "exactly one checksum entry for the selected archive is required")
		}
		if a.ProvenanceStatus == "unavailable" {
			return Unsupported, "artifact_provenance", fmt.Errorf("v0.6.0 provenance is available and mandatory; unverified provenance cannot pass release checking")
		}
		if a.ProvenanceStatus != "verified" {
			return bad("artifact_provenance", "available pinned release provenance must be recorded verified")
		}

	case "calibration":
		if s.Kind != "synthetic-history" && s.Kind != "standin" {
			return bad("calibration_identity", "calibration requires a visibly separate synthetic-history or standin subject")
		}
		if a.CalibrationLabel == "" || s.Tag != "" || s.Commit != "" {
			return bad("calibration_identity", "calibration must be labeled and cannot impersonate a release tag/commit")
		}
	default:
		return bad("namespace", "unknown evidence namespace")
	}
	if m.Scope == "archive" {
		return Unsupported, "archive_scope", fmt.Errorf("full physical archive/checkpoint checking is reserved for M4")
	}
	if m.Scope != "kafka" && m.Scope != "standin" {
		return Unsupported, "scope", fmt.Errorf("unsupported scenario scope")
	}
	if m.Scope == "standin" && (m.Namespace != "calibration" || s.Kind != "standin") {
		return bad("standin_namespace", "standin scenarios require calibration standin identity")
	}
	return Pass, "", nil
}

func validateExecutionMetadata(m Manifest) error {
	source := m.LabSource
	if strings.TrimSpace(source.Proof) == "" {
		return fmt.Errorf("lab source identity lacks independent build/source proof")
	}
	commit, err := hex.DecodeString(source.Commit)
	known := err == nil && len(commit) == 20 && hex.EncodeToString(commit) == source.Commit && source.Commit != strings.Repeat("0", 40)
	if !known && !(m.Namespace == "calibration" && source.Commit == "unavailable" && source.Dirty) {
		return fmt.Errorf("lab source commit must be known canonical 40hex, or explicitly unavailable/dirty in calibration")
	}
	env := m.Environment
	for _, field := range []string{env.OrchestratorPlatform, env.ExecutionPlatform, env.Runtime, env.Storage, env.Topology, env.Limits} {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("record orchestrator/execution platforms, runtime, storage, topology and limits explicitly")
		}
	}
	if m.Namespace == "release" && env.ExecutionPlatform != m.Subject.Platform {
		return fmt.Errorf("recorded execution platform differs from the pinned release platform")
	}
	return nil
}
