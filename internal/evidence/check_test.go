package evidence_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

func TestLiteralControlHistories(t *testing.T) {
	cases := []struct {
		name    string
		verdict evidence.Verdict
		code    string
	}{
		{"valid", evidence.Pass, ""},
		{"permitted-duplicate", evidence.Pass, ""},
		{"permitted-record", evidence.Pass, ""},
		{"corrupt-byte", evidence.Violation, "corrupt_or_unexpected_output"},
		{"required-loss", evidence.Violation, "required_record_missing"},
		{"unsafe-prefix", evidence.Violation, "unsafe_saved_prefix"},
		{"aborted-leak", evidence.Violation, "forbidden_output"},
		{"wrong-partition", evidence.Violation, "wrong_partition"},
		{"missing-trigger", evidence.Inconclusive, "trigger_missing"},
		{"truncated-stream", evidence.HarnessError, "events_truncated"},
		{"incomplete-scan", evidence.Inconclusive, "scan_incomplete"},
		{"indistinguishable-pass", evidence.Pass, ""},
		{"indistinguishable-loss", evidence.Violation, "required_record_missing"},
		{"archive-unsupported", evidence.Unsupported, "archive_scope"},
		{"unknown-contract", evidence.Unsupported, "contract_identity"},
		{"changed-run", evidence.HarnessError, "event_identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join("testdata", tc.name)
			got := evidence.LoadAndCheck(dir)
			if got.Verdict != tc.verdict {
				t.Fatalf("got %s; want %s: %+v", got.Verdict, tc.verdict, got.Findings)
			}
			if tc.code != "" && !hasCode(got, tc.code) {
				t.Fatalf("missing sensitivity finding %s: %+v", tc.code, got.Findings)
			}
			if got.ReleaseQualified {
				t.Fatal("a partial calibration history qualified a release")
			}
			if !reflect.DeepEqual(got, evidence.LoadAndCheck(dir)) {
				t.Fatal("identical offline recheck changed its result")
			}
			if strings.HasPrefix(tc.name, "indistinguishable") && !contains(got.Limitations, "replay can mask loss") {
				t.Fatal("indistinguishable replay limitation was hidden")
			}
		})
	}
}

func TestFramingAndIdentityTamperingNeverPass(t *testing.T) {
	cases := []struct {
		name, code string
		mutate     func(*testing.T, string)
	}{
		{"hash", "events_hash", func(t *testing.T, dir string) {
			p := filepath.Join(dir, evidence.EventsName)
			raw := read(t, p)
			raw = bytes.Replace(raw, []byte("golden-run"), []byte("golden-rux"), 1)
			write(t, p, raw)
		}},
		{"run-in-manifest", "completion_integrity", func(t *testing.T, dir string) {
			var m map[string]any
			decode(t, read(t, filepath.Join(dir, evidence.ManifestName)), &m)
			m["run_id"] = "other-run"
			writeJSON(t, filepath.Join(dir, evidence.ManifestName), m)
		}},
		{"manifest-path", "manifest_path", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				m["events"].(map[string]any)["path"] = "../events.jsonl"
			})
		}},
		{"manifest-version", "manifest_version", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { m["schema_version"] = 2 })
		}},
		{"checker-version", "checker_version", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { m["checker_version"] = "unreviewed" })
		}},
		{"artifact-identity", "subject_mismatch", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				a["subject"].(map[string]any)["executable_sha256"] = strings.Repeat("9", 64)
			})
		}},
		{"calibration-as-release", "execution_metadata", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { m["namespace"] = "release" })
		}},
		{"duplicate-sequence", "event_identity", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { events[4]["seq"] = "4" })
		}},
		{"changed-event-run", "event_identity", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { events[4]["run_id"] = "other-run" })
		}},
		{"missing-required-faults", "required_faults", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { m["required_faults"] = []any{} })
		}},
		{"missing-output-proof", "pending_output", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				events[9]["audit"].(map[string]any)["pending_output_resolved"] = false
			})
		}},
		{"wrong-saved-group", "audit_invalid", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				saved := events[9]["audit"].(map[string]any)["saved"].([]any)
				saved[0].(map[string]any)["group"] = "wrong-group"
			})
		}},
		{"conflicting-physical-output", "audit_invalid", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				events[8]["output"].(map[string]any)["destination"].(map[string]any)["offset"] = "0"
			})
		}},
		{"missing-scan-partition", "audit_invalid", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				audit := events[9]["audit"].(map[string]any)
				audit["scans"] = audit["scans"].([]any)[:1]
			})
		}},
		{"unknown-event-field", "event_json", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { events[0]["untrusted"] = true })
		}},
		{"wrong-event-payload", "event_payload", func(t *testing.T, dir string) {
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) { events[4]["trigger"] = events[3]["trigger"] })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			tc.mutate(t, dir)
			got := evidence.LoadAndCheck(dir)
			if got.Verdict == evidence.Pass || !hasCode(got, tc.code) {
				t.Fatalf("tampering got %+v; expected non-PASS with %s", got, tc.code)
			}
		})
	}
}

func TestMissingRequiredEventsCannotBeFinalizedAsPass(t *testing.T) {
	for _, kind := range []string{"inputs_verified", "trigger", "fault_requested", "fault_reached", "fault_recovered", "audit", "run_finished"} {
		t.Run(kind, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			removeEvent(t, dir, kind)
			result := evidence.LoadAndCheck(dir)
			if result.Verdict == evidence.Pass {
				t.Fatalf("missing %s passed", kind)
			}
			if kind == "run_finished" && !hasCode(result, "finish_missing") {
				t.Fatalf("missing final record was not identified: %+v", result)
			}
		})
	}
}

func TestBinaryAndHeaderFidelityControls(t *testing.T) {
	for _, kind := range []string{"null-to-empty", "header-order", "binary-header-name", "timestamp-rounding"} {
		t.Run(kind, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				record := events[7]["output"].(map[string]any)["record"].(map[string]any)
				switch kind {
				case "null-to-empty":
					record["key"].(map[string]any)["null"] = false
				case "header-order":
					headers := record["headers"].([]any)
					headers[0], headers[1] = headers[1], headers[0]
				case "binary-header-name":
					record["headers"].([]any)[0].(map[string]any)["key_base64"] = "77+9AA=="
				case "timestamp-rounding":
					record["timestamp_ms"] = "9007199254740992"
				}
			})
			got := evidence.LoadAndCheck(dir)
			if got.Verdict != evidence.Violation || !hasCode(got, "corrupt_or_unexpected_output") {
				t.Fatalf("fidelity trap escaped: %+v", got)
			}
		})
	}
}

func TestOverlappingRoutesDoNotDoubleCountAnObservation(t *testing.T) {
	dir := copyFixture(t, "indistinguishable-pass")
	mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
		entries := events[0]["ledger"].(map[string]any)["entries"].([]any)
		entries[0].(map[string]any)["allowed_partitions"] = []any{float64(0), float64(1)}
		events[8]["output"].(map[string]any)["destination"].(map[string]any)["partition"] = float64(1)
		events[8]["output"].(map[string]any)["destination"].(map[string]any)["offset"] = "0"
		scans := events[9]["audit"].(map[string]any)["scans"].([]any)
		for _, scan := range scans {
			s := scan.(map[string]any)
			s["end"] = "1"
			s["reached"] = "1"
			s["stable_end"] = "1"
		}
	})
	if result := evidence.LoadAndCheck(dir); result.Verdict != evidence.Pass {
		t.Fatalf("a complete one-to-one route assignment was rejected: %+v", result)
	}
}

func TestLinksUnexpectedFilesAndCompletionDamageRejected(t *testing.T) {
	for _, name := range []string{evidence.ManifestName, evidence.EventsName, evidence.ArtifactName, evidence.CompleteName} {
		t.Run(name, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			target := filepath.Join(t.TempDir(), "external")
			write(t, target, read(t, filepath.Join(dir, name)))
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError {
				t.Fatalf("symlink accepted: %+v", got)
			}
		})
	}
	dir := copyFixture(t, "valid")
	write(t, filepath.Join(dir, "extra.jsonl"), []byte("{}\n"))
	if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError {
		t.Fatalf("unlisted evidence stream accepted: %+v", got)
	}
	dir = copyFixture(t, "valid")
	if err := os.Remove(filepath.Join(dir, evidence.CompleteName)); err != nil {
		t.Fatal(err)
	}
	if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError {
		t.Fatalf("missing completion accepted: %+v", got)
	}
	dir = copyFixture(t, "valid")
	var complete map[string]any
	decode(t, read(t, filepath.Join(dir, evidence.CompleteName)), &complete)
	complete["manifest_sha256"] = strings.Repeat("9", 64)
	writeJSON(t, filepath.Join(dir, evidence.CompleteName), complete)
	if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError {
		t.Fatalf("altered completion accepted: %+v", got)
	}
}

func TestDuplicateAndCaseFoldedJSONFieldsRejected(t *testing.T) {
	for _, prefix := range []string{`"run_id":"forged",`, `"RUN_ID":"forged",`} {
		t.Run(prefix, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			p := filepath.Join(dir, evidence.ManifestName)
			raw := read(t, p)
			raw = append([]byte("{"+prefix), raw[1:]...)
			write(t, p, raw)
			if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError || !hasCode(got, "manifest_json") {
				t.Fatalf("ambiguous field accepted: %+v", got)
			}
		})
	}
}

func hasCode(r evidence.Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
func contains(values []string, part string) bool {
	for _, v := range values {
		if strings.Contains(v, part) {
			return true
		}
	}
	return false
}
func read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func decode(t *testing.T, raw []byte, value any) {
	t.Helper()
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, raw)
}
func sum(raw []byte) string { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	for _, file := range []string{evidence.ManifestName, evidence.EventsName, evidence.ArtifactName, evidence.CompleteName} {
		write(t, filepath.Join(dir, file), read(t, filepath.Join("testdata", name, file)))
	}
	return dir
}

// Recompute framing hashes only, using the standard library independently of
// the checker. This lets controls reach semantic checks without weakening hash
// verification; expected verdicts and record obligations never come from it.
func mutateBundle(t *testing.T, dir string, mutate func(map[string]any, map[string]any, []map[string]any)) {
	t.Helper()
	var manifest, artifact map[string]any
	decode(t, read(t, filepath.Join(dir, evidence.ManifestName)), &manifest)
	decode(t, read(t, filepath.Join(dir, evidence.ArtifactName)), &artifact)
	lines := bytes.Split(bytes.TrimSuffix(read(t, filepath.Join(dir, evidence.EventsName)), []byte{'\n'}), []byte{'\n'})
	events := make([]map[string]any, len(lines))
	for i, line := range lines {
		decode(t, line, &events[i])
	}
	mutate(manifest, artifact, events)
	var stream bytes.Buffer
	for _, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	artifactRaw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	manifest["artifact"].(map[string]any)["sha256"] = sum(artifactRaw)
	manifest["artifact"].(map[string]any)["bytes"] = jsonInt(len(artifactRaw))
	manifest["events"].(map[string]any)["sha256"] = sum(stream.Bytes())
	manifest["events"].(map[string]any)["bytes"] = jsonInt(stream.Len())
	manifest["event_count"] = jsonInt(len(events))
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	completion := map[string]any{"schema_version": 1, "run_id": manifest["run_id"], "manifest_sha256": sum(manifestRaw), "events_sha256": sum(stream.Bytes()), "event_count": jsonInt(len(events))}
	write(t, filepath.Join(dir, evidence.ArtifactName), artifactRaw)
	write(t, filepath.Join(dir, evidence.EventsName), stream.Bytes())
	write(t, filepath.Join(dir, evidence.ManifestName), manifestRaw)
	writeJSON(t, filepath.Join(dir, evidence.CompleteName), completion)
}
func jsonInt(n int) string { raw, _ := json.Marshal(n); return string(raw) }

func TestNormalExitDoesNotProveRequestedKillReached(t *testing.T) {
	dir := copyFixture(t, "valid")
	mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
		events[5]["fault"].(map[string]any)["exit_code"] = float64(7)
	})
	if result := evidence.LoadAndCheck(dir); result.Verdict != evidence.Inconclusive || !hasCode(result, "fault_not_reached") {
		t.Fatalf("unrelated exit proved kill: %+v", result)
	}
}

func TestMissingNestedZeroValuesCannotMasqueradeAsEvidence(t *testing.T) {
	for _, field := range []string{"timed_out", "source_offset", "timestamp_ms", "headers", "scan_reached"} {
		t.Run(field, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				switch field {
				case "timed_out":
					delete(events[10]["finished"].(map[string]any), "timed_out")
				case "source_offset":
					ledger := events[0]["ledger"].(map[string]any)
					delete(ledger["partitions"].([]any)[0].(map[string]any)["source"].(map[string]any), "offset")
				case "timestamp_ms":
					delete(events[7]["output"].(map[string]any)["record"].(map[string]any), "timestamp_ms")
				case "headers":
					delete(events[7]["output"].(map[string]any)["record"].(map[string]any), "headers")
				case "scan_reached":
					delete(events[2]["audit"].(map[string]any)["scans"].([]any)[0].(map[string]any), "reached")
				}
			})
			if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError || !hasCode(got, "event_json") {
				t.Fatalf("missing %s silently defaulted: %+v", field, got)
			}
		})
	}
}

func TestRecordedReleaseMetadataPinsAndMandatoryProvenance(t *testing.T) {
	baseline := releaseMetadataFixture(t)
	result := evidence.LoadAndCheck(baseline)
	if result.Verdict != evidence.Pass || result.ReleaseQualified {
		t.Fatalf("recorded metadata consistency is not campaign qualification: %+v", result)
	}
	cases := []struct {
		name, code string
		verdict    evidence.Verdict
		mutate     func(map[string]any, map[string]any, []map[string]any)
	}{
		{"unavailable-provenance", "artifact_provenance", evidence.Unsupported, func(m, a map[string]any, events []map[string]any) { a["provenance_status"] = "unavailable" }},
		{"missing-verification", "artifact_verification", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) { a["verification_detail"] = "" }},
		{"archive-name-drift", "archive_identity", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			a["archive_name"] = "other.tar.gz"
			a["published_asset_url"] = "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/other.tar.gz"
			a["checksums_text"] = a["archive_sha256"].(string) + "  other.tar.gz\n"
		}},
		{"self-consistent-wrong-archive", "archive_identity", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			a["archive_sha256"] = strings.Repeat("9", 64)
			a["checksums_text"] = strings.Repeat("9", 64) + "  kaferry-v0.6.0-linux-amd64.tar.gz\n"
		}},
		{"binary-drift", "release_binary_identity", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			m["subject"].(map[string]any)["executable_sha256"] = strings.Repeat("9", 64)
			a["subject"].(map[string]any)["executable_sha256"] = strings.Repeat("9", 64)
		}},
		{"commit-drift", "release_identity", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			m["subject"].(map[string]any)["commit"] = strings.Repeat("9", 40)
			a["subject"].(map[string]any)["commit"] = strings.Repeat("9", 40)
		}},
		{"tag-drift", "release_identity", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			m["subject"].(map[string]any)["tag"] = "v0.6.1"
			a["subject"].(map[string]any)["tag"] = "v0.6.1"
		}},
		{"missing-contract-documents", "contract_documents", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) { delete(a, "contract_documents") }},
		{"changed-contract-document", "contract_documents", evidence.HarnessError, func(m, a map[string]any, events []map[string]any) {
			a["contract_documents"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("9", 64)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := releaseMetadataFixture(t)
			mutateBundle(t, dir, tc.mutate)
			got := evidence.LoadAndCheck(dir)
			if got.Verdict != tc.verdict || !hasCode(got, tc.code) {
				t.Fatalf("metadata drift escaped: %+v; want %s %s", got, tc.verdict, tc.code)
			}
		})
	}
}

// This constructs deliberately synthetic *recorded metadata* to test the
// offline consistency boundary. It is not an artifact verification or a run.
func releaseMetadataFixture(t *testing.T) string {
	t.Helper()
	dir := copyFixture(t, "valid")
	mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
		m["namespace"] = "release"
		m["lab_source"] = map[string]any{"commit": strings.Repeat("a", 40), "dirty": true, "proof": "synthetic recorded-metadata control; no source build claimed"}
		m["environment"].(map[string]any)["execution_platform"] = "linux/amd64"
		for _, subject := range []map[string]any{m["subject"].(map[string]any), a["subject"].(map[string]any)} {
			subject["kind"] = "published-release"
			subject["executable_sha256"] = "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"
			subject["tag"] = "v0.6.0"
			subject["commit"] = "d7d485b96a52b711cb10d76dca09aa9b155dec5e"
			subject["platform"] = "linux/amd64"
			subject["version_output"] = "kaferry v0.6.0 (synthetic recorded-metadata control; never executed)"
		}
		a["archive_name"] = "kaferry-v0.6.0-linux-amd64.tar.gz"
		a["archive_sha256"] = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f"
		a["checksums_text"] = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f  kaferry-v0.6.0-linux-amd64.tar.gz\n"
		a["published_asset_url"] = "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/kaferry-v0.6.0-linux-amd64.tar.gz"
		a["provenance_status"] = "verified"
		a["calibration_label"] = ""
		a["verification_detail"] = "synthetic metadata-only control; no verifier or release executable ran"
		a["contract_documents"] = []any{
			map[string]any{"path": "design/archive.md", "sha256": "c78bb4ea8a48c53835e6c537e0fc4d1b63e6fbec4fb50f9f71771a1a098283d6"},
			map[string]any{"path": "design/client-compatibility.md", "sha256": "7e0a52b112411b6023746a7421845601a004ca54d7de08176c56a972abf70b12"},
			map[string]any{"path": "design/decisions.md", "sha256": "93ce1a40c36b1884c59e9619bb9d85d29ea4348562afa5444aab322bcd801d01"},
		}
		events[1]["inputs_verified"].(map[string]any)["method"] = "independent_source_scan"
	})
	return dir
}

func removeEvent(t *testing.T, dir, kind string) {
	t.Helper()
	var manifest map[string]any
	decode(t, read(t, filepath.Join(dir, evidence.ManifestName)), &manifest)
	var stream bytes.Buffer
	removed, count := false, 0
	for _, line := range bytes.Split(bytes.TrimSuffix(read(t, filepath.Join(dir, evidence.EventsName)), []byte{'\n'}), []byte{'\n'}) {
		var event map[string]any
		decode(t, line, &event)
		if !removed && event["kind"] == kind {
			removed = true
			continue
		}
		count++
		event["seq"] = jsonInt(count)
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	if !removed {
		t.Fatalf("fixture has no %s event", kind)
	}
	manifest["events"].(map[string]any)["sha256"] = sum(stream.Bytes())
	manifest["events"].(map[string]any)["bytes"] = jsonInt(stream.Len())
	manifest["event_count"] = jsonInt(count)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	complete := map[string]any{"schema_version": 1, "run_id": manifest["run_id"], "manifest_sha256": sum(raw), "events_sha256": sum(stream.Bytes()), "event_count": jsonInt(count)}
	write(t, filepath.Join(dir, evidence.ManifestName), raw)
	write(t, filepath.Join(dir, evidence.EventsName), stream.Bytes())
	writeJSON(t, filepath.Join(dir, evidence.CompleteName), complete)
}

func TestExecutionAndSourceMetadataCannotBeOmittedOrInvented(t *testing.T) {
	for _, control := range []string{"lab_source", "environment", "commit", "dirty", "proof", "execution_platform", "runtime", "storage", "topology", "limits"} {
		t.Run(control, func(t *testing.T) {
			dir := copyFixture(t, "valid")
			mutateBundle(t, dir, func(m, a map[string]any, events []map[string]any) {
				switch control {
				case "lab_source", "environment":
					delete(m, control)
				case "commit":
					m["lab_source"].(map[string]any)["commit"] = "unknown"
				case "dirty":
					m["lab_source"].(map[string]any)["dirty"] = false
				case "proof":
					m["lab_source"].(map[string]any)["proof"] = ""
				default:
					m["environment"].(map[string]any)[control] = ""
				}
			})
			if got := evidence.LoadAndCheck(dir); got.Verdict == evidence.Pass {
				t.Fatalf("incomplete/invented %s metadata passed: %+v", control, got)
			}
		})
	}
}

func TestMalformedUTF8CannotChangeEvidenceIdentityByNormalization(t *testing.T) {
	dir := copyFixture(t, "valid")
	p := filepath.Join(dir, evidence.ManifestName)
	raw := bytes.Replace(read(t, p), []byte("golden-run"), []byte{'g', 255, 'n'}, 1)
	write(t, p, raw)
	if got := evidence.LoadAndCheck(dir); got.Verdict != evidence.HarnessError || !hasCode(got, "manifest_json") {
		t.Fatalf("invalid UTF-8 was silently normalized: %+v", got)
	}
}
