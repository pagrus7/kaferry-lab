package evidence_test

import (
	"reflect"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

// These controls change recorded synthetic metadata only. They do not download,
// verify provenance for, or execute either release; a Pass is not qualification.
func arm64RecordedMetadataFixture(t *testing.T) string {
	t.Helper()
	dir := releaseMetadataFixture(t)
	mutateBundle(t, dir, func(m, a map[string]any, _ []map[string]any) {
		m["environment"].(map[string]any)["execution_platform"] = "linux/arm64"
		setRecordedSubjectField(m, a, "platform", "linux/arm64")
		setRecordedSubjectField(m, a, "executable_sha256", "389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92")
		a["archive_name"] = "kaferry-v0.6.0-linux-arm64.tar.gz"
		a["archive_sha256"] = "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2"
		a["checksums_text"] = "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2  kaferry-v0.6.0-linux-arm64.tar.gz\n"
		a["published_asset_url"] = "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/kaferry-v0.6.0-linux-arm64.tar.gz"
	})
	return dir
}

func setRecordedSubjectField(m, a map[string]any, field, value string) {
	m["subject"].(map[string]any)[field] = value
	a["subject"].(map[string]any)[field] = value
}

func TestRecordedReviewedPlatformTuples(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func(*testing.T) string
	}{{"historical-amd64", releaseMetadataFixture}, {"arm64", arm64RecordedMetadataFixture}} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a complete literal synthetic recorded tuple, When checked
			// offline, Then consistency passes without a release qualification.
			dir := tc.fixture(t)
			got := evidence.LoadAndCheck(dir)
			if got.Verdict != evidence.Pass || got.ReleaseQualified {
				t.Fatalf("recorded metadata consistency: %+v", got)
			}
			if !reflect.DeepEqual(got, evidence.LoadAndCheck(dir)) {
				t.Fatal("identical offline metadata recheck changed its result")
			}
		})
	}
}

func TestRecordedARM64TupleRejectsSubstitutions(t *testing.T) {
	cases := []struct {
		name, code string
		verdict    evidence.Verdict
		mutate     func(map[string]any, map[string]any)
	}{
		{"amd64-binary", "release_binary_identity", evidence.HarnessError, func(m, a map[string]any) {
			setRecordedSubjectField(m, a, "executable_sha256", "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770")
		}},
		{"amd64-archive-hash", "archive_identity", evidence.HarnessError, func(m, a map[string]any) {
			a["archive_sha256"] = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f"
			a["checksums_text"] = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f  kaferry-v0.6.0-linux-arm64.tar.gz\n"
		}},
		{"amd64-archive-name", "archive_identity", evidence.HarnessError, func(m, a map[string]any) {
			a["archive_name"] = "kaferry-v0.6.0-linux-amd64.tar.gz"
			a["checksums_text"] = "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2  kaferry-v0.6.0-linux-amd64.tar.gz\n"
			a["published_asset_url"] = "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/kaferry-v0.6.0-linux-amd64.tar.gz"
		}},
		{"amd64-asset-url", "artifact_url", evidence.HarnessError, func(m, a map[string]any) {
			a["published_asset_url"] = "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/kaferry-v0.6.0-linux-amd64.tar.gz"
		}},
		{"amd64-checksum-hash", "artifact_checksum", evidence.HarnessError, func(m, a map[string]any) {
			a["checksums_text"] = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f  kaferry-v0.6.0-linux-arm64.tar.gz\n"
		}},
		{"amd64-checksum-name", "artifact_checksum", evidence.HarnessError, func(m, a map[string]any) {
			a["checksums_text"] = "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2  kaferry-v0.6.0-linux-amd64.tar.gz\n"
		}},
		{"duplicate-selected-checksum", "artifact_checksum", evidence.HarnessError, func(m, a map[string]any) {
			a["checksums_text"] = a["checksums_text"].(string) + a["checksums_text"].(string)
		}},
		{"unknown-platform", "release_platform", evidence.Unsupported, func(m, a map[string]any) {
			setRecordedSubjectField(m, a, "platform", "linux/riscv64")
			m["environment"].(map[string]any)["execution_platform"] = "linux/riscv64"
		}},
		{"noncanonical-platform", "release_platform", evidence.Unsupported, func(m, a map[string]any) {
			setRecordedSubjectField(m, a, "platform", "linux-arm64")
			m["environment"].(map[string]any)["execution_platform"] = "linux-arm64"
		}},
		{"missing-provenance", "artifact_provenance", evidence.HarnessError, func(m, a map[string]any) {
			delete(a, "provenance_status")
		}},
		{"unavailable-provenance", "artifact_provenance", evidence.Unsupported, func(m, a map[string]any) {
			a["provenance_status"] = "unavailable"
		}},
		{"subject-platform-disagreement", "subject_mismatch", evidence.HarnessError, func(m, a map[string]any) {
			a["subject"].(map[string]any)["platform"] = "linux/amd64"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given an ARM64 tuple with one substituted identity component,
			// When checked offline, Then the explicit boundary rejects it.
			dir := arm64RecordedMetadataFixture(t)
			mutateBundle(t, dir, func(m, a map[string]any, _ []map[string]any) { tc.mutate(m, a) })
			got := evidence.LoadAndCheck(dir)
			if got.Verdict != tc.verdict || !hasCode(got, tc.code) || got.ReleaseQualified {
				t.Fatalf("substitution escaped: %+v; want %s %s", got, tc.verdict, tc.code)
			}
		})
	}
}
