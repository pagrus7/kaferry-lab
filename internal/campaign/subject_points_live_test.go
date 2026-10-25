package campaign

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

func TestPinnedReleaseSubjectPointMetadataDataOnly(t *testing.T) {
	// Opt in only after the normal archive/provenance/native-version verification
	// has produced this executable path. This test reads it as DATA; no execution,
	// debugger, memory access, hardware capability or reached event follows.
	if os.Getenv("LAB_SUBJECT_POINTS") == "" {
		t.Skip("data-only pinned subject-PC metadata opt-in absent")
	}
	if os.Getenv("LAB_SUBJECT_POINTS") != "1" || os.Getenv("LAB_SUBJECT_POINTS_BINARY") == "" {
		t.Fatal("explicit data-only artifact path and LAB_SUBJECT_POINTS=1 required")
	}
	if err := nativeProcessPlatform(); err != nil {
		t.Fatal("opt-in metadata control requires native Linux AMD64", err)
	}
	report, err := ReadSubjectPointMap(os.Getenv("LAB_SUBJECT_POINTS_BINARY"))
	body, encodeErr := json.Marshal(report)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	t.Log("STATIC DATA ONLY; not hardware/reached/qualification evidence", string(body))
	if err != nil {
		t.Fatal("pinned artifact static point mapping unsupported", err)
	}
	if report.ArtifactSHA256 != evidence.ReleaseExecutableSHA256 || report.ArtifactBytes != artifact.BinarySize || report.ContractSHA256 != evidence.ContractSHA256 || report.Status != "STATIC_MAP_ONLY" || !report.StaticOnly || report.RuntimeObserved || report.ReleaseQualified || len(report.Points) != 4 {
		t.Fatal("static subject-PC capability binding incomplete")
	}
}
