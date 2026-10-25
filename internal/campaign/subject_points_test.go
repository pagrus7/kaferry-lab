package campaign

import (
	"debug/gosym"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
)

// CALIBRATION ONLY. This lab-owned function is not Kaferry and is never admitted
// as a published subject. Its live function pointer is independent of the
// data-only ELF/gosym reader's runtime.text-symbol anchor.
//
//go:noinline
func calibrationSubjectPointMarker(value uint64) uint64 { return value*37 + 11 }

func TestSubjectPointReleaseGateRejectsAlteredDigestBeforeELF(t *testing.T) {
	// Given exact release-sized but non-ELF synthetic bytes, when release admission
	// checks their altered digest, then no ELF/public-table interpretation occurs.
	path := filepath.Join(t.TempDir(), "not-a-release")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("CALIBRATION ONLY: not ELF; wrong release digest")); err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(artifact.BinarySize); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := ReadSubjectPointMap(path)
	if !errors.Is(err, ErrSubjectPointIdentity) || errors.Is(err, ErrSubjectPointUnsupported) || len(report.Points) != 0 || report.Text.Bytes != 0 || report.RuntimeTextBase != 0 || report.ReleaseQualified || report.RuntimeObserved {
		t.Fatal("altered digest reached metadata admission", err)
	}
}

func TestSubjectPointReleaseGateRejectsOversizeBeforeELF(t *testing.T) {
	// Given a bounded sparse file one byte over32MiB, when admitted, then it fails
	// on descriptor size before hashing/parsing and creates no point metadata.
	path := filepath.Join(t.TempDir(), "oversize-calibration-input")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(33554433); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := ReadSubjectPointMap(path)
	if !errors.Is(err, ErrSubjectPointIdentity) || report.ArtifactSHA256 != "" || len(report.Points) != 0 || report.GoPCMetadata.Bytes != 0 {
		t.Fatal("oversized file reached hashing/ELF admission", err)
	}
}

func TestSubjectPointReleaseGateCannotAdmitLabTestExecutable(t *testing.T) {
	// Given this actual owned Go test executable, when the published-release API
	// sees it, then it cannot substitute the calibration executable for Kaferry.
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	report, err := ReadSubjectPointMap(path)
	if !errors.Is(err, ErrSubjectPointIdentity) || report.Status != "REJECTED" || report.ReleaseQualified || len(report.Points) != 0 {
		t.Fatal("lab executable admitted as release", err)
	}
}

func TestCalibrationPublicSubjectMetadataMatchesIndependentFunctionPC(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("CALIBRATION ONLY: requires owned native Linux AMD64 test executable")
	}
	if err := nativeProcessPlatform(); err != nil {
		t.Fatal("CALIBRATION requires native Linux AMD64 kernel", err)
	}
	// Given the current lab-owned native test binary, when the private public-
	// metadata reader anchors runtime.text using ELF symbols (not the pointer),
	// then its exact noinline marker entry matches an independent runtime pointer.
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := readSubjectPointImage(path, maxCalibrationPointImage, 0)
	if err != nil {
		t.Fatal("calibration image unavailable", err)
	}
	pointer := reflect.ValueOf(calibrationSubjectPointMarker).Pointer()
	actual := runtime.FuncForPC(pointer)
	if actual == nil || actual.Entry() != pointer {
		t.Fatal("independent calibration function entry unavailable")
	}
	file, line := actual.FileLine(pointer)
	metadata, err := readPublicPointMetadata(image, []subjectPointSpec{{"CALIBRATION ONLY", actual.Name(), "/internal/campaign/subject_points_test.go"}}, true)
	if err != nil {
		t.Fatal("owned native calibration public metadata unsupported", err)
	}
	if metadata.anchor != "CALIBRATION ONLY: unique ELF runtime.text symbol" || len(metadata.points) != 1 {
		t.Fatal("calibration used a different/unbound base")
	}
	point := metadata.points[0]
	if point.Status != "STATIC_FUNCTION_RANGE" || point.EntryPC != uint64(pointer) || point.EndPC <= uint64(pointer) || point.SourceFile != file || point.SourceLine != line || point.EntryPrefixHex == "" || point.RangeSHA256 == "" {
		t.Fatal("public metadata differs from independent native marker PC/source")
	}
}

func TestCalibrationSubjectIdentityNeedsStandaloneUniquePublicFunction(t *testing.T) {
	// Given literal name-only/duplicate calibration metadata, when the actual
	// point admission function sees it, then neither can create an admitted PC.
	name := "CALIBRATION ONLY: inline-or-absent-marker"
	missing := readExactSubjectPoint(&gosym.Table{}, subjectPointSpec{"CALIBRATION missing", name, ""}, nil, nil)
	if missing.Status != "UNSUPPORTED" || missing.EntryPC != 0 || missing.Reason == "" {
		t.Fatal("name-only/inline-only identity admitted")
	}
	duplicate := &gosym.Table{Funcs: []gosym.Func{{Entry: 0x401100, End: 0x401120, Sym: &gosym.Sym{Name: name}}, {Entry: 0x401100, End: 0x401120, Sym: &gosym.Sym{Name: name}}}}
	ambiguous := readExactSubjectPoint(duplicate, subjectPointSpec{"CALIBRATION duplicate", name, ""}, nil, nil)
	if ambiguous.Status != "UNSUPPORTED" || ambiguous.EntryPC != 0 || ambiguous.Reason == "" {
		t.Fatal("ambiguous exact public identity admitted")
	}
}
