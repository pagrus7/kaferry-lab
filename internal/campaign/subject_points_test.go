package campaign

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
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
// data-only ELF/gosym reader's public-entry-to-ELF-entry anchor.
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
	// metadata reader proves the same public runtime-entry/ELF-entry anchor as
	// release admission (not the pointer),
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
	specs := []subjectPointSpec{{"CALIBRATION ONLY", actual.Name(), "/internal/campaign/subject_points_test.go"}}
	metadata, err := readPublicPointMetadata(image, specs)
	if err != nil {
		// Static facts from the already captured owned image help distinguish an
		// external/C startup entry from the required public runtime entry. Never
		// log arbitrary decoder/tool errors or substitute a different base.
		header, headerErr := elf.NewFile(bytes.NewReader(image))
		if headerErr == nil {
			var textAddress uint64
			if text := header.Section(".text"); text != nil {
				textAddress = text.Addr
			}
			t.Logf("CALIBRATION STATIC ELF class=%d type=%d machine=%d entry=%#x text=%#x metadata_entry=%#x candidate_base=%#x proven_base=%#x anchor=%q reason=public-metadata-unsupported", uint8(header.Class), uint16(header.Type), uint16(header.Machine), header.Entry, textAddress, metadata.entry, metadata.text.Address, metadata.base, metadata.anchor)
			header.Close() // bytes.Reader owns no OS file descriptor
		} else {
			t.Log("CALIBRATION STATIC ELF reason=header-unavailable; public-metadata-unsupported")
		}
		t.Fatal("owned native calibration public metadata unsupported")
	}
	if metadata.anchor != "unique public _rt0_amd64_linux entry equals ELF e_entry" || len(metadata.points) != 1 {
		t.Fatal("calibration used a different/unbound base")
	}
	point := metadata.points[0]
	if point.Status != "STATIC_FUNCTION_RANGE" || point.EntryPC != uint64(pointer) || point.EndPC <= uint64(pointer) || point.SourceFile != file || point.SourceLine != line || point.EntryPrefixHex == "" || point.RangeSHA256 == "" {
		t.Fatal("public metadata differs from independent native marker PC/source")
	}
	// Given the same actual healthy owned image, corrupt only the independent
	// ELF entry or exact public runtime entry name in memory. Both must fail
	// before a requested marker PC is admitted; no symbols/base fallback or
	// skip may conceal an anchor failure. No on-disk executable is changed.
	elfFile, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	defer elfFile.Close()
	pcln := elfFile.Section(".gopclntab")
	if pcln == nil {
		t.Fatal("owned calibration PC section unavailable")
	}
	pclnBytes, err := pcln.Data()
	if err != nil {
		t.Fatal(err)
	}
	name := []byte("_rt0_amd64_linux\x00")
	if bytes.Count(pclnBytes, name) != 1 {
		t.Fatal("literal runtime entry name not uniquely located for negative control")
	}
	nameOffset := int(pcln.Offset) + bytes.Index(pclnBytes, name)
	for _, corruption := range []string{"wrong-independent-ELF-entry", "missing-public-runtime-entry"} {
		t.Run(corruption, func(t *testing.T) {
			mutated := append([]byte(nil), image...)
			if corruption == "wrong-independent-ELF-entry" {
				// Fixed ELF64 e_entry field: this is a test mutation, not a decoder.
				binary.LittleEndian.PutUint64(mutated[24:32], metadata.entry+1)
			} else {
				mutated[nameOffset] = 'x'
			}
			bad, err := readPublicPointMetadata(mutated, specs)
			if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != "" || bad.base != 0 || len(bad.points) != 0 {
				t.Fatal("unproved entry anchor admitted a function range")
			}
		})
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
