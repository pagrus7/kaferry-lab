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

func TestSubjectPointReleaseGateBindsExactPlatformTuple(t *testing.T) {
	// Given the two fixed published identities, when their sizes and digests are
	// crossed or altered, then neither combination may select a release parser.
	amd, _ := artifact.ReviewedPlatform("linux/amd64")
	arm, _ := artifact.ReviewedPlatform("linux/arm64")
	for _, tc := range []struct {
		name             string
		size             int
		digest, platform string
	}{
		{"AMD64", amd.BinarySize, amd.BinarySHA256, "linux/amd64"},
		{"ARM64", arm.BinarySize, arm.BinarySHA256, "linux/arm64"},
		{"AMD64-size-ARM64-digest", amd.BinarySize, arm.BinarySHA256, ""},
		{"ARM64-size-AMD64-digest", arm.BinarySize, amd.BinarySHA256, ""},
		{"changed-size", arm.BinarySize + 1, arm.BinarySHA256, ""},
		{"changed-digest", arm.BinarySize, "not the whole-file digest", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, ok := reviewedSubjectPointIdentity(tc.size, tc.digest)
			if ok != (tc.platform != "") || profile.Platform != tc.platform {
				t.Fatal("published size/digest platform tuple not bound", profile.Platform, ok)
			}
		})
	}
}

func TestSubjectPointReleaseGateRejectsAlteredDigestBeforeELF(t *testing.T) {
	// Given each exact release size but non-ELF synthetic bytes, when release
	// admission checks the altered digest, then no ELF interpretation occurs.
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			profile, _ := artifact.ReviewedPlatform(platform)
			path := filepath.Join(t.TempDir(), "not-a-release")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.Write([]byte("CALIBRATION ONLY: not ELF; wrong release digest")); err != nil {
				t.Fatal(err)
			}
			if err = file.Truncate(int64(profile.BinarySize)); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			report, err := ReadSubjectPointMap(path)
			if !errors.Is(err, ErrSubjectPointIdentity) || errors.Is(err, ErrSubjectPointUnsupported) || report.Platform != "" || len(report.Points) != 0 || report.Text.Bytes != 0 || report.RuntimeTextBase != 0 || report.ReleaseQualified || report.RuntimeObserved {
				t.Fatal("altered digest reached metadata admission", err)
			}
		})
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
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("CALIBRATION ONLY: requires owned native Linux AMD64 or ARM64 test executable")
	}
	if err := nativeProcessPlatform(); err != nil {
		t.Fatal("CALIBRATION requires native Linux AMD64 or ARM64 kernel", err)
	}
	expectedMachine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		expectedMachine = elf.EM_AARCH64
	}
	entryName := "_rt0_" + runtime.GOARCH + "_linux"
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
	metadata, err := readPublicPointMetadata(image, specs, expectedMachine)
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
	if metadata.anchor != "unique public "+entryName+" entry equals ELF e_entry" || len(metadata.points) != 1 {
		t.Fatal("calibration used a different/unbound base")
	}
	point := metadata.points[0]
	if point.Status != "STATIC_FUNCTION_RANGE" || point.EntryPC != uint64(pointer) || point.EndPC <= uint64(pointer) || point.SourceFile != file || point.SourceLine != line || point.EntryPrefixHex == "" || point.RangeSHA256 == "" {
		t.Fatal("public metadata differs from independent native marker PC/source")
	}
	t.Run("unsupported-ELF-type", func(t *testing.T) {
		// Given this healthy owned ELF64 image, when only its fixed e_type
		// field changes to ET_DYN in memory, then the actual reader rejects
		// that unsupported format before admitting a base or function point.
		mutated := append([]byte(nil), image...)
		binary.LittleEndian.PutUint16(mutated[16:18], uint16(elf.ET_DYN))
		bad, err := readPublicPointMetadata(mutated, specs, expectedMachine)
		if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != "" || bad.base != 0 || len(bad.points) != 0 {
			t.Fatal("unsupported ELF type admitted a base or function range")
		}
	})
	t.Run("wrong-or-unreviewed-machine", func(t *testing.T) {
		// Given the healthy owned image, when its declared machine changes to
		// the other reviewed machine or an unknown machine, then the selected
		// profile refuses before public function parsing or base admission.
		for _, machine := range []elf.Machine{elf.EM_X86_64, elf.EM_AARCH64, elf.EM_RISCV} {
			if machine == expectedMachine {
				continue
			}
			mutated := append([]byte(nil), image...)
			binary.LittleEndian.PutUint16(mutated[18:20], uint16(machine))
			bad, err := readPublicPointMetadata(mutated, specs, expectedMachine)
			if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != "" || bad.base != 0 || len(bad.points) != 0 {
				t.Fatal("wrong ELF machine admitted")
			}
			bad, err = readPublicPointMetadata(image, specs, machine)
			if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != "" || bad.base != 0 || len(bad.points) != 0 {
				t.Fatal("wrong expected machine admitted")
			}
		}
	})
	for _, control := range []struct {
		name  string
		specs []subjectPointSpec
	}{
		{"wrong-reviewed-source", []subjectPointSpec{{"CALIBRATION wrong source", actual.Name(), "/internal/campaign/calibration_wrong_source.go"}}},
		{"valid-and-missing", []subjectPointSpec{specs[0], {"CALIBRATION missing", "CALIBRATION ONLY: deliberately absent public function", ""}}},
	} {
		t.Run(control.name, func(t *testing.T) {
			// Given the independently checked healthy marker image, when a
			// reviewed source suffix is wrong or a valid spec is followed by
			// a missing function, then partial metadata cannot become success.
			bad, err := readPublicPointMetadata(image, control.specs, expectedMachine)
			if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != metadata.anchor || bad.base != metadata.base || len(bad.points) != len(control.specs) {
				t.Fatal("failed requested point did not propagate aggregate Unsupported")
			}
			failed := bad.points[len(bad.points)-1]
			if failed.ID != control.specs[len(control.specs)-1].id || failed.Function != control.specs[len(control.specs)-1].name || failed.Status != "UNSUPPORTED" || failed.Reason == "" || failed.EntryPC != 0 || failed.EndPC != 0 || failed.EntryFileOffset != 0 || failed.SourceFile != "" || failed.SourceLine != 0 || failed.RangeSHA256 != "" || failed.EntryPrefixHex != "" {
				t.Fatal("unsupported source/missing identity admitted a PC or byte range")
			}
			if len(bad.points) == 2 && bad.points[0] != point {
				t.Fatal("mixed request lost the independently checked healthy point")
			}
		})
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
	name := []byte(entryName + "\x00")
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
			bad, err := readPublicPointMetadata(mutated, specs, expectedMachine)
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

func TestCalibrationSubjectPointRejectsRangeBeyondSuppliedText(t *testing.T) {
	// Given one uniquely named calibration function whose exclusive end is
	// one byte beyond this literal 16-byte text, when the actual point reader
	// sees it, then it returns Unsupported before any source lookup or slice.
	// This public gosym specimen is not an application function or oracle.
	name := "CALIBRATION ONLY: out-of-text function"
	table := &gosym.Table{Funcs: []gosym.Func{{Entry: 0x401008, End: 0x401011, Sym: &gosym.Sym{Name: name}}}}
	text := &elf.Section{SectionHeader: elf.SectionHeader{Addr: 0x401000, Offset: 0x1000, Size: 16}}
	textBytes := []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	point := readExactSubjectPoint(table, subjectPointSpec{"CALIBRATION out of text", name, ""}, text, textBytes)
	if point.Status != "UNSUPPORTED" || point.Reason == "" || point.EntryPC != 0 || point.EndPC != 0 || point.EntryFileOffset != 0 || point.SourceFile != "" || point.SourceLine != 0 || point.RangeSHA256 != "" || point.EntryPrefixHex != "" {
		t.Fatal("out-of-text function admitted a PC or byte range")
	}
}
