package campaign

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

func TestPinnedReleaseSubjectPointMetadataDataOnly(t *testing.T) {
	// Opt in to an already retained exact published executable path and platform.
	// This control is data-only on any host: it does not repeat acquisition or
	// provenance verification, execute the subject, or establish native capability.
	if os.Getenv("LAB_SUBJECT_POINTS") == "" {
		t.Skip("data-only pinned subject-PC metadata opt-in absent")
	}
	profile, ok := artifact.ReviewedPlatform(os.Getenv("LAB_SUBJECT_POINTS_PLATFORM"))
	if os.Getenv("LAB_SUBJECT_POINTS") != "1" || os.Getenv("LAB_SUBJECT_POINTS_BINARY") == "" || !ok {
		t.Fatal("explicit reviewed platform, data-only artifact path and LAB_SUBJECT_POINTS=1 required")
	}
	report, err := ReadSubjectPointMap(os.Getenv("LAB_SUBJECT_POINTS_BINARY"))
	body, encodeErr := json.Marshal(report)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	t.Log("STATIC DATA ONLY; retained pin, not fresh provenance/native/hardware/reached/qualification evidence", string(body))
	if err != nil {
		t.Fatal("pinned artifact static point mapping unsupported", err)
	}
	if report.Platform != profile.Platform || report.ArtifactSHA256 != profile.BinarySHA256 || report.ArtifactBytes != profile.BinarySize || report.ContractSHA256 != evidence.ContractSHA256 || report.Status != "STATIC_MAP_ONLY" || !report.StaticOnly || report.RuntimeObserved || report.ReleaseQualified || len(report.Points) != 4 {
		t.Fatal("static subject-PC capability binding incomplete")
	}
	expectedMachine, otherMachine, entryName := elf.EM_X86_64, elf.EM_AARCH64, "_rt0_amd64_linux"
	if profile.Platform == "linux/arm64" {
		expectedMachine, otherMachine, entryName = elf.EM_AARCH64, elf.EM_X86_64, "_rt0_arm64_linux"
	}
	if report.BaseAnchor != "unique public "+entryName+" entry equals ELF e_entry" {
		t.Fatal("selected platform runtime entry not bound")
	}
	image, err := readSubjectPointImage(os.Getenv("LAB_SUBJECT_POINTS_BINARY"), maxSubjectPointImage, profile.BinarySize)
	if err != nil || pointDigest(image) != profile.BinarySHA256 {
		t.Fatal("retained data changed before in-memory refusal controls", err)
	}
	// Given the admitted published bytes, when only a machine or entry binding
	// is corrupted in memory, then no function points or proven base survive.
	name := []byte(entryName + "\x00")
	pcln := image[report.GoPCMetadata.Offset : report.GoPCMetadata.Offset+report.GoPCMetadata.Bytes]
	if bytes.Count(pcln, name) != 1 {
		t.Fatal("selected runtime entry name not unique for refusal control")
	}
	nameOffset := int(report.GoPCMetadata.Offset) + bytes.Index(pcln, name)
	for _, control := range []string{"cross-profile-machine", "wrong-declared-machine", "unknown-machine", "wrong-independent-entry", "missing-selected-anchor"} {
		t.Run(control, func(t *testing.T) {
			mutated := append([]byte(nil), image...)
			machine := expectedMachine
			switch control {
			case "cross-profile-machine":
				machine = otherMachine
			case "wrong-declared-machine":
				binary.LittleEndian.PutUint16(mutated[18:20], uint16(otherMachine))
			case "unknown-machine":
				machine = elf.EM_RISCV
			case "wrong-independent-entry":
				binary.LittleEndian.PutUint64(mutated[24:32], report.ELFEntryPC+1)
			case "missing-selected-anchor":
				mutated[nameOffset] = 'x'
			}
			bad, err := readPublicPointMetadata(mutated, reviewedSubjectPointSpecs(), machine)
			if !errors.Is(err, ErrSubjectPointUnsupported) || bad.anchor != "" || bad.base != 0 || len(bad.points) != 0 {
				t.Fatal("wrong published machine/entry admitted metadata", err)
			}
		})
	}
}
