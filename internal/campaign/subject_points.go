package campaign

// This file reads executable bytes as DATA ONLY. It never loads/runs a subject,
// inspects target memory, or creates a breakpoint. Public Go ELF/PC metadata is
// not a record/progress oracle or evidence that a function was reached.
import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/gosym"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
)

const maxSubjectPointImage = 32 << 20
const maxCalibrationPointImage = 128 << 20 // owned lab test binary only; never release admission

var ErrSubjectPointIdentity = errors.New("subject point input is not the pinned published executable")
var ErrSubjectPointUnsupported = errors.New("public ELF/Go metadata cannot prove an exact subject function point")

type SubjectPointSection struct {
	Address, Offset, Bytes uint64
	SHA256                 string
}
type SubjectFunctionPoint struct {
	ID, Function, Status, Reason    string
	EntryPC, EndPC, EntryFileOffset uint64 // EndPC is exclusive, as defined by gosym.Func.
	SourceFile                      string
	SourceLine                      int
	RangeSHA256, EntryPrefixHex     string // prefix bytes, not decoded instruction boundaries
}
type SubjectPointMap struct {
	Version                                   int
	Kind, Status                              string
	ReleaseTag, ReleaseCommit, ContractSHA256 string
	ArtifactSHA256                            string
	ArtifactBytes                             int
	ELFEntryPC, RuntimeTextBase               uint64
	BaseAnchor                                string
	Text, GoPCMetadata                        SubjectPointSection
	Points                                    []SubjectFunctionPoint
	StaticOnly                                bool `json:"static_only"`
	RuntimeObserved                           bool `json:"runtime_observed"`
	ReleaseQualified                          bool `json:"release_qualified"`
	Limitations                               []string
}
type subjectPointSpec struct{ id, name, fileSuffix string }

func reviewedSubjectPointSpecs() []subjectPointSpec {
	return []subjectPointSpec{
		{"finish-worker-stop", "github.com/pagrus7/kaferry/internal/copy.(*Runner).finishWorkerStop", "/internal/copy/worker_stop.go"},
		{"checkpoint", "github.com/pagrus7/kaferry/internal/copy.(*Runner).checkpoint", "/internal/copy/runner.go"},
		{"revoke", "github.com/pagrus7/kaferry/internal/copy.(*Runner).Revoke", "/internal/copy/runner.go"},
		{"committer-save", "github.com/pagrus7/kaferry/internal/franz.(*Committer).Save", "/internal/franz/commit.go"},
	}
}

// ReadSubjectPointMap admits only the immutable pinned release as data. It
// verifies regular-file/size/digest identity BEFORE calling an ELF/Go parser.
// Artifact acquisition/provenance and any later live mapping remain separate.
func ReadSubjectPointMap(path string) (report SubjectPointMap, err error) {
	report = SubjectPointMap{Version: 1, Kind: "published-release-function-PC-map", Status: "REJECTED", ReleaseTag: evidence.ReleaseTag, ReleaseCommit: evidence.ReleaseCommit, ContractSHA256: evidence.ContractSHA256, StaticOnly: true, Limitations: []string{
		"Static public ELF/Go metadata only; no function execution, reached event, debugger, hardware support or qualification is established.",
		"Function Entry/End and entry source line are metadata boundaries, not decoded call sites, return PCs, instruction boundaries or caller-origin proof.",
		"Runtime mapping/load base, immutable live code, process ownership, stop timing and target wait/resource evidence require separate reviewed native calibration.",
		"Missing, ambiguous or inline-only function identities remain unsupported; name bytes alone never admit a point.",
		"Pinned executable bytes are checked afresh; archive/provenance/native-version acquisition verification is separate and is not replaced by this map.",
	}}
	image, e := readSubjectPointImage(path, maxSubjectPointImage, artifact.BinarySize)
	if e != nil {
		return report, e
	}
	report.ArtifactSHA256 = pointDigest(image)
	report.ArtifactBytes = len(image)
	if report.ArtifactSHA256 != evidence.ReleaseExecutableSHA256 {
		return report, ErrSubjectPointIdentity
	}
	// No parsing occurs on any path before the exact identity gate above.
	metadata, e := readPublicPointMetadata(image, reviewedSubjectPointSpecs())
	report.ELFEntryPC, report.RuntimeTextBase, report.BaseAnchor = metadata.entry, metadata.base, metadata.anchor
	report.Text, report.GoPCMetadata, report.Points = metadata.text, metadata.pcln, metadata.points
	report.Status = "UNSUPPORTED"
	if e != nil {
		return report, e
	}
	report.Status = "STATIC_MAP_ONLY"
	return report, nil
}

func readSubjectPointImage(path string, maximum, exact int) (image []byte, err error) {
	file, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, e := file.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(maximum) || (exact > 0 && info.Size() != int64(exact)) {
		return nil, ErrSubjectPointIdentity
	}
	image, e = io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if e != nil {
		return nil, e
	}
	if len(image) > maximum || (exact > 0 && len(image) != exact) {
		return nil, ErrSubjectPointIdentity
	}
	return image, nil
}
func pointDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

type publicPointMetadata struct {
	entry, base uint64
	anchor      string
	text, pcln  SubjectPointSection
	points      []SubjectFunctionPoint
}

// Both release and visibly separate owned calibration images use the same
// public Go entry-to-ELF entry proof. No ELF symbols, DWARF or alternative base
// source is consulted; gosym always receives a nil symtab.
func readPublicPointMetadata(image []byte, specs []subjectPointSpec) (out publicPointMetadata, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: public metadata decoder rejected the image", ErrSubjectPointUnsupported)
		}
		if err != nil && out.anchor == "" {
			out.base = 0
		}
	}()
	file, e := elf.NewFile(bytes.NewReader(image))
	if e != nil {
		return out, fmt.Errorf("%w: ELF unavailable", ErrSubjectPointUnsupported)
	}
	defer file.Close() // bytes.Reader has no owned OS descriptor
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_EXEC || file.Machine != elf.EM_X86_64 || (file.OSABI != elf.ELFOSABI_NONE && file.OSABI != elf.ELFOSABI_LINUX) {
		return out, fmt.Errorf("%w: requires Linux AMD64 ELF ET_EXEC", ErrSubjectPointUnsupported)
	}
	text, e := uniquePointSection(file, ".text", uint64(len(image)))
	if e != nil {
		return out, e
	}
	pcln, e := uniquePointSection(file, ".gopclntab", uint64(len(image)))
	if e != nil {
		return out, e
	}
	if text.Type != elf.SHT_PROGBITS || text.Flags&elf.SHF_ALLOC == 0 || text.Flags&elf.SHF_EXECINSTR == 0 || text.Flags&(elf.SHF_WRITE|elf.SHF_COMPRESSED) != 0 || pcln.Type != elf.SHT_PROGBITS || pcln.Flags&elf.SHF_ALLOC == 0 || pcln.Flags&(elf.SHF_WRITE|elf.SHF_EXECINSTR|elf.SHF_COMPRESSED) != 0 {
		return out, fmt.Errorf("%w: text/PC sections lack reviewed read-only layout", ErrSubjectPointUnsupported)
	}
	if !pointSectionInLoad(file, text, true, uint64(len(image))) || !pointSectionInLoad(file, pcln, false, uint64(len(image))) || file.Entry < text.Addr || file.Entry-text.Addr >= text.Size {
		return out, fmt.Errorf("%w: sections/ELF entry are not in file-backed reviewed segments", ErrSubjectPointUnsupported)
	}
	textBytes, e := text.Data()
	if e != nil {
		return out, fmt.Errorf("%w: text data unavailable", ErrSubjectPointUnsupported)
	}
	pclnBytes, e := pcln.Data()
	if e != nil {
		return out, fmt.Errorf("%w: Go PC metadata unavailable", ErrSubjectPointUnsupported)
	}
	out.entry, out.base = file.Entry, text.Addr
	out.text = SubjectPointSection{text.Addr, text.Offset, text.Size, pointDigest(textBytes)}
	out.pcln = SubjectPointSection{pcln.Addr, pcln.Offset, pcln.Size, pointDigest(pclnBytes)}

	table, e := gosym.NewTable(nil, gosym.NewLineTable(pclnBytes, out.base))
	if e != nil || table == nil || len(table.Funcs) == 0 {
		return out, fmt.Errorf("%w: public Go function table unavailable", ErrSubjectPointUnsupported)
	}
	// .text.Addr is a proposed runtime.text base, never an assumption. Require
	// one exact public runtime entry at the independent ELF e_entry before any
	// requested function can be admitted, including the owned test specimen.
	anchor, count := uniquePointFunction(table, "_rt0_amd64_linux")
	if count != 1 || anchor.Entry != file.Entry {
		return out, fmt.Errorf("%w: ELF entry cannot anchor runtime.text", ErrSubjectPointUnsupported)
	}
	out.anchor = "unique public _rt0_amd64_linux entry equals ELF e_entry"
	failed := false
	for _, spec := range specs {
		point := readExactSubjectPoint(table, spec, text, textBytes)
		if point.Status != "STATIC_FUNCTION_RANGE" {
			failed = true
		}
		out.points = append(out.points, point)
	}
	if failed {
		return out, ErrSubjectPointUnsupported
	}
	return out, nil
}
func uniquePointSection(file *elf.File, name string, imageBytes uint64) (*elf.Section, error) {
	var selected *elf.Section
	for _, section := range file.Sections {
		if section.Name == name {
			if selected != nil {
				return nil, fmt.Errorf("%w: duplicate required section", ErrSubjectPointUnsupported)
			}
			selected = section
		}
	}
	if selected == nil || selected.Size == 0 || selected.Addr == 0 || selected.Offset > imageBytes || selected.Size > imageBytes-selected.Offset || selected.Addr+selected.Size < selected.Addr {
		return nil, fmt.Errorf("%w: required section bounds unavailable", ErrSubjectPointUnsupported)
	}
	return selected, nil
}
func pointSectionInLoad(file *elf.File, section *elf.Section, executable bool, imageBytes uint64) bool {
	covered := 0
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		if program.Off > imageBytes || program.Filesz > imageBytes-program.Off || program.Memsz < program.Filesz || program.Vaddr+program.Memsz < program.Vaddr {
			return false
		}
		overlaps := section.Addr < program.Vaddr+program.Memsz && program.Vaddr < section.Addr+section.Size
		if overlaps && program.Flags&elf.PF_W != 0 {
			return false
		}
		if program.Flags&elf.PF_R == 0 || (executable && program.Flags&elf.PF_X == 0) {
			continue
		}
		if section.Offset < program.Off || section.Addr < program.Vaddr {
			continue
		}
		offset, address := section.Offset-program.Off, section.Addr-program.Vaddr
		if offset == address && offset <= program.Filesz && section.Size <= program.Filesz-offset && address <= program.Memsz && section.Size <= program.Memsz-address {
			covered++
		}
	}
	return covered == 1
}
func uniquePointFunction(table *gosym.Table, name string) (*gosym.Func, int) {
	var selected *gosym.Func
	count := 0
	for i := range table.Funcs {
		function := &table.Funcs[i]
		if function.Sym != nil && function.Name == name {
			selected = function
			count++
		}
	}
	return selected, count
}
func readExactSubjectPoint(table *gosym.Table, spec subjectPointSpec, text *elf.Section, textBytes []byte) SubjectFunctionPoint {
	point := SubjectFunctionPoint{ID: spec.id, Function: spec.name, Status: "UNSUPPORTED"}
	function, count := uniquePointFunction(table, spec.name)
	if count == 0 {
		point.Reason = "missing standalone public function; may be absent or inline-only (name bytes are insufficient)"
		return point
	}
	if count != 1 {
		point.Reason = "ambiguous exact full function identity"
		return point
	}
	if function.Entry < text.Addr || function.End <= function.Entry || function.End-text.Addr > uint64(len(textBytes)) {
		point.Reason = "function range outside read-only file-backed text"
		return point
	}
	file, line, owner := table.PCToLine(function.Entry)
	last := table.PCToFunc(function.End - 1)
	if owner == nil || last == nil || owner.Entry != function.Entry || owner.End != function.End || owner.Name != spec.name || last.Entry != function.Entry || last.Name != spec.name || line < 1 || file == "" || len(file) > 4096 || strings.ContainsRune(file, 0) || (spec.fileSuffix != "" && !strings.HasSuffix(file, spec.fileSuffix)) {
		point.Reason = "entry/end/source ownership is missing, inline-only, ambiguous or not the reviewed source"
		return point
	}
	start, end := function.Entry-text.Addr, function.End-text.Addr
	prefixEnd := min(start+16, end)
	point.Status = "STATIC_FUNCTION_RANGE"
	point.EntryPC, point.EndPC, point.EntryFileOffset = function.Entry, function.End, text.Offset+start
	point.SourceFile, point.SourceLine = file, line
	point.RangeSHA256 = pointDigest(textBytes[start:end])
	point.EntryPrefixHex = hex.EncodeToString(textBytes[start:prefixEnd])
	return point
}
