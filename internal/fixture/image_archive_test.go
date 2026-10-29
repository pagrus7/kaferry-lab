package fixture

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Literal synthetic archive specimens exercise the reader, not Docker or a
// product oracle. No blob is executed or unpacked as an image filesystem.
type archiveMember struct {
	name   string
	body   []byte
	kind   byte
	format tar.Format
}

type archiveSpecimen struct {
	members  []archiveMember
	expected imageArchiveExpected
}

func archiveDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func archiveBlob(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}
func archiveJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func newArchiveSpecimen(t *testing.T) archiveSpecimen {
	t.Helper()
	layer := []byte("independently known synthetic compressed layer bytes\x00\xff")
	config := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},"config":{"Env":["SYNTHETIC=yes"]}}`)
	ld := imageArchiveDescriptor{"application/vnd.oci.image.layer.v1.tar+gzip", archiveDigest(layer), int64(len(layer))}
	cd := imageArchiveDescriptor{"application/vnd.oci.image.config.v1+json", archiveDigest(config), int64(len(config))}
	manifest := archiveJSON(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"mediaType": cd.MediaType, "digest": cd.Digest, "size": cd.Size}, "layers": []any{map[string]any{"mediaType": ld.MediaType, "digest": ld.Digest, "size": ld.Size}}})
	md := imageArchiveDescriptor{"application/vnd.oci.image.manifest.v1+json", archiveDigest(manifest), int64(len(manifest))}
	index := archiveJSON(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{map[string]any{"mediaType": md.MediaType, "digest": md.Digest, "size": md.Size, "platform": map[string]string{"os": "linux", "architecture": "arm64"}}}})
	return archiveSpecimen{[]archiveMember{
		{"blobs", nil, tar.TypeDir, tar.FormatUSTAR}, {"blobs/sha256", nil, tar.TypeDir, tar.FormatUSTAR},
		{archiveBlob(ld.Digest), layer, tar.TypeReg, tar.FormatUSTAR},
		{archiveBlob(cd.Digest), config, tar.TypeReg, tar.FormatUSTAR},
		{archiveBlob(md.Digest), manifest, tar.TypeReg, tar.FormatUSTAR},
		{"index.json", index, tar.TypeReg, tar.FormatUSTAR},
		{"manifest.json", []byte(`[]`), tar.TypeReg, tar.FormatUSTAR},
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`), tar.TypeReg, tar.FormatUSTAR},
	}, imageArchiveExpected{md, cd, "linux", "arm64"}}
}
func (s archiveSpecimen) bytes(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, member := range s.members {
		h := &tar.Header{Name: member.name, Size: int64(len(member.body)), Mode: 0600, Typeflag: member.kind, Format: member.format}
		if member.format == tar.FormatPAX {
			h.PAXRecords = map[string]string{"comment": "synthetic PAX must refuse"}
		}
		if member.kind == tar.TypeSymlink || member.kind == tar.TypeLink {
			h.Linkname = "index.json"
			h.Size = 0
		}
		if member.kind == tar.TypeDir {
			h.Mode = 0700
			h.Size = 0
		}
		// The stdlib writer refuses regular names ending in '/'. Emit its
		// ordinary USTAR header first, then construct the literal invalid name
		// with a correct raw checksum so this control reaches the reader.
		patchName := member.kind == tar.TypeReg && strings.HasSuffix(member.name, "/")
		if patchName {
			if member.format != tar.FormatUSTAR || len(member.name) >= 100 {
				t.Fatal("malformed-name fixture requires short USTAR name")
			}
			h.Name = strings.TrimSuffix(member.name, "/")
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if patchName {
			header := out.Bytes()[out.Len()-512:]
			clear(header[:100])
			copy(header[:100], member.name)
			for i := 148; i < 156; i++ {
				header[i] = ' '
			}
			sum := 0
			for _, value := range header {
				sum += int(value)
			}
			copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
		}
		if h.Size > 0 {
			if _, err := w.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func (s *archiveSpecimen) replaceManifest(t *testing.T, change func(map[string]any)) {
	t.Helper()
	old := archiveBlob(s.expected.Manifest.Digest)
	for i := range s.members {
		if s.members[i].name != old {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(s.members[i].body, &m); err != nil {
			t.Fatal(err)
		}
		change(m)
		body := archiveJSON(t, m)
		s.expected.Manifest.Digest, s.expected.Manifest.Size = archiveDigest(body), int64(len(body))
		s.members[i].name, s.members[i].body = archiveBlob(s.expected.Manifest.Digest), body
	}
	for i := range s.members {
		if s.members[i].name == "index.json" {
			s.members[i].body = archiveJSON(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []any{map[string]any{"mediaType": s.expected.Manifest.MediaType, "digest": s.expected.Manifest.Digest, "size": s.expected.Manifest.Size}}})
		}
	}
}

func (s *archiveSpecimen) replaceConfig(t *testing.T, body []byte) {
	t.Helper()
	old := archiveBlob(s.expected.Config.Digest)
	for i := range s.members {
		if s.members[i].name == old {
			s.expected.Config.Digest, s.expected.Config.Size = archiveDigest(body), int64(len(body))
			s.members[i].name, s.members[i].body = archiveBlob(s.expected.Config.Digest), body
		}
	}
	s.replaceManifest(t, func(m map[string]any) {
		m["config"] = map[string]any{"mediaType": s.expected.Config.MediaType, "digest": s.expected.Config.Digest, "size": s.expected.Config.Size}
	})
}

func TestImageArchiveCompleteLiteral(t *testing.T) {
	// Given known selected bytes and an extra opaque blob, when the
	// whole archive is read, then exact selected bytes and whole-stream facts agree.
	s := newArchiveSpecimen(t)
	extra := []byte("unselected opaque blob")
	s.members = append(s.members, archiveMember{archiveBlob(archiveDigest(extra)), extra, tar.TypeReg, tar.FormatUSTAR})
	body := s.bytes(t)
	r, err := readImageArchive(bytes.NewReader(body), s.expected)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.ArchiveBytes != int64(len(body)) || r.ArchiveSHA256 != strings.TrimPrefix(archiveDigest(body), "sha256:") || r.Entries != 9 || r.Blobs != 4 || r.ManifestDescriptor != s.expected.Manifest || r.ConfigDescriptor != s.expected.Config || archiveDigest(r.Manifest) != s.expected.Manifest.Digest || archiveDigest(r.Config) != s.expected.Config.Digest {
		t.Fatalf("incorrect complete facts: %+v", r)
	}
}

func TestImageArchiveFixedDirectoryHeaders(t *testing.T) {
	// Given the two exact directory names in stock save, When a directory
	// header has one trailing slash, Then it denotes the same fixed directory.
	for _, names := range [][2]string{{"blobs/", "blobs/sha256/"}, {"blobs", "blobs/sha256/"}, {"blobs/", "blobs/sha256"}} {
		s := newArchiveSpecimen(t)
		s.members[0].name, s.members[1].name = names[0], names[1]
		if result, err := readImageArchive(bytes.NewReader(s.bytes(t)), s.expected); err != nil || !result.Complete {
			t.Fatalf("fixed directory spelling refused: %q %v", names, err)
		}
	}
}

func TestImageArchiveUnselectedBodiesAreOpaque(t *testing.T) {
	// Given an accepted selected metadata pair, changes to unrelated members
	// do not become another image qualification. Whole archive SHA still records
	// every changed byte for the separate retained-archive reuse predicate.
	original := newArchiveSpecimen(t)
	body := original.bytes(t)
	baseline, err := readImageArchive(bytes.NewReader(body), original.expected)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*archiveSpecimen)
	}{
		{"unrelated-layer-bytes", func(s *archiveSpecimen) { s.members[2].body[0] ^= 1 }},
		{"missing-layer", func(s *archiveSpecimen) { s.members = append(s.members[:2], s.members[3:]...) }},
		{"unselected-blob-name-not-content-digest", func(s *archiveSpecimen) {
			s.members = append(s.members, archiveMember{archiveBlob(archiveDigest([]byte("right"))), []byte("other"), tar.TypeReg, tar.FormatUSTAR})
		}},
		{"opaque-export-index", func(s *archiveSpecimen) { s.members[5].body = []byte("not an index oracle") }},
		{"opaque-legacy-export", func(s *archiveSpecimen) { s.members[6].body = []byte("not a legacy image oracle") }},
		{"missing-layout", func(s *archiveSpecimen) { s.members = s.members[:7] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newArchiveSpecimen(t)
			tc.mutate(&s)
			changed := s.bytes(t)
			result, err := readImageArchive(bytes.NewReader(changed), s.expected)
			if err != nil || !result.Complete || result.ArchiveSHA256 == baseline.ArchiveSHA256 || !bytes.Equal(result.Manifest, baseline.Manifest) || !bytes.Equal(result.Config, baseline.Config) {
				t.Fatalf("opaque member affected selected metadata proof: %+v %v", result, err)
			}
		})
	}
}

func TestImageArchiveRefusalControls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*archiveSpecimen)
	}{
		{"corrupted-config-bytes", func(s *archiveSpecimen) { s.members[3].body[0] ^= 1 }},
		{"corrupted-manifest-bytes", func(s *archiveSpecimen) { s.members[4].body[0] ^= 1 }},
		{"missing-selected-manifest", func(s *archiveSpecimen) { s.members = append(s.members[:4], s.members[5:]...) }},
		{"duplicate-member", func(s *archiveSpecimen) { s.members = append(s.members, s.members[2]) }},
		{"duplicate-directory-alias", func(s *archiveSpecimen) {
			s.members = append(s.members, archiveMember{"blobs/", nil, tar.TypeDir, tar.FormatUSTAR})
		}},
		{"duplicate-sha-directory-alias", func(s *archiveSpecimen) {
			s.members = append(s.members, archiveMember{"blobs/sha256/", nil, tar.TypeDir, tar.FormatUSTAR})
		}},
		{"directory-spelling-as-file", func(s *archiveSpecimen) { s.members[0].name, s.members[0].kind = "blobs/", tar.TypeReg }},
		{"double-directory-slash", func(s *archiveSpecimen) { s.members[0].name = "blobs//" }},
		{"selected-file-trailing-slash", func(s *archiveSpecimen) { s.members[3].name += "/" }},
		{"path-escape", func(s *archiveSpecimen) { s.members[0].name = "../blobs" }},
		{"absolute-path", func(s *archiveSpecimen) { s.members[0].name = "/blobs" }},
		{"alias-path", func(s *archiveSpecimen) { s.members[2].name = "blobs/sha256/../" + strings.Repeat("a", 64) }},
		{"unexpected-file", func(s *archiveSpecimen) {
			s.members = append(s.members, archiveMember{"surprise", []byte("raw"), tar.TypeReg, tar.FormatUSTAR})
		}},
		{"symbolic-link", func(s *archiveSpecimen) { s.members[5].kind = tar.TypeSymlink }},
		{"hard-link", func(s *archiveSpecimen) { s.members[5].kind = tar.TypeLink }},
		{"pax-header", func(s *archiveSpecimen) { s.members[5].format = tar.FormatPAX }},
		{"gnu-format", func(s *archiveSpecimen) { s.members[5].format = tar.FormatGNU }},
		{"cross-architecture-request", func(s *archiveSpecimen) { s.expected.Architecture = "amd64" }},
		{"cross-architecture-config", func(s *archiveSpecimen) {
			s.replaceConfig(t, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}`))
		}},
		{"cross-OS-config", func(s *archiveSpecimen) {
			s.replaceConfig(t, []byte(`{"architecture":"arm64","os":"windows","rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}`))
		}},
		{"duplicate-config-key", func(s *archiveSpecimen) {
			s.replaceConfig(t, []byte(`{"architecture":"amd64","architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}`))
		}},
		{"malformed-config-json", func(s *archiveSpecimen) { s.replaceConfig(t, []byte(`{"os":`)) }},
		{"wrong-config-commitment", func(s *archiveSpecimen) { s.expected.Config.Digest = "sha256:" + strings.Repeat("1", 64) }},
		{"wrong-manifest-size", func(s *archiveSpecimen) { s.expected.Manifest.Size++ }},
		{"wrong-config-descriptor", func(s *archiveSpecimen) {
			s.replaceManifest(t, func(m map[string]any) { m["config"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("2", 64) })
		}},
		{"wrong-schema", func(s *archiveSpecimen) { s.replaceManifest(t, func(m map[string]any) { m["schemaVersion"] = 1 }) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a single independently invalid specimen, when read, then no
			// partial result can present Complete or selected bytes as an accepted result.
			s := newArchiveSpecimen(t)
			tc.mutate(&s)
			body := s.bytes(t)
			if tc.name == "directory-spelling-as-file" || tc.name == "selected-file-trailing-slash" {
				// Independently confirm the crafted USTAR checksum and regular
				// type are accepted by archive/tar before the lab path predicate.
				want := s.members[0].name
				if tc.name == "selected-file-trailing-slash" {
					want = s.members[3].name
				}
				reader := tar.NewReader(bytes.NewReader(body))
				for {
					header, err := reader.Next()
					if err != nil {
						t.Fatalf("malformed-name fixture did not reach intended header: %v", err)
					}
					if header.Name == want {
						if header.Typeflag != tar.TypeReg {
							t.Fatal("malformed-name fixture lost regular type")
						}
						break
					}
				}
			}
			r, err := readImageArchive(bytes.NewReader(body), s.expected)
			if err == nil || r.Complete || r.Manifest != nil || r.Config != nil || r.ArchiveSHA256 != "" {
				t.Fatalf("accepted invalid archive: result=%+v err=%v", r, err)
			}
		})
	}
}

type archiveFailureReader struct {
	source    io.Reader
	remaining int64
	cause     error
}

func (r *archiveFailureReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.cause
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.source.Read(p)
	r.remaining -= int64(n)
	return n, e
}

func TestImageArchiveStreamFailureControls(t *testing.T) {
	s := newArchiveSpecimen(t)
	body := s.bytes(t)
	for _, cut := range []int{0, 511, 1024, 3000, len(body) - 1024, len(body) - 1} {
		t.Run("truncated-"+strconv.Itoa(cut), func(t *testing.T) {
			r, e := readImageArchive(bytes.NewReader(body[:cut]), s.expected)
			if e == nil || r.Complete {
				t.Fatalf("truncation %d passed", cut)
			}
		})
	}
	for _, trailer := range [][]byte{[]byte("nonzero"), append(make([]byte, 512), 1), make([]byte, 1)} {
		r, e := readImageArchive(bytes.NewReader(append(append([]byte{}, body...), trailer...)), s.expected)
		if e == nil || r.Complete {
			t.Fatal("invalid trailer passed")
		}
	}
	cause := errors.New("synthetic exact archive read failure")
	for _, at := range []int64{100, 3000, int64(len(body))} {
		reader := &archiveFailureReader{bytes.NewReader(body), at, cause}
		r, e := readImageArchive(reader, s.expected)
		if !errors.Is(e, cause) || r.Complete {
			t.Fatalf("original read failure lost: %v", e)
		}
	}
	padded := append(append([]byte{}, body...), make([]byte, 512)...)
	if r, e := readImageArchive(bytes.NewReader(padded), s.expected); e != nil || !r.Complete || r.ArchiveBytes != int64(len(padded)) {
		t.Fatalf("aligned zero padding rejected: %v", e)
	}
}

func TestImageArchiveBounds(t *testing.T) {
	s := newArchiveSpecimen(t)
	body := s.bytes(t)
	for _, limits := range []imageArchiveLimits{{int64(len(body)) - 1, 256, 64 << 10}, {512 << 20, 7, 64 << 10}, {512 << 20, 256, 100}, {imageArchiveMaximum + 1, 256, 64 << 10}} {
		r, e := readImageArchiveBounded(bytes.NewReader(body), s.expected, limits)
		if e == nil || r.Complete {
			t.Fatalf("bound did not refuse: %+v", limits)
		}
	}
	if _, e := readImageArchive(nil, s.expected); e == nil {
		t.Fatal("nil stream accepted")
	}
}

func TestImageArchiveDecodeErrorOriginal(t *testing.T) {
	// Given malformed selected JSON with matching synthetic content hashes,
	// when decoding fails, then callers can still inspect the original error.
	s := newArchiveSpecimen(t)
	s.replaceConfig(t, []byte(`{"os":"linux",]`))
	result, err := readImageArchive(bytes.NewReader(s.bytes(t)), s.expected)
	var syntax *json.SyntaxError
	if err == nil || !errors.As(err, &syntax) || syntax.Offset == 0 || result.Complete {
		t.Fatalf("concrete JSON syntax error lost: %v", err)
	}
}

func TestImageArchiveProofReuseKeepsWholeArchiveBinding(t *testing.T) {
	// Given literal same-run save facts and a selected-metadata proof, when an
	// unrelated archive byte changes after collection, then reuse still refuses.
	// These literal lifecycle facts do not establish a real process wait/EOF.
	t.Chdir(t.TempDir())
	s := State{RunID: "synthetic-image-proof"}
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(imageDataDirectory(s), 0700); err != nil {
		t.Fatal(err)
	}
	fixture := newArchiveSpecimen(t)
	body := fixture.bytes(t)
	if err := os.WriteFile(savedImageArchivePath(s), body, 0600); err != nil {
		t.Fatal(err)
	}
	argv := []string{"docker", "image", "save", "--platform=linux/arm64", Image, arm64ProxyImage}
	exit := 0
	receipt := imageSaveReceipt{RunID: s.RunID, Argv: argv, ExecutedArgv: argv, ExecutablePath: "/synthetic/docker", Started: true, WaitReturned: true, TerminalWait: true, StdoutEOF: true, StderrEOF: true, PipesClosed: true, ArchiveClosed: true, Complete: true, ArchiveBytes: int64(len(body)), ObservedArchiveBytes: int64(len(body)), ExitCode: &exit}
	if _, err := writeLinkPrivate(linkPrivateDirectory(s.RunID), "image-save-complete.json", receipt); err != nil {
		t.Fatal(err)
	}
	sha := strings.TrimPrefix(archiveDigest(body), "sha256:")
	if err := verifySavedImageDigest(s, int64(len(body)), sha); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), body...)
	changed[1536] ^= 1
	if err := os.WriteFile(savedImageArchivePath(s), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySavedImageDigest(s, int64(len(body)), sha); err == nil {
		t.Fatal("changed unrelated archive bytes admitted on reuse")
	}
	if err := os.WriteFile(savedImageArchivePath(s), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(savedImageArchivePath(s), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifySavedImageDigest(s, int64(len(body)), sha); err == nil {
		t.Fatal("nonprivate archive admitted on reuse")
	}
	if err := os.Chmod(savedImageArchivePath(s), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(savedImageArchivePath(s)); err != nil {
		t.Fatal(err)
	}
	if err := verifySavedImageDigest(s, int64(len(body)), sha); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing archive cause lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-complete.json")); err != nil {
		t.Fatal("literal retained lifecycle was changed", err)
	}
}
