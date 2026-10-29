package fixture

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
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
	// Given known bytes with an extra unselected hash-verified blob, when the
	// whole archive is read, then exact selected bytes and whole-stream facts agree.
	s := newArchiveSpecimen(t)
	extra := []byte("unselected but integrity-checked blob")
	s.members = append(s.members, archiveMember{archiveBlob(archiveDigest(extra)), extra, tar.TypeReg, tar.FormatUSTAR})
	body := s.bytes(t)
	r, err := readImageArchive(bytes.NewReader(body), s.expected)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.ArchiveBytes != int64(len(body)) || r.ArchiveSHA256 != strings.TrimPrefix(archiveDigest(body), "sha256:") || r.Entries != 9 || r.Blobs != 4 || len(r.Layers) != 1 || r.ManifestDescriptor != s.expected.Manifest || r.ConfigDescriptor != s.expected.Config || archiveDigest(r.Manifest) != s.expected.Manifest.Digest || archiveDigest(r.Config) != s.expected.Config.Digest {
		t.Fatalf("incorrect complete facts: %+v", r)
	}
}

func TestImageArchiveRefusalControls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*archiveSpecimen)
	}{
		{"corrupted-layer-bytes", func(s *archiveSpecimen) { s.members[2].body[0] ^= 1 }},
		{"corrupted-config-bytes", func(s *archiveSpecimen) { s.members[3].body[0] ^= 1 }},
		{"unselected-corruption", func(s *archiveSpecimen) {
			s.members = append(s.members, archiveMember{archiveBlob(archiveDigest([]byte("right"))), []byte("wrong"), tar.TypeReg, tar.FormatUSTAR})
		}},
		{"missing-layer", func(s *archiveSpecimen) { s.members = append(s.members[:2], s.members[3:]...) }},
		{"missing-selected-manifest", func(s *archiveSpecimen) { s.members = append(s.members[:4], s.members[5:]...) }},
		{"duplicate-member", func(s *archiveSpecimen) { s.members = append(s.members, s.members[2]) }},
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
		{"wrong-layer-size", func(s *archiveSpecimen) {
			s.replaceManifest(t, func(m map[string]any) { m["layers"].([]any)[0].(map[string]any)["size"] = 999 })
		}},
		{"wrong-config-descriptor", func(s *archiveSpecimen) {
			s.replaceManifest(t, func(m map[string]any) { m["config"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("2", 64) })
		}},
		{"wrong-layer-media", func(s *archiveSpecimen) {
			s.replaceManifest(t, func(m map[string]any) {
				m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.in-toto+json"
			})
		}},
		{"wrong-schema", func(s *archiveSpecimen) { s.replaceManifest(t, func(m map[string]any) { m["schemaVersion"] = 1 }) }},
		{"missing-layout", func(s *archiveSpecimen) { s.members = s.members[:7] }},
		{"bad-layout", func(s *archiveSpecimen) { s.members[7].body = []byte(`{"imageLayoutVersion":"2.0.0"}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a single independently invalid specimen, when read, then no
			// partial result can present Complete or selected bytes as an accepted result.
			s := newArchiveSpecimen(t)
			tc.mutate(&s)
			r, err := readImageArchive(bytes.NewReader(s.bytes(t)), s.expected)
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
