package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixture struct {
	bodies      map[string][]byte
	rel         release
	sums        []byte
	attestCalls int
	pins        releasePins
	client      *http.Client
}

const prefix = "/repos/pagrus7/kaferry"
const releasePath = prefix + "/releases/tags/v0.6.0"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{bodies: map[string][]byte{}}
	f.bodies[prefix+"/git/ref/tags/"+Tag] = []byte(`{"ref":"refs/tags/v0.6.0","object":{"sha":"689234eefe461435a89338322a001c2ea5240ad5","type":"tag"}}`)
	f.bodies[prefix+"/git/tags/"+tagObject] = []byte(`{"sha":"689234eefe461435a89338322a001c2ea5240ad5","tag":"v0.6.0","object":{"sha":"d7d485b96a52b711cb10d76dca09aa9b155dec5e","type":"commit"},"verification":{"verified":false,"reason":"unsigned"}}`)
	archive := makeArchive(t, []member{{"kaferry", tar.TypeReg, 0755, []byte("literal test executable; never run")}, {"LICENSE", tar.TypeReg, 0644, []byte("literal license")}, {"THIRD_PARTY_NOTICES.txt", tar.TypeReg, 0644, []byte("literal notices")}})
	statement := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"kaferry-v0.6.0-linux-amd64.tar.gz","digest":{"sha256":"%s"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"ref":"refs/tags/v0.6.0","repository":"https://github.com/pagrus7/kaferry","path":".github/workflows/release.yml"}},"resolvedDependencies":[{"uri":"git+https://github.com/pagrus7/kaferry@refs/tags/v0.6.0","digest":{"gitCommit":"d7d485b96a52b711cb10d76dca09aa9b155dec5e"}}]},"runDetails":{"builder":{"id":"https://github.com/pagrus7/kaferry/.github/workflows/release.yml@refs/tags/v0.6.0"}}}}`, digest(archive))
	bundle := fmt.Sprintf(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"TEST ONLY: not a certificate"},"tlogEntries":[{}]},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"%s","signatures":[{"sig":"TEST ONLY: not a signature"}]}}`, base64.StdEncoding.EncodeToString([]byte(statement)))
	f.rel = release{ID: 422917545, Tag: Tag, Immutable: false}
	f.pins = releasePins{422917545, digest(archive), digest([]byte("literal test executable; never run")), len([]byte("literal test executable; never run"))}
	f.addAsset(archiveName, archive)
	f.addAsset(provenanceName, []byte(bundle))
	f.sums = []byte(fmt.Sprintf("%s  %s\n%s  %s\n", digest(archive), archiveName, digest([]byte(bundle)), provenanceName))
	f.refreshSums()
	f.saveRelease()
	for _, pin := range contractPins {
		b, err := os.ReadFile("testdata/" + path.Base(pin.Path))
		if err != nil {
			t.Fatal(err)
		}
		f.bodies["/pagrus7/kaferry/"+Commit+"/"+pin.Path] = b
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := f.bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(server.Close)
	endpoint, _ := url.Parse(server.URL)
	base := server.Client().Transport
	// Production URLs remain fixed; only test transport routes HTTPS to fixtures.
	f.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		c := r.Clone(r.Context())
		u := *r.URL
		u.Scheme = endpoint.Scheme
		u.Host = endpoint.Host
		c.URL = &u
		return base.RoundTrip(c)
	})}
	return f
}
func (f *fixture) addAsset(name string, b []byte) {
	f.rel.Assets = append(f.rel.Assets, releaseAsset{Name: name, Digest: "sha256:" + digest(b), Size: int64(len(b)), Download: repository + "/releases/download/" + Tag + "/" + name})
	f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+name] = b
}
func (f *fixture) refreshSums() {
	kept := f.rel.Assets[:0]
	for _, a := range f.rel.Assets {
		if a.Name != "SHA256SUMS" {
			kept = append(kept, a)
		}
	}
	f.rel.Assets = kept
	f.addAsset("SHA256SUMS", f.sums)
}
func (f *fixture) saveRelease() { f.bodies[releasePath], _ = json.Marshal(f.rel) }
func (f *fixture) verifier() Verifier {
	return Verifier{Client: f.client, Attest: func(_ context.Context, archive, bundle []byte, id Identity) (Receipt, error) {
		f.attestCalls++
		if id.SHA256 != digest(archive) || len(bundle) == 0 {
			return Receipt{}, errors.New("test identity mismatch")
		}
		return Receipt{"TEST ONLY verifier", "fixture-v1", []byte("TEST ONLY cryptographic-verifier stand-in receipt")}, nil
	}}
}
func request() Request { return Request{Tag, "linux-amd64"} }

func TestVerifiedRequiresAllIndependentEvidence(t *testing.T) {
	// Given complete literal HTTPS fixtures and an explicitly separate test verifier.
	f := newFixture(t)
	// When verifying, then bytes/identities and exact downloadable evidence survive.
	got, err := f.verifier().verify(t.Context(), request(), f.pins)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag != Tag || got.Commit != Commit || got.ReleaseImmutable || got.ReleaseID != 422917545 || got.ContractSHA256 != ContractRoot || got.BinarySHA256 != digest([]byte("literal test executable; never run")) || len(got.Contracts) != 3 || len(got.Evidence) != 9 || f.attestCalls != 1 {
		t.Fatalf("incomplete verified result: %+v", got)
	}
	for _, d := range got.Evidence {
		if digest(d.Bytes) != d.SHA256 {
			t.Fatal("changed raw evidence")
		}
	}
	// Independently specified sorted GNU-style manifest root binds all three docs.
	sort.Slice(got.Contracts, func(i, j int) bool { return got.Contracts[i].Path < got.Contracts[j].Path })
	lines := []string{}
	for _, c := range got.Contracts {
		lines = append(lines, c.SHA256+"  "+c.Path+"\n")
	}
	if digest([]byte(strings.Join(lines, ""))) != "df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46" {
		t.Fatal("contract root changed")
	}
}

func TestDriftAndUnavailableEvidenceNeverReturnVerified(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fixture)
		want   error
	}{
		{"moved annotated ref", func(f *fixture) {
			p := prefix + "/git/ref/tags/" + Tag
			f.bodies[p] = bytes.Replace(f.bodies[p], []byte(tagObject), []byte(strings.Repeat("0", 40)), 1)
		}, ErrIdentity},
		{"lightweight ref", func(f *fixture) {
			p := prefix + "/git/ref/tags/" + Tag
			f.bodies[p] = bytes.Replace(f.bodies[p], []byte(`"type":"tag"`), []byte(`"type":"commit"`), 1)
		}, ErrIdentity},
		{"wrong source commit", func(f *fixture) {
			p := prefix + "/git/tags/" + tagObject
			f.bodies[p] = bytes.Replace(f.bodies[p], []byte(Commit), []byte(strings.Repeat("0", 40)), 1)
		}, ErrIdentity},
		{"duplicate JSON identity", func(f *fixture) {
			p := prefix + "/git/ref/tags/" + Tag
			f.bodies[p] = bytes.Replace(f.bodies[p], []byte(`{"ref":`), []byte(`{"ref":"refs/tags/evil","ref":`), 1)
		}, ErrEvidence},
		{"release ID replacement", func(f *fixture) { f.rel.ID++; f.saveRelease() }, ErrIdentity},
		{"unpublished draft", func(f *fixture) { f.rel.Draft = true; f.saveRelease() }, ErrIdentity},
		{"wrong release tag", func(f *fixture) { f.rel.Tag = "v0.7.0"; f.saveRelease() }, ErrIdentity},
		{"missing checksums", func(f *fixture) { delete(f.bodies, "/pagrus7/kaferry/releases/download/"+Tag+"/SHA256SUMS") }, ErrEvidence},
		{"missing checksum entry", func(f *fixture) {
			f.sums = []byte(fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), provenanceName))
			f.refreshSums()
			f.saveRelease()
		}, ErrIntegrity},
		{"duplicate checksum", func(f *fixture) { f.sums = append(f.sums, f.sums...); f.refreshSums(); f.saveRelease() }, ErrEvidence},
		{"corrupt checksum", func(f *fixture) {
			p := "/pagrus7/kaferry/releases/download/" + Tag + "/SHA256SUMS"
			f.bodies[p][0] = 'x'
		}, ErrIntegrity},
		{"corrupt archive", func(f *fixture) {
			p := "/pagrus7/kaferry/releases/download/" + Tag + "/" + archiveName
			f.bodies[p][30] ^= 1
		}, ErrIntegrity},
		{"missing API digest", func(f *fixture) { f.rel.Assets[0].Digest = ""; f.saveRelease() }, ErrIntegrity},
		{"oversized asset", func(f *fixture) { f.rel.Assets[0].Size = maxArchive + 1; f.saveRelease() }, ErrEvidence},
		{"duplicate asset", func(f *fixture) { f.rel.Assets = append(f.rel.Assets, f.rel.Assets[0]); f.saveRelease() }, ErrEvidence},
		{"untrusted asset URL", func(f *fixture) { f.rel.Assets[0].Download = "https://example.org/payload"; f.saveRelease() }, ErrEvidence},
		{"missing provenance", func(f *fixture) { delete(f.bodies, "/pagrus7/kaferry/releases/download/"+Tag+"/"+provenanceName) }, ErrEvidence},
		{"missing contract", func(f *fixture) { delete(f.bodies, "/pagrus7/kaferry/"+Commit+"/design/archive.md") }, ErrEvidence},
		{"modified contract", func(f *fixture) {
			f.bodies["/pagrus7/kaferry/"+Commit+"/design/archive.md"] = []byte("main branch changed contract")
		}, ErrIntegrity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given an otherwise valid release, when required evidence changes/disappears,
			// then no Verified result or cryptographic-verifier invocation is permitted.
			f := newFixture(t)
			tc.change(f)
			got, err := f.verifier().verify(t.Context(), request(), f.pins)
			if got != nil || !errors.Is(err, tc.want) || f.attestCalls != 0 {
				t.Fatalf("got=%v err=%v calls=%d", got, err, f.attestCalls)
			}
		})
	}
}

func TestUnknownRequestsNeverFetchOrBuild(t *testing.T) {
	for _, r := range []Request{{"main", "linux-amd64"}, {"v0.7.0", "linux-amd64"}, {Tag, "darwin-arm64"}, {Tag, "linux-386"}} {
		v := Verifier{Client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatal("unexpected network for unsupported identity")
			return nil, nil
		})}}
		if got, err := v.Verify(t.Context(), r); got != nil || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported request accepted: %v %v", got, err)
		}
	}
}

func TestProvenanceRequiresTrustedVerifierAndReceipt(t *testing.T) {
	for _, mode := range []string{"nil verifier", "verifier rejects", "empty receipt"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			v := f.verifier()
			switch mode {
			case "nil verifier":
				v.Attest = nil
			case "verifier rejects":
				v.Attest = func(context.Context, []byte, []byte, Identity) (Receipt, error) {
					return Receipt{}, errors.New("untrusted signing root")
				}
			case "empty receipt":
				v.Attest = func(context.Context, []byte, []byte, Identity) (Receipt, error) { return Receipt{}, nil }
			}
			got, err := v.verify(t.Context(), request(), f.pins)
			if got != nil || !errors.Is(err, ErrProvenance) {
				t.Fatalf("unverified provenance passed: %v %v", got, err)
			}
		})
	}
}

type member struct {
	name string
	kind byte
	mode int64
	data []byte
}

func makeArchive(t *testing.T, members []member) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		h := &tar.Header{Name: m.name, Mode: m.mode, Typeflag: m.kind, Size: int64(len(m.data))}
		if m.kind == tar.TypeSymlink || m.kind == tar.TypeLink {
			h.Linkname = "/outside"
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(m.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
func TestExtractionRejectsUnsafeAndMalformedArchives(t *testing.T) {
	good := []member{{"kaferry", tar.TypeReg, 0755, []byte("binary")}, {"LICENSE", tar.TypeReg, 0644, []byte("license")}, {"THIRD_PARTY_NOTICES.txt", tar.TypeReg, 0644, []byte("notices")}}
	for _, tc := range []struct {
		name   string
		modify func([]member) []member
	}{
		{"traversal", func(m []member) []member { m[0].name = "../kaferry"; return m }},
		{"absolute", func(m []member) []member { m[0].name = "/kaferry"; return m }},
		{"backslash", func(m []member) []member { m[0].name = `..\kaferry`; return m }},
		{"symlink", func(m []member) []member { m[0].kind = tar.TypeSymlink; return m }},
		{"hardlink", func(m []member) []member { m[0].kind = tar.TypeLink; return m }},
		{"duplicate", func(m []member) []member { return append(m, m[0]) }},
		{"missing", func(m []member) []member { return m[:2] }},
		{"oversized notices", func(m []member) []member { m[2].data = make([]byte, (1<<20)+1); return m }},
		{"not executable", func(m []member) []member { m[0].mode = 0644; return m }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := makeArchive(t, tc.modify(append([]member{}, good...)))
			if _, err := extract(raw); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("unsafe archive passed: %v", err)
			}
		})
	}
	raw := makeArchive(t, good)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not gzip", []byte("tar bytes")}, {"truncated gzip", raw[:len(raw)-5]},
		{"concatenated gzip", append(append([]byte{}, raw...), raw...)}, {"trailing bytes", append(append([]byte{}, raw...), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := extract(tc.data); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("malformed archive passed: %v", err)
			}
		})
	}
	broken := append([]byte{}, raw...)
	broken[len(broken)-8] ^= 1
	if _, err := extract(broken); !errors.Is(err, ErrIntegrity) {
		t.Fatal("gzip CRC corruption passed")
	}
}

func TestProvenanceClaimBindingRejectsDrift(t *testing.T) {
	f := newFixture(t)
	bundle := f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+provenanceName]
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	env := b["dsseEnvelope"].(map[string]any)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	want := Identity{repository, ".github/workflows/release.yml", "refs/tags/" + Tag, Commit, archiveName, digest(f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+archiveName])}
	if err := bindProvenance(bundle, want); err != nil {
		t.Fatal(err)
	}
	for _, original := range []string{Commit, archiveName, "https://slsa.dev/provenance/v1", "refs/tags/v0.6.0", ".github/workflows/release.yml"} {
		t.Run(original, func(t *testing.T) {
			changed := bytes.ReplaceAll(payload, []byte(original), []byte("wrong"))
			env["payload"] = base64.StdEncoding.EncodeToString(changed)
			data, _ := json.Marshal(b)
			if err := bindProvenance(data, want); !errors.Is(err, ErrProvenance) {
				t.Fatalf("claim drift passed: %v", err)
			}
		})
	}
}

func TestDownloadBudgetsAndRedirects(t *testing.T) {
	f := newFixture(t)
	f.bodies[prefix+"/git/ref/tags/"+Tag] = bytes.Repeat([]byte("x"), maxDocument+1)
	if got, err := f.verifier().verify(t.Context(), request(), f.pins); got != nil || !errors.Is(err, ErrEvidence) {
		t.Fatal("oversized evidence passed")
	}
	v := Verifier{Client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://example.org/leak"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}}
	if _, err := v.download(t.Context(), api+"/test", 100); !errors.Is(err, ErrEvidence) {
		t.Fatalf("insecure redirect accepted: %v", err)
	}
}

func TestMalformedChecksumNamesAndStructure(t *testing.T) {
	for _, line := range []string{"", "bad  kaferry", strings.Repeat("0", 64) + "  ../kaferry\n", strings.Repeat("0", 64) + "  kaferry\r\n", strings.Repeat("0", 64) + " *kaferry\n"} {
		if _, err := parseChecksums([]byte(line)); !errors.Is(err, ErrEvidence) {
			t.Fatalf("malformed checksum accepted: %q", line)
		}
	}
}

func TestProvenanceMissingTrustMaterialAndAmbiguousJSON(t *testing.T) {
	f := newFixture(t)
	bundle := f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+provenanceName]
	want := Identity{repository, ".github/workflows/release.yml", "refs/tags/" + Tag, Commit, archiveName, digest(f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+archiveName])}
	for _, field := range []string{"verificationMaterial", "dsseEnvelope"} {
		var decoded map[string]any
		_ = json.Unmarshal(bundle, &decoded)
		delete(decoded, field)
		bad, _ := json.Marshal(decoded)
		if err := bindProvenance(bad, want); !errors.Is(err, ErrProvenance) {
			t.Fatalf("missing trust material accepted: %s", field)
		}
	}
	bad := bytes.Replace(bundle, []byte(`{"mediaType":`), []byte(`{"mediaType":"untrusted","mediaType":`), 1)
	if err := bindProvenance(bad, want); !errors.Is(err, ErrProvenance) {
		t.Fatal("ambiguous provenance accepted")
	}
}

func TestTarDataAfterTerminatorIsRejected(t *testing.T) {
	compressed := makeArchive(t, []member{{"kaferry", tar.TypeReg, 0755, []byte("binary")}, {"LICENSE", tar.TypeReg, 0644, []byte("license")}, {"THIRD_PARTY_NOTICES.txt", tar.TypeReg, 0644, []byte("notices")}})
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	_ = gz.Close()
	// Given a valid archive followed by a hidden nonzero tar record and padding.
	raw = append(raw, bytes.Repeat([]byte("x"), 512)...)
	raw = append(raw, make([]byte, 1024)...)
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	_, _ = writer.Write(raw)
	_ = writer.Close()
	// When fully inspected, then the hidden member cannot be silently ignored.
	if _, err := extract(out.Bytes()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("hidden trailing tar data passed")
	}
}

func TestPublicVerifyRejectsConsistentReplacementBytes(t *testing.T) {
	// Given synthetic replacement archive bytes with matching API digest, checksum
	// and provenance subject, the fixture verifier would accept that attestation.
	f := newFixture(t)
	if got, err := f.verifier().verify(t.Context(), request(), f.pins); err != nil || got == nil {
		t.Fatalf("replacement control invalid: %v", err)
	}
	f.attestCalls = 0
	// When the same replacement passes through public Verify, then reviewed pins
	// reject it even though its release ID and all mutable evidence agree.
	got, err := f.verifier().Verify(t.Context(), request())
	if got != nil || !errors.Is(err, ErrIdentity) || !strings.Contains(err.Error(), "reviewed archive digest") || f.attestCalls != 0 {
		t.Fatalf("replacement passed reviewed pin: result=%v error=%v attestCalls=%d", got, err, f.attestCalls)
	}
}

func TestReviewedExecutableIdentityRejectsDrift(t *testing.T) {
	for _, field := range []string{"digest", "size"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			pins := f.pins
			if field == "digest" {
				pins.binarySHA256 = BinarySHA256
			} else {
				pins.binarySize++
			}
			got, err := f.verifier().verify(t.Context(), request(), pins)
			if got != nil || !errors.Is(err, ErrIdentity) || !strings.Contains(err.Error(), "reviewed executable identity") || f.attestCalls != 0 {
				t.Fatalf("executable drift accepted: result=%v error=%v", got, err)
			}
		})
	}
}
