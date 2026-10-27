package artifact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestReviewedPlatformExactIdentities(t *testing.T) {
	// Given exact source pins, then canonical selection preserves both complete
	// identities, including legacy AMD64 values and the separately inspected ARM64.
	for _, want := range []PlatformIdentity{
		{
			Platform: "linux/amd64", RequestPlatform: "linux-amd64",
			ArchiveName: "kaferry-v0.6.0-linux-amd64.tar.gz", ProvenanceName: "provenance-linux-amd64.json",
			ArchiveSHA256: "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f",
			BinarySHA256:  "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770", BinarySize: 23814268,
		},
		{
			Platform: "linux/arm64", RequestPlatform: "linux-arm64",
			ArchiveName: "kaferry-v0.6.0-linux-arm64.tar.gz", ProvenanceName: "provenance-linux-arm64.json",
			ArchiveSHA256: "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2",
			BinarySHA256:  "389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92", BinarySize: 22085756,
		},
	} {
		got, ok := ReviewedPlatform(want.Platform)
		if !ok || got != want {
			t.Fatalf("identity drift: got=%+v ok=%t want=%+v", got, ok, want)
		}
		got.ArchiveSHA256 = "caller modification"
		again, ok := ReviewedPlatform(want.Platform)
		if !ok || again != want {
			t.Fatal("caller changed a shared platform pin")
		}
	}
	amd64, _ := ReviewedPlatform("linux/amd64")
	if amd64.ArchiveSHA256 != ArchiveSHA256 || amd64.BinarySHA256 != BinarySHA256 || amd64.BinarySize != BinarySize || amd64.ArchiveName != archiveName || amd64.ProvenanceName != provenanceName {
		t.Fatal("legacy AMD64 identity changed")
	}
	for _, invalid := range []string{"", "linux-amd64", "linux-arm64", "linux/ARM64", "Linux/amd64", "linux/aarch64", "darwin/arm64", " linux/arm64", "linux/arm64\n", "linux/arm64/v8"} {
		if got, ok := ReviewedPlatform(invalid); ok || got != (PlatformIdentity{}) {
			t.Fatalf("canonical alias accepted: %q %+v", invalid, got)
		}
	}
}

func TestMixedPlatformRequestsRefuseBeforeFetch(t *testing.T) {
	// Given unsupported spellings/tags, when admission is attempted, then neither
	// public nor synthetic-pin entry points may fetch metadata or invoke Attest.
	for _, request := range []Request{
		{Tag, "linux/amd64"}, {Tag, "linux/arm64"}, {Tag, "linux-ARM64"},
		{Tag, "linux-aarch64"}, {Tag, " linux-arm64"}, {Tag, "linux-arm64\n"},
		{"main", "linux-arm64"}, {"v0.7.0", "linux-arm64"},
	} {
		v := Verifier{
			Client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("unsupported request fetched evidence")
				return nil, nil
			})},
			Attest: func(context.Context, []byte, []byte, Identity) (Receipt, error) {
				t.Fatal("unsupported request invoked attestation")
				return Receipt{}, nil
			},
		}
		if got, err := v.Verify(t.Context(), request); got != nil || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("public request accepted: %+v %v %v", request, got, err)
		}
		if got, err := v.verify(t.Context(), request, releasePins{}); got != nil || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("private request accepted: %+v %v %v", request, got, err)
		}
	}
}

func TestPlatformEvidenceSelectsExactSubjectAndMandatoryAttestation(t *testing.T) {
	for _, canonical := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(canonical, func(t *testing.T) {
			// Given distinct synthetic bytes for each platform, when all independent
			// evidence passes, then the trusted callback sees precisely that subject.
			platform, _ := ReviewedPlatform(canonical)
			f := newPlatformFixture(t, platform)
			v := f.verifier()
			v.Attest = func(_ context.Context, archive, bundle []byte, id Identity) (Receipt, error) {
				f.attestCalls++
				if id != (Identity{repository, ".github/workflows/release.yml", "refs/tags/" + Tag, Commit, platform.ArchiveName, f.pins.archiveSHA256}) || digest(archive) != f.pins.archiveSHA256 || !bytes.Equal(bundle, f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+platform.ProvenanceName]) {
					t.Fatal("attestation received another platform's subject or bytes")
				}
				return Receipt{"TEST ONLY verifier", "fixture-v1", []byte("TEST ONLY receipt")}, nil
			}
			request := Request{Tag, platform.RequestPlatform}
			got, err := v.verify(t.Context(), request, f.pins)
			if err != nil || got == nil {
				t.Fatalf("synthetic control failed: %v", err)
			}
			if got.Platform != platform.RequestPlatform || got.Tag != Tag || got.Commit != Commit || got.ContractSHA256 != ContractRoot || len(got.Contracts) != 3 || len(got.Evidence) != 9 || got.BinarySHA256 != f.pins.binarySHA256 || f.attestCalls != 1 {
				t.Fatalf("incomplete platform evidence: %+v calls=%d", got, f.attestCalls)
			}
			for _, document := range got.Evidence {
				if document.SHA256 != digest(document.Bytes) {
					t.Fatal("downloaded evidence changed")
				}
			}
			f.attestCalls = 0
			// Then public Verify rejects these consistent synthetic replacements at
			// its reviewed archive pin, even though the fixture control just passed.
			if got, err := v.Verify(t.Context(), request); got != nil || !errors.Is(err, ErrIdentity) || !strings.Contains(err.Error(), "reviewed archive digest") || f.attestCalls != 0 {
				t.Fatalf("public platform pin bypassed: got=%v err=%v calls=%d", got, err, f.attestCalls)
			}
		})
	}
}

func TestCrossPlatformSubstitutionNeverReturnsVerified(t *testing.T) {
	for _, canonical := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(canonical, func(t *testing.T) {
			platform, _ := ReviewedPlatform(canonical)
			otherCanonical := "linux/arm64"
			if canonical == otherCanonical {
				otherCanonical = "linux/amd64"
			}
			other, _ := ReviewedPlatform(otherCanonical)
			request := Request{Tag, platform.RequestPlatform}
			for _, fault := range []string{"other asset names", "renamed other archive", "other provenance subject"} {
				t.Run(fault, func(t *testing.T) {
					// Given otherwise valid evidence, when another platform's names,
					// archive or statement are substituted, then no receipt is accepted.
					f := newPlatformFixture(t, platform)
					want := ErrIntegrity
					switch fault {
					case "other asset names":
						f = newPlatformFixture(t, other)
					case "renamed other archive":
						foreign := newPlatformFixture(t, other)
						replacePlatformFixtureAsset(f, platform.ArchiveName, foreign.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+other.ArchiveName])
						want = ErrIdentity
					case "other provenance subject":
						key := "/pagrus7/kaferry/releases/download/" + Tag + "/" + platform.ProvenanceName
						var bundle map[string]any
						if err := json.Unmarshal(f.bodies[key], &bundle); err != nil {
							t.Fatal(err)
						}
						envelope := bundle["dsseEnvelope"].(map[string]any)
						payload, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
						if err != nil {
							t.Fatal(err)
						}
						payload = bytes.Replace(payload, []byte(platform.ArchiveName), []byte(other.ArchiveName), 1)
						envelope["payload"] = base64.StdEncoding.EncodeToString(payload)
						changed, err := json.Marshal(bundle)
						if err != nil {
							t.Fatal(err)
						}
						replacePlatformFixtureAsset(f, platform.ProvenanceName, changed)
						want = ErrProvenance
					}
					got, err := f.verifier().verify(t.Context(), request, f.pins)
					if got != nil || !errors.Is(err, want) || f.attestCalls != 0 {
						t.Fatalf("cross-platform substitution passed: got=%v err=%v calls=%d", got, err, f.attestCalls)
					}
				})
			}
		})
	}
}

func TestARM64ExecutablePinsAndTrustedReceiptRemainMandatory(t *testing.T) {
	platform, _ := ReviewedPlatform("linux/arm64")
	for _, fault := range []string{"binary digest", "binary size", "nil verifier", "verifier rejects", "empty receipt"} {
		t.Run(fault, func(t *testing.T) {
			// Given the valid ARM64 fixture control, when a binary pin or mandatory
			// trusted verifier fails, then parsed provenance cannot produce Verified.
			f := newPlatformFixture(t, platform)
			pins, v := f.pins, f.verifier()
			want := ErrProvenance
			switch fault {
			case "binary digest":
				pins.binarySHA256 = BinarySHA256
				want = ErrIdentity
			case "binary size":
				pins.binarySize++
				want = ErrIdentity
			case "nil verifier":
				v.Attest = nil
			case "verifier rejects":
				v.Attest = func(context.Context, []byte, []byte, Identity) (Receipt, error) {
					return Receipt{}, errors.New("TEST ONLY untrusted root")
				}
			case "empty receipt":
				v.Attest = func(context.Context, []byte, []byte, Identity) (Receipt, error) { return Receipt{}, nil }
			}
			if got, err := v.verify(t.Context(), Request{Tag, platform.RequestPlatform}, pins); got != nil || !errors.Is(err, want) {
				t.Fatalf("mandatory ARM64 check bypassed: got=%v err=%v", got, err)
			}
		})
	}
}

// Match a replacement's mutable API and checksum evidence so negative controls
// reach the independent source pins or provenance binding, not incidental drift.
func replacePlatformFixtureAsset(f *fixture, name string, data []byte) {
	for i := range f.rel.Assets {
		if f.rel.Assets[i].Name == name {
			f.rel.Assets[i].Digest = "sha256:" + digest(data)
			f.rel.Assets[i].Size = int64(len(data))
		}
	}
	f.bodies["/pagrus7/kaferry/releases/download/"+Tag+"/"+name] = data
	var sums strings.Builder
	for _, asset := range f.rel.Assets {
		if asset.Name != "SHA256SUMS" {
			fmt.Fprintf(&sums, "%s  %s\n", strings.TrimPrefix(asset.Digest, "sha256:"), asset.Name)
		}
	}
	f.sums = []byte(sums.String())
	f.refreshSums()
	f.saveRelease()
}
