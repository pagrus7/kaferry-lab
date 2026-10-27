package campaign

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

// This is literal synthetic metadata for admission controls, never freshly
// verified provenance or an executable run. No release bytes are opened.
func arm64ScenarioMetadataPlan(t *testing.T) ScenarioPlan {
	t.Helper()
	subject := evidence.Subject{
		Kind: "published-release", Tag: "v0.6.0", Commit: "d7d485b96a52b711cb10d76dca09aa9b155dec5e",
		ExecutableSHA256: "389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92",
		ContractSHA256:   "df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46",
		Platform:         "linux/arm64", VersionOutput: "kaferry v0.6.0 (synthetic metadata; never executed)",
	}
	return ScenarioPlan{
		ID: "healthy", Routing: "PRESERVE", Directory: t.TempDir(), Executable: filepath.Join(t.TempDir(), "never-executed"),
		Subject: subject,
		Artifact: evidence.ArtifactMetadata{
			Subject: subject, ProvenanceStatus: "verified",
			ArchiveSHA256: "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2",
		},
	}
}

func TestScenarioARM64RecordedMetadataAdmission(t *testing.T) {
	// Given a literal complete ARM64 metadata tuple, When normalized without
	// launching, Then reviewed identity and the existing finite defaults hold.
	p, err := normalizeScenarioPlan(arm64ScenarioMetadataPlan(t))
	if err != nil || p.Subject.Platform != "linux/arm64" || p.Records != 96 || p.Budget != 5*time.Minute {
		t.Fatalf("synthetic ARM64 admission: %+v / %v", p, err)
	}
}

func TestScenarioARM64MetadataRejectsCrossPlatformAndMissingTrust(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ScenarioPlan)
	}{
		{"amd64-binary", func(p *ScenarioPlan) {
			p.Subject.ExecutableSHA256 = "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"
			p.Artifact.Subject = p.Subject
		}},
		{"amd64-archive", func(p *ScenarioPlan) {
			p.Artifact.ArchiveSHA256 = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f"
		}},
		{"amd64-platform-with-arm64-bytes", func(p *ScenarioPlan) {
			p.Subject.Platform = "linux/amd64"
			p.Artifact.Subject = p.Subject
		}},
		{"unknown-platform", func(p *ScenarioPlan) {
			p.Subject.Platform = "linux/riscv64"
			p.Artifact.Subject = p.Subject
		}},
		{"noncanonical-platform", func(p *ScenarioPlan) {
			p.Subject.Platform = "linux-arm64"
			p.Artifact.Subject = p.Subject
		}},
		{"missing-provenance", func(p *ScenarioPlan) { p.Artifact.ProvenanceStatus = "" }},
		{"unavailable-provenance", func(p *ScenarioPlan) { p.Artifact.ProvenanceStatus = "unavailable" }},
		{"artifact-subject-disagreement", func(p *ScenarioPlan) { p.Artifact.Subject.Platform = "linux/amd64" }},
		{"unreviewed-contract", func(p *ScenarioPlan) {
			p.Subject.ContractSHA256 = strings.Repeat("9", 64)
			p.Artifact.Subject = p.Subject
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given one substituted ARM64 metadata field, When normalized,
			// Then admission fails before a process or fixture can launch.
			p := arm64ScenarioMetadataPlan(t)
			tc.change(&p)
			if _, err := normalizeScenarioPlan(p); err == nil {
				t.Fatal("substituted scenario identity admitted")
			}
		})
	}
}

func TestScenarioRejectsReviewedSubjectForDifferentNativeGoPlatform(t *testing.T) {
	// Given a valid reviewed tuple for a different Go execution platform,
	// When entering the runner, Then subject admission fails before consulting
	// a fixture executor, reserving output, or probing native process support.
	p := arm64ScenarioMetadataPlan(t)
	if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" {
		p = scenarioTestPlan(t)
	}
	_, err := RunM2Scenario(context.Background(), p, fixture.State{}, nil)
	if err == nil || !strings.Contains(err.Error(), "scenario subject must match the native Go execution platform") {
		t.Fatalf("cross-native subject was not rejected at entry: %v", err)
	}
}

func TestScenarioFixturePlatformRequiresOneNativeReleaseAndBackend(t *testing.T) {
	// Given literal native identity and fixed engine image metadata, When admitted
	// before runtime work, Then alias normalization never admits translated peers.
	for _, tc := range []struct{ goPlatform, engine, proxy string }{
		{"linux/amd64", "linux/amd64", "ghcr.io/shopify/toxiproxy@sha256:a3e244375123dad8849091bcc59775e188624d3f602db01901f9af855682fef8"},
		{"linux/amd64", "linux/x86_64", "ghcr.io/shopify/toxiproxy@sha256:a3e244375123dad8849091bcc59775e188624d3f602db01901f9af855682fef8"},
		{"linux/arm64", "linux/arm64", "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"},
		{"linux/arm64", "linux/aarch64", "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			state := fixture.State{DockerPlatform: tc.engine, Image: fixture.Image, Proxy: &fixture.ProxyState{Image: tc.proxy}}
			if err := validateScenarioFixturePlatform(tc.goPlatform, tc.goPlatform, state); err != nil {
				t.Fatal("literal native platform rejected", err)
			}
			for _, change := range []string{"other-backend", "unsupported-backend", "expanded-alias", "other-proxy", "wrong-broker-reference", "foreign-native-Go", "kernel-alias-as-Go"} {
				t.Run(change, func(t *testing.T) {
					bad := state
					proxy := *state.Proxy
					bad.Proxy = &proxy
					native := tc.goPlatform
					switch change {
					case "other-backend":
						if tc.goPlatform == "linux/arm64" {
							bad.DockerPlatform = "linux/x86_64"
						} else {
							bad.DockerPlatform = "linux/aarch64"
						}
					case "unsupported-backend":
						bad.DockerPlatform = "linux/riscv64"
					case "expanded-alias":
						bad.DockerPlatform = "linux/arm64/v8"
					case "other-proxy":
						if tc.goPlatform == "linux/arm64" {
							bad.Proxy.Image = fixture.ProxyImage
						} else {
							bad.Proxy.Image = "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"
						}
					case "wrong-broker-reference":
						bad.Image = "apache/kafka:3.9.2"
					case "foreign-native-Go":
						if native == "linux/arm64" {
							native = "linux/amd64"
						} else {
							native = "linux/arm64"
						}
					case "kernel-alias-as-Go":
						native = "linux/aarch64"
					}
					if err := validateScenarioFixturePlatform(tc.goPlatform, native, bad); err == nil {
						t.Fatal("cross-native metadata admitted")
					}
				})
			}
		})
	}
}
