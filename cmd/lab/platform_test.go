package main

import (
	"errors"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
)

func TestNativeVersionRejectsTranslatedAndUnknownKernelPairs(t *testing.T) {
	// Given independently specified native pairs and incompatible/unknown kernels,
	// When admitting a version observation, Then translation never becomes native.
	for _, tc := range []struct {
		target, kernel string
		native         bool
	}{
		{"amd64", "x86_64", true}, {"arm64", "aarch64", true},
		{"amd64", "aarch64", false}, {"arm64", "x86_64", false},
		{"arm64", "arm64", false}, {"amd64", "amd64", false},
		{"386", "x86_64", false}, {"riscv64", "riscv64", false},
		{"arm64", "", false}, {"", "aarch64", false},
	} {
		if got := nativeVersionKernel(tc.target, tc.kernel); got != tc.native {
			t.Fatalf("target=%q kernel=%q native=%v; want %v", tc.target, tc.kernel, got, tc.native)
		}
	}
}

func TestScenarioArtifactBindsPlatformToArchiveAndExecutable(t *testing.T) {
	// These are synthetic metadata objects, never artifact verification or execution.
	for _, tc := range []struct{ request, platform, archive, archiveSHA, binarySHA string }{
		{"linux-amd64", "linux/amd64", "kaferry-v0.6.0-linux-amd64.tar.gz",
			"d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f",
			"becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"},
		{"linux-arm64", "linux/arm64", "kaferry-v0.6.0-linux-arm64.tar.gz",
			"e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2",
			"389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92"},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			// Given one fixed platform tuple, When metadata is projected, Then no
			// digest/name/URL/platform is inherited from the other architecture.
			v := artifact.Verified{Tag: "v0.6.0", Commit: "d7d485b96a52b711cb10d76dca09aa9b155dec5e",
				Platform: tc.request, ArchiveSHA256: tc.archiveSHA, BinarySHA256: tc.binarySHA,
				ContractSHA256: "df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46"}
			got, err := scenarioArtifact(&v, "synthetic recorded metadata only; never executed")
			if err != nil || got.Subject.Platform != tc.platform || got.ArchiveName != tc.archive ||
				got.ArchiveSHA256 != tc.archiveSHA || got.Subject.ExecutableSHA256 != tc.binarySHA ||
				got.PublishedAssetURL != "https://github.com/pagrus7/kaferry/releases/download/v0.6.0/"+tc.archive {
				t.Fatalf("mixed projection: %+v / %v", got, err)
			}
			for _, change := range []struct {
				name  string
				apply func(*artifact.Verified)
			}{
				{"canonical spelling is not a verifier request", func(x *artifact.Verified) { x.Platform = tc.platform }},
				{"unknown request", func(x *artifact.Verified) { x.Platform = "linux-386" }},
				{"changed archive", func(x *artifact.Verified) {
					x.ArchiveSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
				}},
				{"changed binary", func(x *artifact.Verified) {
					x.BinarySHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
				}},
				{"cross-platform tuple", func(x *artifact.Verified) {
					if x.Platform == "linux-amd64" {
						x.Platform = "linux-arm64"
					} else {
						x.Platform = "linux-amd64"
					}
				}},
			} {
				t.Run(change.name, func(t *testing.T) {
					bad := v
					change.apply(&bad)
					projected, err := scenarioArtifact(&bad, "synthetic metadata only")
					if !errors.Is(err, artifact.ErrIdentity) || projected.Subject.Platform != "" {
						t.Fatalf("substituted identity projected: %+v / %v", projected, err)
					}
				})
			}
		})
	}
}
