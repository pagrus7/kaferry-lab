package campaign

import (
	"context"
	"encoding/json"
	"testing"
)

func TestLinkedLatencyClassicIdentityRejectsManifestDomainBeforeRemoval(t *testing.T) {
	// Given an otherwise valid classic fixture and independently literal inspect
	// facts, when a selected-manifest field conflicts with the classic config-ID
	// domain, then even lost-test cleanup must refuse before any destruction.
	s, plan, id, raw, _ := driverLatencyCleanupFixture(t, true)
	if _, err := validateLinkCalibrationLatencyContainer(raw, s, plan, id); err != nil {
		t.Fatal("healthy classic ownership control rejected", err)
	}
	var facts map[string]any
	if err := json.Unmarshal(raw, &facts); err != nil {
		t.Fatal(err)
	}
	facts["ImageManifestDescriptor"] = map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"digest":    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"size":      2201,
		"platform":  map[string]string{"os": "linux", "architecture": "arm64"},
	}
	conflicting, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	removals := 0
	result, err := cleanupLinkCalibrationLatency(context.Background(), s, func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "container" && args[1] == "inspect" {
			return conflicting, nil
		}
		if len(args) >= 2 && args[0] == "container" && args[1] == "rm" {
			removals++
			return nil, nil
		}
		t.Fatal("unexpected Docker route", args)
		return nil, nil
	})
	if err == nil || removals != 0 || result.Removed || result.Resolved {
		t.Fatal("ambiguous image authority reached cleanup destruction", removals, result, err)
	}
}
