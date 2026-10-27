package campaign

import (
	"context"
	"strings"
	"testing"
)

func TestProcessReleaseRejectsUnsupportedPlatform(t *testing.T) {
	if nativeProcessPlatform() == nil {
		t.Skip("native runtime lifecycle calibration requires a supported Linux architecture")
	}
	// Given an unsupported execution platform, no executable may be substituted.
	_, err := startReleaseProcess(context.Background(), processPlan{})
	// Then launch fails at the platform boundary before inspecting a path.
	if err == nil || !strings.Contains(err.Error(), "native Linux") {
		t.Fatalf("unsupported platform: %v", err)
	}
}
