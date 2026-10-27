//go:build linux

package campaign

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeProcessArchitectureRejectsTranslation(t *testing.T) {
	// Given known Linux machine names, When process admission compares the Go
	// target with the kernel, Then an emulated or unknown pair is rejected.
	for _, tc := range []struct {
		target, kernel string
		accepted       bool
	}{
		{"amd64", "x86_64", true}, {"arm64", "aarch64", true},
		{"amd64", "aarch64", false}, {"arm64", "x86_64", false},
		{"arm64", "arm64", false}, {"amd64", "amd64", false},
		{"riscv64", "riscv64", false}, {"arm64", "", false},
	} {
		err := nativeProcessArchitecture(tc.target, tc.kernel)
		if (err == nil) != tc.accepted {
			t.Fatalf("target=%q kernel=%q accepted=%v error=%v", tc.target, tc.kernel, tc.accepted, err)
		}
	}
}

func TestProcessRejectsOtherArchitectureDigestBeforePathAdmission(t *testing.T) {
	if nativeProcessPlatform() != nil {
		t.Skip("requires a reviewed native Linux kernel/Go pair")
	}
	// Given the other reviewed executable's digest, When release launch admission
	// starts, Then it rejects the substitution before any executable path opens.
	other := "389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92"
	if runtime.GOARCH == "arm64" {
		other = "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := startOwnedProcess(ctx, processPlan{}, other, false)
	if got != nil || err == nil || !strings.Contains(err.Error(), "unreviewed release executable digest") {
		t.Fatalf("other architecture passed byte admission: process=%v error=%v", got, err)
	}
}
