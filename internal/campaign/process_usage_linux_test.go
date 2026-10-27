//go:build linux && (amd64 || arm64)

package campaign

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxWaitUsageConvertsKiBAndMicrosecondsExactly(t *testing.T) {
	// Given literal Linux wait accounting, independent of observed Kaferry output.
	usage := &syscall.Rusage{Maxrss: 1234, Utime: syscall.Timeval{Sec: 1, Usec: 2}, Stime: syscall.Timeval{Usec: 3}}
	// When converting the documented units, Then no millisecond/KiB ambiguity remains.
	got := linuxProcessUsage(usage)
	if !got.Available || got.Error != "" || got.PeakRSSKiB != 1234 || got.PeakRSSBytes != 1_263_616 || got.UserCPUNanoseconds != 1_000_002_000 || got.SystemCPUNanoseconds != 3_000 {
		t.Fatalf("bad wait accounting: %+v", got)
	}
	// Zero CPU time is valid at microsecond precision when RSS accounting exists.
	got = linuxProcessUsage(&syscall.Rusage{Maxrss: 1})
	if !got.Available || got.PeakRSSBytes != 1024 || got.UserCPUNanoseconds != 0 || got.SystemCPUNanoseconds != 0 {
		t.Fatal(got)
	}
}
func TestLinuxWaitUsageRejectsMissingInvalidAndOverflowAccounting(t *testing.T) {
	cases := []struct {
		name  string
		usage *syscall.Rusage
	}{
		{name: "missing"},
		{name: "zero peak", usage: &syscall.Rusage{}},
		{name: "negative peak", usage: &syscall.Rusage{Maxrss: -1}},
		{name: "peak byte overflow", usage: &syscall.Rusage{Maxrss: math.MaxInt64/1024 + 1}},
		{name: "negative seconds", usage: &syscall.Rusage{Maxrss: 1, Utime: syscall.Timeval{Sec: -1}}},
		{name: "negative microseconds", usage: &syscall.Rusage{Maxrss: 1, Stime: syscall.Timeval{Usec: -1}}},
		{name: "invalid microseconds", usage: &syscall.Rusage{Maxrss: 1, Utime: syscall.Timeval{Usec: 1_000_000}}},
		{name: "seconds overflow", usage: &syscall.Rusage{Maxrss: 1, Utime: syscall.Timeval{Sec: math.MaxInt64/1_000_000_000 + 1}}},
		{name: "fraction overflow", usage: &syscall.Rusage{Maxrss: 1, Stime: syscall.Timeval{Sec: math.MaxInt64 / 1_000_000_000, Usec: 999_999}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given missing or malformed kernel units, When conversion is attempted,
			// Then an explicit unavailable measurement replaces any plausible zero sample.
			got := linuxProcessUsage(tc.usage)
			if got.Available || got.Error == "" {
				t.Fatalf("invalid accounting admitted: %+v", got)
			}
		})
	}
}
func TestOwnedCalibrationRetainsActualWaitResourceUsage(t *testing.T) {
	// Given an already supported owned synthetic helper, not the release subject.
	p, _ := calibrationProcess(t, "wait", 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// When TERM is requested on the TERM-ignoring calibration child, then KILL
	// ends it and the sole reaper completes Cmd.Wait.
	if err := p.Signal(ctx, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(ctx, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	exit, err := p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	// Then the exit receipt retains actual nonzero Linux peak RSS and CPU units;
	// repeated wait and the persisted receipt must not fabricate a fresh sample.
	usage := exit.ResourceUsage
	if !exit.Reaped || !usage.Available || usage.Error != "" || usage.PeakRSSKiB <= 0 || usage.PeakRSSBytes != usage.PeakRSSKiB*1024 || usage.UserCPUNanoseconds < 0 || usage.SystemCPUNanoseconds < 0 {
		t.Fatalf("actual helper accounting unavailable: %+v", exit)
	}
	again, err := p.Wait(ctx)
	if err != nil || again.ResourceUsage != usage {
		t.Fatalf("repeat wait changed usage: %+v / %v", again, err)
	}
	raw, err := os.ReadFile(filepath.Join(p.plan.Directory, "exit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted processExit
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.ResourceUsage != usage || persisted.Identity != exit.Identity {
		t.Fatalf("persisted measurement differs: %+v", persisted)
	}
}
