package evidence

import (
	"math"
	"reflect"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

func measuredM2Control() *m2Control {
	c := newM2Control("healthy")
	c.m.Settings.MeasurementsVersion = 1
	c.worker("w1", "start", "")
	c.worker("w1", "signal", "SIGTERM")
	c.worker("w1", "exit", "")
	c.e[len(c.e)-1].Worker.ResourceUsage = &M2ResourceUsage{Available: true, Source: "os.ProcessState.SysUsage/Linux-rusage", Scope: M2ProcessUsageScope,
		PeakRSSKiB: 1234, PeakRSSBytes: 1_263_616, UserCPUNanoseconds: 1_000_002_000, SystemCPUNanoseconds: 3_000}
	c.worker("w1", "cleanup", "")
	c.settle("final", []int{0, 1, 2}, []identity.Int64{1, 1, 1}, true, false)
	c.finish()
	return c
}

func TestM2MeasurementsDeriveLiteralTimingAndVolumeOffline(t *testing.T) {
	// Given literal wait units, a TERM call at9..10ms and wait at11..12ms.
	c := measuredM2Control()
	// When checking the history, Then derived values preserve that uncertainty.
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict != Pass || r.Measurements == nil || len(r.Measurements.Workers) != 1 {
		t.Fatal(r)
	}
	w := r.Measurements.Workers[0]
	if w.ExitCode == nil || *w.ExitCode != 0 || w.ResourceUsage.PeakRSSBytes != 1_263_616 || w.Shutdown.WaitLatencyLowerNS != 1_000_000 || w.Shutdown.WaitLatencyUpperNS != 3_000_000 || w.Shutdown.WaitOvershootUpperNS != 0 || !w.Shutdown.Available {
		t.Fatalf("incorrect literal timing/units: %+v", w)
	}
	v := r.Measurements.FinalOutput
	if v == nil || v.RequiredInputRecords != 3 || v.ObservedOutputRecords != 3 || v.AmplificationNumerator != 3 || v.AmplificationDenominator != 3 || v.ExcessOutputRecords != 0 {
		t.Fatalf("incorrect fixed-end counts: %+v", v)
	}
	if !reflect.DeepEqual(r, CheckM2(c.m, c.a, c.e)) {
		t.Fatal("measurement recheck changed without changing evidence")
	}
	// The data-only measurement contract does not invent samples for histories
	// that do not declare resource collection.
	legacy := healthyM2Control()
	old := CheckM2(legacy.m, legacy.a, legacy.e)
	if old.Verdict != Pass || old.Measurements != nil {
		t.Fatal(old)
	}
}

func TestM2MissingAndInvalidResourceEvidenceCannotPass(t *testing.T) {
	cases := []struct {
		name    string
		verdict Verdict
		change  func(*m2Control, *M2ResourceUsage)
	}{
		{"missing", Inconclusive, func(c *m2Control, _ *M2ResourceUsage) {
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.Action == "exit" {
					e.Worker.ResourceUsage = nil
				}
			}
		}},
		{"unavailable", Inconclusive, func(_ *m2Control, u *M2ResourceUsage) {
			*u = M2ResourceUsage{Source: u.Source, Scope: u.Scope, Error: "wait accounting unavailable"}
		}},
		{"KiB mistaken for bytes", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.PeakRSSBytes = u.PeakRSSKiB }},
		{"overflow", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.PeakRSSKiB = math.MaxInt64/1024 + 1 }},
		{"negative CPU", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.UserCPUNanoseconds = -1 }},
		{"conflicting error", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.Error = "missing" }},
		{"foreign source", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.Source = "all host processes" }},
		{"unavailable sample", HarnessError, func(_ *m2Control, u *M2ResourceUsage) { u.Available = false; u.Error = "unavailable" }},
		{"wrong lifecycle", HarnessError, func(c *m2Control, u *M2ResourceUsage) {
			for _, e := range c.e {
				if e.Worker != nil && e.Worker.Action == "start" {
					e.Worker.ResourceUsage = u
				}
			}
		}},
		{"undeclared", HarnessError, func(c *m2Control, _ *M2ResourceUsage) { c.m.Settings.MeasurementsVersion = 0 }},
		{"unknown contract", Unsupported, func(c *m2Control, _ *M2ResourceUsage) { c.m.Settings.MeasurementsVersion = 999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given one missing or conflicting retained measurement, When checking,
			// Then neither a successful zero sample nor a data PASS conceals it.
			c := measuredM2Control()
			var usage *M2ResourceUsage
			for _, event := range c.e {
				if event.Worker != nil && event.Worker.Action == "exit" {
					usage = event.Worker.ResourceUsage
				}
			}
			tc.change(c, usage)
			r := CheckM2(c.m, c.a, c.e)
			if r.Verdict != tc.verdict {
				t.Fatalf("got %s want %s: %+v", r.Verdict, tc.verdict, r)
			}
		})
	}
}

func TestM2ShutdownRangesDoNotClaimKernelExitPrecision(t *testing.T) {
	// Given a signal interval1.0..1.1s and Cmd.Wait completion at7.2s.
	h := &m2WorkerHistory{signals: []*M2Worker{{Signal: "SIGTERM", Interval: M2Interval{StartNS: 1_000_000_000, EndNS: 1_100_000_000}}},
		exit: &M2Worker{Reaped: true, Interval: M2Interval{StartNS: 7_200_000_000, EndNS: 7_200_000_000}}}
	// When measuring against6s, Then overshoot is an interval, not kernel timing.
	r := m2ShutdownTiming(h, 6_000_000_000)
	if !r.Available || r.WaitLatencyLowerNS != 6_100_000_000 || r.WaitLatencyUpperNS != 6_200_000_000 || r.WaitOvershootLowerNS != 100_000_000 || r.WaitOvershootUpperNS != 200_000_000 {
		t.Fatal(r)
	}
	h.exit.Interval = M2Interval{StartNS: 1_050_000_000, EndNS: 1_050_000_000}
	r = m2ShutdownTiming(h, 6_000_000_000)
	if !r.Available || r.WaitLatencyLowerNS != 0 || r.WaitLatencyUpperNS != 50_000_000 {
		t.Fatal(r)
	}
	h.signals = append(h.signals, h.signals[0])
	if r = m2ShutdownTiming(h, 6_000_000_000); r.Available || r.Reason == "" {
		t.Fatal(r)
	}
	h.signals = nil
	if r = m2ShutdownTiming(h, 6_000_000_000); r.Available || r.Reason != "no SIGTERM request in this invocation" {
		t.Fatal(r)
	}
}

func TestM2VolumeWithDuplicatesCannotProveMembership(t *testing.T) {
	// Given a complete final snapshot with two copies of A, B, and no C.
	c := measuredM2Control()
	var final m2AuditHistory
	final.complete, final.settled, final.tailCovered = true, true, true
	counts := map[int]identity.Int64{}
	for _, i := range []int{0, 0, 1} {
		position := c.l.Destinations[i]
		position.Offset = counts[i]
		counts[i]++
		final.outputs = append(final.outputs, Output{Destination: position, Record: c.l.Entries[i].Record})
	}
	// When measuring volume, Then ratio1 stays separate from missing membership.
	m := m2Measurements(c.m, c.l, nil, nil, final)
	if m.FinalOutput == nil || m.FinalOutput.AmplificationNumerator != 3 || m.FinalOutput.AmplificationDenominator != 3 {
		t.Fatal(m)
	}
	if missing := unmatchedRequired(c.l.Entries, final.outputs, nil); len(missing) != 1 {
		t.Fatal("control did not omit required input")
	}
	final.complete = false
	if m = m2Measurements(c.m, c.l, nil, nil, final); m.FinalOutput != nil {
		t.Fatal("incomplete output acquired a complete volume summary")
	}
}

func TestM2MeasurementBundleRoundTripNeedsOnlyRecordedFiles(t *testing.T) {
	// Given a closed synthetic measurement history with no worker or brokers.
	c := measuredM2Control()
	dir := t.TempDir() + "/bundle"
	if _, err := WriteM2Bundle(dir, c.m, c.a, c.e); err != nil {
		t.Fatal(err)
	}
	// When the ordinary offline loader checks it twice, Then all measurements
	// and verdicts equal the direct typed check without runtime dependencies.
	want := CheckM2(c.m, c.a, c.e)
	for i := 0; i < 2; i++ {
		if got := LoadAndCheck(dir); !reflect.DeepEqual(got, want) {
			t.Fatalf("bundle measurement mismatch: got %+v want %+v", got, want)
		}
	}
}

func TestM2MeasurementsDoNotInventAbsentOrUnreapedExit(t *testing.T) {
	for _, unreaped := range []bool{false, true} {
		// Given an owned invocation with either no wait or an unreaped placeholder.
		h := &m2WorkerHistory{}
		if unreaped {
			h.exit = &M2Worker{ExitCode: 0, ResourceUsage: &M2ResourceUsage{Available: true}}
		}
		// When deriving an incomplete summary, Then zero never impersonates an
		// actual successful exit and no available wait accounting is copied.
		out := m2Measurements(M2Manifest{}, Ledger{}, []string{"w1"}, map[string]*m2WorkerHistory{"w1": h}, m2AuditHistory{})
		w := out.Workers[0]
		if w.ExitCode != nil || w.ExitSignal != "" || w.ResourceUsage != nil || w.Shutdown.Available {
			t.Fatalf("invented actual outcome from incomplete evidence: %+v", w)
		}
	}
	// A genuinely reaped failed outcome remains distinct from missing evidence.
	c := measuredM2Control()
	for _, event := range c.e {
		if event.Worker != nil && event.Worker.Action == "exit" {
			event.Worker.ExitCode = 1
		}
	}
	r := CheckM2(c.m, c.a, c.e)
	if r.Verdict == Pass || r.Measurements == nil || r.Measurements.Workers[0].ExitCode == nil || *r.Measurements.Workers[0].ExitCode != 1 {
		t.Fatalf("actual failed exit was lost: %+v", r)
	}
}
