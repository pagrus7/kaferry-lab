package evidence

import (
	"fmt"
	"math"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

const M2ProcessUsageScope = "Linux wait accounting for the owned direct child; waited-descendant CPU may be included. Peak RSS is not summed process-tree memory or a tracked-work cap."

// Available is false when the wait result cannot supply valid resource units.
// Zero CPU is possible at kernel precision; unavailable accounting stays explicit.
type M2ResourceUsage struct {
	Available            bool           `json:"available"`
	Source               string         `json:"source"`
	Scope                string         `json:"scope"`
	Error                string         `json:"error"`
	PeakRSSKiB           identity.Int64 `json:"peak_rss_kib"`
	PeakRSSBytes         identity.Int64 `json:"peak_rss_bytes"`
	UserCPUNanoseconds   identity.Int64 `json:"user_cpu_nanoseconds"`
	SystemCPUNanoseconds identity.Int64 `json:"system_cpu_nanoseconds"`
}

type M2ShutdownTiming struct {
	BudgetNS             identity.Int64 `json:"budget_ns"`
	Available            bool           `json:"available"`
	Reason               string         `json:"reason,omitempty"`
	WaitLatencyLowerNS   identity.Int64 `json:"wait_latency_lower_ns"`
	WaitLatencyUpperNS   identity.Int64 `json:"wait_latency_upper_ns"`
	WaitOvershootLowerNS identity.Int64 `json:"wait_overshoot_lower_ns"`
	WaitOvershootUpperNS identity.Int64 `json:"wait_overshoot_upper_ns"`
}

type M2WorkerMeasurement struct {
	ExitSignal    string           `json:"exit_signal"`
	ExitCode      *int             `json:"exit_code"`
	WorkerID      string           `json:"worker_id"`
	ResourceUsage *M2ResourceUsage `json:"resource_usage"`
	Shutdown      M2ShutdownTiming `json:"shutdown"`
}

type M2OutputVolume struct {
	RequiredInputRecords     identity.Int64 `json:"required_input_records"`
	ObservedOutputRecords    identity.Int64 `json:"observed_output_records"`
	AmplificationNumerator   identity.Int64 `json:"amplification_numerator"`
	AmplificationDenominator identity.Int64 `json:"amplification_denominator"`
	ExcessOutputRecords      identity.Int64 `json:"excess_output_records"`
	IndistinguishableInputs  bool           `json:"indistinguishable_inputs"`
}

// The checker derives these values from the same typed lifecycle and complete
// final scan it checks for safety; there is no separately trusted summary input.
type M2Measurements struct {
	Workers     []M2WorkerMeasurement `json:"workers"`
	FinalOutput *M2OutputVolume       `json:"final_output,omitempty"`
	Limitations []string              `json:"limitations"`
}

func m2UsageValid(u M2ResourceUsage) error {
	if u.Source != "os.ProcessState.SysUsage/Linux-rusage" || u.Scope != M2ProcessUsageScope {
		return fmt.Errorf("resource accounting must identify Linux owned-child wait units and scope")
	}
	if !u.Available {
		if u.Error == "" || u.PeakRSSKiB != 0 || u.PeakRSSBytes != 0 || u.UserCPUNanoseconds != 0 || u.SystemCPUNanoseconds != 0 {
			return fmt.Errorf("unavailable accounting requires a reason and no claimed samples")
		}
		return nil
	}
	if u.Error != "" || u.PeakRSSKiB <= 0 || u.PeakRSSKiB > math.MaxInt64/1024 || u.PeakRSSBytes != u.PeakRSSKiB*1024 || u.UserCPUNanoseconds < 0 || u.SystemCPUNanoseconds < 0 {
		return fmt.Errorf("resource accounting has conflicting availability, invalid units or overflow")
	}
	return nil
}

func m2ShutdownTiming(h *m2WorkerHistory, budget identity.Int64) M2ShutdownTiming {
	unavailable := func(reason string) M2ShutdownTiming { return M2ShutdownTiming{Reason: reason} }
	var term *M2Worker
	for _, s := range h.signals {
		if s.Signal == "SIGTERM" {
			if term != nil {
				return unavailable("multiple SIGTERM intervals cannot identify one shutdown request")
			}
			term = s
		}
	}
	if term == nil {
		return unavailable("no SIGTERM request in this invocation")
	}
	if term.Error != "" || h.exit == nil || !h.exit.Reaped || h.exit.Error != "" || h.exit.LogsTruncated || budget <= 0 || h.exit.Interval.StartNS < term.Interval.StartNS {
		return unavailable("successful signal and complete wait evidence are required")
	}
	lower := max(identity.Int64(0), h.exit.Interval.StartNS-term.Interval.EndNS)
	upper := h.exit.Interval.EndNS - term.Interval.StartNS
	return M2ShutdownTiming{BudgetNS: budget, Available: true, WaitLatencyLowerNS: lower, WaitLatencyUpperNS: upper,
		WaitOvershootLowerNS: max(identity.Int64(0), lower-budget), WaitOvershootUpperNS: max(identity.Int64(0), upper-budget)}
}

func m2Measurements(m M2Manifest, ledger Ledger, order []string, workers map[string]*m2WorkerHistory, final m2AuditHistory) *M2Measurements {
	out := &M2Measurements{Workers: []M2WorkerMeasurement{}, Limitations: []string{
		M2ProcessUsageScope,
		"Shutdown ranges compare the retained SIGTERM call interval with Cmd.Wait completion, including bounded log draining and controller scheduling. Observed wait overshoot is not proof of kernel-exit deadline overshoot; a forced exit is not graceful shutdown.",
		"Amplification is observed output volume divided by required input volume after a settled complete scan. Replay may compensate for loss in aggregate counts; a ratio of one does not prove membership or acknowledgments. The separate property checks decide bytes, routing, membership and saved prefixes.",
	}}
	for _, id := range order {
		h := workers[id]
		worker := M2WorkerMeasurement{WorkerID: id, Shutdown: m2ShutdownTiming(h, m.Settings.ShutdownTimeoutNS)}
		if h.exit != nil && h.exit.Reaped {
			worker.ResourceUsage = h.exit.ResourceUsage
			code := h.exit.ExitCode
			worker.ExitSignal, worker.ExitCode = h.exit.Signal, &code
		}
		out.Workers = append(out.Workers, worker)
	}
	if final.complete && final.settled && final.tailCovered && len(ledger.Entries) > 0 {
		input, output := identity.Int64(len(ledger.Entries)), identity.Int64(len(final.outputs))
		out.FinalOutput = &M2OutputVolume{RequiredInputRecords: input, ObservedOutputRecords: output,
			AmplificationNumerator: output, AmplificationDenominator: input,
			ExcessOutputRecords: max(identity.Int64(0), output-input), IndistinguishableInputs: hasIndistinguishable(ledger.Entries)}
	}
	return out
}
