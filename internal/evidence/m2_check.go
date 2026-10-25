package evidence

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

type m2WorkerHistory struct {
	identity             M2WorkerIdentity
	start, exit, cleanup *M2Worker
	signals              []*M2Worker
}

type m2AuditHistory struct {
	seq                                      identity.Int64
	audit                                    M2Audit
	outputs                                  []Output
	complete, settled, tailCovered, assigned bool
}

// CheckM2 checks typed observations only. It performs no I/O. ArtifactMetadata
// retains its v1 verification contract; no v1 trigger/fault history is created.
func CheckM2(m M2Manifest, artifact ArtifactMetadata, events []M2Event) Result {
	r := m2Result(m)
	bad := func(code, message string) Result {
		r.Verdict = HarnessError
		r.Findings = append(r.Findings, Finding{Code: code, Message: message})
		return r
	}
	unsupported := func(code, message string) Result {
		r.Verdict = Unsupported
		r.Findings = append(r.Findings, Finding{Code: code, Message: message})
		return r
	}
	missing, violated := false, false
	need := func(condition bool, code, message string) {
		if !condition {
			missing = true
			r.Findings = append(r.Findings, Finding{Code: code, Message: message})
		}
	}
	violation := func(code, property, message, audit, entry string) {
		violated = true
		r.Findings = append(r.Findings, Finding{Code: code, Property: property, Message: message, AuditID: audit, EntryID: entry})
	}
	if m.SchemaVersion != M2SchemaVersion || m.CheckerVersion != M2CheckerVersion {
		return unsupported("checker_version", "unsupported M2 schema/checker contract")
	}
	switch m.ScenarioID {
	case "healthy", "repeated-kill", "delivery-stop", "delivery-threshold", "source-startup", "source-save":
	default:
		return unsupported("scenario", "unknown M2 scenario")
	}
	if m.Scope != "kafka" {
		return unsupported("scope", "M2 supports finite Kafka topic-to-topic observations only")
	}
	if m.RunID == "" || m.Given == "" || m.When == "" || m.Then == "" || m.BudgetNS <= 0 || (m.ScenarioID != "delivery-threshold" && (m.Group == "" || m.FinalAuditID == "")) {
		return bad("manifest_required", "run/group, Given/When/Then, final audit and bounded duration are required")
	}
	if m.BudgetNS > 600_000_000_000 {
		return unsupported("checker_capacity", "M2 supports campaigns bounded to ten minutes per scenario")
	}
	// Reuse identity validation, without routing the M2 history through v1.
	identityManifest := Manifest{Namespace: m.Namespace, Subject: m.Subject, Scope: m.Scope, LabSource: m.LabSource, Environment: m.Environment}
	if err := validateExecutionMetadata(identityManifest); err != nil {
		return bad("execution_metadata", err.Error())
	}
	if verdict, code, err := validateArtifact(identityManifest, artifact); err != nil {
		r.Verdict = verdict
		r.Findings = append(r.Findings, Finding{Code: code, Message: err.Error()})
		return r
	}
	if m.ScenarioID == "delivery-threshold" {
		return unsupported("threshold_observer", "independent accepted-work/threshold observation has not been calibrated for the negotiated Kafka Produce protocol")
	}
	if m.Settings.MeasurementsVersion != 0 && m.Settings.MeasurementsVersion != 1 {
		return unsupported("measurements_version", "unsupported M2 measurement contract")
	}
	if m.Settings.Routing != "PRESERVE" && m.Settings.Routing != "KEY" {
		return unsupported("routing", "M2 supports PRESERVE and KEY routing only")
	}
	if m.Settings.Args == nil || m.Settings.Environment == nil || len(m.Settings.Args) == 0 || m.Settings.DeliveryTimeoutNS <= 0 || m.Settings.ShutdownTimeoutNS <= 0 || m.Settings.RecordThreshold < 0 {
		return bad("settings", "record exact worker arguments/environment and positive delivery/shutdown timeouts")
	}
	if err := m2SettingsValid(m); err != nil {
		return bad("settings_binding", err.Error())
	}
	if len(events) == 0 || len(events) > maxEvents || events[0].Kind != "ledger" || events[0].Ledger == nil {
		return bad("ledger_order", "first event must contain the complete finite source ledger")
	}
	ledger := *events[0].Ledger
	if len(ledger.Entries) > 1024 || len(ledger.Partitions) > 256 || len(ledger.Destinations) > 256 {
		return unsupported("checker_capacity", "M2 supports 1024 input records and 256 source/destination partitions")
	}
	if err := validateLedger(ledger); err != nil {
		return bad("ledger_invalid", err.Error())
	}
	if err := m2Routes(ledger, m.Settings.Routing); err != nil {
		return bad("ledger_routing", err.Error())
	}
	selected := map[int32]bool{}
	bySignature := map[string][]LedgerEntry{}
	for _, entry := range ledger.Entries {
		if entry.Archive != nil || entry.Disposition != "required" {
			return unsupported("ledger_scope", "M2 admits finite nontransactional required Kafka records only")
		}
		selected[entry.Source.Partition] = true
		signature, _ := recordSignature(entry.Record)
		bySignature[signature] = append(bySignature[signature], entry)
	}
	need(len(selected) >= 3, "selected_partitions", "M2 requires verified input in at least three selected partitions")
	if hasIndistinguishable(ledger.Entries) {
		r.Limitations = append(r.Limitations, "Identical bytes are checked for aggregate multiplicity; replay may hide loss of an indistinguishable occurrence.")
	}
	workers := map[string]*m2WorkerHistory{}
	workerOrder := []string{}
	brokers := map[string][]M2Broker{}
	audits := map[string]m2AuditHistory{}
	pending := map[string][]Output{}
	positions := map[identity.SourcePosition]string{}
	episodes := []M2Episode{}
	diagnostics := []M2Diagnostic{}
	var verifiedAt identity.Int64 = -1
	var elapsed identity.Int64
	finished, finals := false, 0
	argsRaw, _ := json.Marshal(m.Settings.Args)
	envRaw, _ := json.Marshal(m.Settings.Environment)
	for i, event := range events {
		if event.Seq != identity.Int64(i+1) || event.RunID != m.RunID || event.ElapsedNS < elapsed || event.ElapsedNS < 0 {
			return bad("event_identity", fmt.Sprintf("event %d has conflicting sequence/run/monotonic time", i+1))
		}
		elapsed = event.ElapsedNS
		need(elapsed <= m.BudgetNS, "run_budget", "an observation exceeds the recorded experiment duration")
		switch event.Kind {
		case "ledger", "inputs_verified", "output", "audit", "worker", "broker", "episode", "diagnostic", "run_finished":
		default:
			return unsupported("event_kind", "unknown M2 event kind")
		}
		if !validM2Payload(event) {
			return bad("event_payload", "unknown event kind or conflicting/missing typed payload")
		}
		switch event.Kind {
		case "ledger":
			if i != 0 {
				return bad("ledger_duplicate", "prepared ledger cannot be replaced")
			}
		case "inputs_verified":
			v := event.Inputs
			if !m2Interval(v.Interval, elapsed) {
				return bad("input_interval", "invalid input verification interval")
			}
			if !reflect.DeepEqual(v.Ledger, ledger) {
				return bad("input_identity", "independent input scan does not match the prepared ledger")
			}
			need(v.Complete && v.Error == "" && v.Method == "independent_source_scan", "input_unverified", "complete independent source readback is required")
			if v.Complete && v.Error == "" && v.Method == "independent_source_scan" {
				verifiedAt = v.Interval.EndNS
			}
		case "worker":
			w := event.Worker
			if !m2Interval(w.Interval, elapsed) || w.LocalElapsedNS < 0 {
				return bad("worker_interval", "invalid worker observation interval")
			}
			if w.ResourceUsage != nil {
				if m.Settings.MeasurementsVersion != 1 || w.Action != "exit" {
					return bad("resource_usage", "wait accounting belongs only to an exit under measurement contract 1")
				}
				if err := m2UsageValid(*w.ResourceUsage); err != nil {
					return bad("resource_usage", err.Error())
				}
			}
			if m.Settings.MeasurementsVersion == 1 && w.Action == "exit" {
				need(w.ResourceUsage != nil && w.ResourceUsage.Available, "resource_usage_missing", "this history requires actual owned-child Linux wait resource accounting")
			}
			id := w.Identity
			if id.WorkerID == "" || id.PID <= 0 || !m2Ticks(id.StartTicks) || id.ExecutableSHA256 != m.Subject.ExecutableSHA256 || id.ArgsSHA256 != digest(argsRaw) || id.EnvironmentSHA256 != digest(envRaw) {
				return bad("worker_identity", "worker ownership/configuration does not match this run's verified executable and settings")
			}
			h := workers[id.WorkerID]
			if w.Action == "start" {
				if len(workers) >= 32 {
					return unsupported("checker_capacity", "M2 supports at most 32 worker invocations per scenario")
				}
				if h != nil {
					return bad("worker_duplicate", "worker IDs name distinct invocations and cannot be reused")
				}
				for _, previous := range workers {
					if previous.exit == nil {
						return bad("worker_overlap", "M2 starts only one owned group worker at a time")
					}
					if previous.identity.PID == id.PID && previous.identity.StartTicks == id.StartTicks {
						return bad("worker_duplicate", "different worker IDs cannot identify the same OS invocation")
					}
				}
				h = &m2WorkerHistory{identity: id, start: w}
				workers[id.WorkerID] = h
				workerOrder = append(workerOrder, id.WorkerID)
			} else if h == nil || h.identity != id {
				return bad("worker_identity", "worker action does not match a previously owned invocation")
			}
			need(w.Error == "" && !w.LogsTruncated, "worker_evidence", "worker observation failed or bounded logs were truncated")
			switch w.Action {
			case "start":
				need(verifiedAt >= 0 && verifiedAt <= w.Interval.StartNS, "input_before_worker", "worker must start after independent verification of the finite input")
			case "signal":
				if h.exit != nil || w.Interval.StartNS < h.start.Interval.EndNS {
					return bad("signal_order", "signal must affect a live owned invocation")
				}
				if w.Signal != "SIGKILL" && w.Signal != "SIGTERM" && w.Signal != "SIGSTOP" && w.Signal != "SIGCONT" {
					return unsupported("signal", "unknown process signal")
				}
				if w.Signal == "SIGSTOP" {
					need(w.ObservedState == "T" || w.ObservedState == "t", "suspend_unobserved", "SIGSTOP requires independently observed stopped process state")
				}
				h.signals = append(h.signals, w)
			case "exit":
				if h.exit != nil || w.Interval.StartNS < h.start.Interval.EndNS {
					return bad("exit_order", "wait result is duplicated or precedes worker start")
				}
				need(w.Reaped, "worker_unreaped", "worker exit requires an actual completed wait")
				h.exit = w
			case "cleanup":
				if h.exit == nil || h.cleanup != nil || w.Interval.StartNS < h.exit.Interval.EndNS {
					return bad("cleanup_order", "worker cleanup must follow its completed wait exactly once")
				}
				need(w.Reaped, "cleanup_unreaped", "worker cleanup must retain completed wait evidence")
				h.cleanup = w
			default:
				return unsupported("worker_action", "unknown worker lifecycle action")
			}
		case "broker":
			b := *event.Broker
			if err := m2BrokerValid(b, m.RunID, elapsed); err != nil {
				return bad("broker_observation", err.Error())
			}
			cluster := ledger.Partitions[0].Source.Cluster
			if b.Identity.Role == "destination" {
				cluster = ledger.Destinations[0].Cluster
			}
			if b.Identity.ClusterID != cluster {
				return bad("broker_cluster", "broker observation does not identify the ledger's source/destination cluster")
			}
			history := brokers[b.Identity.Role]
			if len(history) >= 128 {
				return unsupported("checker_capacity", "M2 supports at most 128 broker observations per role")
			}
			if len(history) == 0 {
				if b.Action != "inspect" {
					return bad("broker_ownership", "first broker observation must establish owned identity")
				}
			} else if history[0].Identity != b.Identity {
				return bad("broker_identity", "broker identity changed within a run")
			}
			if len(history) > 0 && b.Interval.StartNS < history[len(history)-1].Interval.EndNS {
				return bad("broker_order", "owned broker observations overlap or go backwards")
			}
			switch b.Action {
			case "inspect", "pause", "restore", "restart", "cleanup":
			default:
				return unsupported("broker_action", "unknown broker action")
			}
			need(b.Error == "", "broker_error", "owned broker action or evidence collection failed")
			if !b.Removed {
				need(b.State.RunningPresent && b.State.PausedPresent && b.State.Running && b.State.LoopbackBound, "broker_state", "broker state and loopback ownership must be independently observed")
				if b.Action == "pause" {
					need(b.State.Paused && m2ProbeUnavailable(b.Probe), "pause_unreached", "pause requires Docker paused state and independent Kafka transport impairment")
				} else {
					need(!b.State.Paused && m2ProbeAvailable(b.Probe), "broker_unavailable", "available broker state requires a successful independent Kafka API probe")
				}
			}
			brokers[b.Identity.Role] = append(history, b)
		case "output":
			o := *event.Output
			if verifiedAt < 0 {
				return bad("unverified_output", "output observation precedes independent input verification")
			}
			if _, exists := audits[o.AuditID]; exists || o.AuditID == "" {
				return bad("output_audit", "output lacks a new unfinished audit identity")
			}
			if err := validatePosition(o.Destination); err != nil {
				return bad("output_identity", err.Error())
			}
			sig, err := recordSignature(o.Record)
			if err != nil {
				return bad("output_record", err.Error())
			}
			if old, exists := positions[o.Destination]; exists && old != sig {
				return bad("output_conflict", "audits conflict at the same full destination position")
			}
			positions[o.Destination] = sig
			pending[o.AuditID] = append(pending[o.AuditID], o)
			if len(pending[o.AuditID]) > 16384 {
				return unsupported("checker_capacity", "M2 supports at most 16384 output observations per audit")
			}
		case "audit":
			a := *event.Audit
			if len(audits) >= 96 {
				return unsupported("checker_capacity", "M2 supports at most 96 complete audits per scenario")
			}
			if a.ID == "" {
				return bad("audit_identity", "audit ID is required")
			}
			if _, exists := audits[a.ID]; exists {
				return bad("audit_duplicate", "audit IDs cannot be reused")
			}
			if !m2Interval(a.ScanInterval, elapsed) || !m2Interval(a.SavedInterval, elapsed) || !m2Interval(a.GroupInterval, elapsed) || a.ScanInterval.EndNS > a.SavedInterval.StartNS || a.ScanInterval.EndNS > a.GroupInterval.StartNS {
				return bad("audit_interval", "full output scan must precede its separate saved-position observation")
			}
			assigned, err := m2GroupAssigned(a.Group, m.Group, ledger.Partitions[0].Source.Topic)
			if err != nil {
				return bad("group_observation", err.Error())
			}
			if a.Mode != "snapshot" && a.Mode != "settled" {
				return unsupported("audit_mode", "unknown M2 audit mode")
			}
			v1Audit := Audit{ID: a.ID, Kind: "snapshot", Scans: a.Scans}
			seen := map[partitionKey]bool{}
			for _, saved := range a.Saved {
				if saved.Group != m.Group || seen[key(saved.Source)] || (saved.Present && saved.Source.Offset < 0) || (!saved.Present && saved.Source.Offset != -1) {
					return bad("saved_identity", "saved positions must distinguish absent -1 from present next zero and retain the exact group")
				}
				seen[key(saved.Source)] = true
				found := false
				for _, p := range ledger.Partitions {
					if key(p.Source) == key(saved.Source) {
						found = true
					}
				}
				if !found {
					return bad("saved_identity", "saved position belongs to an unprepared source identity")
				}
				need(saved.ErrorCode == 0, "saved_error", "OffsetFetch returned a partition error")
				if saved.Present {
					v1Audit.Saved = append(v1Audit.Saved, SavedPosition{Source: saved.Source, Group: saved.Group, Proof: "typed OffsetFetch observation"})
				}
			}
			outputs := pending[a.ID]
			delete(pending, a.ID)
			if err := validateAudit(v1Audit, outputs, ledger, m.Group); err != nil {
				return bad("audit_invalid", err.Error())
			}
			complete := len(a.Saved) == len(ledger.Partitions)
			tailCovered := true
			for _, scan := range a.Scans {
				complete = complete && scan.Complete && scan.Reached == scan.End && scan.StableEnd >= scan.End && scan.Proof != ""
				tailCovered = tailCovered && scan.StableEnd == scan.End
			}
			need(complete, "audit_incomplete", "audit requires every complete fixed-end destination scan and all saved-position observations")
			settled := false
			if a.Mode == "settled" {
				lastExit := identity.Int64(-1)
				stopped := len(workers) > 0
				for _, w := range workers {
					if w.exit == nil || !w.exit.Reaped || w.exit.Interval.EndNS > a.ScanInterval.StartNS {
						stopped = false
					} else if w.exit.Interval.EndNS > lastExit {
						lastExit = w.exit.Interval.EndNS
					}
				}
				settled = verifiedAt >= 0 && verifiedAt <= a.ScanInterval.StartNS && tailCovered && stopped && m2RestartAfter(brokers["destination"], lastExit, a.ScanInterval.StartNS)
				if m.ScenarioID == "source-save" || m.ScenarioID == "source-startup" {
					settled = settled && m2RestartAfter(brokers["source"], lastExit, a.ScanInterval.StartNS)
				}
				// Re-read the finite input after broker stabilization; a broker
				// retention failure must not become a product-loss accusation.
				for _, role := range []string{"source", "destination"} {
					for _, b := range brokers[role] {
						if b.Action == "restart" && b.Interval.EndNS > verifiedAt {
							settled = false
						}
					}
				}
				need(settled, "pending_output", "settled audit requires stopped/reaped workers, destination restart, applicable source restart and verified retained input")
			}
			if a.Final {
				finals++
				need(a.ID == m.FinalAuditID && a.Mode == "settled", "final_audit", "manifest final audit must be the settled audit")
			}
			audits[a.ID] = m2AuditHistory{seq: event.Seq, audit: a, outputs: outputs, complete: complete, settled: settled, tailCovered: tailCovered, assigned: assigned}
		case "episode":
			e := *event.Episode
			if len(episodes) >= 32 {
				return unsupported("checker_capacity", "M2 supports at most 32 fault episodes per scenario")
			}
			if e.ID == "" {
				return bad("episode_identity", "episode ID is required")
			}
			for _, old := range episodes {
				if old.ID == e.ID {
					return bad("episode_duplicate", "episode IDs cannot be reused")
				}
			}
			switch e.Kind {
			case "unresolved-kill", "visible-unsaved-kill", "delivery-stop", "delivery-threshold", "source-startup", "source-save":
			default:
				return unsupported("episode_kind", "unknown compiled M2 episode kind")
			}
			episodes = append(episodes, e)
		case "diagnostic":
			d := *event.Diagnostic
			if !m2Interval(d.Interval, elapsed) || workers[d.WorkerID] == nil || d.Proof == "" {
				return bad("diagnostic_identity", "diagnostic requires an owned worker, bounded interval and retained proof")
			}
			switch d.Kind {
			case "delivery-timeout", "startup-failure", "save-failure", "threshold-drain":
			case "unsupported-observation":
				need(false, "unsupported_observation", d.Proof)
			default:
				return unsupported("diagnostic_kind", "unknown diagnostic category")
			}
			diagnostics = append(diagnostics, d)
		case "run_finished":
			if finished || i != len(events)-1 {
				return bad("finish_order", "run_finished must be the final event exactly once")
			}
			finished = true
			need(!event.Finished.TimedOut && event.Finished.CleanupComplete && event.Finished.Proof != "", "run_cleanup", "experiment must finish within budget with independently recorded cleanup")
		}
	}
	if len(pending) != 0 {
		return bad("unfinalized_output", "output refers to an audit absent from the closed history")
	}
	need(finished && finals == 1, "finish_missing", "one closed run and exactly one final settled audit are required")
	_, hasFinal := audits[m.FinalAuditID]
	need(hasFinal, "final_missing", "manifest final audit is absent")
	if hasFinal {
		final := audits[m.FinalAuditID].audit
		need(m2LatestAudit(audits, elapsed) == final.ID, "final_stale", "the final audit must be the last complete observation")
		for _, id := range workerOrder {
			w := workers[id]
			need(w.exit != nil && w.exit.Interval.EndNS <= final.ScanInterval.StartNS, "worker_after_final", "final scan must follow every owned worker exit")
		}
		for _, role := range []string{"source", "destination"} {
			for _, b := range brokers[role] {
				need((b.Action != "pause" && b.Action != "restart") || b.Interval.EndNS <= final.ScanInterval.StartNS, "fault_after_final", "final scan must follow all service faults and stabilization restarts")
			}
		}
	}
	need(len(workers) > 0, "worker_missing", "no released worker invocation was observed")
	for _, id := range workerOrder {
		w := workers[id]
		need(w.exit != nil && w.cleanup != nil && w.exit.Reaped && w.cleanup.Reaped, "cleanup_missing", "every owned worker must be waited and cleaned before finalization")
	}
	for _, role := range []string{"source", "destination"} {
		h := brokers[role]
		ok := len(h) > 0
		if ok {
			b := h[len(h)-1]
			ok = b.Error == "" && (b.Removed || !b.State.Paused && b.State.Running && m2ProbeAvailable(b.Probe))
		}
		need(ok, "broker_cleanup", "source and destination must finish restored and independently available or observed removed")
	}
	if len(brokers["source"]) > 0 && len(brokers["destination"]) > 0 {
		s, d := brokers["source"][0].Identity, brokers["destination"][0].Identity
		if s.ContainerID == d.ContainerID || s.Endpoint == d.Endpoint || s.ClusterID == d.ClusterID {
			return bad("broker_isolation", "M2 requires two distinct owned broker containers, endpoints and Kafka clusters")
		}
		if err := m2SQLValid(m, ledger, s.Endpoint, d.Endpoint); err != nil {
			return unsupported("sql_scope", err.Error())
		}
	}
	lagKillCount, visibleCount := 0, 0
	killedWorkers := map[string]bool{}
	for _, e := range episodes {
		w := workers[e.WorkerID]
		if w == nil {
			return bad("episode_worker", "episode refers to an unknown worker")
		}
		if e.Kind == "unresolved-kill" || e.Kind == "visible-unsaved-kill" {
			if m.ScenarioID != "repeated-kill" {
				return bad("episode_scenario", "kill episode belongs only to repeated-kill")
			}
			if killedWorkers[e.WorkerID] {
				return bad("episode_duplicate", "one process death cannot satisfy two required crash episodes")
			}
			killedWorkers[e.WorkerID] = true
			a, exists := audits[e.TriggerAuditID]
			signal := m2Signal(w, "SIGKILL")
			trigger := exists && a.complete && a.tailCovered && a.assigned && a.audit.ScanInterval.StartNS >= w.start.Interval.EndNS && signal != nil && a.audit.SavedInterval.EndNS <= signal.Interval.StartNS && a.audit.GroupInterval.EndNS <= signal.Interval.StartNS && m2LatestAudit(audits, signal.Interval.StartNS) == a.audit.ID
			lagging := exists && len(unmatchedRequired(ledger.Entries, a.outputs, nil)) > 0
			need(trigger && (e.Kind != "unresolved-kill" || lagging), "kill_trigger", "kill requires a complete pre-request audit covering the observed tail and stable assignment; unresolved kills also require missing output")
			fresh := false
			if exists && signal != nil {
				fresh = m2TriggerFresh(events, a, signal.Interval.StartNS)
				need(fresh, "trigger_changed", "newer raw output or scan observations precede the kill request; the selected trigger audit must be refreshed")
			}
			killed := signal != nil && w.exit != nil && w.exit.Reaped && w.exit.Signal == "SIGKILL" && w.exit.ExitCode == -1 && signal.Interval.StartNS <= w.exit.Interval.EndNS
			need(killed, "kill_unreached", "actual wait must confirm the requested SIGKILL on the same owned invocation")
			if trigger && fresh && killed && lagging {
				lagKillCount++
			}
			replacement := workers[e.RecoveryWorkerID]
			need(replacement != nil && replacement != w && w.exit != nil && replacement.start.Interval.StartNS >= w.exit.Interval.EndNS, "kill_recovery", "each kill requires a distinct same-configuration replacement after its completed wait")
			stopped, exists := audits[e.StoppedAuditID]
			need(exists && stopped.complete && stopped.settled && w.exit != nil && stopped.audit.ScanInterval.StartNS >= w.exit.Interval.EndNS && (replacement == nil || stopped.audit.SavedInterval.EndNS <= replacement.start.Interval.StartNS), "kill_audit", "each crash needs a settled safety audit before its replacement starts")
			if e.Kind == "visible-unsaved-kill" {
				v, ok := audits[e.VisibleAuditID]
				visible := ok && e.VisibleAuditID == e.TriggerAuditID && v.complete && v.audit.ScanInterval.StartNS >= w.start.Interval.EndNS && m2VisibleUnsaved(ledger, v) && signal != nil && max(v.audit.SavedInterval.EndNS, v.audit.GroupInterval.EndNS) <= signal.Interval.StartNS && m2LatestAudit(audits, signal.Interval.StartNS) == v.audit.ID && m2TriggerFresh(events, v, signal.Interval.StartNS)
				need(visible, "visible_unsaved", "the latest pre-kill trigger audit must itself observe visible destination bytes followed by a saved-position sample below that record")
				if trigger && killed && visible {
					visibleCount++
				}
			}
		} else {
			if e.Kind != m.ScenarioID {
				return bad("episode_scenario", "episode kind differs from compiled scenario")
			}
			role := "source"
			if e.Kind == "delivery-stop" || e.Kind == "delivery-threshold" {
				role = "destination"
			}
			pause, restore := m2Outage(brokers[role], w)
			need(pause != nil && restore != nil, "outage_unreached", "case requires independently observed owned service pause and restoration around the worker")
			if e.Kind == "source-startup" {
				need(pause != nil && restore != nil && pause.Interval.EndNS <= w.start.Interval.StartNS && restore.Request.StartNS >= w.start.Interval.EndNS, "startup_unreached", "inaccessible source must be independently observed before worker start and restored afterwards")
				failed := w.exit != nil && w.exit.Reaped && w.exit.ExitCode == 1 && w.exit.Signal == "" && pause != nil && restore != nil && w.exit.Interval.StartNS >= w.start.Interval.EndNS && w.exit.Interval.EndNS <= restore.Request.StartNS
				need(failed, "startup_exit", "startup must end with an observed runtime failure while source impairment remains in place; success and configuration errors do not reach this case")
				term := m2Signal(w, "SIGTERM")
				boundedStop := failed && term != nil && term.Interval.StartNS >= w.start.Interval.EndNS && term.Interval.StartNS >= pause.Interval.EndNS && term.Interval.StartNS <= w.exit.Interval.EndNS && term.Interval.EndNS <= restore.Request.StartNS && w.exit.Interval.EndNS-term.Interval.StartNS <= m.Settings.ShutdownTimeoutNS
				startupFailure := false
				for _, d := range diagnostics {
					if failed && d.WorkerID == e.WorkerID && d.Kind == "startup-failure" && d.Interval.StartNS >= w.start.Interval.EndNS && d.Interval.EndNS <= w.exit.Interval.EndNS {
						startupFailure = true
					}
				}
				need(boundedStop || startupFailure, "startup_termination", "runtime failure during the observed startup outage requires a matching bounded SIGTERM request or a retained startup-failure diagnostic; no particular coordinator request is inferred")
				replacement := workers[e.RecoveryWorkerID]
				need(replacement != nil && replacement != w && w.exit != nil && restore != nil && replacement.start.Interval.StartNS >= w.exit.Interval.EndNS && replacement.start.Interval.StartNS >= restore.Interval.EndNS && replacement.exit != nil && replacement.exit.Reaped && replacement.exit.ExitCode == 0 && replacement.exit.Signal == "", "startup_recovery", "startup failure requires a distinct successful same-configuration recovery worker after the failed worker exits and source service is restored")
				stopped, exists := audits[e.StoppedAuditID]
				need(exists && stopped.complete && stopped.settled && !stopped.audit.Final && w.exit != nil && restore != nil && stopped.audit.ScanInterval.StartNS >= w.exit.Interval.EndNS && stopped.audit.ScanInterval.StartNS >= restore.Interval.EndNS && replacement != nil && max(stopped.audit.SavedInterval.EndNS, stopped.audit.GroupInterval.EndNS) <= replacement.start.Interval.StartNS, "startup_audit", "startup failure requires a settled safety audit after exit and restoration and before the recovery worker starts")
			} else {
				a, ok := audits[e.TriggerAuditID]
				need(ok && a.complete && a.tailCovered && a.assigned && a.audit.ScanInterval.StartNS >= w.start.Interval.EndNS && len(unmatchedRequired(ledger.Entries, a.outputs, nil)) > 0 && pause != nil && a.audit.SavedInterval.EndNS <= pause.Request.StartNS && a.audit.GroupInterval.EndNS <= pause.Request.StartNS && m2LatestAudit(audits, pause.Request.StartNS) == a.audit.ID, "outage_trigger", "outage requires previously observed outstanding required output covering the observed destination tail and stable assignment")
				if ok && pause != nil {
					need(m2TriggerFresh(events, a, pause.Request.StartNS), "trigger_changed", "newer raw output or scan observations precede the pause request; the selected lag audit must be refreshed")
				}
			}
			if e.Kind == "delivery-stop" {
				replacement := workers[e.RecoveryWorkerID]
				need(replacement != nil && replacement != w && w.exit != nil && replacement.start.Interval.StartNS >= w.exit.Interval.EndNS, "outage_recovery", "failed worker must be safely resumed by a distinct same-configuration invocation")
				signal := m2Signal(w, "SIGTERM")
				need(pause != nil && restore != nil && restore.Request.StartNS-pause.Interval.EndNS >= m.Settings.DeliveryTimeoutNS, "delivery_duration", "independently reached outage must last beyond configured delivery timeout")
				need(signal != nil && pause != nil && restore != nil && signal.Interval.StartNS >= pause.Interval.EndNS && signal.Interval.EndNS <= restore.Request.StartNS && w.exit != nil && w.exit.Reaped && w.exit.Interval.EndNS <= restore.Request.StartNS, "delivery_stop", "SIGTERM and actual worker exit must occur while destination impairment is still observed")
				found := false
				for _, d := range diagnostics {
					if d.WorkerID == e.WorkerID && d.Kind == "delivery-timeout" && pause != nil && restore != nil && d.Interval.StartNS >= pause.Interval.EndNS+m.Settings.DeliveryTimeoutNS && d.Interval.EndNS <= restore.Request.StartNS {
						found = true
					}
				}
				need(found, "delivery_timeout", "actual delivery-timeout diagnostic must corroborate the independently timed outage and exit")
			}
			if e.Kind == "source-save" {
				v, ok := audits[e.VisibleAuditID]
				need(ok && v.complete && m2VisibleUnsaved(ledger, v) && pause != nil && restore != nil && v.audit.ScanInterval.StartNS >= pause.Interval.EndNS && restore.Request.StartNS-v.audit.SavedInterval.EndNS >= 1_000_000_000, "save_due", "source outage requires independently visible unsaved output while periodic saves are due")
				need(false, "save_observation", "source impairment and due saves do not independently identify a periodic commit attempt; this observation remains incomplete")
			}
		}
	}
	switch m.ScenarioID {
	case "healthy":
		need(len(episodes) == 0, "healthy_fault", "healthy comparison cannot contain fault episodes")
		for _, id := range workerOrder {
			w := workers[id]
			need(w.exit != nil && w.exit.ExitCode == 0 && w.exit.Signal == "", "healthy_exit", "healthy comparison requires actual successful process exit")
			need(m2Signal(w, "SIGKILL") == nil, "healthy_fault", "healthy comparison cannot kill its worker")
		}
		for _, h := range brokers {
			for _, b := range h {
				need(b.Action != "pause", "healthy_fault", "healthy comparison cannot pause a broker")
			}
		}
	case "repeated-kill":
		need(lagKillCount >= 2 && visibleCount >= 1, "repeated_kill", "repeated kill requires two reached crashes with missing required output and a reached visible-unsaved crash")
	default:
		need(len(episodes) == 1, "episode_missing", "this compiled scenario requires exactly one observed fault episode")
	}
	// Check each observation independently. A later successful resume cannot
	// repair unsafe saved progress at a previously settled audit.
	for _, event := range events {
		if event.Kind != "audit" {
			continue
		}
		a := audits[event.Audit.ID]
		if !a.complete {
			continue
		}
		for _, o := range a.outputs {
			sig, _ := recordSignature(o.Record)
			matched, routed := false, false
			for _, entry := range bySignature[sig] {
				matched = true
				routed = routed || routeMatches(entry, o)
			}
			if !matched {
				violation("corrupt_or_unexpected_output", "byte_fidelity", "output bytes do not match any prepared input", a.audit.ID, "")
			} else if !routed {
				violation("wrong_partition", "routing", "output appears outside its contract route", a.audit.ID, "")
			}
		}
		if a.settled {
			prefix := map[partitionKey]identity.Int64{}
			for _, saved := range a.audit.Saved {
				if saved.Present {
					prefix[key(saved.Source)] = saved.Source.Offset
				}
			}
			for _, id := range unmatchedRequired(ledger.Entries, a.outputs, prefix) {
				violation("unsafe_saved_prefix", "saved_prefix", "saved next offset covers required input absent from this settled output scan", a.audit.ID, id)
			}
			if a.audit.Final {
				for _, id := range unmatchedRequired(ledger.Entries, a.outputs, nil) {
					violation("required_record_missing", "required_membership", "final settled output scan lacks required input", a.audit.ID, id)
				}
			}
		}
	}
	if m.Settings.MeasurementsVersion == 1 {
		r.Measurements = m2Measurements(m, ledger, workerOrder, workers, audits[m.FinalAuditID])
		for _, measured := range r.Measurements.Workers {
			if m2Signal(workers[measured.WorkerID], "SIGTERM") != nil {
				need(measured.Shutdown.Available, "shutdown_measurement_missing", "a SIGTERM invocation requires an unambiguous signal-to-wait timing range")
			}
		}
	}
	r.Verdict = Pass
	if missing {
		r.Verdict = Inconclusive
	} else if violated {
		r.Verdict = Violation
	}
	if m.Namespace == "calibration" {
		r.Limitations = append(r.Limitations, "Synthetic controls are calibration evidence and never qualify a published release.")
	}
	return r
}

func validM2Payload(e M2Event) bool {
	n := 0
	for _, p := range []bool{e.Ledger != nil, e.Inputs != nil, e.Output != nil, e.Audit != nil, e.Worker != nil, e.Broker != nil, e.Episode != nil, e.Diagnostic != nil, e.Finished != nil} {
		if p {
			n++
		}
	}
	if n != 1 {
		return false
	}
	switch e.Kind {
	case "ledger":
		return e.Ledger != nil
	case "inputs_verified":
		return e.Inputs != nil
	case "output":
		return e.Output != nil
	case "audit":
		return e.Audit != nil
	case "worker":
		return e.Worker != nil
	case "broker":
		return e.Broker != nil
	case "episode":
		return e.Episode != nil
	case "diagnostic":
		return e.Diagnostic != nil
	case "run_finished":
		return e.Finished != nil
	}
	return false
}

func m2Interval(i M2Interval, end identity.Int64) bool {
	return i.StartNS >= 0 && i.EndNS >= i.StartNS && i.EndNS <= end
}
func m2Ticks(ticks string) bool {
	n, err := strconv.ParseUint(ticks, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == ticks
}

func m2BrokerValid(b M2Broker, run string, end identity.Int64) error {
	i := b.Identity
	id, err := hex.DecodeString(i.ContainerID)
	host, port, addressErr := net.SplitHostPort(i.Endpoint)
	n, portErr := strconv.Atoi(port)
	if i.RunID != run || (i.Role != "source" && i.Role != "destination") || len(id) != 32 || err != nil || hex.EncodeToString(id) != i.ContainerID || strings.Trim(i.ContainerID, "0") == "" || i.Name == "" || !strings.HasPrefix(i.ImageID, "sha256:") || !digestValid(strings.TrimPrefix(i.ImageID, "sha256:")) || !strings.Contains(i.ImageReference, "@sha256:") || !digestValid(strings.SplitN(i.ImageReference, "@sha256:", 2)[1]) || addressErr != nil || host != "127.0.0.1" || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("broker requires matching run/role, exact container/image identities and owned loopback endpoint")
	}
	noRequest := b.Request == (M2Interval{})
	if !m2Interval(b.Interval, end) || !m2Interval(b.Request, end) || (!noRequest && (b.Request.StartNS < b.Interval.StartNS || b.Request.EndNS > b.Interval.EndNS)) || (noRequest && b.Action != "inspect" && b.Action != "restore" && b.Action != "cleanup") {
		return fmt.Errorf("invalid broker request/observation intervals")
	}
	if b.Probe != nil && (!m2Interval(b.Probe.Interval, end) || b.Probe.Interval.StartNS < b.Interval.StartNS || b.Probe.Interval.EndNS > b.Interval.EndNS || b.Probe.Endpoint != i.Endpoint) {
		return fmt.Errorf("probe interval/endpoint does not match owned broker observation")
	}
	if !noRequest && b.Probe != nil && b.Probe.Interval.StartNS < b.Request.EndNS {
		return fmt.Errorf("independent Kafka probe must follow the completed broker mutation request")
	}
	if b.Removed && b.Action != "cleanup" {
		return fmt.Errorf("removal is only valid as actual fixture cleanup")
	}
	return nil
}

func m2ProbeAvailable(p *M2Probe) bool {
	return p != nil && p.Error == "" && p.Available && !p.Unavailable && p.APIKeys > 0 && p.ErrorCode == 0 && p.Failure == ""
}
func m2ProbeUnavailable(p *M2Probe) bool {
	if p == nil || p.Error != "" || !p.Unavailable || p.Available || p.APIKeys != 0 {
		return false
	}
	switch p.Failure {
	case "timeout", "connection_refused", "connection_reset", "broken_pipe", "connection_closed":
		return true
	}
	return false
}

func m2RestartAfter(h []M2Broker, after, before identity.Int64) bool {
	for _, b := range h {
		if b.Action == "restart" && b.Error == "" && !b.State.Paused && m2ProbeAvailable(b.Probe) && b.Request.StartNS >= after && b.Interval.EndNS <= before {
			return true
		}
	}
	return false
}

func m2Signal(w *m2WorkerHistory, signal string) *M2Worker {
	for _, s := range w.signals {
		if s.Signal == signal && s.Error == "" {
			return s
		}
	}
	return nil
}

func m2Outage(h []M2Broker, w *m2WorkerHistory) (*M2Broker, *M2Broker) {
	for i := range h {
		p := &h[i]
		if p.Action != "pause" || p.Error != "" || !p.State.Paused || !m2ProbeUnavailable(p.Probe) {
			continue
		}
		for j := i + 1; j < len(h); j++ {
			r := &h[j]
			if r.Action != "restore" && r.Action != "restart" {
				continue
			}
			if r.Action == "restore" && r.Request != (M2Interval{}) && r.Error == "" && !r.State.Paused && m2ProbeAvailable(r.Probe) && r.Request.StartNS >= p.Interval.EndNS && r.Request.StartNS >= w.start.Interval.EndNS {
				return p, r
			}
			break
		}
	}
	return nil, nil
}

func m2GroupAssigned(g M2Group, group, topic string) (bool, error) {
	if g.GroupID != group || g.Members == nil {
		return false, fmt.Errorf("group observation requires exact group identity and explicit members")
	}
	if g.ErrorCode != 0 {
		return false, nil
	}
	ids := map[string]bool{}
	assigned := g.State == "Stable" && g.ProtocolType == "consumer" && g.Protocol != "" && len(g.Members) == 1
	for _, member := range g.Members {
		if member.ID == "" || ids[member.ID] {
			return false, fmt.Errorf("group observation contains missing/duplicate member identity")
		}
		ids[member.ID] = true
		raw, err := base64.StdEncoding.Strict().DecodeString(member.AssignmentBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != member.AssignmentBase64 {
			return false, fmt.Errorf("group assignment must use canonical base64")
		}
		a, err := observer.DecodeAssignment(raw)
		if err != nil {
			return false, fmt.Errorf("group member assignment cannot be independently decoded")
		}
		parts := a.Topics[topic]
		if len(a.Topics) != 1 || len(parts) != 3 || (parts[0]+parts[1]+parts[2] != 3) || parts[0] > 2 || parts[1] > 2 || parts[2] > 2 {
			assigned = false
		}
	}
	return assigned, nil
}

func m2VisibleUnsaved(l Ledger, a m2AuditHistory) bool {
	for _, entry := range l.Entries {
		signature, _ := recordSignature(entry.Record)
		count := 0
		for _, other := range l.Entries {
			otherSignature, _ := recordSignature(other.Record)
			if signature == otherSignature {
				count++
			}
		}
		if count != 1 {
			continue
		}
		if len(unmatchedRequired([]LedgerEntry{entry}, a.outputs, nil)) != 0 {
			continue
		}
		for _, saved := range a.audit.Saved {
			if key(saved.Source) == key(entry.Source) && (!saved.Present || saved.Source.Offset <= entry.Source.Offset) {
				return true
			}
		}
	}
	return false
}

func m2Routes(l Ledger, routing string) error {
	for i, p := range l.Partitions {
		first := l.Partitions[0].Source
		if p.Source.Cluster != first.Cluster || p.Source.Topic != first.Topic || p.Source.TopicID != first.TopicID || p.Source.Partition != int32(i) || p.Source.Offset != 0 || len(p.Gaps) != 0 {
			return fmt.Errorf("M2 source must enumerate one complete finite zero-based nontransactional topic")
		}
	}
	for i, p := range l.Destinations {
		if p.Partition != int32(i) {
			return fmt.Errorf("M2 destination partitions must enumerate the complete zero-based layout")
		}
	}
	for _, e := range l.Entries {
		want := []int32{e.Source.Partition}
		if routing == "KEY" {
			k, err := e.Record.Key.Bytes()
			if err != nil {
				return err
			}
			if k == nil {
				want = make([]int32, len(l.Destinations))
				for i := range want {
					want[i] = int32(i)
				}
			} else {
				p, err := observer.KeyPartition(k, int32(len(l.Destinations)))
				if err != nil {
					return err
				}
				want = []int32{p}
			}
		}
		if !reflect.DeepEqual(want, e.AllowedPartitions) {
			return fmt.Errorf("ledger route differs from configured PRESERVE/KEY contract")
		}
	}
	return nil
}

// These are the fixed generated M2 invocation and configuration forms. Unknown
// SQL/configuration forms need a reviewed checker extension, not a guessed
// interpretation of arbitrary SQL or TOML.
func m2SettingsValid(m M2Manifest) error {
	s := m.Settings
	if s.WorkBudgetNS <= 0 || s.CleanupBudgetNS <= 0 || s.WorkBudgetNS > m.BudgetNS || s.CleanupBudgetNS > m.BudgetNS-s.WorkBudgetNS || s.WorkBudgetNS+s.CleanupBudgetNS != m.BudgetNS {
		return fmt.Errorf("work and cleanup budgets must be positive and sum to the total bound")
	}
	if digest([]byte(s.SQL)) != s.SQLSHA256 || digest([]byte(s.ConfigTOML)) != s.ConfigSHA256 || s.SQL == "" || s.ConfigTOML == "" {
		return fmt.Errorf("exact SQL/TOML text and matching hashes are required")
	}
	if len(s.Args) != 5 || s.Args[0] != "run" || s.Args[1] != "--file" || s.Args[3] != "--config" || !filepath.IsAbs(s.Args[2]) || !filepath.IsAbs(s.Args[4]) || s.Args[2] == s.Args[4] {
		return fmt.Errorf("M2 requires the recorded run --file SQL --config TOML invocation")
	}
	values := map[string]string{}
	for _, line := range strings.Split(s.ConfigTOML, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "[worker]" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || values[key] != "" {
			return fmt.Errorf("M2 configuration must contain unambiguous generated worker settings")
		}
		values[key] = value
	}
	for _, setting := range []struct {
		key   string
		value identity.Int64
	}{{"delivery_timeout", s.DeliveryTimeoutNS}, {"shutdown_timeout", s.ShutdownTimeoutNS}} {
		text := values[setting.key]
		if len(text) < 3 || text[0] != '\'' || text[len(text)-1] != '\'' {
			return fmt.Errorf("timeout settings must retain exact generated duration strings")
		}
		duration, err := time.ParseDuration(text[1 : len(text)-1])
		if err != nil || duration <= 0 || identity.Int64(duration) != setting.value {
			return fmt.Errorf("numeric timeout differs from the actual worker configuration")
		}
	}
	want := "[worker]\nrecord_cap=1024\npartition_record_cap=1024\nbyte_cap=16777216\npartition_byte_cap=8388608\ndelivery_timeout=" + values["delivery_timeout"] + "\nshutdown_timeout=" + values["shutdown_timeout"] + "\nidle_exit='8s'\ntip_wait='8s'\nprogress_interval='1s'\n"
	if s.ConfigTOML != want {
		return fmt.Errorf("M2 supports only the compiled bounded worker configuration")
	}
	return nil
}

func m2SQLValid(m M2Manifest, l Ledger, source, destination string) error {
	want := fmt.Sprintf("WITH CONNECTION source AS ('bootstrap.servers'='%s','session.timeout.ms'='6000','heartbeat.interval.ms'='1000','socket.timeout.ms'='500'), CONNECTION destination AS ('bootstrap.servers'='%s','client.id'='lab-m2','linger.ms'='1500','request.timeout.ms'='1000','socket.timeout.ms'='500') INSERT INTO TOPIC '%s@destination' WITH (PARTITIONING = %s) SELECT * FROM TOPIC '%s@source' WITH (GROUP='%s') WHERE PARTITION IN (0,1,2);\n", source, destination, l.Destinations[0].Topic, m.Settings.Routing, l.Partitions[0].Source.Topic, m.Group)
	if m.Settings.SQL != want {
		return fmt.Errorf("M2 supports only the compiled finite three-partition SQL with matching observed endpoints, topics, group and routing")
	}
	return nil
}

func m2LatestAudit(audits map[string]m2AuditHistory, before identity.Int64) string {
	id := ""
	var latest identity.Int64 = -1
	for key, a := range audits {
		end := max(a.audit.SavedInterval.EndNS, a.audit.GroupInterval.EndNS)
		if end <= before && (end > latest || end == latest && key > id) {
			latest, id = end, key
		}
	}
	return id
}

// A later saved/group read cannot hide output already observed before the
// actual fault request. Concurrent or delayed audit finalization is admitted,
// but its newer raw observations require a fresh complete trigger audit.
func m2TriggerFresh(events []M2Event, trigger m2AuditHistory, before identity.Int64) bool {
	for _, e := range events {
		switch e.Kind {
		case "output":
			if e.Output.AuditID != trigger.audit.ID && e.ElapsedNS <= before && (e.Seq > trigger.seq || e.ElapsedNS >= trigger.audit.ScanInterval.StartNS) {
				return false
			}
		case "audit":
			if e.Audit.ID == trigger.audit.ID {
				continue
			}
			if e.ElapsedNS <= before && e.Seq > trigger.seq || e.Audit.ScanInterval.EndNS <= before && e.Audit.ScanInterval.EndNS > trigger.audit.ScanInterval.EndNS {
				return false
			}
		}
	}
	return true
}
