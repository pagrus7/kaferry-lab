package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

func phaseResult(m PhaseManifest) Result {
	r := Result{Verdict: HarnessError, Namespace: m.Namespace, RunID: m.RunID, ScenarioID: m.ScenarioID, Findings: []Finding{}, Limitations: []string{
		"Evidence version 3 is M2 two-phase admission/data checking, not roadmap milestone M3 or qualification.",
		"Recorded scans, waits and hashes do not authenticate a hostile author's claims to have observed reality.",
		"No accepted delivery-timeout/live-TERM or failed threshold-drain mechanism observation is implemented; counts, timers and generic logs cannot establish ACK or path entry.",
	}}
	if m.ScenarioID == "source-save" {
		r.Limitations[0] = "Evidence version3 checks fixed warmup3/save-probe4/full96 data admission, not qualification."
		r.Limitations[2] = "Current periodic-save origin and actual impaired-save failure remain unsupported; a sampled visible-unsaved record, timer, log or ACK establishes neither."
	}
	return r
}

// CheckPhaseHistory checks fixed delivery or source-save data stages without I/O.
// Valid admission remains UNSUPPORTED for mechanism acceptance. An independently
// established data violation takes precedence over that missing mechanism.
func CheckPhaseHistory(m PhaseManifest, artifact ArtifactMetadata, events []PhaseEvent) Result {
	r := phaseResult(m)
	violated := false
	bad := func(code, message string) Result {
		r.Findings = append(r.Findings, Finding{Code: code, Message: message})
		if violated {
			r.Verdict = Violation
		}
		return r
	}
	violation := func(code, property, message, audit, entry string) {
		violated = true
		r.Findings = append(r.Findings, Finding{Code: code, Property: property, Message: message, AuditID: audit, EntryID: entry})
	}
	if m.SchemaVersion != PhaseSchemaVersion || m.CheckerVersion != PhaseCheckerVersion {
		r.Verdict = Unsupported
		return bad("phase_version", "unsupported phase schema/checker")
	}
	sourceSave := m.ScenarioID == "source-save"
	if m.ScenarioID != "delivery-stop" && m.ScenarioID != "delivery-threshold" && !sourceSave {
		r.Verdict = Unsupported
		return bad("phase_scenario", "only compiled M2 delivery/source-save phase experiments are supported")
	}
	if m.RunID == "" || m.Group == "" || m.Scope != "kafka" || m.Given == "" || m.When == "" || m.Then == "" || m.FinalAuditID == "" || m.BudgetNS <= 0 || m.BudgetNS > 600_000_000_000 {
		return bad("phase_manifest", "finite Kafka identity, Given/When/Then, final audit and at most ten minutes are required")
	}
	base := Manifest{Namespace: m.Namespace, Subject: m.Subject, Scope: m.Scope, LabSource: m.LabSource, Environment: m.Environment}
	if err := validateExecutionMetadata(base); err != nil {
		return bad("execution_metadata", err.Error())
	}
	if verdict, code, err := validateArtifact(base, artifact); err != nil {
		r.Verdict = verdict
		return bad(code, err.Error())
	}
	if len(events) == 0 || len(events) > maxEvents || events[0].Kind != "input_declared" || events[0].Declaration == nil {
		return bad("phase_declaration", "first event declares the immutable final96 ledger, not observed input")
	}
	declared := *events[0].Declaration
	if len(declared.Entries) > 1024 || len(declared.Partitions) > 256 || len(declared.Destinations) > 256 {
		r.Verdict = Unsupported
		return bad("checker_capacity", "phase capacities remain1024 records/256 partitions")
	}
	if err := validateLedger(declared); err != nil {
		return bad("phase_ledger", err.Error())
	}
	if len(declared.Partitions) != 3 || len(declared.Destinations) != 3 || len(declared.Entries) != 96 {
		return bad("phase_ledger", "the compiled final ledger has three partitions and96 distinct required records")
	}
	for _, p := range declared.Partitions {
		if p.End != 32 {
			return bad("phase_ledger", "the declared fixed source ends are32")
		}
	}
	for _, entry := range declared.Entries {
		if entry.Disposition != "required" || entry.Archive != nil {
			return bad("phase_ledger", "only gap-free nontransactional required input is supported")
		}
	}
	if hasIndistinguishable(declared.Entries) {
		return bad("phase_ledger", "this known-value experiment requires distinguishable complete record bytes")
	}
	profiles, err := phaseProfiles(m, declared)
	if err != nil {
		return bad("phase_profiles", err.Error())
	}
	warmup := phaseWarmup(declared)
	ledgers := map[string]Ledger{"warmup": warmup, "full": declared}
	if sourceSave {
		probe, err := sourceSaveProbeLedger(declared)
		if err != nil {
			return bad("phase_save_probe_ledger", err.Error())
		}
		ledgers["save-probe"] = probe
	}
	publications := map[string]PhasePublication{}
	workers := map[string]*m2WorkerHistory{}
	settingsIDs := map[string]string{}
	brokers := map[string][]M2Broker{}
	pending := map[string][]Output{}
	pendingPhases := map[string]string{}
	pendingTimes := map[string][]identity.Int64{}
	positions := map[identity.SourcePosition]string{}
	auditIDs := map[string]bool{}
	current := ""
	verifiedAt, lastSettled, lastSettledStart, warmupProgress := identity.Int64(-1), identity.Int64(-1), identity.Int64(-1), identity.Int64(-1)
	var primary, warmupWorker string
	saveLiveEnd, saveWitnessEnd := identity.Int64(-1), identity.Int64(-1)
	saveWitnessID := ""
	stopped := false
	fullVerified, resumed, finished, final := false, false, false, false
	var elapsed identity.Int64
	var streamBytes int
	for i, event := range events {
		raw, encodeErr := json.Marshal(event)
		streamBytes += len(raw) + 1
		if encodeErr != nil || len(raw) > maxEventBytes || streamBytes > maxEventsBytes {
			return bad("checker_capacity", "phase stream exceeds existing4MiB line/64MiB stream bounds")
		}
		if finished || event.Seq != identity.Int64(i+1) || event.RunID != m.RunID || event.ElapsedNS < elapsed || event.ElapsedNS > m.BudgetNS || !phasePayload(event) {
			return bad("phase_event", "event sequence/run/time/payload must be bounded, unique and closed")
		}
		previousElapsed := elapsed
		elapsed = event.ElapsedNS
		if final && event.Kind != "run_finished" {
			return bad("phase_completion", "no later work can invalidate the final settled observation")
		}
		switch event.Kind {
		case "input_declared":
			if i != 0 {
				return bad("phase_declaration", "the final declaration cannot be replaced")
			}
		case "input_published":
			p := *event.Publication
			l, exists := ledgers[p.PhaseID]
			_, duplicate := publications[p.PhaseID]
			body, _ := json.Marshal(l)
			if !exists || duplicate || !m2Interval(p.Interval, elapsed) || p.LedgerSHA256 != digest(body) {
				return bad("phase_publication", "publication must bind one exact compiled ledger once")
			}
			if p.PhaseID == "warmup" {
				if current != "" || len(workers) != 0 || p.WorkerID != "" {
					return bad("phase_publication", "warmup publication precedes the primary")
				}
			} else if sourceSave && p.PhaseID == "save-probe" {
				w := workers[primary]
				if current != "warmup" || w == nil || w.exit != nil || p.WorkerID != primary || stopped || len(w.signals) != 0 || warmupProgress < 0 || warmupWorker != primary || p.Interval.StartNS < max(warmupProgress, previousElapsed) || len(pending) != 0 {
					return bad("phase_save_probe_order", "probe publication needs the same running unlimited primary after complete warmup progress")
				}
				saveLiveEnd = p.Interval.EndNS
			} else {
				w := workers[primary]
				predecessor := "warmup"
				if sourceSave {
					predecessor = "save-probe"
				}
				if current != predecessor || w == nil || w.exit != nil || p.WorkerID != primary || !stopped || warmupProgress < 0 || warmupWorker != primary || len(w.signals) == 0 || w.signals[len(w.signals)-1].Interval.EndNS > p.Interval.StartNS || sourceSave && (saveWitnessID == "" || len(pending) != 0) {
					return bad("phase_stop", "full publication requires the same live primary actually STOPPED after warmup progress")
				}
			}
			publications[p.PhaseID] = p
		case "input_phase_verified":
			v := event.Verified
			if sourceSave && len(pending) != 0 {
				return bad("phase_output", "unfinished source-save output scans cannot cross readback or phase transitions")
			}
			l, exists := ledgers[v.PhaseID]
			p, published := publications[v.PhaseID]
			if !exists || !published || !m2Interval(v.Interval, elapsed) || v.Interval.StartNS < p.Interval.EndNS || v.Interval.StartNS < verifiedAt || !v.Complete || v.Error != "" || v.Method != "independent_source_scan" || !reflect.DeepEqual(v.Ledger, l) {
				return bad("phase_scan", "a fresh complete independent source readback must equal the exact published phase")
			}
			if v.PhaseID == "warmup" && (current != "" || len(workers) != 0) {
				return bad("phase_order", "warmup is verified once before any primary start")
			}
			if sourceSave && v.PhaseID == "save-probe" && (current != "warmup" || stopped || len(workers) != 1 || workers[primary] == nil || workers[primary].exit != nil || v.Interval.StartNS < saveLiveEnd || len(pending) != 0) {
				return bad("phase_save_probe_order", "probe readback follows its sole publication with the same live primary")
			}
			predecessor := "warmup"
			if sourceSave {
				predecessor = "save-probe"
			}
			if v.PhaseID == "full" && current != predecessor && current != "full" {
				return bad("phase_order", "full follows the verified warmup")
			}
			if v.PhaseID == "full" {
				for _, history := range brokers {
					for _, b := range history {
						if (b.Action == "restart" || b.Action == "restore") && b.Interval.EndNS > v.Interval.StartNS {
							return bad("phase_scan", "the entire full-source readback must follow completed broker stabilization")
						}
					}
				}
			}
			for id, w := range workers {
				if w.exit == nil && (id != primary || !stopped && !(sourceSave && v.PhaseID == "save-probe")) {
					return bad("phase_stop", "source verification while a worker exists requires the same owned stopped primary")
				}
			}
			if err := phaseSourceScan(*v); err != nil {
				return bad("phase_scan", err.Error())
			}
			current, verifiedAt = v.PhaseID, v.Interval.EndNS
			if sourceSave && current == "save-probe" {
				saveLiveEnd = verifiedAt
			}
			fullVerified = current == "full"
		case "worker":
			pw := event.Worker
			w := &pw.Observation
			s, known := profiles[pw.SettingsID]
			args, _ := json.Marshal(s.Args)
			env, _ := json.Marshal(s.Environment)
			id := w.Identity
			if !known || !m2Interval(w.Interval, elapsed) || w.Error != "" || w.LogsTruncated || w.ResourceUsage != nil || id.WorkerID == "" || id.PID <= 0 || !m2Ticks(id.StartTicks) || id.ExecutableSHA256 != m.Subject.ExecutableSHA256 || id.ArgsSHA256 != digest(args) || id.EnvironmentSHA256 != digest(env) {
				return bad("phase_worker", "exact owned worker identity/settings and complete observations are required")
			}
			h := workers[id.WorkerID]
			if w.Action == "start" {
				if h != nil || len(workers) >= 2 || verifiedAt < 0 || w.Interval.StartNS < verifiedAt || !phaseBrokersAvailable(brokers, w.Interval.StartNS) {
					return bad("phase_worker_order", "start needs current verified input, restored brokers and a fresh bounded invocation")
				}
				for _, prior := range workers {
					if prior.exit == nil || prior.cleanup == nil || prior.cleanup.Interval.EndNS > w.Interval.StartNS || (prior.identity.PID == id.PID && prior.identity.StartTicks == id.StartTicks) {
						return bad("phase_worker_order", "replacement follows actual exit/cleanup of a distinct owned invocation")
					}
				}
				if len(workers) == 0 {
					if current != "warmup" || pw.SettingsID != m.Profiles[0].ID {
						return bad("phase_profile_order", "primary starts only on warmup with its explicitly selected settings ID")
					}
					primary = id.WorkerID
				} else {
					if !fullVerified || !resumed || pw.SettingsID != "recovery-unlimited" || lastSettled < workers[primary].exit.Interval.EndNS || lastSettled > w.Interval.StartNS {
						return bad("phase_recovery", "unlimited recovery follows full verification, restoration and settled primary safety")
					}
					for _, history := range brokers {
						for _, b := range history {
							if b.Action != "inspect" && b.Interval.EndNS > lastSettledStart {
								return bad("phase_recovery", "settled primary safety must follow the latest relevant broker impairment/restoration")
							}
						}
					}
				}
				h = &m2WorkerHistory{identity: id, start: w}
				workers[id.WorkerID], settingsIDs[id.WorkerID] = h, pw.SettingsID
			} else if h == nil || h.identity != id || settingsIDs[id.WorkerID] != pw.SettingsID || w.Interval.StartNS < h.start.Interval.EndNS {
				return bad("phase_worker_identity", "lifecycle observation differs from the owned invocation/profile")
			}
			if len(h.signals) > 0 && w.Interval.StartNS < h.signals[len(h.signals)-1].Interval.EndNS {
				return bad("phase_worker_order", "lifecycle intervals cannot precede an already observed signal")
			}
			if sourceSave && id.WorkerID == primary && w.Action != "start" && w.Interval.StartNS < saveLiveEnd {
				return bad("phase_save_primary_order", "primary lifecycle cannot backdate across used live-stage observations")
			}
			switch w.Action {
			case "start":
			case "signal":
				if h.exit != nil {
					return bad("phase_signal", "signal cannot follow the owned wait")
				}
				switch w.Signal {
				case "SIGSTOP":
					stopPhase := "warmup"
					if sourceSave {
						stopPhase = "save-probe"
					}
					if id.WorkerID != primary || stopped || current != stopPhase || warmupProgress < 0 || warmupWorker != id.WorkerID || w.Interval.StartNS < warmupProgress || (w.ObservedState != "T" && w.ObservedState != "t") {
						return bad("phase_stop", "STOP needs observed stopped ownership after independently copied/saved warmup3")
					}
					if sourceSave && (saveWitnessID == "" || w.Interval.StartNS < saveWitnessEnd || len(pending) != 0) {
						r.Verdict = Unsupported
						return bad("phase_save_probe_unreached", "no complete visible-unsaved probe snapshot precedes the owned STOP")
					}
					stopped = true
				case "SIGCONT":
					if id.WorkerID != primary || !stopped || !fullVerified || w.Interval.StartNS < verifiedAt || resumed {
						return bad("phase_early_cont", "CONT cannot precede full independent readback or repeat")
					}
					stopped, resumed = false, true
				case "SIGTERM", "SIGKILL":
					if stopped {
						return bad("phase_signal", "the phase transition must resume before termination")
					}
				default:
					return bad("phase_signal", "unsupported worker signal")
				}
				h.signals = append(h.signals, w)
			case "exit":
				if h.exit != nil || !w.Reaped {
					return bad("phase_wait", "actual terminal wait is required exactly once")
				}
				h.exit = w
			case "cleanup":
				if h.exit == nil || h.cleanup != nil || !w.Reaped || w.Interval.StartNS < h.exit.Interval.EndNS {
					return bad("phase_cleanup", "cleanup follows the actual owned wait once")
				}
				h.cleanup = w
			default:
				return bad("phase_worker_action", "unknown lifecycle action")
			}
		case "broker":
			b := *event.Broker
			if err := m2BrokerValid(b, m.RunID, elapsed); err != nil {
				return bad("phase_broker", err.Error())
			}
			// This version3 history requires a serial controller: retain the completed
			// observation before initiating its next broker mutation. A later
			// receipt cannot backdate an action across an already used witness.
			if (b.Action == "pause" || b.Action == "restore" || b.Action == "restart") && b.Interval.StartNS < previousElapsed {
				return bad("phase_broker_order", "serial broker mutation must begin at or after the preceding event elapsed time")
			}
			history := brokers[b.Identity.Role]
			cluster := declared.Partitions[0].Source.Cluster
			if b.Identity.Role == "destination" {
				cluster = declared.Destinations[0].Cluster
			}
			if b.Identity.ClusterID != cluster || b.Error != "" || b.Removed || !b.State.RunningPresent || !b.State.PausedPresent || !b.State.Running || !b.State.LoopbackBound || len(history) >= 128 || (len(history) == 0 && b.Action != "inspect") || (len(history) > 0 && (history[0].Identity != b.Identity || b.Interval.StartNS < history[len(history)-1].Interval.EndNS)) {
				return bad("phase_broker", "broker identity/state must remain exact and observations complete")
			}
			if b.Action == "pause" {
				if !b.State.Paused || !m2ProbeUnavailable(b.Probe) {
					return bad("phase_broker", "pause needs an independent reached impairment")
				}
			} else if (b.Action != "inspect" && b.Action != "restore" && b.Action != "restart") || b.State.Paused || !m2ProbeAvailable(b.Probe) {
				return bad("phase_broker", "restoration/restart needs an independent healthy probe")
			}
			brokers[b.Identity.Role] = append(history, b)
		case "output":
			o := event.Output
			if current == "" || o.PhaseID != current || o.Observation.AuditID == "" || auditIDs[o.Observation.AuditID] {
				return bad("phase_output", "output must bind the current verified phase and an unfinished audit")
			}
			if err := validatePosition(o.Observation.Destination); err != nil {
				return bad("phase_output", err.Error())
			}
			sig, err := recordSignature(o.Observation.Record)
			if err != nil {
				return bad("phase_output", err.Error())
			}
			if old, exists := positions[o.Observation.Destination]; exists && old != sig {
				return bad("phase_output_conflict", "a physical destination position changed between scans")
			}
			positions[o.Observation.Destination] = sig
			if phase, exists := pendingPhases[o.Observation.AuditID]; exists && phase != current {
				return bad("phase_output", "an unfinished output scan cannot cross a phase transition")
			}
			pendingPhases[o.Observation.AuditID] = current
			pendingTimes[o.Observation.AuditID] = append(pendingTimes[o.Observation.AuditID], elapsed)
			pending[o.Observation.AuditID] = append(pending[o.Observation.AuditID], o.Observation)
			if len(pending[o.Observation.AuditID]) > 16384 {
				return bad("checker_capacity", "phase output limit is16384 observations per audit")
			}
		case "audit":
			pa := event.Audit
			a := pa.Observation
			if current == "" || pa.PhaseID != current || (current == "full" && pa.WorkerID != "") || a.ScanInterval.StartNS < verifiedAt || auditIDs[a.ID] || len(auditIDs) >= 96 {
				return bad("phase_audit", "audit must bind the currently verified phase after its completed readback")
			}
			if !m2Interval(a.ScanInterval, elapsed) || !m2Interval(a.SavedInterval, elapsed) || !m2Interval(a.GroupInterval, elapsed) {
				return bad("phase_audit", "audit intervals cannot reach beyond their observation")
			}
			for _, observed := range pendingTimes[a.ID] {
				if pendingPhases[a.ID] != current || observed < a.ScanInterval.StartNS || observed > a.ScanInterval.EndNS {
					return bad("phase_audit", "output observations must belong to this phase scan interval")
				}
			}
			outputs := pending[a.ID]
			delete(pending, a.ID)
			delete(pendingPhases, a.ID)
			delete(pendingTimes, a.ID)
			auditIDs[a.ID] = true
			settled, progress, err := phaseAuditData(m, ledgers[current], a, outputs, workers, brokers, verifiedAt, violation)
			if err != nil {
				return bad("phase_audit", err.Error())
			}
			if current == "warmup" && progress {
				w := workers[primary]
				if w == nil || w.exit != nil || pa.WorkerID != primary || a.ScanInterval.StartNS < w.start.Interval.EndNS || a.SavedInterval.StartNS < w.start.Interval.EndNS || a.GroupInterval.StartNS < w.start.Interval.EndNS {
					return bad("phase_warmup_progress", "warmup progress must name this live primary and scan output/saved/group only after its completed launch")
				}
				warmupProgress, warmupWorker = max(a.SavedInterval.EndNS, a.GroupInterval.EndNS), pa.WorkerID
				if sourceSave {
					saveLiveEnd = warmupProgress
				}
			}
			if sourceSave && current == "save-probe" {
				w := workers[primary]
				if w == nil || w.exit != nil || stopped || pa.WorkerID != primary || a.ScanInterval.StartNS < max(saveLiveEnd, w.start.Interval.EndNS) || a.SavedInterval.StartNS < w.start.Interval.EndNS || a.GroupInterval.StartNS < w.start.Interval.EndNS || a.Mode != "snapshot" || a.Final {
					return bad("phase_save_probe_audit", "probe snapshot must name the same live primary after fresh complete probe readback")
				}
				saveLiveEnd = max(a.ScanInterval.EndNS, max(a.SavedInterval.EndNS, a.GroupInterval.EndNS))
				saveWitnessID, saveWitnessEnd = "", -1
				if sourceSaveProbeVisible(m, ledgers[current], a, outputs) {
					saveWitnessID, saveWitnessEnd = a.ID, saveLiveEnd
				}
			}
			if settled {
				lastSettled, lastSettledStart = max(a.SavedInterval.EndNS, a.GroupInterval.EndNS), a.ScanInterval.StartNS
			}
			if a.Final {
				if final || current != "full" || !fullVerified || !settled || !progress || a.ID != m.FinalAuditID || len(workers) != 2 {
					return bad("phase_final", "completion requires settled full96 membership/progress after same-group recovery")
				}
				final = true
			}
		case "run_finished":
			f := event.Finished
			if !final || !fullVerified || !resumed || !f.CleanupComplete || f.TimedOut || f.Proof == "" || len(pending) != 0 {
				return bad("phase_completion", "only a closed fully verified/recovered history completes data admission")
			}
			finished = true
		}
	}
	if !finished {
		return bad("phase_completion", "the run has no finalized complete observation")
	}
	r.Verdict = Unsupported
	if sourceSave {
		if !violated {
			r.Findings = append(r.Findings, Finding{Code: "source_save_admission_complete", Message: "warmup3/save-probe4/full96 and settled recovered data obligations are complete"})
		}
		r.Findings = append(r.Findings, Finding{Code: "mechanism_unobserved", Message: "current periodic-save origin and actual impaired-save failure remain unsupported"})
	} else {
		r.Findings = append(r.Findings, Finding{Code: "phase_admission_complete", Message: "warmup3/full96 admission and settled final data obligations are complete"}, Finding{Code: "mechanism_unobserved", Message: "delivery/failed-threshold mechanism acceptance remains unsupported; no ACK/path predicate is supplied"})
	}
	if violated {
		r.Verdict = Violation
	}
	return r
}

func phaseWarmup(full Ledger) Ledger {
	warm := Ledger{Destinations: append([]identity.SourcePosition(nil), full.Destinations...), Partitions: []PartitionRange{}, Entries: []LedgerEntry{}}
	for _, p := range full.Partitions {
		p.End = 1
		warm.Partitions = append(warm.Partitions, p)
	}
	for _, entry := range full.Entries {
		if entry.Source.Offset == 0 {
			warm.Entries = append(warm.Entries, entry)
		}
	}
	return warm
}

func phaseProfiles(m PhaseManifest, l Ledger) (map[string]M2Settings, error) {
	if len(m.Profiles) != 2 || (m.Profiles[0].ID != "primary-threshold4" && m.Profiles[0].ID != "primary-unlimited") || m.Profiles[1].ID != "recovery-unlimited" {
		return nil, fmt.Errorf("one explicit primary-threshold4 or primary-unlimited profile followed by recovery-unlimited is required")
	}
	primaryID := m.Profiles[0].ID
	if m.ScenarioID == "source-save" && primaryID != "primary-unlimited" {
		return nil, fmt.Errorf("source-save requires the explicit unlimited primary")
	}
	threshold := identity.Int64(4)
	if primaryID == "primary-unlimited" {
		if m.ScenarioID != "delivery-stop" && m.ScenarioID != "source-save" {
			return nil, fmt.Errorf("primary-unlimited requires explicit delivery-stop or source-save selection")
		}
		threshold = 0
	}
	for _, endpoint := range []string{m.SourceEndpoint, m.DestinationEndpoint} {
		host, port, err := net.SplitHostPort(endpoint)
		n, portErr := strconv.Atoi(port)
		if err != nil || host != "127.0.0.1" || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, fmt.Errorf("fixed worker bootstrap endpoints must use loopback")
		}
	}
	p, recovery := m.Profiles[0].Settings, m.Profiles[1].Settings
	if p.RecordThreshold != threshold || recovery.RecordThreshold != 0 || p.Routing != recovery.Routing || (p.Routing != "PRESERVE" && p.Routing != "KEY") || p.MeasurementsVersion != 0 || recovery.MeasurementsVersion != 0 || p.Environment == nil || recovery.Environment == nil {
		return nil, fmt.Errorf("primary count must match its explicit profile, recovery must be unlimited, and routing/environment identical; measurement extension remains separate")
	}
	if err := m2Routes(l, p.Routing); err != nil {
		return nil, err
	}
	for _, s := range []M2Settings{p, recovery} {
		if err := m2SettingsValid(M2Manifest{Settings: s, BudgetNS: m.BudgetNS}); err != nil {
			return nil, err
		}
	}
	comparison := p
	comparison.Args = append([]string(nil), p.Args...)
	comparison.Args[2] = recovery.Args[2]
	comparison.SQL, comparison.SQLSHA256, comparison.RecordThreshold = recovery.SQL, recovery.SQLSHA256, 0
	if !reflect.DeepEqual(comparison, recovery) || p.Args[2] == recovery.Args[2] {
		return nil, fmt.Errorf("profiles may change only the retained SQL option and its separate SQL invocation path")
	}
	if strings.ContainsAny(m.Group+l.Partitions[0].Source.Topic+l.Destinations[0].Topic, "'\\\r\n") {
		return nil, fmt.Errorf("the compiled SQL identities cannot contain quoting/control syntax")
	}
	if err := m2SQLValid(M2Manifest{Group: m.Group, Settings: recovery}, l, m.SourceEndpoint, m.DestinationEndpoint); err != nil {
		return nil, err
	}
	primarySQL := recovery.SQL
	if threshold == 4 {
		primarySQL = strings.TrimSuffix(recovery.SQL, ";\n") + " OPTIONS (WORKER_STOP_AFTER_RECORDS=4);\n"
	}
	if p.SQL != primarySQL {
		return nil, fmt.Errorf("primary SQL must match its explicit threshold4 or unlimited profile; record_cap is not the worker-stop option")
	}
	return map[string]M2Settings{primaryID: p, "recovery-unlimited": recovery}, nil
}

func phaseSourceScan(v PhaseVerification) error {
	if len(v.RawObservationBase64) == 0 || len(v.RawObservationBase64) > maxEventBytes {
		return fmt.Errorf("bounded independent source readback bytes are required")
	}
	body, decodeErr := base64.StdEncoding.Strict().DecodeString(v.RawObservationBase64)
	if decodeErr != nil || base64.StdEncoding.EncodeToString(body) != v.RawObservationBase64 || int64(len(body)) != int64(v.RawObservationBytes) || digest(body) != v.RawObservationSHA256 {
		return fmt.Errorf("canonical independent source readback bytes/hash/length are required")
	}
	var raw PhaseSourceScan
	if err := strictJSON(body, &raw); err != nil || !reflect.DeepEqual(raw.Ledger, v.Ledger) || !reflect.DeepEqual(raw.Scans, v.Scans) {
		return fmt.Errorf("raw source scan must bind exact typed ledger and scans")
	}
	if len(v.Scans) != 3 {
		return fmt.Errorf("source readback must completely scan all three fixed source partitions")
	}
	for i, s := range v.Scans {
		p := v.Ledger.Partitions[i]
		if s.Source != p.Source || s.End != p.End || len(s.Gaps) != 0 || !s.Complete || s.Reached != p.End || s.StableEnd != p.End || s.Proof == "" {
			return fmt.Errorf("source scan must reach exact published ends with no unseen extras or gaps")
		}
	}
	return nil
}

func phaseBrokersAvailable(brokers map[string][]M2Broker, before identity.Int64) bool {
	for _, role := range []string{"source", "destination"} {
		h := brokers[role]
		if len(h) == 0 || h[len(h)-1].Interval.EndNS > before || h[len(h)-1].State.Paused || !m2ProbeAvailable(h[len(h)-1].Probe) {
			return false
		}
	}
	return true
}

func phaseAuditData(m PhaseManifest, l Ledger, a M2Audit, outputs []Output, workers map[string]*m2WorkerHistory, brokers map[string][]M2Broker, verifiedAt identity.Int64, violation func(string, string, string, string, string)) (settled, progress bool, err error) {
	if a.ID == "" || (a.Mode != "snapshot" && a.Mode != "settled") || !m2Interval(a.ScanInterval, m.BudgetNS) || !m2Interval(a.SavedInterval, m.BudgetNS) || !m2Interval(a.GroupInterval, m.BudgetNS) || a.ScanInterval.EndNS > a.SavedInterval.StartNS || a.ScanInterval.EndNS > a.GroupInterval.StartNS || len(a.Saved) != 3 {
		return false, false, fmt.Errorf("complete scan then exact saved/group intervals and three saved observations are required")
	}
	assigned, e := m2GroupAssigned(a.Group, m.Group, l.Partitions[0].Source.Topic)
	if e != nil {
		return false, false, e
	}
	v1 := Audit{ID: a.ID, Kind: "snapshot", Scans: a.Scans}
	seen := map[partitionKey]bool{}
	prefix := map[partitionKey]identity.Int64{}
	progress = true
	for _, saved := range a.Saved {
		k := key(saved.Source)
		var partition *PartitionRange
		for i := range l.Partitions {
			if k == key(l.Partitions[i].Source) {
				partition = &l.Partitions[i]
			}
		}
		if partition == nil || seen[k] || saved.Group != m.Group || saved.ErrorCode != 0 || (saved.Present && saved.Source.Offset < 0) || (!saved.Present && saved.Source.Offset != -1) {
			return false, false, fmt.Errorf("saved observations require exact source/group identities and explicit absent-1 versus present0")
		}
		seen[k] = true
		progress = progress && saved.Present && saved.Source.Offset == partition.End
		if saved.Present {
			prefix[k] = saved.Source.Offset
			if saved.Source.Offset > partition.End {
				violation("saved_beyond_published", "saved_prefix", "saved next offset exceeds this independently verified phase end", a.ID, "")
			} else {
				v1.Saved = append(v1.Saved, SavedPosition{Source: saved.Source, Group: saved.Group, Proof: "typed independent OffsetFetch"})
			}
		}
	}
	if err := validateAudit(v1, outputs, l, m.Group); err != nil {
		return false, false, err
	}
	tail := true
	for _, scan := range a.Scans {
		if !scan.Complete || scan.Reached != scan.End || scan.StableEnd < scan.End || scan.Proof == "" {
			return false, false, fmt.Errorf("every output scan must reach its independently fixed end")
		}
		tail = tail && scan.StableEnd == scan.End
	}
	progress = progress && len(unmatchedRequired(l.Entries, outputs, nil)) == 0 && (a.Mode == "settled" || assigned)
	for _, output := range outputs {
		sig, _ := recordSignature(output.Record)
		matched, routed := false, false
		for _, entry := range l.Entries {
			want, _ := recordSignature(entry.Record)
			if want == sig {
				matched, routed = true, routed || routeMatches(entry, output)
			}
		}
		if !matched {
			violation("unpublished_or_corrupt_output", "byte_fidelity", "output cannot substitute for independently published phase input", a.ID, "")
		} else if !routed {
			violation("wrong_partition", "routing", "output is outside the fixed phase route", a.ID, "")
		}
	}
	if a.Mode == "settled" {
		lastExit := identity.Int64(-1)
		for _, w := range workers {
			if w.exit == nil || w.cleanup == nil || !w.exit.Reaped || !w.cleanup.Reaped || w.cleanup.Interval.EndNS > a.ScanInterval.StartNS {
				return false, false, fmt.Errorf("settlement requires every owned worker exited/reaped/cleaned before scanning")
			}
			lastExit = max(lastExit, w.exit.Interval.EndNS)
		}
		if len(workers) == 0 || !tail || !phaseBrokersAvailable(brokers, a.ScanInterval.StartNS) || !m2RestartAfter(brokers["destination"], lastExit, a.ScanInterval.StartNS) {
			return false, false, fmt.Errorf("settlement needs restored brokers and destination restart after actual waits")
		}
		for _, history := range brokers {
			for _, b := range history {
				if (b.Action == "restart" || b.Action == "restore") && b.Interval.EndNS > verifiedAt {
					return false, false, fmt.Errorf("retained source must be reverified after broker stabilization")
				}
			}
		}
		settled = true
		for _, id := range unmatchedRequired(l.Entries, outputs, prefix) {
			violation("unsafe_saved_prefix", "saved_prefix", "settled saved progress covers required published input absent from output", a.ID, id)
		}
		if a.Final {
			for _, id := range unmatchedRequired(l.Entries, outputs, nil) {
				violation("required_record_missing", "required_membership", "settled final output lacks a required full-ledger record", a.ID, id)
			}
		}
	}
	return settled, progress, nil
}

func phasePayload(e PhaseEvent) bool {
	count := 0
	for _, exists := range []bool{e.Declaration != nil, e.Publication != nil, e.Verified != nil, e.Worker != nil, e.Broker != nil, e.Output != nil, e.Audit != nil, e.Finished != nil} {
		if exists {
			count++
		}
	}
	if count != 1 {
		return false
	}
	switch e.Kind {
	case "input_declared":
		return e.Declaration != nil
	case "input_published":
		return e.Publication != nil
	case "input_phase_verified":
		return e.Verified != nil
	case "worker":
		return e.Worker != nil
	case "broker":
		return e.Broker != nil
	case "output":
		return e.Output != nil
	case "audit":
		return e.Audit != nil
	case "run_finished":
		return e.Finished != nil
	}
	return false
}

func loadPhaseBundle(dir string, manifestRaw []byte) Result {
	var m PhaseManifest
	r := phaseResult(m)
	fail := func(code string, e error) Result {
		r.Findings = append(r.Findings, Finding{Code: code, Message: e.Error()})
		return r
	}
	if err := strictJSON(manifestRaw, &m); err != nil {
		return fail("manifest_json", err)
	}
	r = phaseResult(m)
	if m.Events.Path != EventsName || m.Artifact.Path != ArtifactName || !digestValid(m.Events.SHA256) || !digestValid(m.Artifact.SHA256) || m.Events.Bytes <= 0 || m.Events.Bytes > maxEventsBytes || m.Artifact.Bytes <= 0 || m.Artifact.Bytes > 4<<20 || m.EventCount <= 0 || m.EventCount > maxEvents {
		return fail("manifest_integrity", fmt.Errorf("version3 uses bounded fixed four-file evidence attachments"))
	}
	completionRaw, err := readRegular(dir, CompleteName, 1<<20)
	if err != nil {
		return fail("completion_read", err)
	}
	var c M2Completion // same integrity envelope, explicitly version3
	if err := strictJSON(completionRaw, &c); err != nil {
		return fail("completion_json", err)
	}
	if c.SchemaVersion != PhaseSchemaVersion || c.RunID != m.RunID || c.ManifestSHA256 != digest(manifestRaw) || c.EventsSHA256 != m.Events.SHA256 || c.EventCount != m.EventCount {
		return fail("completion_integrity", fmt.Errorf("completion does not bind this version3 manifest/stream/count/run"))
	}
	artifactRaw, err := readRegular(dir, ArtifactName, 4<<20)
	if err != nil {
		return fail("artifact_read", err)
	}
	var artifact ArtifactMetadata
	if !matchesFile(artifactRaw, m.Artifact) {
		return fail("artifact_hash", fmt.Errorf("artifact bytes differ from finalized manifest"))
	}
	if err := strictJSON(artifactRaw, &artifact); err != nil {
		return fail("artifact_json", err)
	}
	stream, err := readRegular(dir, EventsName, maxEventsBytes)
	if err != nil {
		return fail("events_read", err)
	}
	if !matchesFile(stream, m.Events) || len(stream) == 0 || stream[len(stream)-1] != '\n' {
		return fail("events_integrity", fmt.Errorf("event bytes must be complete newline-terminated finalized evidence"))
	}
	lines := bytes.Split(stream[:len(stream)-1], []byte{'\n'})
	if int64(len(lines)) != int64(m.EventCount) {
		return fail("events_count", fmt.Errorf("event count differs from finalized manifest"))
	}
	events := make([]PhaseEvent, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 || len(line) > maxEventBytes {
			return fail("event_size", fmt.Errorf("event is empty or exceeds the existing line bound"))
		}
		var event PhaseEvent
		if err := strictJSON(line, &event); err != nil {
			return fail("event_json", err)
		}
		events = append(events, event)
	}
	return CheckPhaseHistory(m, artifact, events)
}
