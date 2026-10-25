package evidence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"sort"
	"strings"
)

type partitionKey struct {
	cluster, topic, id string
	partition          int32
}

func key(p identity.SourcePosition) partitionKey {
	return partitionKey{p.Cluster, p.Topic, p.TopicID, p.Partition}
}

type checkedAudit struct {
	audit    Audit
	outputs  []Output
	seq      identity.Int64
	complete bool
}
type faultState struct {
	spec                                   FaultSpec
	trigger, requested, reached, recovered identity.Int64
	request                                FaultObservation
}

func checkHistory(m Manifest, events []Event, r Result) Result {
	r.Verdict = Pass
	invalid := func(code, msg string) Result {
		r.Verdict = HarnessError
		r.Findings = append(r.Findings, Finding{Code: code, Message: msg})
		return r
	}
	missing, violation := false, false
	addMissing := func(code, msg string) {
		missing = true
		r.Findings = append(r.Findings, Finding{Code: code, Message: msg})
	}
	addViolation := func(code, property, msg, audit, id string) {
		violation = true
		r.Findings = append(r.Findings, Finding{Code: code, Property: property, Message: msg, AuditID: audit, EntryID: id})
	}
	if len(events) == 0 || events[0].Kind != "ledger" {
		return invalid("ledger_order", "first event must be the complete prepared ledger")
	}
	ledger := *events[0].Ledger
	if len(ledger.Entries) > 1024 || len(ledger.Partitions) > 256 || len(ledger.Destinations) > 256 {
		r.Verdict = Unsupported
		r.Findings = append(r.Findings, Finding{Code: "checker_capacity", Message: "v1 supports at most 1024 ledger entries and 256 source/destination partitions; larger evidence requires a reviewed checker extension"})
		return r
	}
	if err := validateLedger(ledger); err != nil {
		return invalid("ledger_invalid", err.Error())
	}
	for _, entry := range ledger.Entries {
		if entry.Archive != nil {
			r.Verdict = Unsupported
			r.Findings = append(r.Findings, Finding{Code: "archive_scope", Message: "physical archive obligation checking is not implemented until M4"})
			return r
		}
	}
	bySignature := map[string][]LedgerEntry{}
	for _, entry := range ledger.Entries {
		sig, _ := recordSignature(entry.Record)
		bySignature[sig] = append(bySignature[sig], entry)
	}
	if hasIndistinguishable(ledger.Entries) {
		r.Limitations = append(r.Limitations, "Identical byte-only obligations are checked for aggregate multiplicity; replay can mask loss of a particular indistinguishable occurrence.")
	}
	if hasAmbiguousForbidden(ledger.Entries) {
		addMissing("ambiguous_forbidden_identity", "required/permitted and forbidden records have identical observable bytes; aborted-record absence cannot be independently decided")
	}
	if len(m.RequiredFaults) == 0 {
		return invalid("required_faults", "v1 fault histories require an explicit nonempty required fault set")
	}
	faults := map[string]*faultState{}
	for _, spec := range m.RequiredFaults {
		if spec.ID == "" || faults[spec.ID] != nil {
			return invalid("fault_identity", "empty or duplicate required fault ID")
		}
		if spec.Kind != "process_kill" || spec.TriggerPredicate != "required_output_outstanding" {
			r.Verdict = Unsupported
			r.Findings = append(r.Findings, Finding{Code: "fault_kind", Message: "v1 supports process_kill with required_output_outstanding only"})
			return r
		}
		faults[spec.ID] = &faultState{spec: spec}
	}
	pendingOutputs := map[string][]Output{}
	observed := map[identity.SourcePosition]string{}
	audits := map[string]checkedAudit{}
	auditOrder := []string{}
	var latestOutput identity.Int64
	verified, finished := false, false
	finals := 0
	for index, e := range events {
		switch e.Kind {
		case "ledger":
			if index != 0 {
				return invalid("ledger_duplicate", "ledger cannot be replaced or appended after preparation")
			}
		case "inputs_verified":
			if verified {
				return invalid("input_verification_duplicate", "input verification event is duplicated")
			}
			verified = true
			v := e.InputsVerified
			if !v.Complete || strings.TrimSpace(v.Proof) == "" {
				addMissing("input_unverified", "acknowledged input ledger lacks a complete independent verification")
			}
			if v.Method != "independent_source_scan" && v.Method != "standin_fsynced_ledger" && !(m.Namespace == "calibration" && v.Method == "synthetic_history") {
				addMissing("input_verification_method", "unsupported independent input verification method")
			}
		case "output":
			o := *e.Output
			latestOutput = e.Seq
			if !verified {
				return invalid("unverified_output", "output observation precedes prepared-input verification")
			}
			if o.AuditID == "" {
				return invalid("output_audit", "output lacks an audit identity")
			}
			if _, exists := audits[o.AuditID]; exists {
				return invalid("output_after_audit", "output cannot be appended to an already finalized audit scan")
			}
			if err := validatePosition(o.Destination); err != nil {
				return invalid("output_identity", err.Error())
			}
			if _, err := recordSignature(o.Record); err != nil {
				return invalid("output_record", err.Error())
			}
			pendingOutputs[o.AuditID] = append(pendingOutputs[o.AuditID], o)
			if len(pendingOutputs[o.AuditID]) > 16384 {
				r.Verdict = Unsupported
				r.Findings = append(r.Findings, Finding{Code: "checker_capacity", Message: "v1 supports at most 16384 observations per audit; this is a checker resource limit, not a product duplicate bound"})
				return r
			}
		case "audit":
			a := *e.Audit
			if !verified {
				return invalid("audit_unverified", "audit precedes independent input verification")
			}
			if a.ID == "" {
				return invalid("audit_identity", "audit ID missing")
			}
			if _, exists := audits[a.ID]; exists {
				return invalid("audit_duplicate", "audit ID reused")
			}
			outputs := pendingOutputs[a.ID]
			delete(pendingOutputs, a.ID)
			if err := validateAudit(a, outputs, ledger, m.Group); err != nil {
				return invalid("audit_invalid", err.Error())
			}
			for _, output := range outputs {
				sig, _ := recordSignature(output.Record)
				if previous, exists := observed[output.Destination]; exists && previous != sig {
					return invalid("output_conflict", "audits report different record bytes at the same full destination position")
				}
				observed[output.Destination] = sig
			}
			complete := true
			for _, scan := range a.Scans {
				if !scan.Complete || scan.Reached != scan.End || scan.StableEnd < scan.End || ((a.Kind == "quiescent" || a.Final) && scan.StableEnd != scan.End) || strings.TrimSpace(scan.Proof) == "" {
					complete = false
				}
			}
			if !complete {
				addMissing("scan_incomplete", "audit "+a.ID+" lacks confirmed complete stable scan boundaries")
			}
			if a.Final {
				finals++
				if a.ID != m.FinalAuditID {
					return invalid("final_audit_identity", "final audit does not match the manifest")
				}
			}
			if a.Kind == "quiescent" {
				if !a.PendingOutputResolved || a.QuiescenceProof == "" {
					addMissing("pending_output", "quiescent audit "+a.ID+" does not resolve pending-output ambiguity")
				}
				if a.QuiescenceMethod != "workers_stopped" && !(m.Scope == "standin" && a.QuiescenceMethod == "standin_barrier") {
					addMissing("quiescence_method", "audit "+a.ID+" lacks a supported process/barrier observation")
				}
				if len(a.Saved) != len(ledger.Partitions) {
					addMissing("saved_missing", "quiescent audit "+a.ID+" omits source saved positions")
				}
			}
			if a.Final && a.Kind != "quiescent" {
				addMissing("final_not_quiescent", "final audit must stop/reap workers and resolve pending output")
			}
			audits[a.ID] = checkedAudit{audit: a, outputs: outputs, seq: e.Seq, complete: complete}
			auditOrder = append(auditOrder, a.ID)
		case "trigger":
			t := e.Trigger
			f := faults[t.FaultID]
			if f == nil || f.trigger != 0 {
				return invalid("trigger_identity", "trigger has unknown or duplicate fault identity")
			}
			a, exists := audits[t.AuditID]
			if !exists || a.seq >= e.Seq || a.audit.Final {
				return invalid("trigger_audit", "trigger must cite a previously finalized non-final scan")
			}
			if auditOrder[len(auditOrder)-1] != t.AuditID {
				addMissing("trigger_audit_stale", "fault "+t.FaultID+" does not cite the latest finalized audit")
			}
			if latestOutput > a.seq {
				addMissing("trigger_changed", "output observations are newer than fault "+t.FaultID+" trigger audit")
			}
			if t.Predicate != f.spec.TriggerPredicate || t.Observer == "" || t.Proof == "" {
				addMissing("trigger_proof", "fault "+t.FaultID+" lacks independent trigger proof")
			}
			if len(unmatchedRequired(ledger.Entries, a.outputs, nil)) == 0 {
				addMissing("trigger_unreached", "no independently observed required output lag at fault "+t.FaultID)
			}
			if !a.complete {
				addMissing("trigger_scan_incomplete", "trigger audit lacks confirmed scan boundaries")
			}
			for _, scan := range a.audit.Scans {
				if scan.End != scan.StableEnd {
					addMissing("trigger_scan_incomplete", "trigger audit omits an observed destination tail that may contain required output")
					break
				}
			}
			f.trigger = e.Seq
		case "fault_requested", "fault_reached", "fault_recovered":
			o := *e.Fault
			f := faults[o.ID]
			if f == nil {
				return invalid("fault_unknown", "event refers to a fault absent from manifest")
			}
			if !verified {
				return invalid("fault_unverified_input", "fault injection precedes independent verification of input")
			}
			if o.Observer == "" || o.Proof == "" {
				addMissing("fault_observation", "fault "+o.ID+" lacks independent request/reached/recovered evidence")
			}
			switch e.Kind {
			case "fault_requested":
				if f.requested != 0 {
					return invalid("fault_request_duplicate", "fault request duplicated")
				}
				if f.trigger == 0 {
					addMissing("trigger_missing", "fault "+o.ID+" was requested without a reached trigger")
				} else if latestOutput > f.trigger || audits[auditOrder[len(auditOrder)-1]].seq > f.trigger {
					addMissing("trigger_changed", "output or audit observations changed after the trigger and before fault "+o.ID+" request")
				}
				if o.PID <= 0 || (o.Signal != "SIGKILL" && o.Signal != "SIGTERM") || o.ExitCode != nil || o.RecoveryPID != 0 {
					return invalid("fault_request_invalid", "process-kill request requires PID and signal only")
				}
				f.requested = e.Seq
				f.request = o
			case "fault_reached":
				if f.requested == 0 || f.reached != 0 {
					return invalid("fault_reached_order", "reached fault must follow exactly one request")
				}
				if o.PID != f.request.PID || o.Signal != f.request.Signal || o.ExitCode == nil || *o.ExitCode != -1 || o.RecoveryPID != 0 {
					addMissing("fault_not_reached", "process wait evidence does not confirm the requested signaled exit (-1)")
				}
				f.reached = e.Seq
			case "fault_recovered":
				if f.reached == 0 || f.recovered != 0 {
					return invalid("fault_recovery_order", "recovery must follow exactly one reached fault")
				}
				if o.PID != f.request.PID || o.Signal != f.request.Signal || o.RecoveryPID <= 0 || o.RecoveryPID == o.PID || o.ExitCode != nil {
					addMissing("fault_not_recovered", "recovery lacks a distinct successfully observed replacement process")
				}
				f.recovered = e.Seq
			}
		case "run_finished":
			if finished || index != len(events)-1 {
				return invalid("finish_order", "run_finished must occur exactly once as the final event")
			}
			finished = true
			if e.Finished.TimedOut {
				addMissing("run_timeout", "bounded experiment timed out")
			}
			if !e.Finished.CleanupComplete || e.Finished.Proof == "" {
				addMissing("cleanup_missing", "bounded process cleanup is not independently confirmed")
			}
		}
		if e.ElapsedMS > m.BudgetMS {
			addMissing("run_budget", "an event exceeds the experiment's recorded time budget")
		}
	}
	if !verified {
		addMissing("inputs_unverified", "independent input verification event is missing")
	}
	if !finished {
		addMissing("finish_missing", "run_finished evidence is missing")
	}
	if len(pendingOutputs) > 0 {
		return invalid("unfinalized_output", "output stream refers to an absent finalized audit")
	}
	if finals != 1 {
		addMissing("final_audit_missing", "exactly one complete final audit is required")
	}
	final, hasFinal := audits[m.FinalAuditID]
	if !hasFinal {
		addMissing("final_audit_missing", "manifest final audit is absent")
	}
	for _, spec := range m.RequiredFaults {
		f := faults[spec.ID]
		if f.trigger == 0 {
			addMissing("trigger_missing", "required fault "+spec.ID+" lacks trigger evidence")
		}
		if f.requested == 0 || f.reached == 0 || f.recovered == 0 {
			addMissing("fault_lifecycle_missing", "required fault "+spec.ID+" lacks requested/reached/recovered observations")
		}
		if hasFinal && f.recovered >= final.seq {
			addMissing("recovery_after_final", "final scan precedes fault recovery")
		}
	}
	// Each audit is checked separately: later output cannot repair an unsafe
	// saved prefix in an earlier quiescent audit, and rescans do not add counts.
	for _, auditID := range auditOrder {
		a := audits[auditID]
		for _, o := range a.outputs {
			sig, _ := recordSignature(o.Record)
			allowed, forbidden, routed := false, false, false
			for _, entry := range bySignature[sig] {
				if entry.Disposition == "forbidden" {
					forbidden = true
					continue
				}
				allowed = true
				if routeMatches(entry, o) {
					routed = true
				}
			}
			if forbidden && !allowed {
				addViolation("forbidden_output", "forbidden_absence", "forbidden/aborted record appears in destination", auditID, "")
			} else if !allowed && !forbidden {
				addViolation("corrupt_or_unexpected_output", "byte_fidelity", "observed bytes do not match any permitted ledger record", auditID, "")
			} else if allowed && !routed {
				addViolation("wrong_partition", "routing", "record appears outside every allowed topic/partition route", auditID, "")
			}
		}
		if a.audit.Final {
			for _, id := range unmatchedRequired(ledger.Entries, a.outputs, nil) {
				addViolation("required_record_missing", "required_membership", "final scan lacks a required physical occurrence", auditID, id)
			}
		}
		if a.audit.Kind == "quiescent" && a.audit.PendingOutputResolved {
			prefix := map[partitionKey]identity.Int64{}
			for _, saved := range a.audit.Saved {
				prefix[key(saved.Source)] = saved.Source.Offset
			}
			for _, id := range unmatchedRequired(ledger.Entries, a.outputs, prefix) {
				addViolation("unsafe_saved_prefix", "saved_prefix", "saved next offset covers a required record absent from this audit's complete output", auditID, id)
			}
		}
	}
	if missing {
		r.Verdict = Inconclusive
	} else if violation {
		r.Verdict = Violation
	}
	if r.Namespace == "calibration" {
		r.Limitations = append(r.Limitations, "Calibration evidence is synthetic or a stand-in and can never qualify a published release.")
	}
	return r
}

func validatePosition(p identity.SourcePosition) error {
	id, err := hex.DecodeString(p.TopicID)
	if p.Cluster == "" || p.Topic == "" || err != nil || len(id) != 16 || hex.EncodeToString(id) != p.TopicID || p.TopicID == strings.Repeat("0", 32) || p.Partition < 0 || p.Offset < 0 {
		return fmt.Errorf("invalid cluster/topic identity, partition or offset")
	}
	return nil
}
func recordSignature(r identity.Record) (string, error) {
	if r.Headers == nil {
		return "", fmt.Errorf("headers must be an explicit ordered array")
	}
	if r.TimestampKind != "unknown" && r.TimestampKind != "create_time" && r.TimestampKind != "log_append_time" {
		return "", fmt.Errorf("unknown timestamp kind")
	}
	if (r.TimestampKind == "unknown") != (r.TimestampMS == nil) {
		return "", fmt.Errorf("timestamp kind and nullable milliseconds disagree")
	}
	// The identity marshaler validates byte encodings while forming the signature.
	wire, err := json.Marshal(r)
	return string(wire), err
}

type interval struct{ start, end identity.Int64 }

func covers(start, end identity.Int64, offsets []identity.Int64, gaps []Gap) error {
	if start < 0 || end < start {
		return fmt.Errorf("invalid partition interval")
	}
	spans := make([]interval, 0, len(offsets)+len(gaps))
	for _, offset := range offsets {
		if offset < start || offset >= end {
			return fmt.Errorf("record outside observed partition bounds")
		}
		spans = append(spans, interval{offset, offset + 1})
	}
	for _, g := range gaps {
		if g.Start < start || g.End > end || g.Start >= g.End || g.Reason == "" || g.Proof == "" {
			return fmt.Errorf("invalid or unsupported offset gap")
		}
		spans = append(spans, interval{g.Start, g.End})
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end < spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	next := start
	for _, span := range spans {
		if span.start != next {
			return fmt.Errorf("partition scan/ledger contains a duplicate, conflict or unexplained offset gap")
		}
		next = span.end
	}
	if next != end {
		return fmt.Errorf("partition scan/ledger does not cover its complete declared interval")
	}
	return nil
}
func validateLedger(l Ledger) error {
	if len(l.Partitions) == 0 || len(l.Destinations) == 0 || len(l.Entries) == 0 {
		return fmt.Errorf("source ranges, destination identities and finite entries are required")
	}
	ranges := map[partitionKey]PartitionRange{}
	for _, p := range l.Partitions {
		if err := validatePosition(p.Source); err != nil {
			return err
		}
		if _, exists := ranges[key(p.Source)]; exists {
			return fmt.Errorf("duplicate source partition range")
		}
		ranges[key(p.Source)] = p
	}
	destinations := map[partitionKey]bool{}
	for _, p := range l.Destinations {
		if err := validatePosition(p); err != nil {
			return err
		}
		fixed := l.Destinations[0]
		if p.Cluster != fixed.Cluster || p.Topic != fixed.Topic || p.TopicID != fixed.TopicID {
			return fmt.Errorf("v1 destination partitions must share one fixed cluster/topic/topic-ID")
		}
		if destinations[key(p)] {
			return fmt.Errorf("duplicate prepared destination partition")
		}
		destinations[key(p)] = true
	}
	ids := map[string]bool{}
	positions := map[identity.SourcePosition]bool{}
	offsets := map[partitionKey][]identity.Int64{}
	for _, e := range l.Entries {
		if e.ID == "" || ids[e.ID] {
			return fmt.Errorf("empty/duplicate ledger entry ID")
		}
		ids[e.ID] = true
		if err := validatePosition(e.Source); err != nil {
			return err
		}
		if positions[e.Source] {
			return fmt.Errorf("duplicate/conflicting source record position")
		}
		positions[e.Source] = true
		if _, exists := ranges[key(e.Source)]; !exists {
			return fmt.Errorf("ledger entry has no prepared source range")
		}
		offsets[key(e.Source)] = append(offsets[key(e.Source)], e.Source.Offset)
		if _, err := recordSignature(e.Record); err != nil {
			return err
		}
		if e.Disposition != "required" && e.Disposition != "permitted" && e.Disposition != "forbidden" {
			return fmt.Errorf("unknown ledger disposition")
		}
		if e.Reason == "" {
			return fmt.Errorf("ledger disposition lacks an independently supported reason")
		}
		if e.DestinationTopic == "" || len(e.AllowedPartitions) == 0 {
			return fmt.Errorf("ledger route must enumerate allowed destination partitions")
		}
		seen := map[int32]bool{}
		for _, part := range e.AllowedPartitions {
			if part < 0 || seen[part] {
				return fmt.Errorf("invalid/duplicate destination route")
			}
			seen[part] = true
			found := false
			for _, dest := range l.Destinations {
				if dest.Topic == e.DestinationTopic && dest.Partition == part {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("route names an unprepared destination partition")
			}
		}
	}
	for _, p := range l.Partitions {
		if err := covers(p.Source.Offset, p.End, offsets[key(p.Source)], p.Gaps); err != nil {
			return err
		}
	}
	return nil
}
func validateAudit(a Audit, outputs []Output, l Ledger, group string) error {
	if a.Kind != "snapshot" && a.Kind != "quiescent" {
		return fmt.Errorf("audit must be snapshot or quiescent")
	}
	if len(a.Scans) != len(l.Destinations) {
		return fmt.Errorf("audit must scan every prepared destination partition")
	}
	seen := map[partitionKey]bool{}
	offsets := map[partitionKey][]identity.Int64{}
	for _, o := range outputs {
		offsets[key(o.Destination)] = append(offsets[key(o.Destination)], o.Destination.Offset)
	}
	for _, s := range a.Scans {
		if err := validatePosition(s.Source); err != nil {
			return err
		}
		k := key(s.Source)
		if seen[k] {
			return fmt.Errorf("duplicate audit scan partition")
		}
		seen[k] = true
		prepared := false
		for _, dest := range l.Destinations {
			if s.Source == dest {
				prepared = true
			}
		}
		if !prepared {
			return fmt.Errorf("scan identity/initial position differs from prepared destination")
		}
		if err := covers(s.Source.Offset, s.End, offsets[k], s.Gaps); err != nil {
			return err
		}
	}
	for k := range offsets {
		if !seen[k] {
			return fmt.Errorf("output is outside the independently scanned destination identities")
		}
	}
	savedSeen := map[partitionKey]bool{}
	for _, s := range a.Saved {
		if err := validatePosition(s.Source); err != nil {
			return err
		}
		k := key(s.Source)
		if savedSeen[k] || s.Group != group || s.Proof == "" {
			return fmt.Errorf("duplicate, wrong-group or unproved saved source position")
		}
		savedSeen[k] = true
		found := false
		for _, p := range l.Partitions {
			if key(p.Source) == k && s.Source.Offset >= p.Source.Offset && s.Source.Offset <= p.End {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("saved position is outside independently verified source interval")
		}
	}
	return nil
}
func routeMatches(e LedgerEntry, o Output) bool {
	if o.Destination.Topic != e.DestinationTopic {
		return false
	}
	for _, part := range e.AllowedPartitions {
		if o.Destination.Partition == part {
			return true
		}
	}
	return false
}

// Each output can satisfy at most one required occurrence. Matching handles
// overlapping partition routes without letting one output satisfy two inputs.
// Additional replay copies remain permitted and are never capped.
func unmatchedRequired(entries []LedgerEntry, outputs []Output, prefix map[partitionKey]identity.Int64) []string {
	required := []LedgerEntry{}
	for _, e := range entries {
		if e.Disposition != "required" {
			continue
		}
		if prefix != nil {
			next, exists := prefix[key(e.Source)]
			if !exists || e.Source.Offset >= next {
				continue
			}
		}
		required = append(required, e)
	}
	outputGroups := map[string][]int{}
	for i, o := range outputs {
		sig, _ := recordSignature(o.Record)
		outputGroups[sig] = append(outputGroups[sig], i)
	}
	entrySig := make([]string, len(required))
	for i, e := range required {
		entrySig[i], _ = recordSignature(e.Record)
	}
	assigned := make([]int, len(outputs))
	for i := range assigned {
		assigned[i] = -1
	}
	var assign func(int, []bool) bool
	assign = func(entry int, seen []bool) bool {
		candidates := outputGroups[entrySig[entry]]
		// Prefer a free observation before searching a reassignment path.
		// Common duplicate groups then need no recursive displacement.
		for _, i := range candidates {
			if !seen[i] && assigned[i] < 0 && routeMatches(required[entry], outputs[i]) {
				seen[i] = true
				assigned[i] = entry
				return true
			}
		}
		for _, i := range candidates {
			if seen[i] || !routeMatches(required[entry], outputs[i]) {
				continue
			}
			seen[i] = true
			if assigned[i] >= 0 && assign(assigned[i], seen) {
				assigned[i] = entry
				return true
			}
		}
		return false
	}
	missing := []string{}
	for i, e := range required {
		if !assign(i, make([]bool, len(outputs))) {
			missing = append(missing, e.ID)
		}
	}
	return missing
}
func hasIndistinguishable(entries []LedgerEntry) bool {
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Disposition != "required" {
			continue
		}
		sig, _ := recordSignature(e.Record)
		if seen[sig] {
			return true
		}
		seen[sig] = true
	}
	return false
}
func hasAmbiguousForbidden(entries []LedgerEntry) bool {
	allowed := map[string]bool{}
	forbidden := map[string]bool{}
	for _, e := range entries {
		sig, _ := recordSignature(e.Record)
		if e.Disposition == "forbidden" {
			forbidden[sig] = true
		} else {
			allowed[sig] = true
		}
	}
	for sig := range allowed {
		if forbidden[sig] {
			return true
		}
	}
	return false
}
