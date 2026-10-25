package campaign

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
	"github.com/pagrus7/kaferry-lab/internal/identity"
)

func (c *scenarioController) initManifest(state fixture.State) {
	c.fixtureState = state
	c.manifest = evidence.M2Manifest{SchemaVersion: evidence.M2SchemaVersion, CheckerVersion: evidence.M2CheckerVersion, Namespace: "release", RunID: c.report.RunID, ScenarioID: c.plan.ID, Scope: "kafka", Subject: c.plan.Subject, LabSource: c.plan.LabSource, BudgetNS: identity.Int64(c.plan.Budget + 150*time.Second), Given: "A freshly verified published release, three selected partitions and finite independently read-back synthetic input.", When: "Run the named compiled M2 scenario with retained process and broker observations.", Then: "Completely scan output, verify bytes and routes, and compare saved source prefixes; replay duplicates are allowed.", Environment: evidence.Environment{OrchestratorPlatform: runtime.GOOS + "/" + runtime.GOARCH, ExecutionPlatform: c.plan.Subject.Platform, Runtime: fmt.Sprintf("native host release process uid=%d; disposable Docker brokers %s", os.Geteuid(), state.DockerPlatform), Storage: "single-replica broker container storage retained across restart", Topology: "two independent single-broker Kafka 3.9.2 clusters; source 3 partitions; destination 3 or 5 partitions", Limits: "broker memory 768MiB and CPU1.5; 8..1024 input records; 96 audits; 1MiB/worker log stream; cleanup150s"}, Settings: evidence.M2Settings{MeasurementsVersion: 1, Routing: c.plan.Routing, WorkBudgetNS: identity.Int64(c.plan.Budget), CleanupBudgetNS: identity.Int64(150 * time.Second), DeliveryTimeoutNS: identity.Int64(4 * time.Second), ShutdownTimeoutNS: identity.Int64(6 * time.Second)}}
}
func scenarioM2Interval(i scenarioInterval) evidence.M2Interval {
	return evidence.M2Interval{StartNS: identity.Int64(i.StartNS), EndNS: identity.Int64(i.EndNS)}
}
func (c *scenarioController) appendEvent(event evidence.M2Event) {
	if len(c.events) == 0 && event.Kind != "ledger" {
		c.preledger = append(c.preledger, event)
		return
	}
	event.Seq = identity.Int64(len(c.events) + 1)
	event.RunID = c.report.RunID
	event.ElapsedNS = identity.Int64(time.Since(c.origin))
	c.events = append(c.events, event)
	if event.Kind == "ledger" {
		queued := c.preledger
		c.preledger = nil
		for _, early := range queued {
			c.appendEvent(early)
		}
	}
}
func (c *scenarioController) inputEvent(v kafkaInputVerification, i scenarioInterval, err error) {
	if len(c.ledger.Entries) == 0 && v.Complete {
		ledger := v.Ledger
		c.appendEvent(evidence.M2Event{Kind: "ledger", Ledger: &ledger})
	}
	c.appendEvent(evidence.M2Event{Kind: "inputs_verified", Inputs: &evidence.M2InputsVerified{Interval: scenarioM2Interval(i), Ledger: v.Ledger, Method: "independent_source_scan", Complete: v.Complete, Error: scenarioError(err)}})
}
func (c *scenarioController) workerEvent(p *ownedProcess, action, signal string, i scenarioInterval, exit processExit, err error) {
	id := p.Identity()
	args, _ := json.Marshal(p.plan.Args)
	env, _ := json.Marshal(p.plan.Env)
	worker := &evidence.M2Worker{Identity: evidence.M2WorkerIdentity{WorkerID: id.WorkerID, PID: id.PID, StartTicks: id.StartTicks, ExecutableSHA256: id.ExecutableSHA256, ArgsSHA256: processDigest(args), EnvironmentSHA256: processDigest(env)}, Action: action, Interval: scenarioM2Interval(i), Signal: signal, ExitCode: exit.ExitCode, Reaped: exit.Reaped, LogsTruncated: exit.LogsTruncated, Error: scenarioError(err)}
	switch action {
	case "start":
		worker.LocalElapsedNS = identity.Int64(id.StartedElapsedNanoseconds)
	case "exit":
		usage := exit.ResourceUsage
		worker.ResourceUsage = &usage
		worker.LocalElapsedNS = identity.Int64(exit.ElapsedNanoseconds)
		if exit.Reaped {
			observed := p.launchRequestedAt.Sub(c.origin).Nanoseconds() + exit.ElapsedNanoseconds
			worker.Interval = evidence.M2Interval{StartNS: identity.Int64(observed), EndNS: identity.Int64(observed)}
		}
	}
	c.appendEvent(evidence.M2Event{Kind: "worker", Worker: worker})
}
func scenarioBrokerIdentity(f *brokerFacts) evidence.M2BrokerIdentity {
	if f == nil {
		return evidence.M2BrokerIdentity{}
	}
	return evidence.M2BrokerIdentity{RunID: f.RunID, Role: f.Role, ContainerID: f.ContainerID, Name: f.Name, ImageID: f.ImageID, ImageReference: f.ImageReference, Endpoint: f.Endpoint}
}
func scenarioBrokerState(f *brokerFacts) evidence.M2BrokerState {
	if f == nil {
		return evidence.M2BrokerState{}
	}
	return evidence.M2BrokerState{RunningPresent: f.RunningPresent, PausedPresent: f.PausedPresent, Running: f.Running, Paused: f.Paused, LoopbackBound: len(f.ConfiguredExternalBindings) == 1 && len(f.PublishedExternalBindings) == 1 && f.ConfiguredExternalBindings[0].HostIP == "127.0.0.1" && f.PublishedExternalBindings[0].HostIP == "127.0.0.1"}
}
func (c *scenarioController) brokerInitialEvent(b *ownedBroker, s brokerSnapshot, p *brokerProbeObservation, i scenarioInterval) {
	event := &evidence.M2Broker{Identity: scenarioBrokerIdentity(s.Facts), Action: "inspect", Interval: scenarioM2Interval(i), State: scenarioBrokerState(s.Facts), Error: s.Error}
	c.setBrokerCluster(&event.Identity)
	if p != nil {
		offset := b.origin.Sub(c.origin).Nanoseconds()
		event.Probe = &evidence.M2Probe{Interval: evidence.M2Interval{StartNS: identity.Int64(offset + p.Interval.StartElapsedNanoseconds), EndNS: identity.Int64(offset + p.Interval.EndElapsedNanoseconds)}, Endpoint: p.Endpoint, Available: p.Result.Available, Unavailable: p.Result.Unavailable, APIKeys: p.Result.APIKeys, ErrorCode: p.Result.ErrorCode, Failure: p.Result.Failure, Error: p.Error}
	}
	c.appendEvent(evidence.M2Event{Kind: "broker", Broker: event})
}
func (c *scenarioController) setBrokerCluster(id *evidence.M2BrokerIdentity) {
	if len(c.fixtureState.ClusterIDs) == 2 {
		if id.Role == "source" {
			id.ClusterID = c.fixtureState.ClusterIDs[0]
		} else {
			id.ClusterID = c.fixtureState.ClusterIDs[1]
		}
	}
}
func (c *scenarioController) brokerEvent(b *ownedBroker, o brokerObservation, i scenarioInterval) {
	event := &evidence.M2Broker{Identity: scenarioBrokerIdentity(o.Before.Facts), Action: o.Operation, Interval: scenarioM2Interval(i), Error: o.Error}
	c.setBrokerCluster(&event.Identity)
	offset := b.origin.Sub(c.origin).Nanoseconds()
	convert := func(i brokerInterval) evidence.M2Interval {
		return evidence.M2Interval{StartNS: identity.Int64(offset + i.StartElapsedNanoseconds), EndNS: identity.Int64(offset + i.EndElapsedNanoseconds)}
	}
	if o.Request != nil {
		event.Request = convert(o.Request.Interval)
	}
	for _, check := range o.Checks {
		event.State = scenarioBrokerState(check.Snapshot.Facts)
		if check.Probe != nil {
			p := check.Probe
			event.Probe = &evidence.M2Probe{Interval: convert(p.Interval), Endpoint: p.Endpoint, Available: p.Result.Available, Unavailable: p.Result.Unavailable, APIKeys: p.Result.APIKeys, ErrorCode: p.Result.ErrorCode, Failure: p.Result.Failure, Error: p.Error}
		}
	}
	c.appendEvent(evidence.M2Event{Kind: "broker", Broker: event})
}
func (c *scenarioController) auditEvent(id string, output kafkaScanSnapshot, group kafkaGroupSnapshot, oi, gi scenarioInterval, settled, final bool) error {
	observations, err := output.Outputs(id)
	if err != nil {
		return err
	}
	for i := range observations {
		out := observations[i]
		c.appendEvent(evidence.M2Event{Kind: "output", Output: &out})
	}
	mode := "snapshot"
	if settled {
		mode = "settled"
	}
	audit := &evidence.M2Audit{ID: id, Mode: mode, ScanInterval: scenarioM2Interval(oi), SavedInterval: scenarioM2Interval(gi), Final: final, Scans: []evidence.Scan{}, Saved: []evidence.M2SavedPosition{}}
	audit.GroupInterval = scenarioM2Interval(gi)
	audit.Group = evidence.M2Group{GroupID: group.GroupID, State: group.Description.State, ProtocolType: group.Description.ProtocolType, Protocol: group.Description.Protocol, ErrorCode: group.Description.ErrorCode, Members: []evidence.M2GroupMember{}}
	for _, m := range group.Description.Members {
		audit.Group.Members = append(audit.Group.Members, evidence.M2GroupMember{ID: m.ID, ClientID: m.ClientID, ClientHost: m.ClientHost, AssignmentBase64: m.AssignmentBase64})
	}
	for _, scan := range output.Scans {
		stableEnd := scan.Boundary.LastStable
		if int(scan.Partition) < len(output.After) {
			stableEnd = max(stableEnd, output.After[scan.Partition].LastStable)
		}
		position := kafkaPosition(output.Topic, scan.Partition, scan.Start)
		audit.Scans = append(audit.Scans, evidence.Scan{PartitionRange: evidence.PartitionRange{Source: position, End: identity.Int64(scan.End), Gaps: []evidence.Gap{}}, Reached: identity.Int64(scan.Next), StableEnd: identity.Int64(stableEnd), Complete: true, Proof: "complete independently admitted Fetch-v11 spans; raw scanner receipts in runtime/observations.jsonl"})
	}
	for _, saved := range group.Offsets.Offsets {
		audit.Saved = append(audit.Saved, evidence.M2SavedPosition{Source: saved.Source, Present: saved.Saved, Group: group.GroupID, ErrorCode: saved.ErrorCode})
	}
	c.appendEvent(evidence.M2Event{Kind: "audit", Audit: audit})
	return nil
}
func (c *scenarioController) latestAudit() string {
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].Audit != nil {
			return c.events[i].Audit.ID
		}
	}
	return ""
}
func (c *scenarioController) episode(id, kind string, p, recovery *ownedProcess, trigger, visible, stopped string) {
	e := &evidence.M2Episode{ID: id, Kind: kind, WorkerID: p.Identity().WorkerID, TriggerAuditID: trigger, VisibleAuditID: visible, StoppedAuditID: stopped}
	if recovery != nil {
		e.RecoveryWorkerID = recovery.Identity().WorkerID
	}
	c.appendEvent(evidence.M2Event{Kind: "episode", Episode: e})
}
func (c *scenarioController) pendingEpisode(id, kind string, p *ownedProcess, trigger, stopped string) {
	c.pending = &evidence.M2Episode{ID: id, Kind: kind, WorkerID: p.Identity().WorkerID, TriggerAuditID: trigger, StoppedAuditID: stopped}
}
func (c *scenarioController) completePending(recovery *ownedProcess) {
	if c.pending != nil {
		c.pending.RecoveryWorkerID = recovery.Identity().WorkerID
		c.appendEvent(evidence.M2Event{Kind: "episode", Episode: c.pending})
		c.pending = nil
	}
}
func (c *scenarioController) diagnostic(worker, kind, proof string) {
	now := identity.Int64(time.Since(c.origin))
	c.appendEvent(evidence.M2Event{Kind: "diagnostic", Diagnostic: &evidence.M2Diagnostic{WorkerID: worker, Kind: kind, Interval: evidence.M2Interval{StartNS: now, EndNS: now}, Proof: proof}})
}
func (c *scenarioController) finishEvent(timedOut, cleaned bool) {
	if c.pending != nil {
		c.appendEvent(evidence.M2Event{Kind: "episode", Episode: c.pending})
		c.pending = nil
	}
	c.appendEvent(evidence.M2Event{Kind: "run_finished", Finished: &evidence.RunFinished{TimedOut: timedOut, CleanupComplete: cleaned, Proof: "Owned child wait/cleanup receipts and owned broker restoration probes; fixture remains for caller-owned cleanup."}})
}
func (c *scenarioController) writeBundle() (bool, error) {
	if len(c.events) == 0 {
		// No finite ledger was verified. Retain the typed setup/finalization
		// receipts as an invalid-for-qualification closed history, never invent
		// a source ledger to make the offline checker accept it.
		for _, event := range c.preledger {
			event.Seq = identity.Int64(len(c.events) + 1)
			event.RunID = c.report.RunID
			event.ElapsedNS = identity.Int64(time.Since(c.origin))
			c.events = append(c.events, event)
		}
		c.preledger = nil
		if len(c.events) == 0 {
			return false, errors.New("no typed events available for incomplete campaign")
		}
	}
	directory := filepath.Join(c.plan.Directory, "bundle")
	reserved, err := evidence.WriteM2Bundle(directory, c.manifest, c.plan.Artifact, c.events)
	if err == nil {
		c.report.Bundle = directory
	}
	return reserved, err
}

// Only the completion marker in this newly reserved scenario bundle is removed.
// Failure histories, raw streams and all other evidence remain available.
func invalidateScenarioCompletion(directory string, reserved bool) error {
	if !reserved {
		return nil
	}
	err := os.Remove(filepath.Join(directory, evidence.CompleteName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
