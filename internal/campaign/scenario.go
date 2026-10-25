package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

// ScenarioPlan is a targeted development run, never a release qualification.
// The caller verifies the published archive/provenance/version immediately
// before calling this function. Every worker independently pins executable bytes.
// Directory exists already; its runtime and bundle output paths must not exist.
type ScenarioPlan struct {
	ID, Routing, Directory, Executable string
	WireToolReceipt                    string
	Subject                            evidence.Subject
	Artifact                           evidence.ArtifactMetadata
	LabSource                          evidence.LabSource
	Records                            int
	Budget                             time.Duration
}

type ScenarioReport struct {
	RunID, ScenarioID, Routing, Group, Directory, Bundle string
	StartedAt, FinishedAt                                time.Time
	Records                                              int
	BudgetNS, WorkBudgetNS, CleanupBudgetNS              int64
	Complete, CleanupComplete                            bool
	Error                                                string
	Limitations                                          []string
}

type scenarioInterval struct{ StartNS, EndNS int64 }
type scenarioObservation struct {
	WireCapture     *wireCaptureReceipt       `json:",omitempty"`
	WireCandidates  *wireSubmissionCandidates `json:",omitempty"`
	ProcessState    string                    `json:",omitempty"`
	BrokerProbe     *brokerProbeObservation   `json:",omitempty"`
	Kind            string
	Interval        scenarioInterval
	WorkerID        string                  `json:",omitempty"`
	ProcessIdentity *processIdentity        `json:",omitempty"`
	ProcessExit     *processExit            `json:",omitempty"`
	Broker          *brokerObservation      `json:",omitempty"`
	BrokerSnapshot  *brokerSnapshot         `json:",omitempty"`
	Preparation     *kafkaPreparation       `json:",omitempty"`
	Publication     []kafkaProduceAttempt   `json:",omitempty"`
	Input           *kafkaInputVerification `json:",omitempty"`
	Output          *kafkaScanSnapshot      `json:",omitempty"`
	Group           *kafkaGroupSnapshot     `json:",omitempty"`
	AuditID         string                  `json:",omitempty"`
	Error           string                  `json:",omitempty"`
}

type scenarioController struct {
	wire                *wireCapture
	fixtureState        fixture.State
	preledger           []evidence.M2Event
	plan                ScenarioPlan
	report              *ScenarioReport
	origin              time.Time
	log                 *os.File
	journalErr          error
	k                   *kafkaRun
	source, destination *ownedBroker
	workers             []*ownedProcess
	settledWorkers      map[string]bool
	events              []evidence.M2Event
	manifest            evidence.M2Manifest
	ledger              evidence.Ledger
	nextAudit           int
	pending             *evidence.M2Episode
}

func normalizeScenarioPlan(p ScenarioPlan) (ScenarioPlan, error) {
	switch p.ID {
	case "healthy", "repeated-kill", "delivery-stop", "delivery-threshold", "source-startup", "source-save":
	default:
		return p, errors.New("unknown compiled M2 scenario")
	}
	if p.Routing != "PRESERVE" && p.Routing != "KEY" {
		return p, errors.New("scenario routing must be PRESERVE or KEY")
	}
	if p.WireToolReceipt != "" && (!filepath.IsAbs(p.WireToolReceipt) || p.ID != "healthy") {
		return p, errors.New("experimental wire receipt requires an absolute path and a healthy calibration")
	}
	if !filepath.IsAbs(p.Directory) || !filepath.IsAbs(p.Executable) {
		return p, errors.New("scenario paths must be absolute")
	}
	if p.Records == 0 {
		p.Records = 96
	}
	if p.Records < 8 || p.Records > 1024 {
		return p, errors.New("scenario requires 8..1024 finite records")
	}
	if p.Budget == 0 {
		p.Budget = 5 * time.Minute
	}
	if p.Budget < time.Minute || p.Budget > 450*time.Second {
		return p, errors.New("scenario work budget must be 1..7.5 minutes, plus 150 seconds for cleanup")
	}
	s := p.Subject
	if s.Kind != "published-release" || s.Tag != evidence.ReleaseTag || s.Commit != evidence.ReleaseCommit || s.ExecutableSHA256 != evidence.ReleaseExecutableSHA256 || s.ContractSHA256 != evidence.ContractSHA256 || s.Platform != "linux/amd64" || !strings.Contains(s.VersionOutput, evidence.ReleaseTag) || p.Artifact.Subject != s || p.Artifact.ProvenanceStatus != "verified" || p.Artifact.ArchiveSHA256 != evidence.ReleaseArchiveSHA256 {
		return p, errors.New("scenario requires freshly verified pinned release identity and provenance")
	}
	return p, nil
}

// RunM2Scenario retains failed/unreached attempts and always restores owned
// services and reaps its own children. The caller retains/removes the fixture.
// A successful function return means orchestration completed; only the offline
// checker decides the product properties and which faults were reached.
func RunM2Scenario(ctx context.Context, plan ScenarioPlan, state fixture.State, run fixture.Executor) (report ScenarioReport, err error) {
	plan, err = normalizeScenarioPlan(plan)
	if err != nil {
		return report, err
	}
	if err = nativeProcessPlatform(); err != nil {
		return report, err
	}
	if _, err = fixture.StatePath(state.RunID); err != nil {
		return report, err
	}
	if run == nil {
		return report, errors.New("scenario requires a fixture executor")
	}
	if err = reserveScenarioRuntime(plan.Directory); err != nil {
		return report, err
	}
	origin := time.Now()
	report = ScenarioReport{RunID: state.RunID, ScenarioID: plan.ID, Routing: plan.Routing, Directory: plan.Directory, StartedAt: origin.UTC(), Records: plan.Records, BudgetNS: int64(plan.Budget + 150*time.Second), WorkBudgetNS: int64(plan.Budget), CleanupBudgetNS: int64(150 * time.Second), Limitations: []string{"Targeted M2 evidence; release_qualified remains false.", "Output lag does not identify accepted writes or pending callbacks.", "Container restart preserves broker storage; this does not model power loss."}}
	log, e := os.OpenFile(filepath.Join(plan.Directory, "runtime", "observations.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return report, e
	}
	c := &scenarioController{plan: plan, report: &report, origin: origin, log: log, settledWorkers: map[string]bool{}}
	ctx, cancel := context.WithTimeout(ctx, plan.Budget)
	defer cancel()
	defer func() {
		workErr, workTimedOut := scenarioWorkEnd(ctx)
		err = errors.Join(err, workErr)
		// A fresh numerical cleanup budget survives campaign cancellation.
		cleanup, done := context.WithTimeout(context.Background(), 150*time.Second)
		cleanupErr := c.cleanup(cleanup)
		done()
		report.CleanupComplete = cleanupErr == nil
		err = errors.Join(err, cleanupErr, log.Sync(), log.Close())
		report.Complete = err == nil
		report.FinishedAt = time.Now().UTC()
		if err != nil {
			report.Error = err.Error()
		}
		// Required raw receipts are durable before a closed typed stream can
		// claim success. Any incomplete orchestration remains nonpassing.
		c.finishEvent(workTimedOut, report.CleanupComplete && err == nil)
		bundleReserved, bundleErr := c.writeBundle()
		err = errors.Join(err, bundleErr)
		if err != nil {
			report.Error = err.Error()
			report.Complete = false
		}
		persistErr := persistProcessJSON(filepath.Join(plan.Directory, "runtime"), "scenario.json", report)
		if bundleErr != nil || persistErr != nil {
			// A late persistence failure must not leave a passing completion
			// marker. Preserve every other byte of the failed attempt.
			markerErr := invalidateScenarioCompletion(filepath.Join(plan.Directory, "bundle"), bundleReserved)
			err = errors.Join(err, persistErr, markerErr)
			report.Complete = false
			report.Error = err.Error()
		}
	}()
	c.initManifest(state)
	if plan.ID == "delivery-threshold" {
		report.Limitations = append(report.Limitations, "UNSUPPORTED: no measured independent packet observation establishes the worker accepted-record threshold or drain entry.")
		_ = c.retain(scenarioObservation{Kind: "unsupported", Interval: c.interval(time.Now()), Error: report.Limitations[len(report.Limitations)-1]})
		return report, errors.New("delivery threshold observation is unsupported")
	}
	if err = c.prepare(ctx, state, run); err != nil {
		return report, err
	}
	if plan.WireToolReceipt != "" {
		if err = c.startWire(ctx); err != nil {
			return report, err
		}
	}
	switch plan.ID {
	case "healthy":
		err = c.healthy(ctx)
	case "source-startup":
		err = c.startup(ctx)
	case "repeated-kill":
		err = c.repeatedKill(ctx)
	case "delivery-stop":
		err = c.deliveryStop(ctx)
	case "source-save":
		err = c.sourceSave(ctx)
	}
	return report, err
}

// Reject earlier evidence before any worker or broker operation. The bundle
// writer still reserves exclusively later, so a subsequent collision is retained.
func reserveScenarioRuntime(directory string) error {
	for _, name := range []string{"runtime", "bundle"} {
		_, err := os.Lstat(filepath.Join(directory, name))
		if err == nil {
			return fmt.Errorf("scenario output %s already exists: %w", name, os.ErrExist)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Mkdir(filepath.Join(directory, "runtime"), 0700)
}

// Capture work cancellation once, before the separate cleanup budget starts.
// A later work-deadline expiry cannot change this already completed phase.
func scenarioWorkEnd(ctx context.Context) (error, bool) {
	err := ctx.Err()
	return err, errors.Is(err, context.DeadlineExceeded)
}

func (c *scenarioController) interval(start time.Time) scenarioInterval {
	return scenarioInterval{start.Sub(c.origin).Nanoseconds(), time.Since(c.origin).Nanoseconds()}
}
func (c *scenarioController) retain(o scenarioObservation) error {
	if c.journalErr != nil {
		return c.journalErr
	}
	raw, err := json.Marshal(o)
	if err != nil {
		c.journalErr = err
		return err
	}
	_, err = c.log.Write(append(raw, '\n'))
	c.journalErr = errors.Join(err, c.log.Sync())
	return c.journalErr
}
func (c *scenarioController) prepare(ctx context.Context, state fixture.State, run fixture.Executor) (err error) {
	for _, role := range []string{"source", "destination"} {
		start := time.Now()
		b, s, e := openOwnedBroker(ctx, state, role, run)
		var probe *brokerProbeObservation
		if e == nil {
			observed := b.observeProbe(ctx)
			probe = &observed
			if observed.Error != "" {
				e = errors.New(observed.Error)
			} else if !observed.Result.Available {
				e = errors.New("owned broker did not answer independent readiness probe")
			}
		}
		o := scenarioObservation{Kind: "broker_inspect", Interval: c.interval(start), BrokerSnapshot: &s, BrokerProbe: probe, Error: scenarioError(e)}
		if e = errors.Join(e, c.retain(o)); e != nil {
			return e
		}
		c.brokerInitialEvent(b, s, probe, o.Interval)
		if role == "source" {
			c.source = b
		} else {
			c.destination = b
		}
	}
	start := time.Now()
	k, p, e := openKafka(ctx, state, kafkaPlan{Routing: c.plan.Routing, Records: c.plan.Records}, run)
	c.k = k
	if e = errors.Join(e, c.retain(scenarioObservation{Kind: "preparation", Interval: c.interval(start), Preparation: &p, Error: scenarioError(e)})); e != nil {
		return e
	}
	c.report.Group = p.Source.Topic + "-group"
	c.manifest.Group = c.report.Group
	sql, config := scenarioConfiguration(state, p, c.report.Group, c.plan.Routing)
	for _, f := range []struct{ name, value string }{{"copy.sql", sql}, {"worker.toml", config}} {
		if err = os.WriteFile(filepath.Join(c.plan.Directory, "runtime", f.name), []byte(f.value), 0600); err != nil {
			return err
		}
	}
	c.manifest.Settings.Args = []string{"run", "--file", filepath.Join(c.plan.Directory, "runtime", "copy.sql"), "--config", filepath.Join(c.plan.Directory, "runtime", "worker.toml")}
	c.manifest.Settings.Environment = []string{"HOME=" + filepath.Join(c.plan.Directory, "runtime")}
	c.manifest.Settings.SQL = sql
	c.manifest.Settings.ConfigTOML = config
	c.manifest.Settings.SQLSHA256 = processDigest([]byte(sql))
	c.manifest.Settings.ConfigSHA256 = processDigest([]byte(config))
	for _, warmup := range []bool{true, false} {
		start = time.Now()
		attempts, e := k.Publish(ctx, warmup)
		if e = errors.Join(e, c.retain(scenarioObservation{Kind: "publication", Interval: c.interval(start), Publication: attempts, Error: scenarioError(e)})); e != nil {
			return e
		}
	}
	_, err = c.verify(ctx)
	return err
}
func scenarioConfiguration(state fixture.State, p kafkaPreparation, group, routing string) (string, string) {
	// Values originate only from validated owned endpoints and generated topic/group
	// names. No user SQL or credentials enter these retained arguments.
	sql := fmt.Sprintf("WITH CONNECTION source AS ('bootstrap.servers'='%s','session.timeout.ms'='6000','heartbeat.interval.ms'='1000','socket.timeout.ms'='500'), CONNECTION destination AS ('bootstrap.servers'='%s','client.id'='lab-m2','linger.ms'='1500','request.timeout.ms'='1000','socket.timeout.ms'='500') INSERT INTO TOPIC '%s@destination' WITH (PARTITIONING = %s) SELECT * FROM TOPIC '%s@source' WITH (GROUP='%s') WHERE PARTITION IN (0,1,2);\n", state.Source, state.Destination, p.Destination.Topic, routing, p.Source.Topic, group)
	config := "[worker]\nrecord_cap=1024\npartition_record_cap=1024\nbyte_cap=16777216\npartition_byte_cap=8388608\ndelivery_timeout='4s'\nshutdown_timeout='6s'\nidle_exit='8s'\ntip_wait='8s'\nprogress_interval='1s'\n"
	return sql, config
}
func (c *scenarioController) verify(ctx context.Context) (kafkaInputVerification, error) {
	start := time.Now()
	v, err := c.k.VerifyInputs(ctx, false)
	interval := c.interval(start)
	err = errors.Join(err, c.retain(scenarioObservation{Kind: "inputs_verified", Interval: interval, Input: &v, Error: scenarioError(err)}))
	if err == nil {
		c.inputEvent(v, interval, nil)
		c.ledger = v.Ledger
	}
	// Failed readiness/scan attempts remain in the mandatory raw journal.
	// They are not presented as successful verification of a different ledger.
	return v, err
}
func (c *scenarioController) start(ctx context.Context) (*ownedProcess, error) {
	for _, file := range []struct{ name, digest string }{{"copy.sql", c.manifest.Settings.SQLSHA256}, {"worker.toml", c.manifest.Settings.ConfigSHA256}} {
		bytes, err := os.ReadFile(filepath.Join(c.plan.Directory, "runtime", file.name))
		if err != nil {
			return nil, err
		}
		if processDigest(bytes) != file.digest {
			return nil, errors.New("retained worker configuration changed before invocation")
		}
	}
	id := fmt.Sprintf("worker-%02d", len(c.workers)+1)
	start := time.Now()
	p, err := startReleaseProcess(ctx, processPlan{RunID: c.report.RunID, WorkerID: id, Directory: filepath.Join(c.plan.Directory, "runtime", id), Executable: c.plan.Executable, Args: c.manifest.Settings.Args, Env: c.manifest.Settings.Environment, CleanupTimeout: 10 * time.Second, TermGrace: 2 * time.Second, LogLimit: 1 << 20})
	o := scenarioObservation{Kind: "worker_start", Interval: c.interval(start), WorkerID: id, Error: scenarioError(err)}
	if p != nil {
		c.workers = append(c.workers, p)
		identity := p.Identity()
		o.ProcessIdentity = &identity
		c.workerEvent(p, "start", "", o.Interval, processExit{}, err)
	}
	return p, errors.Join(err, c.retain(o))
}
func (c *scenarioController) signal(ctx context.Context, p *ownedProcess, s syscall.Signal) error {
	start := time.Now()
	err := p.Signal(ctx, s)
	state := ""
	if err == nil && s == syscall.SIGSTOP {
		observed, ticks, e := readProcessState(p.Identity().PID)
		if e != nil {
			err = e
		} else if ticks != p.Identity().StartTicks || (observed != 'T' && observed != 't') {
			err = errors.New("owned worker stopped state was not retained")
		} else {
			state = string(observed)
		}
	}
	o := scenarioObservation{Kind: "signal_" + processSignalName(s), Interval: c.interval(start), WorkerID: p.Identity().WorkerID, Error: scenarioError(err)}
	o.ProcessState = state
	c.workerEvent(p, "signal", processSignalName(s), o.Interval, processExit{}, err)
	if len(c.events) > 0 && c.events[len(c.events)-1].Worker != nil {
		c.events[len(c.events)-1].Worker.ObservedState = state
	}
	return errors.Join(err, c.retain(o))
}
func (c *scenarioController) stop(ctx context.Context, p *ownedProcess, signal syscall.Signal) error {
	if c.settledWorkers[p.Identity().WorkerID] {
		return nil
	}
	var signalErr error
	select {
	case <-p.done:
	default:
		signalErr = c.signal(ctx, p, signal)
	}
	wait, cancel := context.WithTimeout(ctx, 12*time.Second)
	start := time.Now()
	exit, waitErr := p.Wait(wait)
	cancel()
	// Receipt or caller failures cannot bypass the retained-handle cleanup path.
	// Its fresh deadline remains numerical and independent of cancelled work.
	var emergencyErr error
	if waitErr != nil || !exit.Reaped {
		emergency, done := context.WithTimeout(context.Background(), 10*time.Second)
		emergencyErr = p.Cleanup(emergency)
		exit, _ = p.Wait(emergency)
		done()
	}
	err := errors.Join(signalErr, waitErr, emergencyErr)
	if !exit.Reaped {
		return errors.Join(err, errors.New("worker was not reaped"))
	}
	o := scenarioObservation{Kind: "worker_exit", Interval: c.interval(start), WorkerID: p.Identity().WorkerID, ProcessExit: &exit, Error: scenarioError(err)}
	c.workerEvent(p, "exit", exit.Signal, o.Interval, exit, err)
	err = errors.Join(err, c.retain(o))
	start = time.Now()
	cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
	cleanErr := p.Cleanup(cleanup)
	done()
	o = scenarioObservation{Kind: "worker_cleanup", Interval: c.interval(start), WorkerID: p.Identity().WorkerID, Error: scenarioError(cleanErr)}
	c.workerEvent(p, "cleanup", "", o.Interval, exit, cleanErr)
	err = errors.Join(err, cleanErr, c.retain(o))
	// Avoid duplicate lifecycle events even if an earlier request failed. That
	// failure stays in the first receipt and prevents an offline passing verdict.
	c.settledWorkers[p.Identity().WorkerID] = true
	return err
}
func (c *scenarioController) broker(ctx context.Context, b *ownedBroker, operation string) error {
	var observation brokerObservation
	var err error
	switch operation {
	case "pause":
		observation, err = b.Pause(ctx)
	case "restore":
		observation, err = b.Restore(ctx)
	case "restart":
		observation, err = b.Restart(ctx)
	default:
		return errors.New("unknown scenario broker action")
	}
	// The helper origins retain the same Go process monotonic clock. Convert its
	// local interval by the origin difference; no UTC subtraction is used.
	offset := b.origin.Sub(c.origin).Nanoseconds()
	interval := scenarioInterval{offset + observation.Interval.StartElapsedNanoseconds, offset + observation.Interval.EndElapsedNanoseconds}
	c.brokerEvent(b, observation, interval)
	if err == nil && !observation.Reached {
		err = errors.New("broker action was not independently reached")
	}
	return errors.Join(err, c.retain(scenarioObservation{Kind: "broker_" + operation, Interval: interval, Broker: &observation, Error: scenarioError(err)}))
}

type scenarioAuditResult struct {
	ID     string
	Output kafkaScanSnapshot
	Group  kafkaGroupSnapshot
}

func (c *scenarioController) audit(ctx context.Context, settled, final bool) (result scenarioAuditResult, err error) {
	c.nextAudit++
	result.ID = fmt.Sprintf("audit-%03d", c.nextAudit)
	if c.nextAudit > 96 {
		return result, errors.New("bounded audit count exceeded")
	}
	start := time.Now()
	result.Output, err = c.k.SnapshotOutput(ctx)
	oi := c.interval(start)
	err = errors.Join(err, c.retain(scenarioObservation{Kind: "output_scan", Interval: oi, AuditID: result.ID, Output: &result.Output, Error: scenarioError(err)}))
	if err != nil {
		return result, err
	}
	start = time.Now()
	result.Group, err = c.k.SnapshotGroup(ctx, c.report.Group)
	gi := c.interval(start)
	err = errors.Join(err, c.retain(scenarioObservation{Kind: "group_snapshot", Interval: gi, AuditID: result.ID, Group: &result.Group, Error: scenarioError(err)}))
	if err != nil {
		return result, err
	}
	if err = c.auditEvent(result.ID, result.Output, result.Group, oi, gi, settled, final); err != nil {
		return result, err
	}
	if final {
		c.manifest.FinalAuditID = result.ID
	}
	return result, nil
}
func (c *scenarioController) awaitAssigned(ctx context.Context, p *ownedProcess) error {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for i := 0; i < 80; i++ {
		select {
		case <-p.done:
			return errors.New("worker exited before complete assignment")
		default:
		}
		start := time.Now()
		g, err := c.k.SnapshotGroup(bounded, c.report.Group)
		if err = errors.Join(err, c.retain(scenarioObservation{Kind: "assignment_snapshot", Interval: c.interval(start), WorkerID: p.Identity().WorkerID, Group: &g, Error: scenarioError(err)})); err != nil {
			return err
		}
		if scenarioAssigned(g, c.k.Preparation.Source.Topic) {
			return nil
		}
		if err = scenarioPoll(bounded, 100*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("complete assignment not observed within sample bound")
}
func scenarioAssigned(g kafkaGroupSnapshot, topic string) bool {
	if g.Error != "" || g.Description.State != "Stable" || len(g.Description.Members) != 1 {
		return false
	}
	p := g.Description.Members[0].Topics[topic]
	if len(p) != 3 {
		return false
	}
	seen := map[int32]bool{}
	for _, id := range p {
		if id < 0 || id > 2 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return len(seen) == 3
}
func scenarioPoll(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func scenarioError(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func (c *scenarioController) healthy(ctx context.Context) error {
	p, err := c.start(ctx)
	if err != nil {
		return err
	}
	if err = c.awaitComplete(ctx, p); err != nil {
		return err
	}
	if err = c.stop(ctx, p, syscall.SIGTERM); err != nil {
		return err
	}
	return c.settledAudit(ctx, true)
}
func (c *scenarioController) awaitComplete(ctx context.Context, p *ownedProcess) error {
	bounded, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	for i := 0; i < 24; i++ {
		audit, err := c.audit(bounded, false, false)
		if err != nil {
			return err
		}
		membership, err := scenarioMembership(c.ledger, audit.Output)
		if err != nil {
			return err
		}
		if len(membership.Missing) == 0 {
			return nil
		}
		select {
		case <-p.done:
			return errors.New("worker exited with required output absent")
		default:
		}
		if err = scenarioPoll(bounded, 150*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("required output not complete within audit bound")
}
func (c *scenarioController) settledAudit(ctx context.Context, final bool) error {
	for _, p := range c.workers {
		if !c.settledWorkers[p.Identity().WorkerID] {
			return errors.New("settled audit requires every worker reaped and cleaned")
		}
	}
	for _, b := range []*ownedBroker{c.destination, c.source} {
		if err := c.broker(ctx, b, "restore"); err != nil {
			return err
		}
		if err := c.broker(ctx, b, "restart"); err != nil {
			return err
		}
	}
	// API readiness can precede topic leader/offset readiness. Retain preread
	// failures and retry only when no record scan has begun.
	for i := 0; i < 12; i++ {
		verification, err := c.verify(ctx)
		if err == nil {
			_, err = c.audit(ctx, true, final)
			return err
		}
		if c.journalErr != nil || len(verification.Snapshot.Scans) != 0 {
			return err
		}
		if e := scenarioPoll(ctx, 250*time.Millisecond); e != nil {
			return errors.Join(err, e)
		}
	}
	return errors.New("source metadata did not stabilize for retained-input verification")
}
func (c *scenarioController) startup(ctx context.Context) error {
	if err := c.broker(ctx, c.source, "pause"); err != nil {
		return err
	}
	p, err := c.start(ctx)
	if err != nil {
		return err
	}
	// The observed transport impairment precedes launch. The hold is a measured
	// schedule only: it never establishes that a particular coordinator RPC ran.
	if err = scenarioPoll(ctx, 5*time.Second); err != nil {
		return err
	}
	if err = c.stop(ctx, p, syscall.SIGTERM); err != nil {
		return err
	}
	if err = c.broker(ctx, c.source, "restore"); err != nil {
		return err
	}
	if err = c.settledAudit(ctx, false); err != nil {
		return err
	}
	recovery, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.episode("startup-1", "source-startup", p, recovery, "", "", c.latestAudit())
	if err = c.awaitComplete(ctx, recovery); err != nil {
		return err
	}
	if err = c.stop(ctx, recovery, syscall.SIGTERM); err != nil {
		return err
	}
	return c.settledAudit(ctx, true)
}
func (c *scenarioController) repeatedKill(ctx context.Context) error {
	for i := 0; i < 2; i++ {
		p, err := c.start(ctx)
		if err != nil {
			return err
		}
		c.completePending(p)
		if err = c.awaitAssigned(ctx, p); err != nil {
			return err
		}
		if err = c.signal(ctx, p, syscall.SIGSTOP); err != nil {
			return err
		}
		audit, err := c.audit(ctx, false, false)
		if err != nil {
			return err
		}
		m, err := scenarioMembership(c.ledger, audit.Output)
		if err != nil {
			return err
		}
		if len(m.Missing) == 0 {
			return errors.New("kill window unreached: complete destination already visible")
		}
		if err = c.broker(ctx, c.destination, "pause"); err != nil {
			return err
		}
		if err = c.signal(ctx, p, syscall.SIGCONT); err != nil {
			return err
		}
		if err = c.stop(ctx, p, syscall.SIGKILL); err != nil {
			return err
		}
		if err = c.settledAudit(ctx, false); err != nil {
			return err
		}
		// Record the actual audit references now; recovery ID is filled when the
		// next process has really started, never a predicted worker identity.
		c.pendingEpisode(fmt.Sprintf("kill-%d", i+1), "unresolved-kill", p, audit.ID, c.latestAudit())
	}
	// A separate visible-but-unsaved window is sought once, independently of the
	// lag kills. Failing to observe it retains the two kills but cannot pass M2.
	p, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.completePending(p)
	if err = c.awaitAssigned(ctx, p); err != nil {
		return err
	}
	var visible string
	for i := 0; i < 24; i++ {
		audit, e := c.audit(ctx, false, false)
		if e != nil {
			return e
		}
		m, e := scenarioMembership(c.ledger, audit.Output)
		if e != nil {
			return e
		}
		if scenarioVisibleUnsaved(c.ledger, m, audit.Group) {
			visible = audit.ID
			break
		}
		if e = scenarioPoll(ctx, 100*time.Millisecond); e != nil {
			return e
		}
	}
	if visible == "" {
		return errors.New("visible-unsaved crash window not observed; retained unresolved kill attempts are partial")
	}
	if err = c.signal(ctx, p, syscall.SIGSTOP); err != nil {
		return err
	}
	audit, err := c.audit(ctx, false, false)
	if err != nil {
		return err
	}
	visible = audit.ID
	m, err := scenarioMembership(c.ledger, audit.Output)
	if err != nil {
		return err
	}
	if !scenarioVisibleUnsaved(c.ledger, m, audit.Group) {
		return errors.New("visible-unsaved condition disappeared before worker suspension")
	}
	if err = c.stop(ctx, p, syscall.SIGKILL); err != nil {
		return err
	}
	if err = c.settledAudit(ctx, false); err != nil {
		return err
	}
	recovery, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.episode("visible-unsaved-1", "visible-unsaved-kill", p, recovery, visible, visible, c.latestAudit())
	if err = c.awaitComplete(ctx, recovery); err != nil {
		return err
	}
	if err = c.stop(ctx, recovery, syscall.SIGTERM); err != nil {
		return err
	}
	return c.settledAudit(ctx, true)
}
func (c *scenarioController) deliveryStop(ctx context.Context) error {
	p, err := c.start(ctx)
	if err != nil {
		return err
	}
	if err = c.awaitAssigned(ctx, p); err != nil {
		return err
	}
	if err = c.signal(ctx, p, syscall.SIGSTOP); err != nil {
		return err
	}
	trigger, err := c.audit(ctx, false, false)
	if err != nil {
		return err
	}
	m, err := scenarioMembership(c.ledger, trigger.Output)
	if err != nil {
		return err
	}
	if len(m.Missing) == 0 {
		return errors.New("delivery outage unreached: required output already complete")
	}
	if err = c.broker(ctx, c.destination, "pause"); err != nil {
		return err
	}
	if err = c.signal(ctx, p, syscall.SIGCONT); err != nil {
		return err
	}
	// Hold beyond recorded delivery timeout, then TERM while destination remains
	// independently paused. The hold alone does not prove submission/deadline.
	if err = scenarioPoll(ctx, 5*time.Second); err != nil {
		return err
	}
	if err = c.stop(ctx, p, syscall.SIGTERM); err != nil {
		return err
	}
	if err = c.settledAudit(ctx, false); err != nil {
		return err
	}
	stopped := c.latestAudit()
	recovery, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.episode("delivery-stop-1", "delivery-stop", p, recovery, trigger.ID, "", stopped)
	c.diagnostic(p.Identity().WorkerID, "unsupported-observation", "Broker outage exceeded configured delivery timeout; no packet observation proves when missing records were accepted. Timeout and TERM overlap require actual exit/diagnostic inspection.")
	if err = c.awaitComplete(ctx, recovery); err != nil {
		return err
	}
	if err = c.stop(ctx, recovery, syscall.SIGTERM); err != nil {
		return err
	}
	return c.settledAudit(ctx, true)
}
func (c *scenarioController) sourceSave(ctx context.Context) error {
	p, err := c.start(ctx)
	if err != nil {
		return err
	}
	if err = c.awaitAssigned(ctx, p); err != nil {
		return err
	}
	trigger, err := c.audit(ctx, false, false)
	if err != nil {
		return err
	}
	m, err := scenarioMembership(c.ledger, trigger.Output)
	if err != nil {
		return err
	}
	if len(m.Missing) == 0 {
		return errors.New("source-save window unreached: no required output remains")
	}
	if err = c.broker(ctx, c.source, "pause"); err != nil {
		return err
	}
	if err = scenarioPoll(ctx, 5*time.Second); err != nil {
		return err
	}
	if err = c.stop(ctx, p, syscall.SIGTERM); err != nil {
		return err
	}
	if err = c.settledAudit(ctx, false); err != nil {
		return err
	}
	stopped := c.latestAudit()
	recovery, err := c.start(ctx)
	if err != nil {
		return err
	}
	c.episode("source-save-1", "source-save", p, recovery, trigger.ID, "", stopped)
	c.diagnostic(p.Identity().WorkerID, "unsupported-observation", "Source transport was unavailable while output was missing. No independent OffsetCommit request observation establishes a periodic save was hit; this attempt cannot establish the required save-outage mechanism.")
	if err = c.awaitComplete(ctx, recovery); err != nil {
		return err
	}
	if err = c.stop(ctx, recovery, syscall.SIGTERM); err != nil {
		return err
	}
	if err = c.settledAudit(ctx, true); err != nil {
		return err
	}
	return errors.New("source outage recovered, but exact save-outage mechanism remains unsupported")
}
func (c *scenarioController) cleanup(ctx context.Context) error {
	var errs []error
	for _, p := range c.workers {
		if !c.settledWorkers[p.Identity().WorkerID] {
			errs = append(errs, c.stop(ctx, p, syscall.SIGTERM))
		}
	}
	for _, b := range []*ownedBroker{c.destination, c.source} {
		if b != nil {
			errs = append(errs, c.broker(ctx, b, "restore"))
		}
	}
	if c.k != nil {
		if c.manifest.FinalAuditID == "" && len(c.ledger.Entries) > 0 {
			errs = append(errs, c.settledAudit(ctx, true))
		}
		errs = append(errs, c.finishWire(ctx))
		errs = append(errs, c.k.Close())
	}
	errs = append(errs, ctx.Err())
	return errors.Join(errs...)
}

// Membership matching uses complete record bytes, timestamp, topic and route.
// Exact fidelity fixtures occur once in the input. Replay duplicates do not
// conceal a missing uniquely identifiable stress record.
type scenarioMembershipResult struct {
	Visible map[string]bool
	Missing []string
}

func scenarioMembership(ledger evidence.Ledger, output kafkaScanSnapshot) (scenarioMembershipResult, error) {
	result := scenarioMembershipResult{Visible: map[string]bool{}}
	observations, err := output.Outputs("membership")
	if err != nil {
		return result, err
	}
	for _, out := range observations {
		signature, err := kafkaRecordSignature(out.Record)
		if err != nil {
			return result, err
		}
		found := false
		for _, entry := range ledger.Entries {
			expected, err := kafkaRecordSignature(entry.Record)
			if err != nil {
				return result, err
			}
			route := false
			for _, p := range entry.AllowedPartitions {
				if p == out.Destination.Partition {
					route = true
				}
			}
			if signature == expected && entry.DestinationTopic == out.Destination.Topic && route {
				result.Visible[entry.ID] = true
				found = true
				break
			}
		}
		if !found {
			return result, errors.New("output contains unknown, corrupt or misrouted bytes")
		}
	}
	for _, entry := range ledger.Entries {
		if entry.Disposition == "required" && !result.Visible[entry.ID] {
			result.Missing = append(result.Missing, entry.ID)
		}
	}
	return result, nil
}
func scenarioVisibleUnsaved(ledger evidence.Ledger, m scenarioMembershipResult, g kafkaGroupSnapshot) bool {
	if g.Error != "" {
		return false
	}
	for _, entry := range ledger.Entries {
		if !m.Visible[entry.ID] {
			continue
		}
		for _, saved := range g.Offsets.Offsets {
			if saved.ErrorCode == 0 && saved.Source.Cluster == entry.Source.Cluster && saved.Source.Topic == entry.Source.Topic && saved.Source.TopicID == entry.Source.TopicID && saved.Source.Partition == entry.Source.Partition && (!saved.Saved || saved.Source.Offset <= entry.Source.Offset) {
				return true
			}
		}
	}
	return false
}
