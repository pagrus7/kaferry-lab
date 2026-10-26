package evidence

import "github.com/pagrus7/kaferry-lab/internal/identity"

// Evidence version 3 prepares the two finite input phases of M2. It is not
// roadmap milestone M3 and supplies no delivery/threshold path observation.
const PhaseSchemaVersion = 3
const PhaseCheckerVersion = "evidence-v3"

type PhaseSettings struct {
	ID       string     `json:"id"` // first: primary-threshold4 or primary-unlimited; second: recovery-unlimited
	Settings M2Settings `json:"settings"`
}

type PhaseManifest struct {
	SchemaVersion       int             `json:"schema_version"`
	CheckerVersion      string          `json:"checker_version"`
	Namespace           string          `json:"namespace"`
	RunID               string          `json:"run_id"`
	ScenarioID          string          `json:"scenario_id"`
	Scope               string          `json:"scope"`
	Group               string          `json:"group"`
	Given               string          `json:"given"`
	When                string          `json:"when"`
	Then                string          `json:"then"`
	BudgetNS            identity.Int64  `json:"budget_ns"`
	Subject             Subject         `json:"subject"`
	LabSource           LabSource       `json:"lab_source"`
	Environment         Environment     `json:"environment"`
	SourceEndpoint      string          `json:"source_endpoint"` // fixed worker bootstrap endpoints
	DestinationEndpoint string          `json:"destination_endpoint"`
	Profiles            []PhaseSettings `json:"profiles"`
	Artifact            FileHash        `json:"artifact"`
	Events              FileHash        `json:"events"`
	EventCount          identity.Int64  `json:"event_count"`
	FinalAuditID        string          `json:"final_audit_id"`
}

// A publication receipt alone creates no delivery obligation. Its exact
// declared-ledger digest must subsequently match an independent source scan.
type PhasePublication struct {
	PhaseID      string     `json:"phase_id"` // warmup or full only
	WorkerID     string     `json:"worker_id"`
	Interval     M2Interval `json:"interval"`
	LedgerSHA256 string     `json:"ledger_sha256"`
}

// Source scans retain exact independent readback bytes and their binding, not
// just a producer success/count. RawObservationBase64 retains the exact strict
// JSON PhaseSourceScan bytes; its ledger and complete zero-to-fixed-end scans
// must equal the typed fields.
type PhaseSourceScan struct {
	Ledger Ledger `json:"ledger"`
	Scans  []Scan `json:"scans"`
}

type PhaseVerification struct {
	PhaseID              string         `json:"phase_id"`
	Interval             M2Interval     `json:"interval"`
	Ledger               Ledger         `json:"ledger"`
	Scans                []Scan         `json:"scans"`
	Method               string         `json:"method"`
	Complete             bool           `json:"complete"`
	Error                string         `json:"error"`
	RawObservationBase64 string         `json:"raw_observation_base64"`
	RawObservationSHA256 string         `json:"raw_observation_sha256"`
	RawObservationBytes  identity.Int64 `json:"raw_observation_bytes"`
}

type PhaseWorker struct {
	SettingsID  string   `json:"worker_settings_id"`
	Observation M2Worker `json:"observation"`
}

type PhaseOutput struct {
	PhaseID     string `json:"phase_id"`
	Observation Output `json:"observation"`
}

type PhaseAudit struct {
	PhaseID     string  `json:"phase_id"`
	WorkerID    string  `json:"worker_id"` // warmup witness names the owned primary; empty for settled full audits
	Observation M2Audit `json:"observation"`
}

// Version3 selects a serial controller. Each pause/restore/restart broker
// interval must start at or after the preceding event's ElapsedNS; its receipt
// is appended before the next controller operation. Delayed/backdated mutation
// receipts are not admitted by this fixed history form, not an alternate clock.
type PhaseEvent struct {
	Seq         identity.Int64     `json:"seq"`
	RunID       string             `json:"run_id"`
	ElapsedNS   identity.Int64     `json:"elapsed_ns"`
	Kind        string             `json:"kind"`
	Declaration *Ledger            `json:"declaration,omitempty"`
	Publication *PhasePublication  `json:"publication,omitempty"`
	Verified    *PhaseVerification `json:"verified,omitempty"`
	Worker      *PhaseWorker       `json:"worker,omitempty"`
	Broker      *M2Broker          `json:"broker,omitempty"`
	Output      *PhaseOutput       `json:"output,omitempty"`
	Audit       *PhaseAudit        `json:"audit,omitempty"`
	Finished    *RunFinished       `json:"finished,omitempty"`
}
