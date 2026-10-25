package evidence

import "github.com/pagrus7/kaferry-lab/internal/identity"

const M2SchemaVersion = 2
const M2CheckerVersion = "evidence-v2"

// M2Interval uses one monotonic clock established by the campaign. The helper
// process and broker clocks are retained separately and never compared.
type M2Interval struct {
	StartNS identity.Int64 `json:"start_ns"`
	EndNS   identity.Int64 `json:"end_ns"`
}

type M2Settings struct {
	Routing           string         `json:"routing"`
	Args              []string       `json:"args"`
	Environment       []string       `json:"environment"`
	SQL               string         `json:"sql"`
	ConfigTOML        string         `json:"config_toml"`
	SQLSHA256         string         `json:"sql_sha256"`
	ConfigSHA256      string         `json:"config_sha256"`
	WorkBudgetNS      identity.Int64 `json:"work_budget_ns"`
	CleanupBudgetNS   identity.Int64 `json:"cleanup_budget_ns"`
	DeliveryTimeoutNS identity.Int64 `json:"delivery_timeout_ns"`
	ShutdownTimeoutNS identity.Int64 `json:"shutdown_timeout_ns"`
	RecordThreshold   identity.Int64 `json:"record_threshold"`
}

type M2Manifest struct {
	SchemaVersion  int            `json:"schema_version"`
	CheckerVersion string         `json:"checker_version"`
	Namespace      string         `json:"namespace"`
	RunID          string         `json:"run_id"`
	ScenarioID     string         `json:"scenario_id"`
	Scope          string         `json:"scope"`
	Group          string         `json:"group"`
	Given          string         `json:"given"`
	When           string         `json:"when"`
	Then           string         `json:"then"`
	BudgetNS       identity.Int64 `json:"budget_ns"`
	Subject        Subject        `json:"subject"`
	LabSource      LabSource      `json:"lab_source"`
	Environment    Environment    `json:"environment"`
	Settings       M2Settings     `json:"settings"`
	Artifact       FileHash       `json:"artifact"`
	Events         FileHash       `json:"events"`
	EventCount     identity.Int64 `json:"event_count"`
	FinalAuditID   string         `json:"final_audit_id"`
}

type M2Completion struct {
	SchemaVersion  int            `json:"schema_version"`
	RunID          string         `json:"run_id"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	EventsSHA256   string         `json:"events_sha256"`
	EventCount     identity.Int64 `json:"event_count"`
}

type M2WorkerIdentity struct {
	WorkerID          string `json:"worker_id"`
	PID               int    `json:"pid"`
	StartTicks        string `json:"start_ticks"`
	ExecutableSHA256  string `json:"executable_sha256"`
	ArgsSHA256        string `json:"args_sha256"`
	EnvironmentSHA256 string `json:"environment_sha256"`
}

// Action is start, signal, exit or cleanup. Signal observations retain the
// requested signal; exit observations retain the actual wait result. Reaped
// means Cmd.Wait returned, not merely that kill accepted a request.
type M2Worker struct {
	Identity       M2WorkerIdentity `json:"identity"`
	Action         string           `json:"action"`
	Interval       M2Interval       `json:"interval"`
	LocalElapsedNS identity.Int64   `json:"local_elapsed_ns"`
	Signal         string           `json:"signal"`
	ObservedState  string           `json:"observed_state"`
	ExitCode       int              `json:"exit_code"`
	Reaped         bool             `json:"reaped"`
	LogsTruncated  bool             `json:"logs_truncated"`
	Error          string           `json:"error"`
}

type M2BrokerIdentity struct {
	RunID          string `json:"run_id"`
	Role           string `json:"role"`
	ContainerID    string `json:"container_id"`
	Name           string `json:"name"`
	ImageID        string `json:"image_id"`
	ImageReference string `json:"image_reference"`
	Endpoint       string `json:"endpoint"`
	ClusterID      string `json:"cluster_id"`
}

type M2BrokerState struct {
	RunningPresent bool `json:"running_present"`
	PausedPresent  bool `json:"paused_present"`
	Running        bool `json:"running"`
	Paused         bool `json:"paused"`
	LoopbackBound  bool `json:"loopback_bound"`
}

type M2Probe struct {
	Interval    M2Interval `json:"interval"`
	Endpoint    string     `json:"endpoint"`
	Available   bool       `json:"available"`
	Unavailable bool       `json:"unavailable"`
	APIKeys     int        `json:"api_keys"`
	ErrorCode   int16      `json:"error_code"`
	Failure     string     `json:"failure"`
	Error       string     `json:"error"`
}

// Inspect establishes ownership. Pause/restore/restart require both Docker
// state and an independent Kafka API probe. Removed records actual fixture
// removal; a shared fixture can instead remain restored and available.
type M2Broker struct {
	Identity M2BrokerIdentity `json:"identity"`
	Action   string           `json:"action"`
	Interval M2Interval       `json:"interval"`
	Request  M2Interval       `json:"request"`
	State    M2BrokerState    `json:"state"`
	Probe    *M2Probe         `json:"probe"`
	Removed  bool             `json:"removed"`
	Error    string           `json:"error"`
}

type M2InputsVerified struct {
	Interval M2Interval `json:"interval"`
	Ledger   Ledger     `json:"ledger"`
	Method   string     `json:"method"`
	Complete bool       `json:"complete"`
	Error    string     `json:"error"`
}

// Present=false requires source.offset=-1; saved next zero is present=true.
type M2SavedPosition struct {
	Source    identity.SourcePosition `json:"source"`
	Present   bool                    `json:"present"`
	Group     string                  `json:"group"`
	ErrorCode int16                   `json:"error_code"`
}

type M2GroupMember struct {
	ID               string `json:"id"`
	ClientID         string `json:"client_id"`
	ClientHost       string `json:"client_host"`
	AssignmentBase64 string `json:"assignment_base64"`
}

type M2Group struct {
	GroupID      string          `json:"group_id"`
	State        string          `json:"state"`
	ProtocolType string          `json:"protocol_type"`
	Protocol     string          `json:"protocol"`
	ErrorCode    int16           `json:"error_code"`
	Members      []M2GroupMember `json:"members"`
}

type M2Audit struct {
	ID            string            `json:"id"`
	Mode          string            `json:"mode"` // snapshot or settled
	ScanInterval  M2Interval        `json:"scan_interval"`
	SavedInterval M2Interval        `json:"saved_interval"`
	GroupInterval M2Interval        `json:"group_interval"`
	Group         M2Group           `json:"group"`
	Scans         []Scan            `json:"scans"`
	Saved         []M2SavedPosition `json:"saved"`
	Final         bool              `json:"final"`
}

// Episodes name compiled cases, not arbitrary predicates. Referenced audits
// and actual OS/Docker observations determine whether the case was reached.
type M2Episode struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	WorkerID         string `json:"worker_id"`
	RecoveryWorkerID string `json:"recovery_worker_id"`
	TriggerAuditID   string `json:"trigger_audit_id"`
	VisibleAuditID   string `json:"visible_audit_id"`
	StoppedAuditID   string `json:"stopped_audit_id"`
}

// Diagnostics corroborate paths only. They cannot satisfy record, offset,
// ownership, threshold-entry or process-exit evidence.
type M2Diagnostic struct {
	WorkerID string     `json:"worker_id"`
	Kind     string     `json:"kind"`
	Interval M2Interval `json:"interval"`
	Proof    string     `json:"proof"`
}

type M2Event struct {
	Seq        identity.Int64    `json:"seq"`
	RunID      string            `json:"run_id"`
	ElapsedNS  identity.Int64    `json:"elapsed_ns"`
	Kind       string            `json:"kind"`
	Ledger     *Ledger           `json:"ledger,omitempty"`
	Inputs     *M2InputsVerified `json:"inputs,omitempty"`
	Output     *Output           `json:"output,omitempty"`
	Audit      *M2Audit          `json:"audit,omitempty"`
	Worker     *M2Worker         `json:"worker,omitempty"`
	Broker     *M2Broker         `json:"broker,omitempty"`
	Episode    *M2Episode        `json:"episode,omitempty"`
	Diagnostic *M2Diagnostic     `json:"diagnostic,omitempty"`
	Finished   *RunFinished      `json:"finished,omitempty"`
}
