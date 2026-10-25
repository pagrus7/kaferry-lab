// Package evidence checks recorded, bounded histories without Kafka, Docker,
// network access, the target executable, or application-under-test imports.
package evidence

import "github.com/pagrus7/kaferry-lab/internal/identity"

const (
	ReleaseExecutableSHA256 = "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"
	ReleaseArchiveName      = "kaferry-v0.6.0-linux-amd64.tar.gz"
	ReleaseArchiveSHA256    = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f"
	SchemaVersion           = 1
	CheckerVersion          = "evidence-v1"
	ReleaseTag              = "v0.6.0"
	ReleaseCommit           = "d7d485b96a52b711cb10d76dca09aa9b155dec5e"
	ContractSHA256          = "df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46"
	ManifestName            = "manifest.json"
	EventsName              = "events.jsonl"
	ArtifactName            = "artifact.json"
	CompleteName            = "complete.json"
)

type Verdict string

const (
	Pass         Verdict = "PASS"
	Violation    Verdict = "VIOLATION"
	Inconclusive Verdict = "INCONCLUSIVE"
	HarnessError Verdict = "HARNESS_ERROR"
	Unsupported  Verdict = "UNSUPPORTED"
)

type Finding struct {
	Code     string `json:"code"`
	Property string `json:"property,omitempty"`
	Message  string `json:"message"`
	AuditID  string `json:"audit_id,omitempty"`
	EntryID  string `json:"entry_id,omitempty"`
}

type Result struct {
	Verdict     Verdict   `json:"verdict"`
	RunID       string    `json:"run_id,omitempty"`
	ScenarioID  string    `json:"scenario_id,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Findings    []Finding `json:"findings"`
	Limitations []string  `json:"limitations"`
	// A single history cannot qualify the complete M0-M6 campaign.
	ReleaseQualified bool `json:"release_qualified"`
}

type FileHash struct {
	Path   string         `json:"path"`
	SHA256 string         `json:"sha256"`
	Bytes  identity.Int64 `json:"bytes"`
}

type Subject struct {
	Kind             string `json:"kind"` // published-release, synthetic-history, standin
	Tag              string `json:"tag"`
	Commit           string `json:"commit"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ContractSHA256   string `json:"contract_sha256"`
	Platform         string `json:"platform"`
	VersionOutput    string `json:"version_output"`
}

// ArtifactMetadata is recorded verification evidence, not a trusted assertion
// that an untrusted bundle author downloaded or executed anything. Release
// metadata retains the actual checksum text and published asset identity.
type ContractDocument struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ArtifactMetadata struct {
	SchemaVersion      int                `json:"schema_version"`
	Subject            Subject            `json:"subject"`
	ContractDocuments  []ContractDocument `json:"contract_documents,omitempty"`
	ArchiveName        string             `json:"archive_name"`
	ArchiveSHA256      string             `json:"archive_sha256"`
	ChecksumsText      string             `json:"checksums_text"`
	PublishedAssetURL  string             `json:"published_asset_url"`
	ProvenanceStatus   string             `json:"provenance_status,omitempty"` // verified or unavailable
	VerificationDetail string             `json:"verification_detail"`
	CalibrationLabel   string             `json:"calibration_label"`
}

type FaultSpec struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`              // v1 supports process_kill
	TriggerPredicate string `json:"trigger_predicate"` // required_output_outstanding
}

type LabSource struct {
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty"`
	Proof  string `json:"proof"`
}

type Environment struct {
	OrchestratorPlatform string `json:"orchestrator_platform"`
	ExecutionPlatform    string `json:"execution_platform"`
	Runtime              string `json:"runtime"`
	Storage              string `json:"storage"`
	Topology             string `json:"topology"`
	Limits               string `json:"limits"`
}

type Manifest struct {
	LabSource      LabSource      `json:"lab_source"`
	Environment    Environment    `json:"environment"`
	SchemaVersion  int            `json:"schema_version"`
	CheckerVersion string         `json:"checker_version"`
	Namespace      string         `json:"namespace"` // release or calibration
	RunID          string         `json:"run_id"`
	ScenarioID     string         `json:"scenario_id"`
	Scope          string         `json:"scope"` // kafka, standin; archive is explicitly unsupported
	Group          string         `json:"group"`
	Given          string         `json:"given"`
	When           string         `json:"when"`
	Then           string         `json:"then"`
	BudgetMS       identity.Int64 `json:"budget_ms"`
	Subject        Subject        `json:"subject"`
	Artifact       FileHash       `json:"artifact"`
	Events         FileHash       `json:"events"`
	EventCount     identity.Int64 `json:"event_count"`
	RequiredFaults []FaultSpec    `json:"required_faults"`
	FinalAuditID   string         `json:"final_audit_id"`
}

type Completion struct {
	SchemaVersion  int            `json:"schema_version"`
	RunID          string         `json:"run_id"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	EventsSHA256   string         `json:"events_sha256"`
	EventCount     identity.Int64 `json:"event_count"`
}

type Gap struct {
	Start  identity.Int64 `json:"start"`
	End    identity.Int64 `json:"end"` // exclusive
	Reason string         `json:"reason"`
	Proof  string         `json:"proof"`
}

// PartitionRange records initial inclusive/end exclusive bounds. Source.Offset
// is the initial offset. Explicit gaps plus ledger/output offsets must cover
// the entire interval; offset differences are never record counts.
type PartitionRange struct {
	Source identity.SourcePosition `json:"source"`
	End    identity.Int64          `json:"end"`
	Gaps   []Gap                   `json:"gaps"`
}

type LedgerEntry struct {
	ID                string                    `json:"id"`
	Source            identity.SourcePosition   `json:"source"`
	Record            identity.Record           `json:"record"`
	Disposition       string                    `json:"disposition"` // required, permitted, forbidden
	Reason            string                    `json:"reason"`
	DestinationTopic  string                    `json:"destination_topic"`
	AllowedPartitions []int32                   `json:"allowed_partitions"`
	Archive           *identity.ArchivePosition `json:"archive,omitempty"`
}

type Ledger struct {
	Partitions   []PartitionRange          `json:"partitions"`
	Destinations []identity.SourcePosition `json:"destinations"`
	Entries      []LedgerEntry             `json:"entries"`
}

type InputVerification struct {
	Method   string `json:"method"`
	Proof    string `json:"proof"`
	Complete bool   `json:"complete"`
}

type Output struct {
	AuditID     string                  `json:"audit_id"`
	Destination identity.SourcePosition `json:"destination"`
	Record      identity.Record         `json:"record"`
}

type Scan struct {
	PartitionRange
	Reached   identity.Int64 `json:"reached"`
	StableEnd identity.Int64 `json:"stable_end"`
	Complete  bool           `json:"complete"`
	Proof     string         `json:"proof"`
}

type SavedPosition struct {
	Source identity.SourcePosition `json:"source"` // saved next source offset
	Group  string                  `json:"group"`
	Proof  string                  `json:"proof"`
}

type Audit struct {
	ID                    string          `json:"id"`
	Kind                  string          `json:"kind"` // snapshot or quiescent
	Scans                 []Scan          `json:"scans"`
	Saved                 []SavedPosition `json:"saved"`
	PendingOutputResolved bool            `json:"pending_output_resolved"`
	QuiescenceMethod      string          `json:"quiescence_method"` // workers_stopped or standin_barrier
	QuiescenceProof       string          `json:"quiescence_proof"`
	Final                 bool            `json:"final"`
}

type Trigger struct {
	FaultID   string `json:"fault_id"`
	AuditID   string `json:"audit_id"`
	Predicate string `json:"predicate"`
	Observer  string `json:"observer"`
	Proof     string `json:"proof"`
}

// FaultObservation v1 records a requested signal, observed wait result, and a
// distinct recovered process. Proof retains the independent observer's detail.
type FaultObservation struct {
	ID          string `json:"id"`
	PID         int    `json:"pid"`
	Signal      string `json:"signal"`
	ExitCode    *int   `json:"exit_code,omitempty"`
	RecoveryPID int    `json:"recovery_pid,omitempty"`
	Observer    string `json:"observer"`
	Proof       string `json:"proof"`
}

type RunFinished struct {
	TimedOut        bool   `json:"timed_out"`
	CleanupComplete bool   `json:"cleanup_complete"`
	Proof           string `json:"proof"`
}

// Event has exactly one payload selected by Kind. Seq is contiguous starting
// at one; ElapsedMS is nondecreasing lab-monotonic elapsed time, not wall time.
type Event struct {
	Seq            identity.Int64     `json:"seq"`
	RunID          string             `json:"run_id"`
	ElapsedMS      identity.Int64     `json:"elapsed_ms"`
	Kind           string             `json:"kind"`
	Ledger         *Ledger            `json:"ledger,omitempty"`
	InputsVerified *InputVerification `json:"inputs_verified,omitempty"`
	Output         *Output            `json:"output,omitempty"`
	Audit          *Audit             `json:"audit,omitempty"`
	Trigger        *Trigger           `json:"trigger,omitempty"`
	Fault          *FaultObservation  `json:"fault,omitempty"`
	Finished       *RunFinished       `json:"finished,omitempty"`
}
