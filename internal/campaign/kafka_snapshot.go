package campaign

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

const kafkaSnapshotMaxEnd = 16384 // exclusive offset on each new, finite campaign topic

type kafkaScanSnapshot struct {
	StartedAt, EndedAt time.Time
	Topic              kafkaTopic
	Before, After      []observer.Boundary // indexed by partition, sampled separately
	Scans              []observer.Scan     // raw admitted spans and records, including partial failures
	Error              string
}
type kafkaInputVerification struct {
	Snapshot kafkaScanSnapshot
	Ledger   evidence.Ledger
	Complete bool
}

// VerifyInputs reads every source partition from zero. A warmup-only check is
// useful before worker preflight. After bulk publication, the caller verifies
// the full finite ledger before using it to establish fault obligations.
func (k *kafkaRun) VerifyInputs(ctx context.Context, warmupOnly bool) (v kafkaInputVerification, err error) {
	v.Snapshot, err = snapshotKafkaTopic(ctx, k.sourceAdmin, k.sourceObserver, k.Preparation.Source)
	if err != nil {
		return v, err
	}
	for p := range v.Snapshot.Before {
		if v.Snapshot.Before[p] != v.Snapshot.After[p] {
			return v, errors.New("source bounds changed while verifying finite input")
		}
	}
	var inputs []kafkaInput
	ids := map[string]bool{}
	for _, input := range k.Inputs {
		if !warmupOnly || input.Warmup {
			inputs = append(inputs, input)
			ids[input.ID] = true
		}
	}
	var attempts []kafkaProduceAttempt
	for _, attempt := range k.Attempts {
		if ids[attempt.InputID] {
			attempts = append(attempts, attempt)
		}
	}
	v.Ledger, err = kafkaSourceLedger(k.Preparation.Source, k.Preparation.Destination, k.Routing, inputs, attempts, v.Snapshot.Scans)
	v.Complete = err == nil
	return v, err
}

// SnapshotOutput scans EVERY destination partition, including unselected and
// empty partitions, to sampled ends, then rereads each boundary. It does not
// establish quiescence: equal ends cannot exclude pending produce requests.
// The caller stops/reaps workers and restarts the broker when pending writes
// could affect the audit, and records those actions as separate evidence.
func (k *kafkaRun) SnapshotOutput(ctx context.Context) (kafkaScanSnapshot, error) {
	return snapshotKafkaTopic(ctx, k.destAdmin, k.destObserver, k.Preparation.Destination)
}

func snapshotKafkaTopic(ctx context.Context, a sarama.ClusterAdmin, o *observer.Observer, topic kafkaTopic) (snapshot kafkaScanSnapshot, err error) {
	snapshot = kafkaScanSnapshot{StartedAt: time.Now().UTC(), Topic: topic, Before: []observer.Boundary{}, After: []observer.Boundary{}, Scans: []observer.Scan{}}
	defer func() {
		snapshot.EndedAt = time.Now().UTC()
		if err != nil {
			snapshot.Error = err.Error()
		}
	}()
	if err = kafkaBounded(ctx); err != nil {
		return snapshot, err
	}
	if a == nil || o == nil {
		return snapshot, errors.New("Kafka snapshot clients are closed")
	}
	if err = checkKafkaTopic(ctx, a, o, topic); err != nil {
		return snapshot, err
	}
	for p := range topic.Partitions {
		b, e := o.Boundary(ctx, topic.Topic, p)
		if e != nil {
			return snapshot, e
		}
		snapshot.Before = append(snapshot.Before, b)
		if b.Oldest != 0 || b.LastStable != b.HighWatermark || b.HighWatermark > kafkaSnapshotMaxEnd {
			return snapshot, errors.New("snapshot exceeds finite retained nontransactional topic bounds")
		}
	}
	for p, b := range snapshot.Before {
		scan, e := o.ScanPartition(ctx, topic.Topic, int32(p), 0, b.HighWatermark, sarama.ReadCommitted)
		snapshot.Scans = append(snapshot.Scans, scan)
		if e != nil {
			return snapshot, e
		}
		if e = kafkaCompleteScan(topic, scan); e != nil {
			return snapshot, e
		}
	}
	for p := range topic.Partitions {
		b, e := o.Boundary(ctx, topic.Topic, p)
		if e != nil {
			return snapshot, e
		}
		snapshot.After = append(snapshot.After, b)
		if b.Oldest != 0 || b.HighWatermark < snapshot.Before[p].HighWatermark || b.LastStable < b.HighWatermark {
			return snapshot, errors.New("topic availability or stable boundary changed during snapshot")
		}
	}
	if err = checkKafkaTopic(ctx, a, o, topic); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func checkKafkaTopic(ctx context.Context, a sarama.ClusterAdmin, o *observer.Observer, topic kafkaTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cluster, id, err := o.TopicIdentity(topic.Topic)
	if err != nil {
		return err
	}
	if cluster != topic.ClusterID || id != topic.TopicID || topic.TopicID == "" {
		return errors.New("Kafka topic or cluster identity changed")
	}
	metadata, err := a.DescribeTopics([]string{topic.Topic})
	if err != nil {
		return err
	}
	if len(metadata) != 1 || metadata[0] == nil || metadata[0].Name != topic.Topic {
		return errors.New("Kafka topic partition layout changed or missing")
	}
	if metadata[0].Err != sarama.ErrNoError {
		return metadata[0].Err
	}
	if len(metadata[0].Partitions) != int(topic.Partitions) {
		return errors.New("Kafka topic partition layout changed or missing")
	}
	seen := map[int32]bool{}
	var partitionErr error
	for _, p := range metadata[0].Partitions {
		if p == nil || p.ID < 0 || p.ID >= topic.Partitions || seen[p.ID] {
			return errors.New("invalid Kafka topic partition metadata")
		}
		if p.Err != sarama.ErrNoError {
			partitionErr = errors.Join(partitionErr, p.Err)
		}
		seen[p.ID] = true
	}
	return errors.Join(partitionErr, ctx.Err())
}

// Outputs converts complete raw scans to evidence observations. It does not
// match source IDs or decide membership, routing, or saved-prefix safety.
func (s kafkaScanSnapshot) Outputs(auditID string) ([]evidence.Output, error) {
	if auditID == "" || s.Error != "" || len(s.Scans) != int(s.Topic.Partitions) || len(s.Before) != int(s.Topic.Partitions) || len(s.After) != int(s.Topic.Partitions) {
		return nil, errors.New("incomplete output snapshot")
	}
	outputs := []evidence.Output{}
	seen := map[int32]bool{}
	for _, scan := range s.Scans {
		if err := kafkaCompleteScan(s.Topic, scan); err != nil {
			return nil, err
		}
		if seen[scan.Partition] || scan.Start != 0 || scan.End != s.Before[scan.Partition].HighWatermark {
			return nil, errors.New("output snapshot has repeated partition or incorrect sampled range")
		}
		seen[scan.Partition] = true
		for _, r := range scan.Records {
			outputs = append(outputs, evidence.Output{AuditID: auditID, Destination: r.Position, Record: r.Record})
		}
	}
	return outputs, nil
}

type kafkaMemberSnapshot struct {
	ID, ClientID, ClientHost         string
	InstanceID                       *string
	MetadataBase64, AssignmentBase64 string
	AssignmentVersion                int16
	Topics                           map[string][]int32
}
type kafkaGroupDescription struct {
	Version                                int16
	GroupID, State, ProtocolType, Protocol string
	ErrorCode, LegacyErrorCode             int16
	Members                                []kafkaMemberSnapshot
}
type kafkaSavedOffset struct {
	Source         identity.SourcePosition // Offset -1 means no saved position
	Saved          bool                    // saved next offset zero is distinct from absence
	LeaderEpoch    int32
	MetadataBase64 string
	ErrorCode      int16
}
type kafkaOffsetSnapshot struct {
	Version   int16
	GroupID   string
	ErrorCode int16
	Offsets   []kafkaSavedOffset
}
type kafkaGroupSnapshot struct {
	GroupID                                                          string
	DescribeStartedAt, DescribeEndedAt, FetchStartedAt, FetchEndedAt time.Time
	Description                                                      kafkaGroupDescription
	Offsets                                                          kafkaOffsetSnapshot
	Error                                                            string
}

// SnapshotGroup retains separate DescribeGroups and OffsetFetch intervals;
// their responses are not an atomic group-generation observation. Raw metadata
// and assignment bytes remain base64 even if they are not UTF-8.
func (k *kafkaRun) SnapshotGroup(ctx context.Context, group string) (snapshot kafkaGroupSnapshot, err error) {
	snapshot.GroupID = group
	defer func() {
		if err != nil {
			snapshot.Error = err.Error()
		}
	}()
	if err = kafkaBounded(ctx); err != nil {
		return snapshot, err
	}
	if group == "" || k.sourceAdmin == nil || k.sourceObserver == nil {
		return snapshot, errors.New("missing group or source admin")
	}
	if err = checkKafkaTopic(ctx, k.sourceAdmin, k.sourceObserver, k.Preparation.Source); err != nil {
		return snapshot, err
	}
	snapshot.DescribeStartedAt = time.Now().UTC()
	descriptions, e := k.sourceAdmin.DescribeConsumerGroups([]string{group})
	snapshot.DescribeEndedAt = time.Now().UTC()
	if e != nil {
		return snapshot, e
	}
	if len(descriptions) != 1 || descriptions[0] == nil {
		return snapshot, errors.New("missing or ambiguous raw group description")
	}
	snapshot.Description, err = kafkaDecodeGroup(group, descriptions[0])
	describeErr := err
	if err != nil && !errors.Is(err, sarama.ErrOffsetsLoadInProgress) && !errors.Is(err, sarama.ErrConsumerCoordinatorNotAvailable) && !errors.Is(err, sarama.ErrNotCoordinatorForConsumer) {
		return snapshot, err
	}
	if err = ctx.Err(); err != nil {
		return snapshot, errors.Join(describeErr, err)
	}
	// Sarama's offset probe refreshes its coordinator cache on unavailable or
	// wrong-coordinator responses; DescribeConsumerGroups does not. Retain the
	// failed description even when this read-only probe succeeds.
	partitions := make([]int32, k.Preparation.Source.Partitions)
	for p := range partitions {
		partitions[p] = int32(p)
	}
	snapshot.FetchStartedAt = time.Now().UTC()
	raw, e := k.sourceAdmin.ListConsumerGroupOffsets(group, map[string][]int32{k.Preparation.Source.Topic: partitions})
	snapshot.FetchEndedAt = time.Now().UTC()
	// Preserve a raw error response as typed observations where available.
	if raw == nil && e != nil {
		return snapshot, errors.Join(describeErr, e, ctx.Err())
	}
	snapshot.Offsets, err = kafkaDecodeOffsets(group, k.Preparation.Source, raw)
	if err = errors.Join(describeErr, e, err, ctx.Err()); err != nil {
		return snapshot, err
	}
	if err = checkKafkaTopic(ctx, k.sourceAdmin, k.sourceObserver, k.Preparation.Source); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func kafkaDecodeGroup(group string, raw *sarama.GroupDescription) (g kafkaGroupDescription, err error) {
	if raw == nil {
		return g, errors.New("missing group description")
	}
	g = kafkaGroupDescription{Version: raw.Version, GroupID: raw.GroupId, State: raw.State, ProtocolType: raw.ProtocolType, Protocol: raw.Protocol, ErrorCode: raw.ErrorCode, LegacyErrorCode: int16(raw.Err), Members: []kafkaMemberSnapshot{}}
	if raw.GroupId != group {
		return g, errors.New("raw group identity prevents assignment observation")
	}
	for _, code := range []sarama.KError{raw.Err, sarama.KError(raw.ErrorCode)} {
		if code != sarama.ErrNoError {
			err = errors.Join(err, code)
		}
	}
	if err != nil {
		return g, err
	}
	if raw.ProtocolType != "consumer" && !(len(raw.Members) == 0 && raw.ProtocolType == "" && (raw.State == "Empty" || raw.State == "Dead")) {
		return g, errors.New("unsupported group protocol")
	}
	ids := make([]string, 0, len(raw.Members))
	for id := range raw.Members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		m := raw.Members[id]
		if m == nil || id == "" || m.MemberId != id {
			return g, errors.New("inconsistent raw group member identity")
		}
		member := kafkaMemberSnapshot{ID: id, ClientID: m.ClientId, ClientHost: m.ClientHost, InstanceID: m.GroupInstanceId, MetadataBase64: base64.StdEncoding.EncodeToString(m.MemberMetadata), AssignmentBase64: base64.StdEncoding.EncodeToString(m.MemberAssignment)}
		assignment, e := observer.DecodeAssignment(m.MemberAssignment)
		if e != nil {
			g.Members = append(g.Members, member)
			return g, e
		}
		member.AssignmentVersion = assignment.Version
		member.Topics = assignment.Topics
		g.Members = append(g.Members, member)
	}
	return g, nil
}

func kafkaDecodeOffsets(group string, source kafkaTopic, raw *sarama.OffsetFetchResponse) (snapshot kafkaOffsetSnapshot, err error) {
	snapshot = kafkaOffsetSnapshot{GroupID: group, Offsets: []kafkaSavedOffset{}}
	if raw == nil {
		return snapshot, errors.New("missing OffsetFetch response")
	}
	snapshot.Version = raw.Version
	if raw.Version < 0 || raw.Version > 8 {
		return snapshot, errors.New("unsupported OffsetFetch response version")
	}
	snapshot.ErrorCode = int16(raw.Err)
	blocks := raw.Blocks
	if raw.Version >= 8 {
		if len(raw.Groups) != 1 || raw.Groups[0].GroupId != group {
			return snapshot, errors.New("missing or conflicting OffsetFetch group")
		}
		blocks = raw.Groups[0].Blocks
		snapshot.ErrorCode = int16(raw.Groups[0].Err)
	}
	if snapshot.ErrorCode != 0 {
		err = sarama.KError(snapshot.ErrorCode)
		// A failed group response may omit partition blocks. If it includes
		// blocks, preserve them and reject malformed coordinates as usual.
		if len(blocks) == 0 {
			return snapshot, err
		}
	}
	if len(blocks) != 1 || len(blocks[source.Topic]) != int(source.Partitions) {
		err = errors.Join(err, errors.New("OffsetFetch omitted or added requested topic/partition blocks"))
	}
	for p := range source.Partitions {
		b := blocks[source.Topic][p]
		if b == nil {
			err = errors.Join(err, fmt.Errorf("OffsetFetch missing partition %d", p))
			continue
		}
		position := kafkaPosition(source, p, b.Offset)
		snapshot.Offsets = append(snapshot.Offsets, kafkaSavedOffset{Source: position, Saved: b.Offset >= 0, LeaderEpoch: b.LeaderEpoch, MetadataBase64: base64.StdEncoding.EncodeToString([]byte(b.Metadata)), ErrorCode: int16(b.Err)})
		if b.Err != sarama.ErrNoError {
			err = errors.Join(err, b.Err)
		}
		if b.Offset < -1 {
			err = errors.Join(err, fmt.Errorf("OffsetFetch invalid offset partition %d", p))
		}
	}
	return snapshot, err
}
