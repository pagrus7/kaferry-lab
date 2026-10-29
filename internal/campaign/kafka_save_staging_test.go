package campaign

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

// This fake retains whole records decoded from producer messages. It is a
// synthetic controller/checker control, not a Kafka or released-process run.
type kafkaSaveStagingFake struct {
	t        *testing.T
	source   kafkaTopic
	messages []*sarama.ProducerMessage
	records  [3][]observer.Observed
	sendErr  error
}

func newKafkaSaveStagingControl(t *testing.T) (*kafkaRun, *kafkaSaveStagingFake, context.Context) {
	t.Helper()
	inputs, err := knownKafkaInputs("synthetic-save-staging", 96)
	if err != nil {
		t.Fatal(err)
	}
	source := kafkaTopic{ClusterID: "synthetic-source-cluster", Topic: "synthetic-source", TopicID: "00112233445566778899aabbccddeeff", Partitions: 3}
	dest := kafkaTopic{ClusterID: "synthetic-dest-cluster", Topic: "synthetic-dest", TopicID: "ffeeddccbbaa99887766554433221100", Partitions: 5}
	fake := &kafkaSaveStagingFake{t: t, source: source}
	run := &kafkaRun{Inputs: inputs, Routing: "KEY", Preparation: kafkaPreparation{Source: source, Destination: dest}, producer: kafkaSendCallback{send: fake.send}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return run, fake, ctx
}

func (f *kafkaSaveStagingFake) send(message *sarama.ProducerMessage) (int32, int64, error) {
	f.t.Helper()
	f.messages = append(f.messages, message)
	key, err := message.Key.Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	value, err := message.Value.Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	stamp := identity.Int64(message.Timestamp.UnixMilli())
	record := identity.Record{Key: identity.NewNullableBytes(key), Value: identity.NewNullableBytes(value), Headers: []identity.Header{}, TimestampMS: &stamp, TimestampKind: "create_time"}
	for _, header := range message.Headers {
		record.Headers = append(record.Headers, identity.NewHeader(header.Key, header.Value))
	}
	p := message.Partition
	offset := identity.Int64(len(f.records[p]))
	f.records[p] = append(f.records[p], observer.Observed{Position: kafkaPosition(f.source, p, int64(offset)), Partition: p, Offset: offset, Record: record})
	// Even an errored send can be present. Only readback may resolve ambiguity.
	return p, int64(offset), f.sendErr
}

func (f *kafkaSaveStagingFake) snapshot() kafkaScanSnapshot {
	snapshot := kafkaScanSnapshot{Topic: f.source}
	for p, records := range f.records {
		end := int64(len(records))
		boundary := observer.Boundary{HighWatermark: end, LastStable: end}
		snapshot.Before = append(snapshot.Before, boundary)
		snapshot.After = append(snapshot.After, boundary)
		snapshot.Scans = append(snapshot.Scans, observer.Scan{Cluster: f.source.ClusterID, Topic: f.source.Topic, TopicID: f.source.TopicID, Partition: int32(p), End: end, Next: end, Boundary: boundary, Records: append([]observer.Observed{}, records...), Spans: []observer.Span{{First: 0, End: end, ProducerID: 71}}})
	}
	return snapshot
}

func TestKafkaSaveStagingPublishesAndVerifiesThreeFourThenNinetySix(t *testing.T) {
	// Given 96 declared inputs and a synthetic producer that retains exact bytes.
	run, fake, ctx := newKafkaSaveStagingControl(t)
	attempts, err := run.Publish(ctx, true)
	if err != nil || len(attempts) != 3 || len(fake.messages) != 3 {
		t.Fatalf("warmup sends: %+v %v", attempts, err)
	}
	warmup, err := run.verifyInputSnapshot(fake.snapshot(), run.Inputs[:3], run.Attempts)
	if err != nil || !warmup.Complete || len(warmup.Ledger.Entries) != 3 {
		t.Fatalf("warmup readback: %+v %v", warmup, err)
	}
	// When only the save probe is published, exactly one new attempt is retained.
	attempts, err = run.PublishSaveProbe(ctx)
	if err != nil || len(attempts) != 1 || attempts[0].InputID != "input-0003" || len(fake.messages) != 4 {
		t.Fatalf("probe sends: %+v count=%d %v", attempts, len(fake.messages), err)
	}
	inputs, err := run.saveProbeInputs(4)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := run.verifyInputSnapshot(fake.snapshot(), inputs, run.Attempts)
	if err != nil || !probe.Complete || len(probe.Ledger.Entries) != 4 || len(probe.Ledger.Partitions) != 3 || len(probe.Ledger.Destinations) != 5 {
		t.Fatalf("probe readback: %+v %v", probe, err)
	}
	var found bool
	for _, entry := range probe.Ledger.Entries {
		if entry.ID != "input-0003" {
			continue
		}
		found = true
		if entry.Source != kafkaPosition(run.Preparation.Source, 0, 1) || !entry.Record.Key.Null || !entry.Record.Value.Null || len(entry.Record.Headers) != 0 || !reflect.DeepEqual(entry.AllowedPartitions, []int32{0, 1, 2, 3, 4}) {
			t.Fatalf("probe bytes, provenance or null-key routing changed: %+v", entry)
		}
	}
	if !found || !reflect.DeepEqual(run.Inputs[3].Record, fake.records[0][1].Record) || run.Inputs[3].LogicalID != nil {
		t.Fatal("undecorated nullable-byte probe missing or changed")
	}
	// Then the partial stage cannot claim full membership or hide future input.
	if v, err := run.verifyInputSnapshot(fake.snapshot(), run.Inputs, run.Attempts); err == nil || v.Complete {
		t.Fatal("four-record observation verified unpublished finite input")
	}
	attempts, err = run.Publish(ctx, false)
	if err != nil || len(attempts) != 92 || attempts[0].InputID != "input-0004" || attempts[91].InputID != "input-0095" || len(fake.messages) != 96 || len(run.Attempts) != 96 {
		t.Fatalf("remaining finite sends: count=%d total=%d %v", len(attempts), len(fake.messages), err)
	}
	full, err := run.verifyInputSnapshot(fake.snapshot(), run.Inputs, run.Attempts)
	if err != nil || !full.Complete || len(full.Ledger.Entries) != 96 {
		t.Fatalf("full readback: count=%d %v", len(full.Ledger.Entries), err)
	}
	if v, err := run.verifyInputSnapshot(fake.snapshot(), inputs, run.Attempts[:4]); err == nil || v.Complete {
		t.Fatal("four-record ledger concealed later published records")
	}
	attempts, err = run.Publish(ctx, false)
	if err != nil || len(attempts) != 0 || len(fake.messages) != 96 {
		t.Fatal("remaining input retried", err)
	}
}

func TestKafkaSaveProbeAmbiguousSendIsNeverRetried(t *testing.T) {
	// Given an independently verified warmup prefix and an ambiguous probe receipt.
	run, fake, ctx := newKafkaSaveStagingControl(t)
	if _, err := run.Publish(ctx, true); err != nil {
		t.Fatal(err)
	}
	if v, err := run.verifyInputSnapshot(fake.snapshot(), run.Inputs[:3], run.Attempts); err != nil || !v.Complete {
		t.Fatal("warmup readback failed", err)
	}
	fake.sendErr = errors.New("synthetic ambiguous probe timeout")
	attempts, err := run.PublishSaveProbe(ctx)
	if err == nil || len(attempts) != 1 || attempts[0].Offset != nil || attempts[0].Error == "" || len(fake.messages) != 4 {
		t.Fatalf("ambiguous probe outcome lost: %+v %v", attempts, err)
	}
	// When a caller repeats the one-probe operation, no second send is possible.
	if repeated, err := run.PublishSaveProbe(ctx); err == nil || len(repeated) != 0 || len(fake.messages) != 4 || len(run.Attempts) != 4 {
		t.Fatal("ambiguous save probe retried or silently skipped", err)
	}
	inputs, err := run.saveProbeInputs(4)
	if err != nil {
		t.Fatal(err)
	}
	v, err := run.verifyInputSnapshot(fake.snapshot(), inputs, run.Attempts)
	// Then only independently retained whole records resolve the ambiguity.
	if err != nil || !v.Complete || len(v.Ledger.Entries) != 4 || run.Attempts[3].Error == "" {
		t.Fatal("visible ambiguous probe was not independently resolved", err)
	}
	fake.records[0] = fake.records[0][:1]
	if v, err := run.verifyInputSnapshot(fake.snapshot(), inputs, run.Attempts); err == nil || v.Complete {
		t.Fatal("ambiguous absent probe accepted")
	}
}

func TestKafkaSaveProbeRefusesInvalidPrerequisitesBeforeProducer(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*kafkaRun)
	}{
		{"no warmups", func(k *kafkaRun) { k.Attempts = nil }},
		{"missing warmup", func(k *kafkaRun) { k.Attempts = k.Attempts[:2] }},
		{"unknown attempted identity", func(k *kafkaRun) { k.Attempts[1].InputID = "foreign-input" }},
		{"duplicate attempted identity", func(k *kafkaRun) { k.Attempts[1].InputID = k.Attempts[0].InputID }},
		{"misordered attempted identity", func(k *kafkaRun) { k.Attempts[0], k.Attempts[1] = k.Attempts[1], k.Attempts[0] }},
		{"already attempted probe", func(k *kafkaRun) {
			n := identity.Int64(1)
			k.Attempts = append(k.Attempts, kafkaProduceAttempt{InputID: "input-0003", Offset: &n})
		}},
		{"future attempt replaces warmup", func(k *kafkaRun) { k.Attempts[2].InputID = "input-0004" }},
		{"unknown outcome", func(k *kafkaRun) { k.Attempts[0].Offset = nil }},
		{"conflicting outcome", func(k *kafkaRun) { k.Attempts[0].Error = "ambiguous with acknowledgment" }},
		{"negative acknowledgment", func(k *kafkaRun) { n := identity.Int64(-1); k.Attempts[0].Offset = &n }},
		{"unknown declared identity", func(k *kafkaRun) { k.Inputs[3].ID = "foreign-input" }},
		{"misordered declaration", func(k *kafkaRun) { k.Inputs[3], k.Inputs[4] = k.Inputs[4], k.Inputs[3] }},
		{"duplicate declaration", func(k *kafkaRun) { k.Inputs[4].ID = k.Inputs[3].ID }},
		{"probe marked warmup", func(k *kafkaRun) { k.Inputs[3].Warmup = true }},
		{"probe wrong partition", func(k *kafkaRun) { k.Inputs[3].Partition = 1 }},
		{"probe null becomes empty", func(k *kafkaRun) { k.Inputs[3].Record.Key = identity.NewNullableBytes([]byte{}) }},
		{"probe decorated identity", func(k *kafkaRun) { logical := identity.LogicalStressID("decorated"); k.Inputs[3].LogicalID = &logical }},
		{"source identity missing", func(k *kafkaRun) { k.Preparation.Source.TopicID = "" }},
		{"incomplete declaration", func(k *kafkaRun) { k.Inputs = k.Inputs[:3] }},
		{"wrong source layout", func(k *kafkaRun) { k.Preparation.Source.Partitions = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a valid warmup prefix followed by one invalid prerequisite.
			run, fake, ctx := newKafkaSaveStagingControl(t)
			if _, err := run.Publish(ctx, true); err != nil {
				t.Fatal(err)
			}
			tc.mutate(run)
			before := len(run.Attempts)
			// When requesting the probe, Then refusal precedes any producer call.
			if attempts, err := run.PublishSaveProbe(ctx); err == nil || len(attempts) != 0 || len(fake.messages) != 3 || len(run.Attempts) != before {
				t.Fatalf("invalid prerequisites sent input: %+v %v", attempts, err)
			}
		})
	}
}

func TestKafkaSaveProbeWholeScanDetectsLossCorruptionRoutingAndFutureRecords(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*kafkaRun, *kafkaScanSnapshot)
	}{
		{"probe loss", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Scans[0].Records = s.Scans[0].Records[:1] }},
		{"probe null becomes empty", func(_ *kafkaRun, s *kafkaScanSnapshot) {
			s.Scans[0].Records[1].Record.Key = identity.NewNullableBytes([]byte{})
		}},
		{"probe corrupt value", func(_ *kafkaRun, s *kafkaScanSnapshot) {
			s.Scans[0].Records[1].Record.Value = identity.NewNullableBytes([]byte("corrupt"))
		}},
		{"probe misrouted", func(_ *kafkaRun, s *kafkaScanSnapshot) {
			s.Scans[0].Records[1].Record, s.Scans[1].Records[0].Record = s.Scans[1].Records[0].Record, s.Scans[0].Records[1].Record
		}},
		{"foreign provenance", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Scans[0].Records[1].Position.TopicID = "foreign-topic" }},
		{"acknowledged position mismatch", func(k *kafkaRun, _ *kafkaScanSnapshot) { n := identity.Int64(42); k.Attempts[3].Offset = &n }},
		{"future unpublished input", func(k *kafkaRun, s *kafkaScanSnapshot) {
			r := observer.Observed{Position: kafkaPosition(k.Preparation.Source, 1, 1), Partition: 1, Offset: 1, Record: k.Inputs[4].Record}
			s.Scans[1].Records = append(s.Scans[1].Records, r)
			s.Scans[1].End, s.Scans[1].Next = 2, 2
			s.Scans[1].Boundary = observer.Boundary{HighWatermark: 2, LastStable: 2}
			s.Before[1], s.After[1] = s.Scans[1].Boundary, s.Scans[1].Boundary
		}},
		{"missing partition", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Scans = s.Scans[:2] }},
		{"duplicate partition", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Scans[2] = s.Scans[1] }},
		{"scan stops before sampled end", func(_ *kafkaRun, s *kafkaScanSnapshot) {
			s.Scans[0].End, s.Scans[0].Next = 1, 1
			s.Scans[0].Records = s.Scans[0].Records[:1]
		}},
		{"moving boundary", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.After[0].HighWatermark++ }},
		{"unstable boundary", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Before[0].LastStable--; s.After[0] = s.Before[0] }},
		{"snapshot error", func(_ *kafkaRun, s *kafkaScanSnapshot) { s.Error = "synthetic incomplete scan" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given an exact four-record readback that first passes as a control.
			run, fake, ctx := newKafkaSaveStagingControl(t)
			if _, err := run.Publish(ctx, true); err != nil {
				t.Fatal(err)
			}
			if _, err := run.PublishSaveProbe(ctx); err != nil {
				t.Fatal(err)
			}
			inputs, err := run.saveProbeInputs(4)
			if err != nil {
				t.Fatal(err)
			}
			snapshot := fake.snapshot()
			if v, err := run.verifyInputSnapshot(snapshot, inputs, run.Attempts); err != nil || !v.Complete {
				t.Fatal("healthy synthetic control failed", err)
			}
			// When one whole-scan fact changes, Then exact membership must fail.
			tc.mutate(run, &snapshot)
			if v, err := run.verifyInputSnapshot(snapshot, inputs, run.Attempts); err == nil || v.Complete {
				t.Fatal("invalid four-record readback accepted")
			}
		})
	}
}

func TestKafkaVerifySaveProbeInputsRefusesWrongStageBeforeSnapshot(t *testing.T) {
	// Given the public verifier with no admin/observer clients, a wrong stage
	// must be rejected as such before any network-backed snapshot is possible.
	run, _, ctx := newKafkaSaveStagingControl(t)
	if _, err := run.Publish(ctx, true); err != nil {
		t.Fatal(err)
	}
	// When only warmups exist, Then the four-input entrypoint cannot complete.
	v, err := run.VerifySaveProbeInputs(ctx)
	if err == nil || v.Complete || !v.Snapshot.StartedAt.IsZero() {
		t.Fatalf("wrong stage reached snapshot: %+v %v", v, err)
	}
}

func TestKafkaVerifySaveProbeInputsRejectsForeignRepeatedOrMisorderedAttempts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*kafkaRun)
	}{
		{"unknown identity", func(k *kafkaRun) { k.Attempts[3].InputID = "unknown" }},
		{"duplicate identity", func(k *kafkaRun) { k.Attempts[3].InputID = k.Attempts[0].InputID }},
		{"misordered identity", func(k *kafkaRun) { k.Attempts[2], k.Attempts[3] = k.Attempts[3], k.Attempts[2] }},
		{"future identity", func(k *kafkaRun) { k.Attempts[3].InputID = "input-0004" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given a four-attempt prefix and closed snapshot clients.
			run, _, ctx := newKafkaSaveStagingControl(t)
			if _, err := run.Publish(ctx, true); err != nil {
				t.Fatal(err)
			}
			if _, err := run.PublishSaveProbe(ctx); err != nil {
				t.Fatal(err)
			}
			tc.mutate(run)
			// When one attempted identity is invalid, Then it cannot be filtered
			// away or reach the network-backed snapshot operation.
			v, err := run.VerifySaveProbeInputs(ctx)
			if err == nil || v.Complete || !v.Snapshot.StartedAt.IsZero() {
				t.Fatalf("invalid attempts reached snapshot: %+v %v", v, err)
			}
		})
	}
}
