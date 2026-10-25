package campaign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

func TestKnownKafkaInputKeepsFidelityAndLogicalIdentitySeparate(t *testing.T) {
	// Given run-labelled stress records and independently specified byte fixtures.
	inputs, err := knownKafkaInputs("calibration-run-a", 11)
	if err != nil {
		t.Fatal(err)
	}
	other, err := knownKafkaInputs("calibration-run-b", 11)
	if err != nil {
		t.Fatal(err)
	}
	warmupPartitions := map[int32]bool{}
	for i, input := range inputs {
		// When the records are prepared, only deliberately identifiable records get
		// logical IDs; fidelity fixtures retain their exact undecorated bytes.
		if input.Warmup {
			if i >= 3 || input.LogicalID == nil {
				t.Fatal("invalid warmup")
			}
			warmupPartitions[input.Partition] = true
		}
		if i >= 3 && i <= 7 {
			if input.LogicalID != nil || !reflect.DeepEqual(input.Record, other[i].Record) {
				t.Fatal("fidelity fixture decorated with run identity")
			}
		} else {
			value, e := input.Record.Value.Bytes()
			if e != nil || input.LogicalID == nil || string(value) != string(*input.LogicalID) || !bytes.Contains(value, []byte("calibration-run-a")) || reflect.DeepEqual(input.Record, other[i].Record) {
				t.Fatal("stress identity is not independently observable in value")
			}
		}
		if input.Record.TimestampMS == nil || *input.Record.TimestampMS != 1700000000123 || input.Record.TimestampKind != "create_time" {
			t.Fatal("fixture escaped known timestamp domain")
		}
	}
	// Then all three partitions have a separate warmup, and null/empty combinations
	// and ordered duplicate binary headers match literal expectations.
	if !reflect.DeepEqual(warmupPartitions, map[int32]bool{0: true, 1: true, 2: true}) {
		t.Fatal(warmupPartitions)
	}
	for i, flags := range [][2]bool{{true, true}, {false, true}, {true, false}, {false, false}} {
		r := inputs[i+3].Record
		if r.Key.Null != flags[0] || r.Value.Null != flags[1] || r.Key.Base64 != "" || r.Value.Base64 != "" || len(r.Headers) != 0 {
			t.Fatalf("fixture %d changed: %+v", i, r)
		}
	}
	binary := inputs[7].Record
	if binary.Key.Base64 != "AP8=" || binary.Value.Base64 != "/wCA" || !reflect.DeepEqual(binary.Headers, []identity.Header{{KeyBase64: "/wA=", Value: identity.NullableBytes{Null: true}}, {KeyBase64: "/wA=", Value: identity.NullableBytes{}}, {KeyBase64: "AIA=", Value: identity.NullableBytes{Base64: "AP8="}}}) {
		t.Fatalf("binary fixture changed: %+v", binary)
	}
	for _, n := range []int{0, 7, 1025} {
		if _, err := knownKafkaInputs("run", n); err == nil {
			t.Fatalf("unbounded/insufficient count %d accepted", n)
		}
	}
}

func TestKafkaRoutesUseIndependentKnownExpectations(t *testing.T) {
	// Given Apache golden Murmur2 vectors, the Sarama empty-key golden hash
	// 275646681, and a five-partition destination.
	cases := []struct {
		key  []byte
		want []int32
	}{{[]byte("abc"), []int32{2}}, {[]byte("21"), []int32{0}}, {[]byte{}, []int32{1}}, {nil, []int32{0, 1, 2, 3, 4}}}
	for _, tc := range cases {
		input := kafkaInput{Partition: 2, Record: identity.Record{Key: identity.NewNullableBytes(tc.key)}}
		// When deriving KEY and PRESERVE routes, null keys admit every destination.
		got, err := kafkaAllowedPartitions("KEY", input, 5)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("KEY %x: %v %v, want %v", tc.key, got, err, tc.want)
		}
		got, err = kafkaAllowedPartitions("PRESERVE", input, 5)
		// Then PRESERVE always retains the source partition, including null keys.
		if err != nil || !reflect.DeepEqual(got, []int32{2}) {
			t.Fatalf("PRESERVE %v %v", got, err)
		}
	}
	if _, err := kafkaAllowedPartitions("PRESERVE", kafkaInput{Partition: 3}, 3); err == nil {
		t.Fatal("missing preserved partition accepted")
	}
}

// syntheticKafkaSource provides synthetic, visibly separate calibration scans.
// It does not claim a Kafka run or use the application under test as its oracle.
func syntheticKafkaSource(t *testing.T) (kafkaTopic, kafkaTopic, []kafkaInput, []kafkaProduceAttempt, []observer.Scan) {
	t.Helper()
	source := kafkaTopic{ClusterID: "source-cluster", Topic: "source", TopicID: "00112233445566778899aabbccddeeff", Partitions: 3}
	dest := kafkaTopic{ClusterID: "dest-cluster", Topic: "dest", TopicID: "ffeeddccbbaa99887766554433221100", Partitions: 5}
	inputs, err := knownKafkaInputs("synthetic-calibration", 11)
	if err != nil {
		t.Fatal(err)
	}
	scans := make([]observer.Scan, 3)
	for p := range scans {
		scans[p] = observer.Scan{Cluster: source.ClusterID, Topic: source.Topic, TopicID: source.TopicID, Partition: int32(p), Spans: []observer.Span{}, Records: []observer.Observed{}}
	}
	var attempts []kafkaProduceAttempt
	for _, input := range inputs {
		scan := &scans[input.Partition]
		offset := identity.Int64(len(scan.Records))
		position := identity.SourcePosition{Cluster: source.ClusterID, Topic: source.Topic, TopicID: source.TopicID, Partition: input.Partition, Offset: offset}
		scan.Records = append(scan.Records, observer.Observed{Position: position, Partition: input.Partition, Offset: offset, Record: input.Record})
		attempts = append(attempts, kafkaProduceAttempt{InputID: input.ID, Offset: &offset})
	}
	for p := range scans {
		scan := &scans[p]
		scan.End = int64(len(scan.Records))
		scan.Next = scan.End
		scan.Boundary = observer.Boundary{HighWatermark: scan.End, LastStable: scan.End}
		scan.Spans = []observer.Span{{First: 0, End: scan.End, ProducerID: 71}}
	}
	return source, dest, inputs, attempts, scans
}

func TestKafkaSourceLedgerRejectsCorruptIncompleteOrForeignInput(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*kafkaTopic, []kafkaInput, []kafkaProduceAttempt, []observer.Scan)
	}{
		{"byte corruption", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records[0].Record.Value = identity.NewNullableBytes([]byte("corrupt"))
		}},
		{"null becomes empty", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records[1].Record.Key = identity.NewNullableBytes([]byte{})
		}},
		{"missing record", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records = s[0].Records[1:]
		}},
		{"unexplained gap", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].End++
			s[0].Next++
			s[0].Boundary.HighWatermark++
			s[0].Boundary.LastStable++
		}},
		{"wrong partition", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records[0].Partition = 1
		}},
		{"known bytes in wrong partition", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records[0].Record, s[1].Records[0].Record = s[1].Records[0].Record, s[0].Records[0].Record
		}},
		{"binary header order", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			r := &s[1].Records[2].Record
			r.Headers = append([]identity.Header{}, r.Headers...)
			r.Headers[0], r.Headers[1] = r.Headers[1], r.Headers[0]
		}},
		{"wrong source coordinate", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Records[0].Position.Offset = 2
		}},
		{"wrong acknowledged offset", func(_ *kafkaTopic, _ []kafkaInput, a []kafkaProduceAttempt, _ []observer.Scan) {
			n := identity.Int64(42)
			a[0].Offset = &n
		}},
		{"topic recreated", func(source *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, _ []observer.Scan) {
			source.TopicID = "00000000000000000000000000000011"
		}},
		{"different source cluster", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Cluster = "another-cluster"
		}},
		{"scan did not reach tail", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) { s[0].Next-- }},
		{"duplicate scan", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) { s[1] = s[0] }},
		{"retention advanced", func(_ *kafkaTopic, _ []kafkaInput, _ []kafkaProduceAttempt, s []observer.Scan) {
			s[0].Boundary.Oldest = 1
		}},
		{"unattempted known record", func(_ *kafkaTopic, _ []kafkaInput, a []kafkaProduceAttempt, _ []observer.Scan) { a[0].Offset = nil }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			// Given a complete known source ledger, establish a passing control first.
			source, dest, inputs, attempts, scans := syntheticKafkaSource(t)
			ledger, err := kafkaSourceLedger(source, dest, "KEY", inputs, attempts, scans)
			if err != nil || len(ledger.Entries) != 11 || len(ledger.Partitions) != 3 || len(ledger.Destinations) != 5 {
				t.Fatalf("healthy synthetic control failed: %+v %v", ledger, err)
			}
			// When one observation/coordinate is corrupted, the same comparison fails.
			tc.mutate(&source, inputs, attempts, scans)
			if _, err = kafkaSourceLedger(source, dest, "KEY", inputs, attempts, scans); err == nil {
				t.Fatal("damaged source accepted as verified")
			}
		})
	}
}

func TestKafkaSourceLedgerResolvesAmbiguousAcknowledgmentOnlyByReadback(t *testing.T) {
	// Given an input send whose outcome was ambiguous but bytes are observed.
	source, dest, inputs, attempts, scans := syntheticKafkaSource(t)
	attempts[0].Offset = nil
	attempts[0].Error = "synthetic timeout"
	// When complete independent readback sees that record, its actual coordinates
	// establish the obligation, without replacing the retained timeout receipt.
	ledger, err := kafkaSourceLedger(source, dest, "PRESERVE", inputs, attempts, scans)
	if err != nil || len(ledger.Entries) != 11 || attempts[0].Error != "synthetic timeout" {
		t.Fatal(err)
	}
	for _, entry := range ledger.Entries {
		if entry.Disposition != "required" || !reflect.DeepEqual(entry.AllowedPartitions, []int32{entry.Source.Partition}) {
			t.Fatalf("incorrect route/obligation %+v", entry)
		}
	}
	// Then absence cannot be inferred from the send error or a partial scan.
	scans[0].Records = scans[0].Records[1:]
	if _, err = kafkaSourceLedger(source, dest, "PRESERVE", inputs, attempts, scans); err == nil {
		t.Fatal("ambiguous missing input accepted")
	}
}

func TestKafkaRawOffsetsRetainAbsentAndSavedZero(t *testing.T) {
	// Given literal raw saved positions, including binary metadata and absence.
	source := kafkaTopic{ClusterID: "cluster", Topic: "input", TopicID: "00112233445566778899aabbccddeeff", Partitions: 3}
	raw := &sarama.OffsetFetchResponse{Version: 8, Groups: []sarama.OffsetFetchResponseGroup{{GroupId: "g", Blocks: map[string]map[int32]*sarama.OffsetFetchResponseBlock{"input": {0: {Offset: -1}, 1: {Offset: 0, Metadata: string([]byte{255, 0})}, 2: {Offset: 7, LeaderEpoch: 4}}}}}}
	// When converting the response, offsets are retained exactly as returned.
	snapshot, err := kafkaDecodeOffsets("g", source, raw)
	if err != nil {
		t.Fatal(err)
	}
	// Then zero is saved, -1 is absent, and metadata never crosses UTF-8 conversion.
	if len(snapshot.Offsets) != 3 || snapshot.Offsets[0].Saved || snapshot.Offsets[0].Source.Offset != -1 || !snapshot.Offsets[1].Saved || snapshot.Offsets[1].Source.Offset != 0 || snapshot.Offsets[1].MetadataBase64 != "/wA=" || snapshot.Offsets[2].Source.Offset != 7 {
		t.Fatalf("changed raw offsets: %+v", snapshot)
	}
	for _, change := range []func(*sarama.OffsetFetchResponse){
		func(r *sarama.OffsetFetchResponse) { delete(r.Groups[0].Blocks["input"], 1) },
		func(r *sarama.OffsetFetchResponse) { r.Groups[0].Blocks["input"][0].Offset = -2 },
		func(r *sarama.OffsetFetchResponse) {
			r.Groups[0].Blocks["input"][2].Err = sarama.ErrNotCoordinatorForConsumer
		},
		func(r *sarama.OffsetFetchResponse) { r.Groups[0].Err = sarama.ErrGroupAuthorizationFailed },
		func(r *sarama.OffsetFetchResponse) { r.Groups[0].GroupId = "wrong" },
		func(r *sarama.OffsetFetchResponse) { r.Version = 9 },
	} {
		data, _ := json.Marshal(raw)
		var changed sarama.OffsetFetchResponse
		if err := json.Unmarshal(data, &changed); err != nil {
			t.Fatal(err)
		}
		change(&changed)
		if _, err := kafkaDecodeOffsets("g", source, &changed); err == nil {
			t.Fatal("missing/error raw offset response accepted")
		}
	}
}

func TestKafkaGroupSnapshotRetainsRawAssignmentAndMetadata(t *testing.T) {
	// Given a literal assignment v0 for topic a, partitions 0,2,9, user data null.
	assignment, err := hex.DecodeString("00000000000100016100000003000000000000000200000009ffffffff")
	if err != nil {
		t.Fatal(err)
	}
	raw := &sarama.GroupDescription{GroupId: "g", State: "Stable", ProtocolType: "consumer", Protocol: "range", Members: map[string]*sarama.GroupMemberDescription{"m": {MemberId: "m", ClientId: "worker", MemberMetadata: []byte{255, 0}, MemberAssignment: assignment}}}
	// When decoding membership, retain raw wire bytes beside decoded ownership.
	group, err := kafkaDecodeGroup("g", raw)
	if err != nil {
		t.Fatal(err)
	}
	// Then the decoded assignment and binary metadata have independent expectations.
	if len(group.Members) != 1 || group.Members[0].MetadataBase64 != "/wA=" || group.Members[0].AssignmentBase64 != base64.StdEncoding.EncodeToString(assignment) || !reflect.DeepEqual(group.Members[0].Topics, map[string][]int32{"a": {0, 2, 9}}) {
		t.Fatal(group)
	}
	raw.Members["m"].MemberAssignment = assignment[:len(assignment)-1]
	if _, err := kafkaDecodeGroup("g", raw); err == nil {
		t.Fatal("truncated assignment accepted")
	}
}

func TestKafkaOutputConversionRequiresEveryPartitionAndSampledEnd(t *testing.T) {
	// Given three complete synthetic output scans, including an empty partition.
	topic := kafkaTopic{ClusterID: "dest", Topic: "out", TopicID: "00112233445566778899aabbccddeeff", Partitions: 3}
	snapshot := kafkaScanSnapshot{Topic: topic, Before: make([]observer.Boundary, 3), After: make([]observer.Boundary, 3)}
	for p := range 3 {
		scan := observer.Scan{Cluster: topic.ClusterID, Topic: topic.Topic, TopicID: topic.TopicID, Partition: int32(p)}
		if p != 1 {
			scan.End = 1
			scan.Next = 1
			scan.Boundary = observer.Boundary{HighWatermark: 1, LastStable: 1}
			scan.Records = []observer.Observed{{Position: identity.SourcePosition{Cluster: topic.ClusterID, Topic: topic.Topic, TopicID: topic.TopicID, Partition: int32(p)}, Partition: int32(p)}}
		}
		snapshot.Before[p] = scan.Boundary
		snapshot.After[p] = scan.Boundary
		snapshot.Scans = append(snapshot.Scans, scan)
	}
	// When converting for an audit, complete empty partitions remain covered.
	outputs, err := snapshot.Outputs("audit")
	if err != nil || len(outputs) != 2 {
		t.Fatalf("%+v %v", outputs, err)
	}
	// Then omitting an empty partition or using another sampled end cannot pass.
	snapshot.Before[0].HighWatermark++
	if _, err = snapshot.Outputs("audit"); err == nil {
		t.Fatal("incorrect sampled destination end accepted")
	}
	snapshot.Before[0].HighWatermark--
	snapshot.Scans = snapshot.Scans[:2]
	if _, err = snapshot.Outputs("audit"); err == nil {
		t.Fatal("unscanned destination accepted")
	}
	snapshot.Scans = append(snapshot.Scans, snapshot.Scans[1])
	if _, err = snapshot.Outputs("audit"); err == nil {
		t.Fatal("duplicate empty destination scan accepted")
	}
}

func TestKafkaWarmupVerificationKeepsBulkObligationsPending(t *testing.T) {
	// Given only the three warmups are present, one on each source partition.
	source, dest, inputs, attempts, scans := syntheticKafkaSource(t)
	for p := range scans {
		scans[p].Records = scans[p].Records[:1]
		scans[p].End = 1
		scans[p].Next = 1
		scans[p].Boundary = observer.Boundary{HighWatermark: 1, LastStable: 1}
		scans[p].Spans = []observer.Span{{First: 0, End: 1, ProducerID: 71}}
	}
	// When the preflight verifies warmup membership, it can form a partial ledger.
	ledger, err := kafkaSourceLedger(source, dest, "PRESERVE", inputs[:3], attempts[:3], scans)
	if err != nil || len(ledger.Entries) != 3 {
		t.Fatal(err)
	}
	// Then that observation cannot verify the finite bulk input before publication.
	if _, err = kafkaSourceLedger(source, dest, "PRESERVE", inputs, attempts, scans); err == nil {
		t.Fatal("warmup observation verified unpublished bulk")
	}
}

// Only SendMessage participates in this control. The embedded interface avoids
// introducing fake behavior for the producer's unrelated methods.
type kafkaSendCallback struct {
	sarama.SyncProducer
	send func(*sarama.ProducerMessage) (int32, int64, error)
}

func (p kafkaSendCallback) SendMessage(message *sarama.ProducerMessage) (int32, int64, error) {
	return p.send(message)
}

func TestKafkaPublishRetainsFinalAcknowledgmentAfterCancellation(t *testing.T) {
	// Given a single remaining input and a caller with a bounded context.
	inputs, err := knownKafkaInputs("synthetic-cancel", 8)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sends := 0
	producer := kafkaSendCallback{send: func(message *sarama.ProducerMessage) (int32, int64, error) {
		sends++
		cancel()
		return message.Partition, 42, nil
	}}
	run := &kafkaRun{
		Inputs:      inputs[:1],
		Preparation: kafkaPreparation{Source: kafkaTopic{Topic: "synthetic-source"}},
		producer:    producer,
	}
	// When cancellation happens inside the final synchronous send, its valid
	// acknowledgment remains evidence and the operation reports cancellation.
	attempts, err := run.Publish(ctx, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled final send returned %v", err)
	}
	if sends != 1 || len(attempts) != 1 || len(run.Attempts) != 1 {
		t.Fatalf("send/receipt counts %d/%d/%d", sends, len(attempts), len(run.Attempts))
	}
	for _, attempt := range []kafkaProduceAttempt{attempts[0], run.Attempts[0]} {
		if attempt.InputID != inputs[0].ID || attempt.Offset == nil || *attempt.Offset != 42 || attempt.Error != "" {
			t.Fatalf("acknowledged outcome changed: %+v", attempt)
		}
	}
	// Then a later call with a fresh budget cannot retry that attempted record.
	fresh, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	attempts, err = run.Publish(fresh, true)
	if err != nil || len(attempts) != 0 || sends != 1 || len(run.Attempts) != 1 {
		t.Fatalf("acknowledged input retried: attempts=%+v sends=%d retained=%d err=%v", attempts, sends, len(run.Attempts), err)
	}
}

func TestKafkaGroupPreparationErrorsRetainTypedCoordinatorCodes(t *testing.T) {
	// Given raw unavailable, loading, moved, and denied group responses.
	for _, code := range []sarama.KError{sarama.ErrOffsetsLoadInProgress, sarama.ErrConsumerCoordinatorNotAvailable, sarama.ErrNotCoordinatorForConsumer, sarama.ErrGroupAuthorizationFailed} {
		for _, legacy := range []bool{false, true} {
			raw := &sarama.GroupDescription{GroupId: "g"}
			if legacy {
				raw.Err = code
			} else {
				raw.ErrorCode = int16(code)
			}
			// When decoding the response, Then the raw code and typed cause survive.
			g, err := kafkaDecodeGroup("g", raw)
			if !errors.Is(err, code) || g.ErrorCode != raw.ErrorCode || g.LegacyErrorCode != int16(raw.Err) {
				t.Fatalf("group code=%d legacy=%v: %+v / %v", code, legacy, g, err)
			}
			if scenarioTransientPreparation(err) != (code != sarama.ErrGroupAuthorizationFailed) {
				t.Fatalf("incorrect retry admission for group code=%d: %v", code, err)
			}
		}
		source := kafkaTopic{Topic: "input", Partitions: 3}
		raw := &sarama.OffsetFetchResponse{Version: 8, Groups: []sarama.OffsetFetchResponseGroup{{GroupId: "g", Err: code}}}
		offsets, err := kafkaDecodeOffsets("g", source, raw)
		if !errors.Is(err, code) || offsets.ErrorCode != int16(code) || scenarioTransientPreparation(err) != (code != sarama.ErrGroupAuthorizationFailed) {
			t.Fatalf("offset code=%d: %+v / %v", code, offsets, err)
		}
		// Then a conflicting group identity is permanent even beside a transient code.
		raw.Groups[0].GroupId = "wrong"
		if _, err := kafkaDecodeOffsets("g", source, raw); err == nil || scenarioTransientPreparation(err) {
			t.Fatalf("conflicting offset group admitted: %v", err)
		}
	}
}

func TestKafkaCoordinatorErrorCannotConcealMalformedReturnedOffsets(t *testing.T) {
	// Given a moved-coordinator response that nevertheless contains offsets.
	source := kafkaTopic{Topic: "input", Partitions: 3}
	raw := &sarama.OffsetFetchResponse{Version: 8, Groups: []sarama.OffsetFetchResponseGroup{{GroupId: "g", Err: sarama.ErrNotCoordinatorForConsumer, Blocks: map[string]map[int32]*sarama.OffsetFetchResponseBlock{"input": {0: {Offset: -2}, 1: {Offset: -1}, 2: {Offset: 0}}}}}}
	// When those returned blocks include an invalid offset, Then the error is
	// permanent and the failed observation retains every supplied position.
	snapshot, err := kafkaDecodeOffsets("g", source, raw)
	if !errors.Is(err, sarama.ErrNotCoordinatorForConsumer) || scenarioTransientPreparation(err) || len(snapshot.Offsets) != 3 || snapshot.Offsets[0].Source.Offset != -2 {
		t.Fatalf("malformed offset hidden: %+v / %v", snapshot, err)
	}
}
