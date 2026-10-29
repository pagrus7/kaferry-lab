package campaign

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/evidence"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

const kafkaFixtureTimestampMS = 1700000000123 // measured modern CreateTime domain from M0

type kafkaPlan struct {
	Routing string // PRESERVE or KEY
	Records int    // includes three warmups and five exact byte fixtures
}
type kafkaTopic struct {
	ClusterID, Topic, TopicID string
	Partitions                int32
	Config                    map[string]string
}
type kafkaInput struct {
	ID        string // ledger identity, never inserted into fidelity fixtures
	LogicalID *identity.LogicalStressID
	Partition int32
	Record    identity.Record
	Warmup    bool
}
type kafkaProduceAttempt struct {
	InputID            string
	StartedAt, EndedAt time.Time
	Offset             *identity.Int64 // only present after an acknowledged SendMessage
	Error              string          // an error does not establish absence
}
type kafkaPreparation struct {
	SourceOwnership, DestinationOwnership brokerSnapshot
	Source, Destination                   kafkaTopic
}

// kafkaRun owns clients, not containers. The controller restores/restarts the
// retained owned brokers and cleans the fixture after collecting evidence.
// Methods are serialized by the controller and require a bounded context.
type kafkaRun struct {
	RunID, Routing               string
	Preparation                  kafkaPreparation
	Inputs                       []kafkaInput
	Attempts                     []kafkaProduceAttempt
	sourceAdmin, destAdmin       sarama.ClusterAdmin
	sourceObserver, destObserver *observer.Observer
	producer                     sarama.SyncProducer
}

// openKafka checks BOTH Docker ownership receipts before any Kafka dial. Topic
// creation is exclusive: an existing name is an error, never reusable input.
// The returned partial preparation survives setup failures for evidence.
func openKafka(ctx context.Context, state fixture.State, plan kafkaPlan, run fixture.Executor) (k *kafkaRun, preparation kafkaPreparation, err error) {
	if err = kafkaBounded(ctx); err != nil {
		return nil, preparation, err
	}
	if (plan.Routing != "PRESERVE" && plan.Routing != "KEY") || plan.Records < 8 || plan.Records > 1024 {
		return nil, preparation, errors.New("Kafka plan requires PRESERVE/KEY and 8..1024 records")
	}
	if len(state.ClusterIDs) != 2 || state.ClusterIDs[0] == "" || state.ClusterIDs[1] == "" || state.ClusterIDs[0] == state.ClusterIDs[1] {
		return nil, preparation, errors.New("Kafka fixture requires two distinct recorded cluster IDs")
	}
	_, preparation.SourceOwnership, err = openOwnedBroker(ctx, state, "source", run)
	if err != nil {
		return nil, preparation, err
	}
	_, preparation.DestinationOwnership, err = openOwnedBroker(ctx, state, "destination", run)
	if err != nil {
		return nil, preparation, err
	}
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		return nil, preparation, err
	}
	name := "m2-" + state.RunID + "-" + hex.EncodeToString(nonce)
	k = &kafkaRun{RunID: state.RunID, Routing: plan.Routing}
	defer func() {
		if err != nil {
			err = errors.Join(err, k.Close())
			k = nil
		}
	}()
	if k.sourceAdmin, err = observer.NewAdmin([]string{state.Source}); err != nil {
		return k, preparation, err
	}
	if k.destAdmin, err = observer.NewAdmin([]string{state.Destination}); err != nil {
		return k, preparation, err
	}
	for i, a := range []sarama.ClusterAdmin{k.sourceAdmin, k.destAdmin} {
		if err = kafkaClusterIdentity(ctx, a, state.ClusterIDs[i]); err != nil {
			return k, preparation, err
		}
	}
	if k.sourceObserver, err = observer.New([]string{state.Source}); err != nil {
		return k, preparation, err
	}
	if k.destObserver, err = observer.New([]string{state.Destination}); err != nil {
		return k, preparation, err
	}
	destinationPartitions := int32(3)
	if plan.Routing == "KEY" {
		destinationPartitions = 5
	}
	preparation.Source, err = createKafkaTopic(ctx, k.sourceAdmin, k.sourceObserver, name+"-source", state.ClusterIDs[0], 3)
	if err != nil {
		return k, preparation, err
	}
	preparation.Destination, err = createKafkaTopic(ctx, k.destAdmin, k.destObserver, name+"-dest", state.ClusterIDs[1], destinationPartitions)
	if err != nil {
		return k, preparation, err
	}
	k.Preparation = preparation
	k.Inputs, err = knownKafkaInputs(state.RunID+"/"+name, plan.Records)
	if err != nil {
		return k, preparation, err
	}
	c := observer.Config("kaferry-lab-m2-input")
	c.Producer.Idempotent = true
	c.Net.MaxOpenRequests = 1
	k.producer, err = sarama.NewSyncProducer([]string{state.Source}, c)
	err = errors.Join(err, ctx.Err())
	return k, preparation, err
}

func kafkaBounded(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("Kafka campaign operation requires a bounded context")
	}
	return nil
}

func kafkaClusterIdentity(ctx context.Context, a sarama.ClusterAdmin, want string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := a.Controller()
	if err != nil {
		return err
	}
	r, err := b.GetMetadata(&sarama.MetadataRequest{Version: 11, Topics: []string{}, AllowAutoTopicCreation: false})
	if err != nil {
		return err
	}
	if r == nil || r.ClusterID == nil || *r.ClusterID != want {
		return errors.New("broker cluster ID differs from owned fixture manifest")
	}
	return ctx.Err()
}

func kafkaTopicConfig() map[string]string {
	// Fixed known timestamps need explicit limits; broker defaults can reject
	// these old synthetic records even though their bytes are supported.
	return map[string]string{"cleanup.policy": "delete", "retention.ms": "-1", "retention.bytes": "-1", "message.timestamp.type": "CreateTime", "message.timestamp.before.max.ms": "9223372036854775807", "message.timestamp.after.max.ms": "9223372036854775807"}
}

func createKafkaTopic(ctx context.Context, a sarama.ClusterAdmin, o *observer.Observer, name, cluster string, partitions int32) (topic kafkaTopic, err error) {
	topic = kafkaTopic{ClusterID: cluster, Topic: name, Partitions: partitions, Config: kafkaTopicConfig()}
	settings := make(map[string]*string, len(topic.Config))
	for name, value := range topic.Config {
		settings[name] = &value
	}
	if err = ctx.Err(); err != nil {
		return topic, err
	}
	if err = a.CreateTopic(name, &sarama.TopicDetail{NumPartitions: partitions, ReplicationFactor: 1, ConfigEntries: settings}, false); err != nil {
		return topic, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		metadata, e := a.DescribeTopics([]string{name})
		ready := e == nil && len(metadata) == 1 && metadata[0] != nil && metadata[0].Name == name && metadata[0].Err == sarama.ErrNoError && len(metadata[0].Partitions) == int(partitions)
		seen := map[int32]bool{}
		if ready {
			for _, p := range metadata[0].Partitions {
				if p == nil || p.Err != sarama.ErrNoError || p.ID < 0 || p.ID >= partitions || p.Leader < 0 || seen[p.ID] {
					ready = false
					break
				}
				seen[p.ID] = true
			}
		}
		if ready {
			break
		}
		select {
		case <-readyCtx.Done():
			return topic, errors.Join(errors.New("created topic did not reach complete leader metadata"), e, readyCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	actualCluster, id, err := o.TopicIdentity(name)
	if err != nil {
		return topic, err
	}
	if actualCluster != cluster {
		return topic, errors.New("created topic belongs to unexpected cluster")
	}
	topic.TopicID = id
	entries, err := a.DescribeConfig(sarama.ConfigResource{Type: sarama.TopicResource, Name: name})
	if err != nil {
		return topic, err
	}
	actual := map[string]string{}
	for _, entry := range entries {
		actual[entry.Name] = entry.Value
	}
	for name, value := range topic.Config {
		if actual[name] != value {
			return topic, fmt.Errorf("created topic config %s differs from requested value", name)
		}
	}
	return topic, ctx.Err()
}

// knownKafkaInputs uses three identifiable warmups followed by byte fixtures
// exactly once and identifiable stress records. No headers are inserted.
func knownKafkaInputs(label string, count int) ([]kafkaInput, error) {
	if label == "" || count < 8 || count > 1024 {
		return nil, errors.New("known input requires a run label and 8..1024 records")
	}
	makeRecord := func(key, value []byte, headers ...identity.Header) identity.Record {
		ms := identity.Int64(kafkaFixtureTimestampMS)
		return identity.Record{Key: identity.NewNullableBytes(key), Value: identity.NewNullableBytes(value), Headers: append([]identity.Header{}, headers...), TimestampMS: &ms, TimestampKind: "create_time"}
	}
	inputs := make([]kafkaInput, 0, count)
	for i := range count {
		id := fmt.Sprintf("%s/record-%04d", label, i)
		logical := identity.LogicalStressID(id)
		r := makeRecord([]byte(fmt.Sprintf("%s/key-%04d", label, i)), []byte(id))
		input := kafkaInput{ID: fmt.Sprintf("input-%04d", i), LogicalID: &logical, Partition: int32(i % 3), Record: r, Warmup: i < 3}
		switch i {
		case 3:
			input.Record, input.LogicalID = makeRecord(nil, nil), nil
		case 4:
			input.Record, input.LogicalID = makeRecord([]byte{}, nil), nil
		case 5:
			input.Record, input.LogicalID = makeRecord(nil, []byte{}), nil
		case 6:
			input.Record, input.LogicalID = makeRecord([]byte{}, []byte{}), nil
		case 7:
			input.Record, input.LogicalID = makeRecord([]byte{0, 255}, []byte{255, 0, 128}, identity.NewHeader([]byte{255, 0}, nil), identity.NewHeader([]byte{255, 0}, []byte{}), identity.NewHeader([]byte{0, 128}, []byte{0, 255})), nil
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

// Publish sends either the three warmups or the remaining finite input. Each
// input is attempted once by this controller. Retained errors need independent
// readback; calling Publish again cannot retry ambiguous deliveries. Cancellation
// during a synchronous send is reported after retaining that send's outcome.
func (k *kafkaRun) Publish(ctx context.Context, warmup bool) ([]kafkaProduceAttempt, error) {
	var inputs []kafkaInput
	for _, input := range k.Inputs {
		if input.Warmup == warmup {
			inputs = append(inputs, input)
		}
	}
	return k.publishInputs(ctx, inputs)
}

// PublishSaveProbe attempts only input-0003, the first non-warmup fixture.
// Exactly three ordered warmup attempts must precede it; the caller must retain
// their independent readback and establish the live primary separately. A
// repeated call refuses even if the first probe outcome was ambiguous.
func (k *kafkaRun) PublishSaveProbe(ctx context.Context) ([]kafkaProduceAttempt, error) {
	inputs, err := k.saveProbeInputs(3)
	if err != nil {
		return nil, err
	}
	return k.publishInputs(ctx, inputs[3:4])
}

// saveProbeInputs admits only the known declaration and its exact ordered
// attempt prefix. It never filters unknown or later attempts out of a phase.
func (k *kafkaRun) saveProbeInputs(attemptCount int) ([]kafkaInput, error) {
	if len(k.Inputs) < 8 || len(k.Inputs) > 1024 || k.Preparation.Source.Partitions != 3 || k.Preparation.Source.ClusterID == "" || k.Preparation.Source.Topic == "" || k.Preparation.Source.TopicID == "" {
		return nil, errors.New("save probe requires bounded known input on three source partitions")
	}
	for i, input := range k.Inputs {
		if input.ID != fmt.Sprintf("input-%04d", i) || input.Warmup != (i < 3) || input.Partition != int32(i%3) {
			return nil, errors.New("save probe requires the original ordered known input declaration")
		}
	}
	probe := k.Inputs[3]
	if probe.LogicalID != nil || probe.Record.Key != (identity.NullableBytes{Null: true}) || probe.Record.Value != (identity.NullableBytes{Null: true}) || len(probe.Record.Headers) != 0 || probe.Record.TimestampMS == nil || *probe.Record.TimestampMS != kafkaFixtureTimestampMS || probe.Record.TimestampKind != "create_time" {
		return nil, errors.New("save probe requires the unchanged null-key null-value byte fixture")
	}
	if len(k.Attempts) != attemptCount {
		return nil, errors.New("save probe requires the exact preceding publication stage")
	}
	for i, attempt := range k.Attempts {
		if attempt.InputID != k.Inputs[i].ID || (attempt.Offset == nil && attempt.Error == "") || (attempt.Offset != nil && (*attempt.Offset < 0 || attempt.Error != "")) {
			return nil, errors.New("save probe has missing, unknown, repeated, misordered or inconsistent input attempts")
		}
	}
	return k.Inputs[:4], nil
}

func (k *kafkaRun) publishInputs(ctx context.Context, inputs []kafkaInput) ([]kafkaProduceAttempt, error) {
	if err := kafkaBounded(ctx); err != nil {
		return nil, err
	}
	if k.producer == nil {
		return nil, errors.New("Kafka input producer is closed")
	}
	already := map[string]bool{}
	for _, a := range k.Attempts {
		already[a.InputID] = true
	}
	var attempts []kafkaProduceAttempt
	var errs []error
	for _, input := range inputs {
		if already[input.ID] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return attempts, errors.Join(append(errs, err)...)
		}
		a := kafkaProduceAttempt{InputID: input.ID, StartedAt: time.Now().UTC()}
		offset, err := observer.Produce(k.producer, k.Preparation.Source.Topic, input.Partition, input.Record)
		a.EndedAt = time.Now().UTC()
		if err != nil {
			a.Error = err.Error()
			errs = append(errs, fmt.Errorf("input %s delivery ambiguous: %w", input.ID, err))
		} else {
			n := identity.Int64(offset)
			a.Offset = &n
		}
		k.Attempts = append(k.Attempts, a)
		attempts = append(attempts, a)
		if err := ctx.Err(); err != nil {
			return attempts, errors.Join(append(errs, err)...)
		}
	}
	return attempts, errors.Join(errs...)
}

// Close preserves every cleanup error. Topics remain in the lab fixture for
// retained observations; fixture cleanup is the controller's responsibility.
func (k *kafkaRun) Close() error {
	var errs []error
	if k.producer != nil {
		errs = append(errs, k.producer.Close())
		k.producer = nil
	}
	if k.sourceObserver != nil {
		errs = append(errs, k.sourceObserver.Close())
		k.sourceObserver = nil
	}
	if k.destObserver != nil {
		errs = append(errs, k.destObserver.Close())
		k.destObserver = nil
	}
	if k.sourceAdmin != nil {
		errs = append(errs, k.sourceAdmin.Close())
		k.sourceAdmin = nil
	}
	if k.destAdmin != nil {
		errs = append(errs, k.destAdmin.Close())
		k.destAdmin = nil
	}
	return errors.Join(errs...)
}

func kafkaRecordSignature(r identity.Record) (string, error) {
	data, err := json.Marshal(r)
	return string(data), err
}
func kafkaAllowedPartitions(routing string, input kafkaInput, partitions int32) ([]int32, error) {
	if partitions <= 0 {
		return nil, errors.New("destination has no partitions")
	}
	switch routing {
	case "PRESERVE":
		if input.Partition < 0 || input.Partition >= partitions {
			return nil, errors.New("preserved source partition absent in destination")
		}
		return []int32{input.Partition}, nil
	case "KEY":
		key, err := input.Record.Key.Bytes()
		if err != nil {
			return nil, err
		}
		if key != nil {
			p, err := observer.KeyPartition(key, partitions)
			return []int32{p}, err
		}
		allowed := make([]int32, partitions)
		for p := range partitions {
			allowed[p] = p
		}
		return allowed, nil
	default:
		return nil, errors.New("unsupported Kafka routing")
	}
}

// kafkaSourceLedger compares full known bytes and acknowledged coordinates.
// An ambiguous send is resolved only when its specific known record is visible.
// It never infers counts from offset differences or an empty response.
func kafkaSourceLedger(source, destination kafkaTopic, routing string, inputs []kafkaInput, attempts []kafkaProduceAttempt, scans []observer.Scan) (evidence.Ledger, error) {
	ledger := evidence.Ledger{Partitions: []evidence.PartitionRange{}, Destinations: []identity.SourcePosition{}, Entries: []evidence.LedgerEntry{}}
	if source.Partitions != 3 || len(scans) != 3 || len(inputs) == 0 || len(inputs) > 1024 {
		return ledger, errors.New("source verification requires three complete partitions and bounded known inputs")
	}
	byID := map[string]kafkaProduceAttempt{}
	for _, a := range attempts {
		if _, found := byID[a.InputID]; found {
			return ledger, errors.New("repeated controller input attempt")
		}
		byID[a.InputID] = a
	}
	type expected struct {
		input   kafkaInput
		attempt kafkaProduceAttempt
	}
	wanted := map[string]expected{}
	inputIDs := map[string]bool{}
	for _, input := range inputs {
		a, found := byID[input.ID]
		if !found || (a.Offset == nil && a.Error == "") || (a.Offset != nil && (*a.Offset < 0 || a.Error != "")) || inputIDs[input.ID] {
			return ledger, errors.New("missing or inconsistent input attempt/identity")
		}
		inputIDs[input.ID] = true
		if input.Partition < 0 || input.Partition >= source.Partitions {
			return ledger, errors.New("known input outside selected partitions")
		}
		signature, err := kafkaRecordSignature(input.Record)
		if err != nil {
			return ledger, err
		}
		key := fmt.Sprintf("%d/%s", input.Partition, signature)
		if _, found := wanted[key]; found {
			return ledger, errors.New("known source fixtures must have distinguishable bytes within each partition")
		}
		wanted[key] = expected{input: input, attempt: a}
	}
	if len(byID) != len(inputs) {
		return ledger, errors.New("input attempts differ from expected phase")
	}
	seenPartitions, seenInputs := map[int32]bool{}, map[string]bool{}
	for _, scan := range scans {
		if err := kafkaCompleteScan(source, scan); err != nil {
			return ledger, err
		}
		if seenPartitions[scan.Partition] || scan.Start != 0 || scan.Boundary.Oldest != 0 {
			return ledger, errors.New("source partition duplicated or initial availability changed")
		}
		seenPartitions[scan.Partition] = true
		ledger.Partitions = append(ledger.Partitions, evidence.PartitionRange{Source: kafkaPosition(source, scan.Partition, scan.Start), End: identity.Int64(scan.End), Gaps: []evidence.Gap{}})
		for _, observed := range scan.Records {
			signature, err := kafkaRecordSignature(observed.Record)
			if err != nil {
				return ledger, err
			}
			match, found := wanted[fmt.Sprintf("%d/%s", scan.Partition, signature)]
			if !found || seenInputs[match.input.ID] {
				return ledger, errors.New("source scan has unknown, corrupt, misrouted or duplicate record")
			}
			if match.attempt.Offset != nil && *match.attempt.Offset != observed.Offset {
				return ledger, errors.New("acknowledged source offset differs from independent readback")
			}
			seenInputs[match.input.ID] = true
			allowed, err := kafkaAllowedPartitions(routing, match.input, destination.Partitions)
			if err != nil {
				return ledger, err
			}
			ledger.Entries = append(ledger.Entries, evidence.LedgerEntry{ID: match.input.ID, Source: observed.Position, Record: match.input.Record, Disposition: "required", Reason: "finite synthetic input independently read back before faults", DestinationTopic: destination.Topic, AllowedPartitions: allowed})
		}
		// Fresh nontransactional topics have no supported offset gaps. A control
		// record or missing record cannot silently become an explained gap.
		if int64(len(scan.Records)) != scan.End-scan.Start {
			return ledger, errors.New("unexplained gap in fresh nontransactional source input")
		}
	}
	if len(seenInputs) != len(inputs) {
		return ledger, errors.New("known input not observed; ambiguous sends remain unresolved")
	}
	for p := range destination.Partitions {
		ledger.Destinations = append(ledger.Destinations, kafkaPosition(destination, p, 0))
	}
	return ledger, nil
}
func kafkaPosition(topic kafkaTopic, partition int32, offset int64) identity.SourcePosition {
	return identity.SourcePosition{Cluster: topic.ClusterID, Topic: topic.Topic, TopicID: topic.TopicID, Partition: partition, Offset: identity.Int64(offset)}
}
func kafkaCompleteScan(topic kafkaTopic, scan observer.Scan) error {
	if scan.Cluster != topic.ClusterID || scan.Topic != topic.Topic || scan.TopicID != topic.TopicID || scan.Partition < 0 || scan.Partition >= topic.Partitions || scan.Start < 0 || scan.End < scan.Start || scan.Next != scan.End || scan.Boundary.Oldest < 0 || scan.Boundary.Oldest > scan.Start || scan.Boundary.LastStable < scan.End || scan.Boundary.HighWatermark < scan.Boundary.LastStable {
		return errors.New("incomplete scan or changed Kafka identity/bounds")
	}
	last := scan.Start - 1
	for _, r := range scan.Records {
		if r.Partition != scan.Partition || int64(r.Offset) <= last || int64(r.Offset) < scan.Start || int64(r.Offset) >= scan.End || r.Position != kafkaPosition(topic, scan.Partition, int64(r.Offset)) {
			return errors.New("scan record has inconsistent coordinates")
		}
		last = int64(r.Offset)
	}
	return nil
}
