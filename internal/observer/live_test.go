package observer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	kafka "github.com/segmentio/kafka-go"
)

func liveEnv(t *testing.T) (string, string, string) {
	t.Helper()
	source, dest, id := os.Getenv("LAB_SOURCE_ADDR"), os.Getenv("LAB_DEST_ADDR"), os.Getenv("LAB_RUN_ID")
	requested := os.Getenv("LAB_INTEGRATION") == "1" || source != "" || dest != "" || id != ""
	if !requested {
		t.Skip("live integration opt-in absent: set LAB_SOURCE_ADDR, LAB_DEST_ADDR, LAB_RUN_ID")
	}
	for name, addr := range map[string]string{"LAB_SOURCE_ADDR": source, "LAB_DEST_ADDR": dest} {
		host, port, e := net.SplitHostPort(addr)
		if e != nil || host == "" || port == "" {
			t.Fatalf("invalid required %s: %q", name, addr)
		}
	}
	if source == dest {
		t.Fatal("live capability topology requires two distinct clusters")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`).MatchString(id) {
		t.Fatal("invalid required LAB_RUN_ID")
	}
	return source, dest, id
}
func fixture(key, value []byte, headers ...identity.Header) identity.Record {
	ms := identity.Int64(1700000000123)
	return identity.Record{Key: identity.NewNullableBytes(key), Value: identity.NewNullableBytes(value), Headers: append([]identity.Header{}, headers...), TimestampMS: &ms, TimestampKind: "create_time"}
}
func createLiveTopic(t *testing.T, a sarama.ClusterAdmin, name string, partitions int32) {
	t.Helper()
	policy, retention, kind := "delete", "-1", "CreateTime"
	before, after := "9223372036854775807", "9223372036854775807"
	e := a.CreateTopic(name, &sarama.TopicDetail{NumPartitions: partitions, ReplicationFactor: 1, ConfigEntries: map[string]*string{"cleanup.policy": &policy, "retention.ms": &retention, "message.timestamp.type": &kind, "message.timestamp.before.max.ms": &before, "message.timestamp.after.max.ms": &after}}, false)
	if e != nil {
		t.Fatal(e)
	}
	readyUntil := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		metadata, e := a.DescribeTopics([]string{name})
		ready := e == nil && len(metadata) == 1 && metadata[0].Err == sarama.ErrNoError && len(metadata[0].Partitions) == int(partitions)
		if ready {
			for _, p := range metadata[0].Partitions {
				if p.Err != sarama.ErrNoError || p.Leader < 0 {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(readyUntil) {
			t.Fatalf("topic metadata never became ready: %s %v", name, e)
		}
		<-ticker.C
	}
	t.Cleanup(func() {
		if e := a.DeleteTopic(name); e != nil {
			t.Errorf("cleanup topic %s: %v", name, e)
		}
	})
}
func logJSON(t *testing.T, label string, value any) {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	t.Log(label + " " + string(b))
}
func saramaFixtureRead(o *Observer, topic string, partition int32, n int) ([]identity.Record, error) {
	block, e := o.fetch(topic, partition, 0, sarama.ReadCommitted)
	if e != nil {
		return nil, e
	}
	if block.HighWaterMarkOffset != int64(n) || block.LastStableOffset != int64(n) || block.Partial {
		return nil, errors.New("known fixture boundary differs")
	}
	out := []identity.Record{}
	for _, set := range block.RecordsSet {
		if set == nil || set.RecordBatch == nil {
			return nil, errors.New("known fixture batch missing")
		}
		b := set.RecordBatch
		if b.Control || b.IsTransactional || b.PartialTrailingRecord || b.Version != 2 {
			return nil, errors.New("known fixture is not a complete nontransactional v2 batch")
		}
		if b.FirstTimestamp.IsZero() {
			return nil, &UnsupportedTimestamp{0, "Sarama decoded negative wire timestamp as zero Time"}
		}
		for _, r := range b.Records {
			if b.FirstOffset+r.OffsetDelta != int64(len(out)) {
				return nil, errors.New("known fixture offset mismatch")
			}
			ms := identity.Int64(b.FirstTimestamp.Add(r.TimestampDelta).UnixMilli())
			record := identity.Record{Key: identity.NewNullableBytes(r.Key), Value: identity.NewNullableBytes(r.Value), Headers: []identity.Header{}, TimestampMS: &ms, TimestampKind: "create_time"}
			for _, h := range r.Headers {
				record.Headers = append(record.Headers, identity.NewHeader(h.Key, h.Value))
			}
			out = append(out, record)
		}
	}
	if len(out) != n {
		return nil, errors.New("known fixture count differs")
	}
	return out, nil
}

func secondaryClient(addr, topic string) (*kafka.Client, *kafka.Transport) {
	transport := &kafka.Transport{DialTimeout: 2 * time.Second, ClientID: "lab-independent-protocol", MetadataTopics: []string{topic}}
	return &kafka.Client{Addr: kafka.TCP(addr), Timeout: 5 * time.Second, Transport: transport}, transport
}
func secondaryProduceRecord(ctx context.Context, addr, topic string, partition int, r identity.Record) (int64, error) {
	client, transport := secondaryClient(addr, topic)
	defer transport.CloseIdleConnections()
	key, e := r.Key.Bytes()
	if e != nil {
		return 0, e
	}
	value, e := r.Value.Bytes()
	if e != nil {
		return 0, e
	}
	m := kafka.Record{Key: kafka.NewBytes(key), Value: kafka.NewBytes(value), Time: time.UnixMilli(int64(*r.TimestampMS))}
	for _, h := range r.Headers {
		k, e := h.KeyBytes()
		if e != nil {
			return 0, e
		}
		v, e := h.Value.Bytes()
		if e != nil {
			return 0, e
		}
		m.Headers = append(m.Headers, kafka.Header{Key: string(k), Value: v})
	}
	response, e := client.Produce(ctx, &kafka.ProduceRequest{Topic: topic, Partition: partition, RequiredAcks: kafka.RequireAll, MessageVersion: 2, Records: kafka.NewRecordReader(m)})
	if e != nil {
		return 0, e
	}
	if response.Error != nil {
		return 0, response.Error
	}
	return response.BaseOffset, nil
}
func secondaryProduce(t *testing.T, ctx context.Context, addr, topic string, partition int, records []identity.Record) {
	t.Helper()
	for i, r := range records {
		offset, e := secondaryProduceRecord(ctx, addr, topic, partition, r)
		if e != nil || offset != int64(i) {
			t.Fatalf("distinct produce offset %d/%v want %d", offset, e, i)
		}
	}
}
func waitBoundary(t *testing.T, ctx context.Context, o *Observer, topic string, partition int32, predicate func(Boundary) bool) Boundary {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, e := o.Boundary(ctx, topic, partition)
		if e != nil {
			t.Fatal(e)
		}
		if predicate(b) {
			return b
		}
		select {
		case <-ctx.Done():
			t.Fatalf("boundary predicate not reached: %v last=%+v", ctx.Err(), b)
		case <-ticker.C:
		}
	}
}
func assertRecords(t *testing.T, actual []Observed, want []identity.Record) {
	t.Helper()
	if len(actual) != len(want) {
		t.Fatalf("observed %d records want %d: %#v", len(actual), len(want), actual)
	}
	for i := range want {
		if !reflect.DeepEqual(actual[i].Record, want[i]) {
			t.Fatalf("record %d mismatch\ngot %#v\nwant %#v", i, actual[i].Record, want[i])
		}
	}
}

// TestLiveCapabilities exercises independent known expectations and a distinct
// byte client. It tests the observer, never a released Kaferry executable.
func TestLiveCapabilities(t *testing.T) {
	source, dest, id := liveEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	sourceAdmin, e := NewAdmin([]string{source})
	if e != nil {
		t.Fatal(e)
	}
	defer sourceAdmin.Close()
	destAdmin, e := NewAdmin([]string{dest})
	if e != nil {
		t.Fatal(e)
	}
	defer destAdmin.Close()
	src, e := New([]string{source})
	if e != nil {
		t.Fatal(e)
	}
	defer src.Close()
	dst, e := New([]string{dest})
	if e != nil {
		t.Fatal(e)
	}
	defer dst.Close()
	t.Run("bytes-distinct-client-and-destination", func(t *testing.T) {
		sourceTopic := "lab-" + id + "-bytes-src"
		destTopic := "lab-" + id + "-bytes-dst"
		createLiveTopic(t, sourceAdmin, sourceTopic, 3)
		createLiveTopic(t, destAdmin, destTopic, 5)
		fixtures := []identity.Record{fixture(nil, nil), fixture(nil, []byte{}), fixture([]byte{}, nil), fixture([]byte{}, []byte{}), fixture([]byte{0, 255}, []byte{0, 128, 255}), fixture(nil, []byte("headers"), identity.NewHeader([]byte{255, 0}, nil), identity.NewHeader([]byte{255, 0}, []byte{}), identity.NewHeader([]byte{}, []byte{0, 128, 255}))}
		epoch := identity.Int64(0)
		epochFixture := fixture(nil, []byte("epoch"))
		epochFixture.TimestampMS = &epoch
		fixtures = append(fixtures, epochFixture)
		p, e := NewProducer([]string{source}, "")
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		for i, r := range fixtures {
			offset, e := Produce(p, sourceTopic, 2, r)
			if e != nil || offset != int64(i) {
				t.Fatalf("input acknowledgment %d/%v want %d", offset, e, i)
			}
		}
		b := waitBoundary(t, ctx, src, sourceTopic, 2, func(b Boundary) bool { return b.LastStable == int64(len(fixtures)) })
		scan, e := src.ScanPartition(ctx, sourceTopic, 2, 0, b.HighWatermark, sarama.ReadCommitted)
		if e != nil {
			t.Fatal(e)
		}
		assertRecords(t, scan.Records, fixtures)
		saramaScan, e := saramaFixtureRead(src, sourceTopic, 2, len(fixtures))
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(saramaScan, fixtures) {
			t.Fatal("Sarama known-fixture crosscheck mismatch")
		}
		logJSON(t, "source_full_scan", scan)

		empty, e := src.ScanPartition(ctx, sourceTopic, 0, 0, 0, sarama.ReadCommitted)
		if e != nil || empty.Next != 0 || len(empty.Records) != 0 {
			t.Fatalf("empty scan failed: %+v/%v", empty, e)
		}
		sourceCluster, _, e := src.TopicIdentity(sourceTopic)
		if e != nil {
			t.Fatal(e)
		}
		destinationCluster, _, e := dst.TopicIdentity(destTopic)
		if e != nil {
			t.Fatal(e)
		}
		if sourceCluster == destinationCluster {
			t.Fatal("source and destination are the same broker cluster")
		}
		// kafka-go protocol producer maps epoch timestamp zero to current time.
		// All byte shapes remain in the six modern-timestamp secondary fixtures;
		// epoch0 is separately Sarama-produced and protocol-read above.
		secondaryFixtures := fixtures[:len(fixtures)-1]
		secondaryProduce(t, ctx, dest, destTopic, 4, secondaryFixtures)
		b = waitBoundary(t, ctx, dst, destTopic, 4, func(b Boundary) bool { return b.LastStable == int64(len(secondaryFixtures)) })
		scan, e = dst.ScanPartition(ctx, destTopic, 4, 0, b.HighWatermark, sarama.ReadCommitted)
		if e != nil {
			t.Fatal(e)
		}
		assertRecords(t, scan.Records, secondaryFixtures)
		saramaDestination, e := saramaFixtureRead(dst, destTopic, 4, len(secondaryFixtures))
		if e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(saramaDestination, secondaryFixtures) {
			t.Fatal("protocol-produced/Sarama-read known fixture mismatch")
		}
		logJSON(t, "destination_full_scan", scan)
		// Measure the actual client limitation independently of the lab's guard.
		_, _, e = p.SendMessage(&sarama.ProducerMessage{Topic: sourceTopic, Partition: 2, Value: sarama.ByteEncoder([]byte("negative-timestamp-probe")), Timestamp: time.UnixMilli(-1)})
		if e == nil {
			t.Fatal("negative timestamp unexpectedly accepted; observer domain needs review")
		}
		logJSON(t, "timestamp_capability", map[string]any{"negative_milliseconds": "UNSUPPORTED", "actual_client_error": e.Error(), "ordinary_fixture_milliseconds": "1700000000123", "sarama_full_signed_int64_domain": "UNSUPPORTED; protocol primary is tested separately"})
	})
	for _, abort := range []bool{false, true} {
		name := "commit"
		if abort {
			name = "abort"
		}
		t.Run("transaction-"+name, func(t *testing.T) {
			topic := "lab-" + id + "-tx-" + name
			createLiveTopic(t, sourceAdmin, topic, 1)
			plain, e := NewProducer([]string{source}, "")
			if e != nil {
				t.Fatal(e)
			}
			defer plain.Close()
			tx, e := NewProducer([]string{source}, id+"-"+name)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Close()
			a, o, tail := fixture(nil, []byte("A")), fixture(nil, []byte("O")), fixture(nil, []byte("T"))
			if _, e = Produce(plain, topic, 0, a); e != nil {
				t.Fatal(e)
			}
			if e = tx.BeginTxn(); e != nil {
				t.Fatal(e)
			}
			decided := false
			defer func() {
				if !decided {
					_ = tx.AbortTxn()
				}
			}()
			openOffset, e := Produce(tx, topic, 0, o)
			if e != nil {
				t.Fatal(e)
			}
			tailOffset, e := Produce(plain, topic, 0, tail)
			if e != nil {
				t.Fatal(e)
			}
			b := waitBoundary(t, ctx, src, topic, 0, func(b Boundary) bool { return b.HighWatermark > tailOffset && b.LastStable <= openOffset })
			logJSON(t, "open_transaction_boundary", b)
			uncommitted, e := src.ScanPartition(ctx, topic, 0, 0, b.HighWatermark, sarama.ReadUncommitted)
			if e != nil {
				t.Fatal(e)
			}
			assertRecords(t, uncommitted.Records, []identity.Record{a, o, tail})
			if _, e = src.ScanPartition(ctx, topic, 0, 0, b.HighWatermark, sarama.ReadCommitted); e == nil {
				t.Fatal("open transaction unstable boundary incorrectly certified complete")
			}
			stable, e := src.ScanPartition(ctx, topic, 0, 0, b.LastStable, sarama.ReadCommitted)
			if e != nil {
				t.Fatal(e)
			}
			assertRecords(t, stable.Records, []identity.Record{a})
			if abort {
				e = tx.AbortTxn()
			} else {
				e = tx.CommitTxn()
			}
			if e != nil {
				t.Fatal(e)
			}
			decided = true
			b = waitBoundary(t, ctx, src, topic, 0, func(b Boundary) bool { return b.LastStable == b.HighWatermark && b.HighWatermark > tailOffset+1 })
			final, e := src.ScanPartition(ctx, topic, 0, 0, b.HighWatermark, sarama.ReadCommitted)
			if e != nil {
				t.Fatal(e)
			}
			want := []identity.Record{a, o, tail}
			if abort {
				want = []identity.Record{a, tail}
			}
			assertRecords(t, final.Records, want)
			controls, aborted := 0, 0
			for _, s := range final.Spans {
				if s.Control {
					controls++
				}
				if s.Aborted && !s.Control {
					aborted++
				}
			}
			if controls != 1 || final.Next != b.HighWatermark || abort && aborted != 1 {
				t.Fatalf("transaction tail/gaps not evidenced: %+v", final)
			}
			logJSON(t, "final_transaction_scan", final)
		})
	}
	t.Run("negative-timestamp-domain-measurement", func(t *testing.T) {
		topic := "lab-" + id + "-negative-ts"
		createLiveTopic(t, sourceAdmin, topic, 1)
		negative := fixture(nil, []byte("negative-two-ms"))
		negativeMS := identity.Int64(-2)
		negative.TimestampMS = &negativeMS
		_, e := secondaryProduceRecord(ctx, source, topic, 0, negative)
		if e != nil {
			if !errors.Is(e, kafka.InvalidTimestamp) {
				t.Fatalf("negative timestamp probe inconclusive: %v", e)
			}
			logJSON(t, "negative_timestamp_domain", map[string]any{"milliseconds": "-2", "secondary_write": "BROKER_REJECTED", "error": e.Error(), "full_signed_domain": "UNSUPPORTED; broker rejection is not fidelity proof"})
			t.Fatalf("UNSUPPORTED mandatory negative timestamp fixture: broker rejected -2ms")
		}

		b := waitBoundary(t, ctx, src, topic, 0, func(b Boundary) bool { return b.LastStable == 1 })
		_, e = saramaFixtureRead(src, topic, 0, 1)
		var unsupported *UnsupportedTimestamp
		if !errors.As(e, &unsupported) {
			t.Fatalf("negative timestamp capability changed: %v", e)
		}
		primary, e := src.ScanPartition(ctx, topic, 0, 0, b.LastStable, sarama.ReadCommitted)
		if e != nil {
			t.Fatal(e)
		}
		assertRecords(t, primary.Records, []identity.Record{negative})
		logJSON(t, "negative_timestamp_domain", map[string]any{"milliseconds": "-2", "protocol_write": "ACCEPTED", "protocol_observed_ms": fmt.Sprint(*primary.Records[0].Record.TimestampMS), "primary_scan": "SUPPORTED for measured -2ms", "sarama_observer": "UNSUPPORTED"})
		logJSON(t, "negative_primary_scan", primary)
	})
	t.Run("live-group-assignment", func(t *testing.T) { liveGroup(t, ctx, source, sourceAdmin, id) })
}

type groupHandler struct {
	mu     sync.Mutex
	member string
	claims map[string][]int32
}

func (h *groupHandler) Setup(s sarama.ConsumerGroupSession) error {
	h.mu.Lock()
	h.member = s.MemberID()
	h.claims = s.Claims()
	h.mu.Unlock()
	for topic, partitions := range s.Claims() {
		for _, p := range partitions {
			s.MarkOffset(topic, p, 0, "")
		}
	}
	s.Commit()
	return nil
}
func (*groupHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }
func (*groupHandler) ConsumeClaim(s sarama.ConsumerGroupSession, c sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-s.Context().Done():
			return nil
		case _, ok := <-c.Messages():
			if !ok {
				return nil
			}
		}
	}
}
func liveGroup(t *testing.T, ctx context.Context, addr string, admin sarama.ClusterAdmin, id string) {
	topic, group := "lab-"+id+"-group-topic", "lab-"+id+"-group"
	createLiveTopic(t, admin, topic, 3)
	groupCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var consumers []sarama.ConsumerGroup
	var handlers []*groupHandler
	errs := make(chan error, 2)
	defer func() {
		cancel()
		for _, c := range consumers {
			if e := c.Close(); e != nil {
				t.Errorf("close control group: %v", e)
			}
		}
		wg.Wait()
		select {
		case e := <-errs:
			if e != nil && !errors.Is(e, context.Canceled) {
				t.Errorf("control group: %v", e)
			}
		default:
		}
	}()
	add := func(index int) {
		c := Config(fmt.Sprintf("lab-member-%d", index))
		c.Consumer.Offsets.AutoCommit.Enable = false
		c.Consumer.Group.Session.Timeout = 6 * time.Second
		c.Consumer.Group.Heartbeat.Interval = time.Second
		c.Consumer.Group.Rebalance.Timeout = 10 * time.Second
		consumer, e := sarama.NewConsumerGroup([]string{addr}, group, c)
		if e != nil {
			t.Fatal(e)
		}
		handler := &groupHandler{}
		consumers = append(consumers, consumer)
		handlers = append(handlers, handler)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for groupCtx.Err() == nil {
				if e := consumer.Consume(groupCtx, []string{topic}, handler); e != nil {
					errs <- e
					return
				}
			}
		}()
	}
	wait := func(n int) Group {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		var last Group
		for {
			g, e := DescribeGroup(admin, group)
			if e == nil {
				last = g
				if g.State == "Stable" && len(g.Members) == n {
					expected := map[string]map[string][]int32{}
					for _, h := range handlers {
						h.mu.Lock()
						expected[h.member] = h.claims
						h.mu.Unlock()
					}
					all := []int32{}
					match := true
					for _, m := range g.Members {
						if !reflect.DeepEqual(expected[m.ID], m.Topics) {
							match = false
						}
						all = append(all, m.Topics[topic]...)
					}
					sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
					if match && reflect.DeepEqual(all, []int32{0, 1, 2}) {
						return g
					}
				}
			}
			select {
			case <-groupCtx.Done():
				t.Fatalf("stable group predicate not reached: %v last=%+v", groupCtx.Err(), last)
			case e := <-errs:
				t.Fatal(e)
			case <-ticker.C:
			}
		}
	}
	add(0)
	logJSON(t, "one_member_assignment", wait(1))
	add(1)
	logJSON(t, "two_member_assignment", wait(2))
	offsets, e := admin.ListConsumerGroupOffsets(group, map[string][]int32{topic: {0, 1, 2}})
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []int32{0, 1, 2} {
		block := offsets.GetBlock(topic, p)
		if block == nil || block.Err != sarama.ErrNoError || block.Offset != 0 {
			t.Fatalf("known saved next offset not observed for %d: %+v", p, block)
		}
	}
}
