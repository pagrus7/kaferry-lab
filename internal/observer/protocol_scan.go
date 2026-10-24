package observer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

func (o *Observer) fetchProtocol(ctx context.Context, transport *kafka.Transport, topic string, partition int32, offset int64, isolation sarama.IsolationLevel) (*fetchAPI.ResponsePartition, error) {
	response, e := transport.RoundTrip(ctx, kafka.TCP(o.address), &fetchAPI.Request{ReplicaID: -1, MaxWaitTime: 100, MinBytes: 1, MaxBytes: 4 << 20, IsolationLevel: int8(isolation), SessionID: -1, SessionEpoch: -1, Topics: []fetchAPI.RequestTopic{{Topic: topic, Partitions: []fetchAPI.RequestPartition{{Partition: partition, CurrentLeaderEpoch: -1, FetchOffset: offset, LogStartOffset: -1, PartitionMaxBytes: 4 << 20}}}}})
	if e != nil {
		return nil, e
	}
	r, ok := response.(*fetchAPI.Response)
	if !ok {
		return nil, errors.New("unexpected protocol fetch response")
	}
	if r.ErrorCode != 0 {
		return nil, kafka.Error(r.ErrorCode)
	}
	if len(r.Topics) != 1 || r.Topics[0].Topic != topic || len(r.Topics[0].Partitions) != 1 || r.Topics[0].Partitions[0].Partition != partition {
		return nil, errors.New("missing/ambiguous protocol partition response")
	}
	b := &r.Topics[0].Partitions[0]
	if b.ErrorCode != 0 {
		return nil, kafka.Error(b.ErrorCode)
	}
	return b, nil
}

// ScanPartition uses kafka-go's protocol decoder rather than its high-level
// Reader, which loses empty-byte and timestamp information. Explicit cursors are
// advanced through all decoded wire records, including control records. An empty
// or compacted tail whose final offset cannot be observed is an error; neither
// high watermark nor silence can manufacture a successful scan.
func (o *Observer) ScanPartition(ctx context.Context, topic string, partition int32, start, end int64, isolation sarama.IsolationLevel) (Scan, error) {
	result := Scan{Topic: topic, Partition: partition, Start: start, End: end, Next: start, Spans: []Span{}, Records: []Observed{}}
	if topic == "" || partition < 0 || start < 0 || end < start {
		return result, errors.New("invalid scan range")
	}
	if isolation != sarama.ReadCommitted && isolation != sarama.ReadUncommitted {
		return result, errors.New("invalid isolation")
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	cluster, topicID, e := o.TopicIdentity(topic)
	if e != nil {
		return result, e
	}
	result.Cluster = cluster
	result.TopicID = topicID
	transport := &kafka.Transport{DialTimeout: 2 * time.Second, ClientID: "kaferry-lab-protocol-observer", MetadataTopics: []string{topic}}
	defer transport.CloseIdleConnections()
	for {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		block, e := o.fetchProtocol(ctx, transport, topic, partition, result.Next, isolation)
		if e != nil {
			return result, e
		}
		b := Boundary{Oldest: block.LogStartOffset, HighWatermark: block.HighWatermark, LastStable: block.LastStableOffset}
		result.Boundary = b
		if b.Oldest < 0 || b.HighWatermark < b.Oldest || isolation == sarama.ReadCommitted && (b.LastStable < b.Oldest || b.LastStable > b.HighWatermark) {
			return result, errors.New("invalid protocol fetch boundaries")
		}
		if result.Next < b.Oldest {
			return result, errors.New("retention advanced beyond scan cursor")
		}
		limit := b.HighWatermark
		if isolation == sarama.ReadCommitted {
			limit = b.LastStable
		}
		if end > limit {
			return result, fmt.Errorf("scan end %d exceeds visible exclusive boundary %d", end, limit)
		}
		if result.Next == end {
			return result, nil
		}
		previous := result.Next
		records, spans, next, e := readProtocolBlock(block, partition, previous, end, isolation)
		if e != nil {
			return result, e
		}
		for i := range records {
			records[i].Position = identity.SourcePosition{Cluster: cluster, Topic: topic, TopicID: topicID, Partition: partition, Offset: records[i].Offset}
		}
		result.Records = append(result.Records, records...)
		result.Spans = append(result.Spans, spans...)
		result.Next = next
		if next <= previous {
			return result, fmt.Errorf("protocol fetch made no proven progress at %d before end %d; compacted/truncated tails are unsupported", previous, end)
		}
	}
}

func readProtocolBlock(block *fetchAPI.ResponsePartition, partition int32, start, end int64, isolation sarama.IsolationLevel) ([]Observed, []Span, int64, error) {
	if block.RecordSet.Records == nil {
		return nil, nil, start, nil
	}
	stream, ok := block.RecordSet.Records.(*protocol.RecordStream)
	if !ok {
		return nil, nil, start, errors.New("unsupported protocol record stream")
	}
	txs := append([]fetchAPI.ResponseTransaction(nil), block.AbortedTransactions...)
	sort.Slice(txs, func(i, j int) bool { return txs[i].FirstOffset < txs[j].FirstOffset })
	txIndex := 0
	aborted := map[int64]bool{}
	next := start
	var output []Observed
	var spans []Span
	for _, reader := range stream.Records {
		var first, pid int64
		var attributes protocol.Attributes
		control := false
		switch batch := reader.(type) {
		case *protocol.RecordBatch:
			first = batch.BaseOffset
			pid = batch.ProducerID
			attributes = batch.Attributes
			reader = batch.Records
		case *protocol.ControlBatch:
			first = batch.BaseOffset
			pid = batch.ProducerID
			attributes = batch.Attributes
			reader = batch.Records
			control = true
		default:
			return nil, nil, start, errors.New("unsupported legacy protocol record batch")
		}
		if first < 0 {
			return nil, nil, start, errors.New("negative protocol batch offset")
		}
		if attributes&(1<<3) != 0 {
			return nil, nil, start, &UnsupportedTimestamp{0, "kafka-go v0.4.49 protocol API discards LogAppendTime batch maximum; do not assert timestamp fidelity"}
		}
		var batchRecords []Observed
		last := first - 1
		var controlKind uint16
		count := 0
		for {
			r, e := reader.ReadRecord()
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return nil, nil, start, e
			}
			if r == nil || r.Offset < first || r.Offset <= last || r.Offset == math.MaxInt64 {
				return nil, nil, start, errors.New("invalid/nonmonotonic protocol record offsets")
			}
			last = r.Offset
			count++
			key, e := kafka.ReadAll(r.Key)
			if r.Key != nil {
				_ = r.Key.Close()
			}
			if e != nil {
				return nil, nil, start, e
			}
			value, e := kafka.ReadAll(r.Value)
			if r.Value != nil {
				_ = r.Value.Close()
			}
			if e != nil {
				return nil, nil, start, e
			}
			if control {
				if count != 1 || len(key) != 4 || binary.BigEndian.Uint16(key[:2]) != 0 || binary.BigEndian.Uint16(key[2:]) > 1 {
					return nil, nil, start, errors.New("invalid protocol control record")
				}
				controlKind = binary.BigEndian.Uint16(key[2:])
				continue
			}
			if r.Offset < next || r.Offset >= end {
				continue
			}
			ms := identity.Int64(r.Time.UnixMilli())
			record := identity.Record{Key: identity.NewNullableBytes(key), Value: identity.NewNullableBytes(value), Headers: []identity.Header{}, TimestampMS: &ms, TimestampKind: "create_time"}
			for _, h := range r.Headers {
				record.Headers = append(record.Headers, identity.NewHeader([]byte(h.Key), h.Value))
			}
			batchRecords = append(batchRecords, Observed{Partition: partition, Offset: identity.Int64(r.Offset), Record: record})
		}
		if count == 0 {
			return nil, nil, start, errors.New("empty protocol batch has no retained last-offset delta; completeness unsupported")
		}
		for txIndex < len(txs) && txs[txIndex].FirstOffset <= last {
			aborted[txs[txIndex].ProducerID] = true
			txIndex++
		}
		isAborted := attributes.Transactional() && aborted[pid]
		if control && controlKind == 0 {
			delete(aborted, pid)
		}
		batchEnd := last + 1
		if batchEnd <= next {
			continue
		}
		if first >= end {
			break
		}
		spans = append(spans, Span{First: first, End: batchEnd, Control: control, Aborted: isAborted, ProducerID: pid})
		if !control && !(isolation == sarama.ReadCommitted && isAborted) {
			output = append(output, batchRecords...)
		}
		next = batchEnd
		if next > end {
			next = end
		}
		if next == end {
			break
		}
	}
	return output, spans, next, nil
}
