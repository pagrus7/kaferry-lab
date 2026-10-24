package observer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	kafka "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

func (o *Observer) fetchProtocol(ctx context.Context, topic string, partition int32, offset int64, isolation sarama.IsolationLevel) (*admittedFetch, error) {
	leader, e := o.client.Leader(topic, partition)
	if e != nil {
		return nil, e
	}
	conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", leader.Addr())
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	request := &fetchAPI.Request{ReplicaID: -1, MaxWaitTime: 100, MinBytes: 1, MaxBytes: 4 << 20, IsolationLevel: int8(isolation), SessionID: -1, SessionEpoch: -1, Topics: []fetchAPI.RequestTopic{{Topic: topic, Partitions: []fetchAPI.RequestPartition{{Partition: partition, CurrentLeaderEpoch: -1, FetchOffset: offset, LogStartOffset: -1, PartitionMaxBytes: 4 << 20}}}}}
	const correlation int32 = 1
	if e = protocol.WriteRequest(conn, 11, correlation, "kaferry-lab-admitted-fetch", request); e != nil {
		return nil, e
	}
	prefix := make([]byte, 4)
	if _, e = io.ReadFull(conn, prefix); e != nil {
		return nil, e
	}
	size := int32(binary.BigEndian.Uint32(prefix))
	if size < 0 || size > maxFetchFrame-4 {
		return nil, errors.New("invalid/oversized Fetch-v11 response")
	}
	frame := make([]byte, 4+int(size))
	copy(frame, prefix)
	if _, e = io.ReadFull(conn, frame[4:]); e != nil {
		return nil, e
	}
	return decodeFetchV11(frame, correlation, topic, partition)
}

// ScanPartition uses kafka-go's protocol decoder rather than its high-level
// Reader, which loses empty-byte and timestamp information. Before decoding,
// strict Fetch-v11 admission validates all raw records and retains declared batch
// ends. Cursors include validated control/compacted spans; neither high watermark
// nor silence can manufacture a successful scan.
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
	for {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		admitted, e := o.fetchProtocol(ctx, topic, partition, result.Next, isolation)
		if e != nil {
			return result, e
		}
		block := admitted.partition
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
		records, spans, next, e := readProtocolBlock(admitted, partition, previous, end, isolation)
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
			return result, fmt.Errorf("protocol fetch made no proven progress at %d before end %d; no admitted batch proves the remaining tail", previous, end)
		}
	}
}

func readProtocolBlock(admitted *admittedFetch, partition int32, start, end int64, isolation sarama.IsolationLevel) ([]Observed, []Span, int64, error) {
	if admitted == nil || admitted.partition == nil {
		return nil, nil, start, errors.New("missing raw Fetch admission")
	}
	block := admitted.partition
	if block.RecordSet.Records == nil {
		if len(admitted.batches) != 0 {
			return nil, nil, start, errors.New("client omitted admitted batches")
		}
		return nil, nil, start, nil
	}
	stream, ok := block.RecordSet.Records.(*protocol.RecordStream)
	if !ok {
		return nil, nil, start, errors.New("unsupported protocol record stream")
	}
	if len(stream.Records) != len(admitted.batches) {
		return nil, nil, start, errors.New("client decoded batch count differs from strict admission")
	}
	txs := append([]fetchAPI.ResponseTransaction(nil), block.AbortedTransactions...)
	sort.Slice(txs, func(i, j int) bool { return txs[i].FirstOffset < txs[j].FirstOffset })
	txIndex := 0
	aborted := map[int64]bool{}
	next := start
	var output []Observed
	var spans []Span
	for batchIndex, reader := range stream.Records {
		metadata := admitted.batches[batchIndex]
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
		if first != metadata.first || int16(attributes) != metadata.attributes || pid != metadata.producerID {
			return nil, nil, start, errors.New("decoded batch metadata differs from raw admission")
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
			if count >= len(metadata.offsets) || r.Offset != metadata.offsets[count] {
				return nil, nil, start, errors.New("decoded offsets differ from raw admission")
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
				if count != 1 || !attributes.Transactional() || len(key) != 4 || binary.BigEndian.Uint16(key[:2]) != 0 || binary.BigEndian.Uint16(key[2:]) > 1 || len(value) != 6 || binary.BigEndian.Uint16(value[:2]) != 0 {
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
		if int32(count) != metadata.count {
			return nil, nil, start, errors.New("client returned successful prefix of admitted record count")
		}
		for txIndex < len(txs) && txs[txIndex].FirstOffset < metadata.end {
			aborted[txs[txIndex].ProducerID] = true
			txIndex++
		}
		isAborted := attributes.Transactional() && aborted[pid]
		if control && controlKind == 0 {
			delete(aborted, pid)
		}
		batchEnd := metadata.end
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
