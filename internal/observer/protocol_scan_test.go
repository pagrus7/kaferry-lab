package observer

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

// Literal independently specified Kafka v2 RecordSet: batch base offset 5,
// timestamp -2ms, nil key, present empty value, ordered duplicate binary key ff00
// with null then empty values. CRC32C covers attributes through records. Layout:
// https://kafka.apache.org/39/design.html#recordbatch
// The bytes are fixed, not produced by any Kafka client encoder in this test.
const negativeWireFixture = "0000004c000000000000000500000040ffffffff02fe9bd12a000000000000fffffffffffffffefffffffffffffffeffffffffffffffffffffffffffff000000011c00000001000404ff000104ff0000"

func TestProtocolNegativeTimestampAndBinaryWireFixture(t *testing.T) {
	raw, e := hex.DecodeString(negativeWireFixture)
	if e != nil {
		t.Fatal(e)
	}
	var set protocol.RecordSet
	if _, e = set.ReadFrom(bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	records, spans, next, e := readProtocolBlock(&fetchAPI.ResponsePartition{RecordSet: set}, 2, 5, 6, sarama.ReadCommitted)
	if e != nil {
		t.Fatal(e)
	}
	if next != 6 || len(spans) != 1 || len(records) != 1 || records[0].Offset != 5 {
		t.Fatalf("wrong wire coordinates: %+v %+v %d", records, spans, next)
	}
	ms := identity.Int64(-2)
	want := identity.Record{Key: identity.NewNullableBytes(nil), Value: identity.NewNullableBytes([]byte{}), TimestampMS: &ms, TimestampKind: "create_time", Headers: []identity.Header{identity.NewHeader([]byte{255, 0}, nil), identity.NewHeader([]byte{255, 0}, []byte{})}}
	if !reflect.DeepEqual(records[0].Record, want) {
		t.Fatalf("wire bytes/timestamp mismatch\ngot %+v\nwant %+v", records[0].Record, want)
	}
	for n := 0; n < len(raw); n++ {
		var truncated protocol.RecordSet
		if _, e := truncated.ReadFrom(bytes.NewReader(raw[:n])); e == nil {
			t.Fatalf("truncated sole wire batch length %d accepted", n)
		}
	}
	corrupt := append([]byte{}, raw...)
	corrupt[len(corrupt)-1] ^= 1
	var damaged protocol.RecordSet
	if _, e := damaged.ReadFrom(bytes.NewReader(corrupt)); e == nil {
		t.Fatal("corrupt record batch CRC accepted")
	}
}
func rawData(offset, pid int64, transactional bool, value string) protocol.RecordReader {
	a := protocol.Attributes(0)
	if transactional {
		a = protocol.Transactional
	}
	return &protocol.RecordBatch{BaseOffset: offset, ProducerID: pid, Attributes: a, Records: protocol.NewRecordReader(protocol.Record{Offset: offset, Time: time.UnixMilli(-2), Value: protocol.NewBytes([]byte(value))})}
}
func rawControl(offset, pid int64, abort bool) protocol.RecordReader {
	kind := byte(1)
	if abort {
		kind = 0
	}
	return &protocol.ControlBatch{BaseOffset: offset, ProducerID: pid, Attributes: protocol.Transactional | protocol.Control, Records: protocol.NewRecordReader(protocol.Record{Offset: offset, Time: time.UnixMilli(1700000000123), Key: protocol.NewBytes([]byte{0, 0, 0, kind})})}
}
func TestProtocolAbortedControlTailAndReusedProducer(t *testing.T) {
	b := &fetchAPI.ResponsePartition{AbortedTransactions: []fetchAPI.ResponseTransaction{{ProducerID: 7, FirstOffset: 0}}, RecordSet: protocol.RecordSet{Records: &protocol.RecordStream{Records: []protocol.RecordReader{rawData(0, 7, true, "forbidden"), rawControl(1, 7, true), rawData(2, 7, true, "required"), rawControl(3, 7, false)}}}}
	records, spans, next, e := readProtocolBlock(b, 0, 0, 4, sarama.ReadCommitted)
	if e != nil {
		t.Fatal(e)
	}
	if next != 4 || len(spans) != 4 || len(records) != 1 || records[0].Offset != 2 {
		t.Fatalf("wrong transactional result next=%d records=%+v spans=%+v", next, records, spans)
	}
	value, e := records[0].Record.Value.Bytes()
	if e != nil || string(value) != "required" {
		t.Fatalf("bad output %q/%v", value, e)
	}
}
func TestProtocolEmptyAndUnobservableTailFailClosed(t *testing.T) {
	if _, _, next, e := readProtocolBlock(&fetchAPI.ResponsePartition{}, 0, 4, 8, sarama.ReadCommitted); e != nil || next != 4 {
		t.Fatalf("empty response invented progress %d/%v", next, e)
	}
	b := &fetchAPI.ResponsePartition{RecordSet: protocol.RecordSet{Records: &protocol.RecordStream{Records: []protocol.RecordReader{&protocol.RecordBatch{BaseOffset: 4, Records: protocol.NewRecordReader()}}}}}
	if _, _, _, e := readProtocolBlock(b, 0, 4, 8, sarama.ReadCommitted); e == nil {
		t.Fatal("empty compacted batch invented last offset")
	}
}

func TestProtocolRefusesUnobservableLogAppendTimestamp(t *testing.T) {
	batch := rawData(0, -1, false, "wall-clock").(*protocol.RecordBatch)
	batch.Attributes = 1 << 3
	block := &fetchAPI.ResponsePartition{RecordSet: protocol.RecordSet{Records: &protocol.RecordStream{Records: []protocol.RecordReader{batch}}}}
	if _, _, _, e := readProtocolBlock(block, 0, 0, 1, sarama.ReadCommitted); e == nil {
		t.Fatal("LogAppendTime maximum was discarded but fidelity was asserted")
	}
}
