package observer

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

// testdata/*.hex are fixed Fetch-v11 frames specified from Kafka's published
// record-batch layout, independently of client encoders. They include raw CRC32C
// values, declared counts/last deltas, and negative timestamps. Malformed fixtures
// intentionally have valid batch CRCs except the explicit CRC/truncation cases.
// https://kafka.apache.org/39/design.html#recordbatch
func wireFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, e := os.ReadFile("testdata/" + name + ".hex")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := hex.DecodeString(strings.TrimSpace(string(data)))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func decodeFixture(t *testing.T, name string) *admittedFetch {
	t.Helper()
	admitted, e := decodeFetchV11(wireFixture(t, name), 1, "a", 0)
	if e != nil {
		t.Fatal(e)
	}
	return admitted
}
func TestProtocolNegativeTimestampAndBinaryWireFixture(t *testing.T) {
	admitted := decodeFixture(t, "valid-negative-binary")
	records, spans, next, e := readProtocolBlock(admitted, 0, 5, 6, sarama.ReadCommitted)
	if e != nil {
		t.Fatal(e)
	}
	if next != 6 || len(spans) != 1 || len(records) != 1 || records[0].Offset != 5 {
		t.Fatalf("wrong wire coordinates records=%+v spans=%+v next=%d", records, spans, next)
	}
	ms := identity.Int64(-2)
	want := identity.Record{Key: identity.NewNullableBytes(nil), Value: identity.NewNullableBytes([]byte{}), TimestampMS: &ms, TimestampKind: "create_time", Headers: []identity.Header{identity.NewHeader([]byte{255, 0}, nil), identity.NewHeader([]byte{255, 0}, []byte{})}}
	if !reflect.DeepEqual(records[0].Record, want) {
		t.Fatalf("wire bytes/timestamp mismatch\ngot %+v\nwant %+v", records[0].Record, want)
	}
}
func TestProtocolCompleteMultirecordMultibatchAndCompression(t *testing.T) {
	for _, name := range []string{"valid-multibatch", "valid-gzip-multibatch"} {
		t.Run(name, func(t *testing.T) {
			a := decodeFixture(t, name)
			records, spans, next, e := readProtocolBlock(a, 0, 0, 3, sarama.ReadCommitted)
			if e != nil {
				t.Fatal(e)
			}
			if next != 3 || len(spans) != 2 || len(records) != 3 {
				t.Fatalf("incomplete valid batches next=%d spans=%+v records=%+v", next, spans, records)
			}
			for i, want := range []string{"A", "B", "C"} {
				value, e := records[i].Record.Value.Bytes()
				if e != nil || string(value) != want || records[i].Offset != identity.Int64(i) {
					t.Fatalf("wrong known record %d value=%q offset=%d err=%v", i, value, records[i].Offset, e)
				}
			}
		})
	}
}
func TestProtocolRejectsSuccessfulPrefixAndLaterBatchErrors(t *testing.T) {
	for _, name := range []string{"malformed-successful-prefix", "malformed-record-length", "malformed-later-crc", "malformed-later-truncated", "malformed-trailing-recordset", "malformed-trailing-payload", "malformed-control-count", "unsupported-compression"} {
		t.Run(name, func(t *testing.T) {
			admitted, e := decodeFetchV11(wireFixture(t, name), 1, "a", 0)
			if e == nil {
				t.Fatalf("malformed frame admitted before scan: %+v", admitted)
			}
		})
	}
}
func TestProtocolEveryPhysicalPrefixAndEnvelopeMismatch(t *testing.T) {
	raw := wireFixture(t, "valid-multibatch")
	for n := 0; n < len(raw); n++ {
		if _, e := decodeFetchV11(raw[:n], 1, "a", 0); e == nil {
			t.Fatalf("truncated frame prefix length %d accepted", n)
		}
	}
	for _, tc := range []struct {
		name, topic            string
		partition, correlation int32
	}{{"topic", "other", 0, 1}, {"partition", "a", 1, 1}, {"correlation", "a", 0, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := decodeFetchV11(raw, tc.correlation, tc.topic, tc.partition); e == nil {
				t.Fatal("mismatched envelope admitted")
			}
		})
	}
	if _, e := decodeFetchV11(append(append([]byte{}, raw...), 0), 1, "a", 0); e == nil {
		t.Fatal("trailing frame bytes admitted")
	}
}
func TestProtocolAbortedControlTailAndReusedProducer(t *testing.T) {
	admitted := decodeFixture(t, "valid-transaction-reuse")
	records, spans, next, e := readProtocolBlock(admitted, 0, 0, 4, sarama.ReadCommitted)
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
	all, _, _, e := readProtocolBlock(decodeFixture(t, "valid-transaction-reuse"), 0, 0, 4, sarama.ReadUncommitted)
	if e != nil || len(all) != 2 {
		t.Fatalf("uncommitted data changed count=%d err=%v", len(all), e)
	}
}
func TestProtocolSparseAndEmptyDeclaredSpans(t *testing.T) {
	admitted := decodeFixture(t, "valid-sparse-empty")
	records, spans, next, e := readProtocolBlock(admitted, 0, 0, 6, sarama.ReadCommitted)
	if e != nil {
		t.Fatal(e)
	}
	if next != 6 || len(spans) != 2 || spans[0].End != 4 || spans[1].First != 4 || spans[1].End != 6 || len(records) != 2 || records[0].Offset != 0 || records[1].Offset != 2 {
		t.Fatalf("valid sparse/empty metadata not retained next=%d spans=%+v records=%+v", next, spans, records)
	}
}
func TestProtocolMalformedControlCannotAdvance(t *testing.T) {
	a := decodeFixture(t, "malformed-control-key")
	_, _, next, e := readProtocolBlock(a, 0, 0, 1, sarama.ReadCommitted)
	if e == nil || next != 0 {
		t.Fatalf("bad control promoted to progress %d/%v", next, e)
	}
}
func TestProtocolDecoderCannotDropAdmittedRecord(t *testing.T) {
	a := decodeFixture(t, "valid-multibatch")
	a.batches[0].count++ // Simulate a decoder's successful-prefix result against retained metadata.
	if _, _, _, e := readProtocolBlock(a, 0, 0, 3, sarama.ReadCommitted); e == nil {
		t.Fatal("decoder successful prefix accepted despite strict count mismatch")
	}
}

// This proves the retained literal reaches the rejected client's successful-
// prefix behavior, rather than merely failing an unrelated envelope check.
func TestKnownDecoderSuccessfulPrefixNeedsAdmission(t *testing.T) {
	raw := wireFixture(t, "malformed-successful-prefix")
	_, message, e := protocol.ReadResponse(bytes.NewReader(raw), protocol.Fetch, 11)
	if e != nil {
		t.Fatalf("pinned decoder behavior changed: %v", e)
	}
	response := message.(*fetchAPI.Response)
	reader := response.Topics[0].Partitions[0].RecordSet.Records
	var offsets []int64
	for {
		record, e := reader.ReadRecord()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		offsets = append(offsets, record.Offset)
		if record.Key != nil {
			_ = record.Key.Close()
		}
		if record.Value != nil {
			_ = record.Value.Close()
		}
	}
	if !reflect.DeepEqual(offsets, []int64{0, 2}) {
		t.Fatalf("counterexample no longer reproduces successful-prefix suppression: %v", offsets)
	}
	if _, e := decodeFetchV11(raw, 1, "a", 0); e == nil {
		t.Fatal("strict boundary admitted the client's known loss of offset1")
	}
}
