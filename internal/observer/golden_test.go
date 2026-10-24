package observer

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/IBM/sarama"
)

// Expected hashes are literals from Apache Kafka 3.9.2 UtilsTest.testMurmur2:
// https://github.com/apache/kafka/blob/3.9.2/clients/src/test/java/org/apache/kafka/common/utils/UtilsTest.java
func TestMurmur2ApacheGolden(t *testing.T) {
	cases := []struct {
		key  string
		hash int32
	}{{"21", -973932308}, {"foobar", -790332482}, {"a-little-bit-long-string", -985981536}, {"a-little-bit-longer-string", -1486304829}, {"lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8", -58897971}, {"abc", 479470107}}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := int32(Murmur2([]byte(tc.key))); got != tc.hash {
				t.Fatalf("hash %d want Apache golden %d", got, tc.hash)
			}
			for _, n := range []int32{1, 3, 7, 17} {
				want := int32((uint32(tc.hash) & 0x7fffffff) % uint32(n))
				got, e := KeyPartition([]byte(tc.key), n)
				if e != nil || got != want {
					t.Fatalf("partition %d/%v want %d", got, e, want)
				}
				p := sarama.NewMurmur2Partitioner("golden")
				actual, e := p.Partition(&sarama.ProducerMessage{Key: sarama.ByteEncoder([]byte(tc.key))}, n)
				if e != nil || actual != want {
					t.Fatalf("Sarama partition %d/%v want %d", actual, e, want)
				}
			}
		})
	}
	if _, e := KeyPartition(nil, 0); e == nil {
		t.Fatal("invalid partition count accepted")
	}
}

// Literal Kafka consumer protocol assignment v0, topic a, partitions 0,2,9,
// nullable user data. This fixture is not encoded by Sarama or the lab decoder.
func TestAssignmentWireFixture(t *testing.T) {
	raw, e := hex.DecodeString("00000000000100016100000003000000000000000200000009ffffffff")
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeAssignment(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got.Version != 0 || got.UserData != nil || !reflect.DeepEqual(got.Topics, map[string][]int32{"a": {0, 2, 9}}) {
		t.Fatalf("wrong assignment %#v", got)
	}
	for n := 0; n < len(raw); n++ {
		if _, e := DecodeAssignment(raw[:n]); e == nil {
			t.Fatalf("truncated fixture length %d accepted", n)
		}
	}
	for _, mutation := range []struct {
		name string
		raw  []byte
	}{{"trailing", append(append([]byte{}, raw...), 0)}, {"unsupported-version", append([]byte{0, 4}, raw[2:]...)}, {"negative-count", []byte{0, 0, 255, 255, 255, 255}}} {
		t.Run(mutation.name, func(t *testing.T) {
			if _, e := DecodeAssignment(mutation.raw); e == nil {
				t.Fatal("invalid wire assignment accepted")
			}
		})
	}
}
func TestTimestampDomainExplicit(t *testing.T) {
	for _, ms := range []int64{0, 1700000000123, MaxTimestampMS} {
		if e := ValidateTimestamp(ms); e != nil {
			t.Fatal(e)
		}
	}
	for _, ms := range []int64{-1, -9223372036854, MaxTimestampMS + 1} {
		var unsupported *UnsupportedTimestamp
		if e := ValidateTimestamp(ms); !errors.As(e, &unsupported) {
			t.Fatalf("timestamp %d must be explicitly unsupported, got %v", ms, e)
		}
	}
}
