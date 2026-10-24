package identity

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestNullableBytesKeepNullAndPresentEmptyDistinct(t *testing.T) {
	for _, value := range [][]byte{nil, {}, {0, 255, 128, 1}} {
		evidence := NewNullableBytes(value)
		wire, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		var got NullableBytes
		if err := json.Unmarshal(wire, &got); err != nil {
			t.Fatal(err)
		}
		raw, err := got.Bytes()
		if err != nil || (raw == nil) != (value == nil) || !bytes.Equal(raw, value) {
			t.Fatalf("nullable round trip: input=%#v output=%#v error=%v", value, raw, err)
		}
	}
	for _, tc := range []struct {
		value []byte
		want  string
	}{
		{nil, `{"null":true,"base64":""}`},
		{[]byte{}, `{"null":false,"base64":""}`},
	} {
		got, err := json.Marshal(NewNullableBytes(tc.value))
		if err != nil || string(got) != tc.want {
			t.Fatalf("got %s error=%v; want %s", got, err, tc.want)
		}
	}
}

func TestMalformedByteEvidenceCannotBecomeAnEmptyValue(t *testing.T) {
	for _, wire := range []string{
		`null`, `{}`, `{"null":false}`, `{"base64":""}`,
		`{"null":null,"base64":""}`, `{"null":false,"base64":null}`,
		`{"null":true,"base64":"AA=="}`, `{"null":false,"base64":"?"}`,
		`{"null":false,"base64":"AB=="}`, // nonzero unused padding bits
		`{"null":false,"base64":"AA==\n"}`,
		`{"null":true,"null":false,"base64":""}`,
		`{"NULL":false,"base64":""}`,
		`{"null":false,"base64":"","unexpected":0}`,
		`{"null":false,"base64":""} {}`,
	} {
		var got NullableBytes
		if err := json.Unmarshal([]byte(wire), &got); err == nil {
			t.Errorf("accepted ambiguous/corrupt bytes: %s", wire)
		}
	}
	if _, err := json.Marshal(NullableBytes{Null: true, Base64: "AA=="}); err == nil {
		t.Fatal("serialized a contradictory null marker")
	}
}

func TestHeadersPreserveBinaryKeysOrderAndDuplicateNullValues(t *testing.T) {
	key := []byte{255, 0, 128}
	stamp := Int64(math.MinInt64)
	want := Record{
		Key: NewNullableBytes(nil), Value: NewNullableBytes([]byte{}),
		Headers:     []Header{NewHeader(key, nil), NewHeader(key, []byte{}), NewHeader([]byte{}, []byte{255})},
		TimestampMS: &stamp, TimestampKind: "create_time",
	}
	wire, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(`\ufffd`)) {
		t.Fatal("binary header names were converted through replacement characters")
	}
	var got Record
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("record changed:\nwant %#v\ngot %#v", want, got)
	}
	for i := range got.Headers {
		name, err := got.Headers[i].KeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && !bytes.Equal(name, key) {
			t.Fatalf("header %d key changed: %x", i, name)
		}
	}
	if !got.Headers[0].Value.Null || got.Headers[1].Value.Null {
		t.Fatal("duplicate header null/empty distinction changed")
	}
	noHeaders, err := json.Marshal(Record{Key: NewNullableBytes(nil), Value: NewNullableBytes(nil)})
	if err != nil || !bytes.Contains(noHeaders, []byte(`"headers":[]`)) {
		t.Fatalf("no-header fixture is not an empty ordered array: %s (%v)", noHeaders, err)
	}
}

func TestSignedIntegersUseExactDecimalStrings(t *testing.T) {
	for _, tc := range []struct {
		value Int64
		wire  string
	}{
		{Int64(math.MinInt64), `"-9223372036854775808"`},
		{-1, `"-1"`}, {0, `"0"`},
		{9007199254740993, `"9007199254740993"`},
		{Int64(math.MaxInt64), `"9223372036854775807"`},
	} {
		wire, err := json.Marshal(tc.value)
		if err != nil || string(wire) != tc.wire {
			t.Fatalf("integer serialized %s (%v), want %s", wire, err, tc.wire)
		}
		var got Int64
		if err := json.Unmarshal(wire, &got); err != nil || got != tc.value {
			t.Fatalf("integer changed: %d (%v)", got, err)
		}
	}
	for _, wire := range []string{`9007199254740993`, `null`, `""`, `"01"`, `"-0"`, `"+1"`, `"1.0"`, `"1e3"`, `"9223372036854775808"`, `"-9223372036854775809"`} {
		var got Int64
		if err := json.Unmarshal([]byte(wire), &got); err == nil {
			t.Errorf("accepted lossy/noncanonical integer %s", wire)
		}
	}
}

func TestPhysicalOccurrencesDoNotCollapseIntoSourceOffsets(t *testing.T) {
	provenance := SourcePosition{Cluster: "cluster-a", Topic: "orders", TopicID: strings.Repeat("1", 32), Partition: 3, Offset: 9007199254740993}
	first := ArchivePosition{WriterID: strings.Repeat("2", 32), FileID: strings.Repeat("3", 32), Ordinal: 0, Cursor: ArchiveCursor{Block: 100, Record: 0}, Provenance: provenance}
	second := first
	second.Ordinal, second.Cursor.Record = 1, 1
	third := first
	third.FileID = strings.Repeat("4", 32)
	identities := map[ArchivePosition]bool{first: true, second: true, third: true}
	if len(identities) != 3 {
		t.Fatal("physical identity deduplicated equal source positions")
	}
	wire, err := json.Marshal(first)
	if err != nil || !bytes.Contains(wire, []byte(`"offset":"9007199254740993"`)) || !bytes.Contains(wire, []byte(`"ordinal":"0"`)) {
		t.Fatalf("physical evidence contains inexact integers: %s (%v)", wire, err)
	}
	fixture := Observation{Record: Record{Key: NewNullableBytes(nil), Value: NewNullableBytes([]byte{}), Headers: []Header{}}}
	wire, err = json.Marshal(fixture)
	if err != nil || bytes.Contains(wire, []byte(`logical_id`)) || bytes.Contains(wire, []byte(`key_base64`)) {
		t.Fatalf("identity decoration changed byte fixture: %s (%v)", wire, err)
	}
}
