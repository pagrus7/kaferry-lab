package campaign

import (
	"encoding/hex"
	"fmt"
	"html"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These synthetic PDML controls test candidate rejection, not a claim about a
// real capture or a particular installed TShark build. Native controls remain
// mandatory before threshold/source-save evidence can become supported.
func TestWireCandidatesPreserveHierarchyAndRemainUnsupported(t *testing.T) {
	// Given two coalesced Produce PDUs, a retransmitted value and one reassembled
	// PDU whose final frame is later than its initial segment.
	first := wireTestPDU("kaferry-fixture", "t", 0, 1, []byte{0, 1, 255})
	second := wireTestPDU("kaferry-fixture", "t", 1, 2, []byte("two"))
	capture := "<pdml>" + wireTestSYN() + wireTestPacket(2, first+second, false) + wireTestPacket(3, first, true) + "</pdml>"
	known := []wireKnownValue{{ID: "a", Topic: "t", Partition: 0, Value: []byte{0, 1, 255}}, {ID: "b", Topic: "t", Partition: 1, Value: []byte("two")}}
	// When the standard output hierarchy is read.
	got, err := parseWirePDML(strings.NewReader(capture), "kaferry-fixture", 19092, known)
	// Then distinct known values count once, their PDU references survive, and
	// neither output/acks nor unmeasured capture completeness is claimed.
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.DistinctIDs, []string{"a", "b"}) || len(got.PDUs) != 3 {
		t.Fatalf("candidate refs/count: %+v", got)
	}
	if got.Supported || got.CompletenessEstablished || got.Limitation == "" {
		t.Fatalf("unsupported capability promoted: %+v", got)
	}
	if !got.PDUs[2].Reassembled || !got.PDUs[2].CompletedAt.Equal(time.Unix(1700000003, 125000000).UTC()) {
		t.Fatalf("reassembly timestamp: %+v", got.PDUs[2])
	}
}

func TestWireCandidatesRejectIncompleteOrMisattributedPDUs(t *testing.T) {
	value := []byte{0, 1, 255}
	pdu := wireTestPDU("kaferry-fixture", "t", 0, 1, value)
	valid := "<pdml>" + wireTestSYN() + wireTestPacket(2, pdu, false) + "</pdml>"
	cases := []struct {
		name   string
		mutate func(string) string
	}{
		{"truncated XML", func(s string) string { return strings.TrimSuffix(s, "</pdml>") }},
		{"truncated frame", func(s string) string {
			return strings.Replace(s, `name="frame.cap_len" show="100"`, `name="frame.cap_len" show="99"`, 1)
		}},
		{"missing stream", func(s string) string { return strings.ReplaceAll(s, `name="tcp.stream"`, `name="unavailable"`) }},
		{"missing SYN", func(s string) string { return strings.Replace(s, wireTestSYN(), "", 1) }},
		{"unsupported version", func(s string) string {
			return strings.Replace(s, `name="kafka.request.version" show="11"`, `name="kafka.request.version" show="8"`, 1)
		}},
		{"unsupported diagnostic", func(s string) string {
			return strings.Replace(s, `</proto></packet></pdml>`, `<field name="kafka.assumed_api_version"/></proto></packet></pdml>`, 1)
		}},
		{"truncated binary", func(s string) string {
			return strings.Replace(s, `name="kafka.message_value" value="0001ff" size="3"`, `name="kafka.message_value" value="0001ff" size="4"`, 1)
		}},
		{"PDU size mismatch", func(s string) string {
			return strings.Replace(s, `name="kafka.len" show="96"`, `name="kafka.len" show="95"`, 1)
		}},
		{"wrong topic ancestry", func(s string) string {
			return strings.Replace(s, `name="kafka.topic_name" show="t"`, `name="kafka.topic_name" show="u"`, 1)
		}},
		{"compressed batch", func(s string) string {
			return strings.Replace(s, `name="kafka.batch_codec" show="0"`, `name="kafka.batch_codec" show="1"`, 1)
		}},
		{"malformed codec", func(s string) string {
			return strings.Replace(s, `name="kafka.batch_codec" show="0"`, `name="kafka.batch_codec" show="unknown"`, 1)
		}},
		{"unknown magic", func(s string) string {
			return strings.Replace(s, `name="kafka.message_magic" show="2"`, `name="kafka.message_magic" show="1"`, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given one broken completeness/attribution condition, when parsed, then it
			// cannot produce accepted candidates or a supported result.
			got, err := parseWirePDML(strings.NewReader(tc.mutate(valid)), "kaferry-fixture", 19092, []wireKnownValue{{ID: "a", Topic: "t", Partition: 0, Value: value}})
			if err == nil || got.Supported || got.CompletenessEstablished {
				t.Fatalf("accepted invalid observation: %+v, %v", got, err)
			}
		})
	}
}

func TestWireCandidatesDoNotCountOtherClientsSubstringsOrTCPAcks(t *testing.T) {
	// Given a matching substring from another client, a larger same-client value,
	// and an ACK-only frame, when parsed, then no known record is counted.
	other := wireTestPDU("kaferry-other", "t", 0, 1, []byte("one"))
	longer := wireTestPDU("kaferry-fixture", "t", 0, 2, []byte("one-plus"))
	capture := "<pdml>" + wireTestSYN() + wireTestPacket(2, other+longer, false) + wireTestPacket(3, "", false) + "</pdml>"
	got, err := parseWirePDML(strings.NewReader(capture), "kaferry-fixture", 19092, []wireKnownValue{{ID: "a", Topic: "t", Partition: 0, Value: []byte("one")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DistinctIDs) != 0 || got.Supported || got.CompletenessEstablished {
		t.Fatalf("false submission/absence proof: %+v", got)
	}
}

func TestWireCandidatesRejectAmbiguousLedgerValues(t *testing.T) {
	// Given two IDs with identical binary values, when selecting stress matches,
	// then a request cannot stand for two submitted records.
	_, err := parseWirePDML(strings.NewReader("<pdml/>"), "kaferry-fixture", 19092, []wireKnownValue{{ID: "a", Topic: "t", Value: []byte("same")}, {ID: "b", Topic: "t", Value: []byte("same")}})
	if err == nil {
		t.Fatal("ambiguous stress values accepted")
	}
}

func wireTestSYN() string {
	return `<packet><proto name="tcp"><field name="tcp.stream" show="0"/><field name="tcp.srcport" show="40000"/><field name="tcp.dstport" show="19092"/><field name="tcp.flags.syn" show="1"/><field name="tcp.flags.ack" show="0"/></proto></packet>`
}
func wireTestPacket(frame int, pdus string, reassembled bool) string {
	extra := ""
	if reassembled {
		extra = `<field name="tcp.reassembled.length" show="100"/>`
	}
	return fmt.Sprintf(`<packet><proto name="frame"><field name="frame.number" show="%d"/><field name="frame.len" show="100"/><field name="frame.cap_len" show="100"/><field name="frame.time_epoch" show="%d.125000000"/></proto><proto name="tcp"><field name="tcp.stream" show="0"/><field name="tcp.srcport" show="40000"/><field name="tcp.dstport" show="19092"/>%s</proto>%s</packet>`, frame, 1700000000+frame, extra, pdus)
}
func wireTestPDU(client, topic string, partition, correlation int, value []byte) string {
	// Pinned Wireshark4.6.6 uses an ordinary two-byte string span for the
	// header clientID and a compact string span for the Produce11 topic. PDML
	// raw value includes those prefixes; show is the decoded string.
	clientSpan := append([]byte{byte(len(client) >> 8), byte(len(client))}, []byte(client)...)
	topicSpan := append([]byte{byte(len(topic) + 1)}, []byte(topic)...)
	return fmt.Sprintf(`<proto name="kafka" size="100"><field name="kafka.len" show="96"/><field name="kafka.api_key" show="0"/><field name="kafka.request.version" show="11"/><field name="kafka.correlation_id" show="%d"/><field name="kafka.required_acks" show="-1"/><field name="kafka.client_id" show="%s" value="%s" size="%d"/><field><field name="kafka.topic_name" show="%s" value="%s" size="%d"/><field><field name="kafka.partition_id" show="%d"/><field><field name="kafka.message_magic" show="2"/><field name="kafka.batch_codec" show="0"/><field><field name="kafka.message_value" value="%s" size="%d"/></field></field></field></field></proto>`, correlation, html.EscapeString(client), hex.EncodeToString(clientSpan), len(clientSpan), html.EscapeString(topic), hex.EncodeToString(topicSpan), len(topicSpan), partition, hex.EncodeToString(value), len(value))
}

func TestWireCandidatesUseDecodedStringsInsteadOfLengthPrefixSubstrings(t *testing.T) {
	// Given standard prefixed raw string spans and XML-escaped decoded ASCII,
	// when matching the worker and topic, then exact show values identify them.
	client := "kaferry-fixture&\""
	packet := wireTestPDU(client, "t", 0, 1, []byte("one"))
	known := []wireKnownValue{{ID: "a", Topic: "t", Partition: 0, Value: []byte("one")}}
	capture := func(pdu string) string { return "<pdml>" + wireTestSYN() + wireTestPacket(2, pdu, false) + "</pdml>" }
	got, err := parseWirePDML(strings.NewReader(capture(packet)), client, 19092, known)
	if err != nil || !reflect.DeepEqual(got.DistinctIDs, []string{"a"}) {
		t.Fatalf("decoded string attribution: %+v, %v", got, err)
	}
	// Raw bytes still contain the expected client, but a different decoded
	// client (or a longer client containing it) cannot identify this worker.
	for _, other := range []string{
		strings.Replace(packet, `show="kaferry-fixture&amp;&#34;"`, `show="kaferry-other"`, 1),
		wireTestPDU(client+"-extra", "t", 0, 1, []byte("one")),
	} {
		got, err = parseWirePDML(strings.NewReader(capture(other)), client, 19092, known)
		if err != nil || len(got.DistinctIDs) != 0 {
			t.Fatalf("client substring/raw-span accepted: %+v, %v", got, err)
		}
	}
	// Raw prefix/payload substrings cannot compensate for a missing decoded
	// client, incorrect span length, or a different decoded topic.
	for _, broken := range []string{
		strings.Replace(packet, `show="kaferry-fixture&amp;&#34;"`, "", 1),
		strings.Replace(packet, `name="kafka.client_id" show="kaferry-fixture&amp;&#34;" value="00116b6166657272792d666978747572652622" size="19"`, `name="kafka.client_id" show="kaferry-fixture&amp;&#34;" value="00116b6166657272792d666978747572652622" size="17"`, 1),
		wireTestPDU(client, "t-extra", 0, 1, []byte("one")),
	} {
		if _, err = parseWirePDML(strings.NewReader(capture(broken)), client, 19092, known); err == nil {
			t.Fatal("incomplete/substring string attribution accepted")
		}
	}
}
