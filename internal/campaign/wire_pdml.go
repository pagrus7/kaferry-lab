package campaign

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Only unique, nonempty stress values can identify submission candidates.
// Full byte fidelity and saved-prefix checks remain the independent scan's job.
type wireKnownValue struct {
	ID, Topic string
	Partition int
	Value     []byte
}
type wirePDU struct {
	Frame, Stream, Correlation int64
	CompletedAt                time.Time // frame containing the completed reassembled PDU
	APIVersion                 int
	Reassembled                bool
	IDs                        []string
}
type wireSubmissionCandidates struct {
	Schema                             int
	ClientID                           string
	PDUs                               []wirePDU
	DistinctIDs                        []string
	KnownIDs                           []string
	Supported, CompletenessEstablished bool
	Limitation                         string
}
type wireNode struct {
	Kind, Name, Show, Value, Size string
	Children                      []*wireNode
}

// parseWirePDML reads TShark's hierarchy, never Kafka bytes. Native capture
// completeness and sensitivity controls remain prerequisites. Even a successful
// parse cannot reach a threshold fault or prove that no response existed.
func parseWirePDML(r io.Reader, clientID string, destinationPort int, known []wireKnownValue) (wireSubmissionCandidates, error) {
	result := wireSubmissionCandidates{Schema: 1, ClientID: clientID, Limitation: "capture completeness and native Produce11 sensitivity controls unmeasured; candidates prove neither threshold, output, acknowledgments nor absence of responses"}
	if !strings.HasPrefix(clientID, "kaferry-") || len(clientID) > 256 || destinationPort < 1 || destinationPort > 65535 || len(known) == 0 || len(known) > 1024 {
		return result, errors.New("wire attribution/ledger bounds invalid")
	}
	values := make(map[string]wireKnownValue)
	ids := make(map[string]bool)
	for _, v := range known {
		if v.ID == "" || v.Topic == "" || v.Partition < 0 || len(v.Value) == 0 || len(v.Value) > 1<<16 || ids[v.ID] {
			return result, errors.New("wire stress ledger requires unique IDs and nonempty bounded values")
		}
		if _, ok := values[string(v.Value)]; ok {
			return result, errors.New("wire values cannot identify distinct records")
		}
		values[string(v.Value)] = v
		ids[v.ID] = true
	}
	for id := range ids {
		result.KnownIDs = append(result.KnownIDs, id)
	}
	sort.Strings(result.KnownIDs)
	limited := &io.LimitedReader{R: r, N: (32 << 20) + 1}
	decoder := xml.NewDecoder(limited)
	count := 0
	opened, closed := false, false
	streams := make(map[int64]string)
	seen := make(map[string]bool)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !opened || !closed || limited.N <= 0 {
				return result, errors.New("wire PDML missing, truncated or oversized")
			}
			break
		}
		if err != nil || limited.N <= 0 {
			return result, errors.New("wire PDML malformed, truncated or oversized")
		}
		switch t := token.(type) {
		case xml.StartElement:
			if !opened && t.Name.Local == "pdml" {
				opened = true
				continue
			}
			if !opened || closed || t.Name.Local != "packet" {
				return result, errors.New("wire PDML hierarchy unsupported")
			}
			packet, e := readWireNode(decoder, t, 0, &count)
			if e != nil {
				return result, e
			}
			pdus, e := wirePacket(packet, clientID, destinationPort, values, streams)
			if e != nil {
				return result, e
			}
			result.PDUs = append(result.PDUs, pdus...)
			for _, p := range pdus {
				for _, id := range p.IDs {
					seen[id] = true
				}
			}
		case xml.EndElement:
			if t.Name.Local != "pdml" || closed {
				return result, errors.New("wire PDML closing hierarchy invalid")
			}
			closed = true
		case xml.Directive:
			return result, errors.New("wire PDML directives unsupported")
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return result, errors.New("wire PDML unexpected text")
			}
		}
	}
	for id := range seen {
		result.DistinctIDs = append(result.DistinctIDs, id)
	}
	sort.Strings(result.DistinctIDs)
	return result, nil
}
func readWireNode(d *xml.Decoder, s xml.StartElement, depth int, count *int) (*wireNode, error) {
	(*count)++
	if depth > 48 || *count > 300000 {
		return nil, errors.New("wire PDML nesting/node limit")
	}
	n := &wireNode{Kind: s.Name.Local}
	for _, a := range s.Attr {
		switch a.Name.Local {
		case "name":
			n.Name = a.Value
		case "show":
			n.Show = a.Value
		case "value":
			n.Value = a.Value
		case "size":
			n.Size = a.Value
		}
	}
	for {
		t, e := d.Token()
		if e != nil {
			return nil, errors.New("wire PDML node truncated")
		}
		switch v := t.(type) {
		case xml.StartElement:
			if v.Name.Local != "field" && v.Name.Local != "proto" {
				return nil, errors.New("wire PDML node kind unsupported")
			}
			c, e := readWireNode(d, v, depth+1, count)
			if e != nil {
				return nil, e
			}
			n.Children = append(n.Children, c)
		case xml.EndElement:
			return n, nil
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return nil, errors.New("wire PDML node unexpected text")
			}
		default:
			return nil, errors.New("wire PDML node token unsupported")
		}
	}
}
func wirePacket(packet *wireNode, client string, port int, known map[string]wireKnownValue, streams map[int64]string) ([]wirePDU, error) {
	kafkas := wireFind(packet, "kafka")
	stream, se := wireNumber(packet, "tcp.stream")
	src, sre := wireNumber(packet, "tcp.srcport")
	dst, de := wireNumber(packet, "tcp.dstport")
	if len(kafkas) == 0 {
		syn, _ := wireNumber(packet, "tcp.flags.syn")
		ack, _ := wireNumber(packet, "tcp.flags.ack")
		if se == nil && sre == nil && de == nil && dst == int64(port) && syn == 1 && ack == 0 {
			streams[stream] = strconv.FormatInt(src, 10)
		}
		return nil, nil
	}
	if se != nil || sre != nil || de != nil {
		return nil, errors.New("Kafka PDU lacks unambiguous stream/ports")
	}
	frame, fe := wireNumber(packet, "frame.number")
	length, le := wireNumber(packet, "frame.len")
	caplen, ce := wireNumber(packet, "frame.cap_len")
	stamp, te := wireField(packet, "frame.time_epoch")
	at, ae := wireEpoch(stamp)
	if fe != nil || frame < 1 || le != nil || ce != nil || length != caplen || te != nil || ae != nil {
		return nil, errors.New("Kafka PDU frame truncated or lacks completion timestamp")
	}
	bad := false
	wireWalk(packet, func(n *wireNode) {
		name := n.Name
		if name == "_ws.malformed" || strings.HasPrefix(name, "kafka.bad_") || strings.HasPrefix(name, "kafka.ei_") || name == "kafka.truncated_content" || name == "kafka.unsupported_api_version" || name == "kafka.assumed_api_version" || name == "kafka.pdu_length_mismatch" || name == "kafka.unknown_message_magic" || name == "kafka.request_missing" || name == "tcp.analysis.lost_segment" || name == "tcp.segment.error" || name == "tcp.segment.overlap.conflict" {
			bad = true
		}
	})
	if bad {
		return nil, errors.New("Kafka/TCP dissection reports unsupported, missing, malformed or incomplete data")
	}
	var result []wirePDU
	for _, k := range kafkas {
		// Responses and TCP ACK-only frames never count as submissions.
		if len(wireFind(k, "kafka.request.version")) == 0 {
			continue
		}
		id, e := wireBytes(k, "kafka.client_id")
		if e != nil {
			return nil, errors.New("request client attribution missing/ambiguous")
		}
		if string(id) != client {
			continue
		}
		if dst != int64(port) || streams[stream] != strconv.FormatInt(src, 10) {
			return nil, errors.New("worker stream lacks captured initiating SYN/destination tuple")
		}
		key, e := wireNumber(k, "kafka.api_key")
		if e != nil {
			return nil, e
		}
		if key != 0 {
			continue
		}
		version, ve := wireNumber(k, "kafka.request.version")
		length, le := wireNumber(k, "kafka.len")
		size, ze := strconv.ParseInt(k.Size, 10, 64)
		correlation, ce := wireNumber(k, "kafka.correlation_id")
		acks, ke := wireNumber(k, "kafka.required_acks")
		if ve != nil || version != 11 || le != nil || ze != nil || length < 1 || size != length+4 || ce != nil || ke != nil || acks != -1 {
			return nil, errors.New("Produce request version/boundary/ack contract unsupported")
		}
		p := wirePDU{Frame: frame, Stream: stream, Correlation: correlation, CompletedAt: at, APIVersion: 11, Reassembled: len(wireFind(packet, "tcp.reassembled.length")) > 0}
		matched := make(map[string]bool)
		var walk func(*wireNode, []*wireNode) error
		walk = func(n *wireNode, ancestors []*wireNode) error {
			if n.Name == "kafka.message_value" {
				value, e := hex.DecodeString(n.Value)
				if e != nil || strconv.Itoa(len(value)) != n.Size {
					return errors.New("record value is not a complete binary field")
				}
				expected, ok := known[string(value)]
				if !ok {
					return nil
				}
				var topic []byte
				partition, codec, magic := int64(-1), int64(-1), int64(-1)
				for i := len(ancestors) - 1; i >= 0; i-- {
					for _, f := range ancestors[i].Children {
						switch f.Name {
						case "kafka.topic_name":
							topic, _ = hex.DecodeString(f.Value)
						case "kafka.partition_id":
							partition = wireAncestryNumber(f.Show)
						case "kafka.batch_codec":
							codec = wireAncestryNumber(f.Show)
						case "kafka.message_magic":
							magic = wireAncestryNumber(f.Show)
						}
					}
				}
				if string(topic) != expected.Topic || partition != int64(expected.Partition) || codec != 0 || magic != 2 {
					return errors.New("known value lacks expected topic/partition/uncompressed magic2 ancestry")
				}
				matched[expected.ID] = true
			}
			for _, c := range n.Children {
				if e := walk(c, append(ancestors, n)); e != nil {
					return e
				}
			}
			return nil
		}
		if e = walk(k, nil); e != nil {
			return nil, e
		}
		for id := range matched {
			p.IDs = append(p.IDs, id)
		}
		sort.Strings(p.IDs)
		result = append(result, p)
	}
	return result, nil
}
func wireWalk(n *wireNode, visit func(*wireNode)) {
	visit(n)
	for _, c := range n.Children {
		wireWalk(c, visit)
	}
}
func wireFind(n *wireNode, name string) []*wireNode {
	var fields []*wireNode
	wireWalk(n, func(n *wireNode) {
		if n.Name == name {
			fields = append(fields, n)
		}
	})
	return fields
}
func wireField(n *wireNode, name string) (string, error) {
	f := wireFind(n, name)
	if len(f) != 1 {
		return "", errors.New("required PDML field missing/ambiguous")
	}
	return f[0].Show, nil
}
func wireNumber(n *wireNode, name string) (int64, error) {
	f, e := wireField(n, name)
	if e != nil {
		return 0, e
	}
	return strconv.ParseInt(f, 10, 64)
}
func wireBytes(n *wireNode, name string) ([]byte, error) {
	f := wireFind(n, name)
	if len(f) != 1 {
		return nil, errors.New("required binary PDML field missing/ambiguous")
	}
	b, e := hex.DecodeString(f[0].Value)
	if e != nil || strconv.Itoa(len(b)) != f[0].Size {
		return nil, errors.New("PDML binary field incomplete")
	}
	return b, nil
}
func wireEpoch(value string) (time.Time, error) {
	p := strings.Split(value, ".")
	if len(p) != 2 || len(p[1]) < 1 || len(p[1]) > 9 {
		return time.Time{}, errors.New("PDML epoch unsupported")
	}
	s, e := strconv.ParseInt(p[0], 10, 64)
	if e != nil || s < 0 {
		return time.Time{}, errors.New("PDML epoch invalid")
	}
	n, e := strconv.ParseInt(p[1]+strings.Repeat("0", 9-len(p[1])), 10, 64)
	if e != nil {
		return time.Time{}, e
	}
	return time.Unix(s, n).UTC(), nil
}

func wireAncestryNumber(value string) int64 {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
