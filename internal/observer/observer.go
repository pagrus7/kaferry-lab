// Package observer is an independent Kafka producer and bounded partition observer.
// It does not import Kaferry or its Kafka client.
package observer

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
)

const MaxTimestampMS int64 = 9223372036854

// UnsupportedTimestamp is explicit because Sarama cannot preserve all Kafka int64
// timestamps: negative timestamps decode to zero and its writer uses UnixNano.
type UnsupportedTimestamp struct {
	Milliseconds int64
	Reason       string
}

func (e *UnsupportedTimestamp) Error() string {
	return fmt.Sprintf("unsupported timestamp %d ms: %s", e.Milliseconds, e.Reason)
}

func ValidateTimestamp(ms int64) error {
	if ms < 0 || ms > MaxTimestampMS {
		return &UnsupportedTimestamp{ms, "Sarama v1.61.0 cannot faithfully encode this domain"}
	}
	return nil
}

func Config(clientID string) *sarama.Config {
	c := sarama.NewConfig()
	c.Version = sarama.V3_9_0_0
	c.ClientID = clientID
	c.Net.DialTimeout = 2 * time.Second
	c.Net.ReadTimeout = 2 * time.Second
	c.Net.WriteTimeout = 2 * time.Second
	c.Metadata.Retry.Max = 2
	c.Metadata.Retry.Backoff = 100 * time.Millisecond
	c.Admin.Timeout = 3 * time.Second
	c.Producer.RequiredAcks = sarama.WaitForAll
	c.Producer.Return.Successes = true
	c.Producer.Partitioner = sarama.NewManualPartitioner
	c.Producer.Retry.Max = 2
	c.Producer.Timeout = 3 * time.Second
	c.Consumer.Return.Errors = true
	return c
}

type Observer struct {
	client  sarama.Client
	address string
}

func New(brokers []string) (*Observer, error) {
	if len(brokers) == 0 {
		return nil, errors.New("missing broker addresses")
	}
	c, e := sarama.NewClient(brokers, Config("kaferry-lab-observer"))
	if e != nil {
		return nil, e
	}
	return &Observer{client: c, address: brokers[0]}, nil
}
func (o *Observer) Close() error { return o.client.Close() }
func NewAdmin(brokers []string) (sarama.ClusterAdmin, error) {
	return sarama.NewClusterAdmin(brokers, Config("kaferry-lab-admin"))
}
func NewProducer(brokers []string, transactionID string) (sarama.SyncProducer, error) {
	c := Config("kaferry-lab-input")
	if transactionID != "" {
		c.Producer.Transaction.ID = transactionID
		c.Producer.Transaction.Timeout = 30 * time.Second
		c.Producer.Idempotent = true
		c.Net.MaxOpenRequests = 1
	}
	return sarama.NewSyncProducer(brokers, c)
}

// Produce records only broker-acknowledged coordinates. Caller must independently
// observe ambiguous errors; an error does not imply that the record is absent.
func Produce(p sarama.SyncProducer, topic string, partition int32, r identity.Record) (int64, error) {
	if partition < 0 {
		return 0, errors.New("negative manual partition")
	}
	key, e := r.Key.Bytes()
	if e != nil {
		return 0, e
	}
	value, e := r.Value.Bytes()
	if e != nil {
		return 0, e
	}
	m := &sarama.ProducerMessage{Topic: topic, Partition: partition, Key: sarama.ByteEncoder(key), Value: sarama.ByteEncoder(value)}
	if r.TimestampMS == nil {
		return 0, errors.New("fixture requires explicit timestamp")
	}
	if e = ValidateTimestamp(int64(*r.TimestampMS)); e != nil {
		return 0, e
	}
	m.Timestamp = time.UnixMilli(int64(*r.TimestampMS))
	for _, h := range r.Headers {
		k, e := h.KeyBytes()
		if e != nil {
			return 0, e
		}
		v, e := h.Value.Bytes()
		if e != nil {
			return 0, e
		}
		m.Headers = append(m.Headers, sarama.RecordHeader{Key: k, Value: v})
	}
	actual, offset, e := p.SendMessage(m)
	if e != nil {
		return 0, e
	}
	if actual != partition {
		return 0, fmt.Errorf("manual partition changed: wanted %d, got %d", partition, actual)
	}
	return offset, nil
}

// DecodeAssignment accepts the classic consumer assignment schema versions 0–3.
// Empty, trailing, malformed and unsupported bytes cannot establish ownership.
func DecodeAssignment(raw []byte) (*sarama.ConsumerGroupMemberAssignment, error) {
	if len(raw) < 2 {
		return nil, errors.New("missing/truncated member assignment")
	}
	v := int16(binary.BigEndian.Uint16(raw))
	if v < 0 || v > 3 {
		return nil, fmt.Errorf("unsupported consumer assignment version %d", v)
	}
	// Validate the complete wire shape independently of Sarama's decoder so its
	// tolerance of trailing bytes or duplicate topics cannot manufacture evidence.
	pos := 2
	take := func(n int) ([]byte, error) {
		if n < 0 || n > len(raw)-pos {
			return nil, errors.New("truncated assignment")
		}
		b := raw[pos : pos+n]
		pos += n
		return b, nil
	}
	i32 := func() (int32, error) {
		b, e := take(4)
		if e != nil {
			return 0, e
		}
		return int32(binary.BigEndian.Uint32(b)), nil
	}
	n, e := i32()
	if e != nil || n < 0 || int64(n) > int64(len(raw)) {
		return nil, errors.New("invalid assignment topic count")
	}
	topics := make(map[string]bool)
	for range n {
		b, e := take(2)
		if e != nil {
			return nil, e
		}
		ln := int16(binary.BigEndian.Uint16(b))
		if ln < 0 {
			return nil, errors.New("invalid assignment topic length")
		}
		b, e = take(int(ln))
		if e != nil {
			return nil, e
		}
		topic := string(b)
		if topics[topic] {
			return nil, errors.New("duplicate assignment topic")
		}
		topics[topic] = true
		count, e := i32()
		if e != nil || count < 0 || int64(count) > int64(len(raw)-pos)/4 {
			return nil, errors.New("invalid partition count")
		}
		seen := map[int32]bool{}
		for range count {
			p, e := i32()
			if e != nil {
				return nil, e
			}
			if p < 0 || seen[p] {
				return nil, errors.New("negative/duplicate assignment partition")
			}
			seen[p] = true
		}
	}
	ln, e := i32()
	if e != nil || ln < -1 {
		return nil, errors.New("invalid assignment user data")
	}
	if ln >= 0 {
		if _, e = take(int(ln)); e != nil {
			return nil, e
		}
	}
	if pos != len(raw) {
		return nil, errors.New("trailing assignment bytes")
	}
	return (&sarama.GroupMemberDescription{MemberAssignment: raw}).GetMemberAssignment()
}

type Member struct {
	ID                  string             `json:"id"`
	ClientID            string             `json:"client_id"`
	RawAssignmentBase64 string             `json:"raw_assignment_base64"`
	Topics              map[string][]int32 `json:"topics"`
}
type Group struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Protocol string   `json:"protocol"`
	Members  []Member `json:"members"`
}

func DescribeGroup(a sarama.ClusterAdmin, id string) (Group, error) {
	descriptions, e := a.DescribeConsumerGroups([]string{id})
	if e != nil {
		return Group{}, e
	}
	if len(descriptions) != 1 {
		return Group{}, errors.New("missing/ambiguous group description")
	}
	d := descriptions[0]
	if d.Err != sarama.ErrNoError {
		return Group{}, d.Err
	}
	if d.ErrorCode != 0 {
		return Group{}, sarama.KError(d.ErrorCode)
	}
	g := Group{ID: d.GroupId, State: d.State, Protocol: d.Protocol, Members: []Member{}}
	if d.ProtocolType != "consumer" {
		return g, fmt.Errorf("unsupported group protocol type %q", d.ProtocolType)
	}
	for id, m := range d.Members {
		assignment, e := DecodeAssignment(m.MemberAssignment)
		if e != nil {
			return g, e
		}
		g.Members = append(g.Members, Member{ID: id, ClientID: m.ClientId, RawAssignmentBase64: base64.StdEncoding.EncodeToString(m.MemberAssignment), Topics: assignment.Topics})
	}
	return g, nil
}
