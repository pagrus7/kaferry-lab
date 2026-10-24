package observer

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/identity"
)

type Boundary struct {
	Oldest        int64 `json:"oldest,string"`
	HighWatermark int64 `json:"high_watermark,string"`
	LastStable    int64 `json:"last_stable,string"`
}
type Span struct {
	First      int64 `json:"first,string"`
	End        int64 `json:"end,string"`
	Control    bool  `json:"control"`
	Aborted    bool  `json:"aborted"`
	ProducerID int64 `json:"producer_id,string"`
}
type Observed struct {
	Position  identity.SourcePosition `json:"source_position"`
	Partition int32                   `json:"partition"`
	Offset    identity.Int64          `json:"offset"`
	Record    identity.Record         `json:"record"`
}
type Scan struct {
	Cluster   string     `json:"cluster"`
	TopicID   string     `json:"topic_id"`
	Topic     string     `json:"topic"`
	Partition int32      `json:"partition"`
	Start     int64      `json:"start,string"`
	End       int64      `json:"end,string"`
	Next      int64      `json:"next,string"`
	Boundary  Boundary   `json:"boundary"`
	Spans     []Span     `json:"spans"`
	Records   []Observed `json:"records"`
}

// TopicIdentity obtains broker-reported cluster and immutable topic identities.
func (o *Observer) TopicIdentity(topic string) (string, string, error) {
	leader, e := o.client.Leader(topic, 0)
	if e != nil {
		return "", "", e
	}
	response, e := leader.GetMetadata(&sarama.MetadataRequest{Version: 11, Topics: []string{topic}, AllowAutoTopicCreation: false})
	if e != nil {
		return "", "", e
	}
	if response.ClusterID == nil || *response.ClusterID == "" {
		return "", "", errors.New("missing broker cluster identity")
	}
	for _, t := range response.Topics {
		if t.Name == topic {
			if t.Err != sarama.ErrNoError {
				return "", "", t.Err
			}
			if t.Uuid == (sarama.Uuid{}) {
				return "", "", errors.New("missing immutable topic identity")
			}
			return *response.ClusterID, hex.EncodeToString(t.Uuid[:]), nil
		}
	}
	return "", "", errors.New("missing topic metadata")
}

func (o *Observer) fetch(topic string, partition int32, offset int64, isolation sarama.IsolationLevel) (*sarama.FetchResponseBlock, error) {
	leader, e := o.client.Leader(topic, partition)
	if e != nil {
		return nil, e
	}
	request := &sarama.FetchRequest{Version: 11, MaxWaitTime: 100, MinBytes: 1, MaxBytes: 4 << 20, Isolation: isolation, SessionID: 0, SessionEpoch: -1}
	request.AddBlock(topic, partition, offset, 4<<20, -1)
	response, e := leader.Fetch(request)
	if e != nil {
		return nil, e
	}
	block := response.GetBlock(topic, partition)
	if block == nil {
		return nil, errors.New("missing partition fetch block")
	}
	if block.Err != sarama.ErrNoError {
		return nil, block.Err
	}
	return block, nil
}

// Boundary records independent Kafka watermarks, not a record count. It does not
// establish that pending writes or open transactions have settled.
func (o *Observer) Boundary(ctx context.Context, topic string, partition int32) (Boundary, error) {
	if e := ctx.Err(); e != nil {
		return Boundary{}, e
	}
	end, e := o.client.GetOffset(topic, partition, sarama.OffsetNewest)
	if e != nil {
		return Boundary{}, e
	}
	block, e := o.fetch(topic, partition, end, sarama.ReadCommitted)
	if e != nil {
		return Boundary{}, e
	}
	if e = ctx.Err(); e != nil {
		return Boundary{}, e
	}
	b := Boundary{Oldest: block.LogStartOffset, HighWatermark: block.HighWaterMarkOffset, LastStable: block.LastStableOffset}
	if b.Oldest < 0 || b.LastStable < b.Oldest || b.HighWatermark < b.LastStable {
		return b, errors.New("invalid broker offset boundary")
	}
	return b, nil
}
