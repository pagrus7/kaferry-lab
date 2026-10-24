package observer

// The client decoder tolerates successful-prefix corruption and discards declared
// record counts/last deltas. This fixed Fetch-v11 admission gate checks framing
// and record boundaries before that decoder may establish a scan cursor. It does
// not materialize keys, values, headers or timestamps as a second payload oracle.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"

	"github.com/segmentio/kafka-go/compress"
	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

const maxFetchFrame = 16 << 20
const maxDecodedBatch = 16 << 20

type batchAdmission struct {
	first, end int64
	count      int32
	attributes int16
	producerID int64
	offsets    []int64
}
type admittedFetch struct {
	partition *fetchAPI.ResponsePartition
	batches   []batchAdmission
}

type wireCursor struct {
	raw []byte
	pos int
}

func (c *wireCursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.raw)-c.pos {
		return nil, errors.New("truncated Kafka evidence")
	}
	b := c.raw[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}
func (c *wireCursor) i16() (int16, error) {
	b, e := c.take(2)
	if e != nil {
		return 0, e
	}
	return int16(binary.BigEndian.Uint16(b)), nil
}
func (c *wireCursor) i32() (int32, error) {
	b, e := c.take(4)
	if e != nil {
		return 0, e
	}
	return int32(binary.BigEndian.Uint32(b)), nil
}
func (c *wireCursor) variable() (int64, error) {
	if c.pos == len(c.raw) {
		return 0, errors.New("truncated record varint")
	}
	v, n := binary.Varint(c.raw[c.pos:])
	if n <= 0 {
		return 0, errors.New("invalid/truncated record varint")
	}
	c.pos += n
	return v, nil
}
func (c *wireCursor) bytes(nullable bool) error {
	n, e := c.variable()
	if e != nil {
		return e
	}
	if n == -1 && nullable {
		return nil
	}
	if n < 0 || n > math.MaxInt32 {
		return errors.New("invalid record byte length")
	}
	_, e = c.take(int(n))
	return e
}

// decodeFetchV11 checks the complete fixed-schema envelope and each raw batch
// before invoking kafka-go's decoder. Limits are explicit observation limits;
// exceeding one is an error, never a partial passing observation.
func decodeFetchV11(frame []byte, correlation int32, topic string, partition int32) (*admittedFetch, error) {
	if len(frame) > maxFetchFrame || len(frame) < 4 {
		return nil, errors.New("invalid/oversized Fetch-v11 evidence frame")
	}
	c := wireCursor{raw: frame}
	size, e := c.i32()
	if e != nil || size < 0 || int64(size) != int64(len(frame)-4) {
		return nil, errors.New("Fetch-v11 frame length mismatch")
	}
	id, e := c.i32()
	if e != nil || id != correlation {
		return nil, errors.New("Fetch-v11 correlation mismatch")
	}
	if _, e = c.take(4 + 2 + 4); e != nil {
		return nil, e
	} // throttle, response error, session
	topics, e := c.i32()
	if e != nil || topics != 1 {
		return nil, errors.New("Fetch-v11 expected exactly one topic")
	}
	nameSize, e := c.i16()
	if e != nil || nameSize < 0 {
		return nil, errors.New("invalid Fetch-v11 topic length")
	}
	name, e := c.take(int(nameSize))
	if e != nil || string(name) != topic {
		return nil, errors.New("Fetch-v11 topic mismatch")
	}
	partitions, e := c.i32()
	if e != nil || partitions != 1 {
		return nil, errors.New("Fetch-v11 expected exactly one partition")
	}
	p, e := c.i32()
	if e != nil || p != partition {
		return nil, errors.New("Fetch-v11 partition mismatch")
	}
	if _, e = c.take(2 + 8 + 8 + 8); e != nil {
		return nil, e
	} // partition error, HW, LSO, start
	transactions, e := c.i32()
	if e != nil || transactions < -1 || int64(transactions) > int64(len(frame)-c.pos)/16 {
		return nil, errors.New("invalid Fetch-v11 aborted transaction count")
	}
	if transactions > 0 {
		if _, e = c.take(int(transactions) * 16); e != nil {
			return nil, e
		}
	}
	if _, e = c.take(4); e != nil {
		return nil, e
	} // preferred replica
	length, e := c.i32()
	if e != nil || length < -1 {
		return nil, errors.New("invalid Fetch-v11 recordset length")
	}
	var raw []byte
	if length >= 0 {
		raw, e = c.take(int(length))
		if e != nil {
			return nil, e
		}
	}
	if c.pos != len(frame) {
		return nil, errors.New("trailing Fetch-v11 evidence bytes")
	}
	batches, e := admitRecordSet(raw)
	if e != nil {
		return nil, e
	}
	decodedID, message, e := protocol.ReadResponse(bytes.NewReader(frame), protocol.Fetch, 11)
	if e != nil {
		return nil, e
	}
	if decodedID != correlation {
		return nil, errors.New("decoded correlation mismatch")
	}
	response, ok := message.(*fetchAPI.Response)
	if !ok || len(response.Topics) != 1 || len(response.Topics[0].Partitions) != 1 {
		return nil, errors.New("unexpected decoded Fetch-v11 envelope")
	}
	if response.ErrorCode != 0 {
		return nil, fmt.Errorf("Fetch-v11 response error %d", response.ErrorCode)
	}
	block := &response.Topics[0].Partitions[0]
	if block.ErrorCode != 0 {
		return nil, fmt.Errorf("Fetch-v11 partition error %d", block.ErrorCode)
	}
	return &admittedFetch{partition: block, batches: batches}, nil
}

func admitRecordSet(raw []byte) ([]batchAdmission, error) {
	if len(raw) > maxFetchFrame {
		return nil, errors.New("oversized recordset")
	}
	result := []batchAdmission{}
	for len(raw) > 0 {
		if len(raw) < 61 {
			return nil, errors.New("truncated v2 batch header")
		}
		first := int64(binary.BigEndian.Uint64(raw[:8]))
		length := int32(binary.BigEndian.Uint32(raw[8:12]))
		if first < 0 || length < 49 || int64(length) > int64(len(raw)-12) {
			return nil, errors.New("invalid/truncated v2 batch extent")
		}
		batch := raw[:12+int(length)]
		raw = raw[len(batch):]
		if batch[16] != 2 {
			return nil, errors.New("unsupported Kafka batch magic")
		}
		if crc32.Checksum(batch[21:], crc32.MakeTable(crc32.Castagnoli)) != binary.BigEndian.Uint32(batch[17:21]) {
			return nil, errors.New("Kafka batch CRC32C mismatch")
		}
		attrs := int16(binary.BigEndian.Uint16(batch[21:23]))
		lastDelta := int32(binary.BigEndian.Uint32(batch[23:27]))
		if lastDelta < 0 || first > math.MaxInt64-int64(lastDelta)-1 {
			return nil, errors.New("invalid Kafka declared last offset")
		}
		end := first + int64(lastDelta) + 1
		if len(result) > 0 && first < result[len(result)-1].end {
			return nil, errors.New("overlapping/out-of-order Kafka batch spans")
		}
		count := int32(binary.BigEndian.Uint32(batch[57:61]))
		if attrs&(1<<5) != 0 && count != 1 {
			return nil, errors.New("control batch must declare exactly one record")
		}
		if count < 0 {
			return nil, errors.New("negative declared record count")
		}
		payload := batch[61:]
		codec := attrs & 7
		if codec != 0 {
			if codec < 1 || codec > 4 {
				return nil, fmt.Errorf("unsupported Kafka compression codec %d", codec)
			}
			implementation := compress.Compression(codec).Codec()
			if implementation == nil {
				return nil, fmt.Errorf("unavailable Kafka compression codec %d", codec)
			}
			reader := implementation.NewReader(bytes.NewReader(payload))
			decoded, e := io.ReadAll(io.LimitReader(reader, maxDecodedBatch+1))
			closeErr := reader.Close()
			if e != nil {
				return nil, fmt.Errorf("Kafka batch decompression: %w", e)
			}
			if closeErr != nil {
				return nil, closeErr
			}
			if len(decoded) > maxDecodedBatch {
				return nil, errors.New("Kafka batch decompression exceeds admission limit")
			}
			payload = decoded
		}
		if len(payload) > maxDecodedBatch || int64(count) > int64(len(payload))/7 {
			return nil, errors.New("declared record count exceeds complete payload")
		}
		records := wireCursor{raw: payload}
		metadata := batchAdmission{first: first, end: end, count: count, attributes: attrs, producerID: int64(binary.BigEndian.Uint64(batch[43:51])), offsets: make([]int64, 0, int(count))}
		firstTimestamp := int64(binary.BigEndian.Uint64(batch[27:35]))
		var previous int64 = -1
		for i := int32(0); i < count; i++ {
			size, e := records.variable()
			if e != nil || size < 6 || size > math.MaxInt32 {
				return nil, errors.New("invalid record extent")
			}
			body, e := records.take(int(size))
			if e != nil {
				return nil, e
			}
			r := wireCursor{raw: body}
			if _, e = r.take(1); e != nil {
				return nil, e
			}
			delta, e := r.variable()
			if e != nil {
				return nil, e
			}
			if delta > 0 && firstTimestamp > math.MaxInt64-delta || delta < 0 && firstTimestamp < math.MinInt64-delta {
				return nil, errors.New("record timestamp arithmetic overflow")
			}
			offset, e := r.variable()
			if e != nil || offset < 0 || offset > int64(lastDelta) || offset <= previous {
				return nil, errors.New("invalid/nonmonotonic declared record offset delta")
			}
			previous = offset
			metadata.offsets = append(metadata.offsets, first+offset)
			if e = r.bytes(true); e != nil {
				return nil, e
			}
			if e = r.bytes(true); e != nil {
				return nil, e
			}
			headers, e := r.variable()
			if e != nil || headers < 0 || headers > int64(len(body)-r.pos)/2 {
				return nil, errors.New("invalid record header count")
			}
			for j := int64(0); j < headers; j++ {
				if e = r.bytes(false); e != nil {
					return nil, e
				}
				if e = r.bytes(true); e != nil {
					return nil, e
				}
			}
			if r.pos != len(body) {
				return nil, errors.New("record length does not match declared contents")
			}
		}
		if records.pos != len(payload) {
			return nil, errors.New("record count does not consume complete batch payload")
		}
		result = append(result, metadata)
	}
	return result, nil
}
