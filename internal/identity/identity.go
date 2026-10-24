// Package identity defines independent evidence representations. It does not
// import the application under test or infer delivery from source offsets.
package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Int64 encodes an exact signed integer as a JSON decimal string. JSON numbers
// would lose precision in consumers that decode them through IEEE 754 doubles.
type Int64 int64

func (n Int64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(n), 10))
}

func (n *Int64) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("decimal int64 must be a JSON string: %w", err)
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != text {
		return fmt.Errorf("invalid canonical decimal int64 %q", text)
	}
	*n = Int64(value)
	return nil
}

// NullableBytes distinguishes null from a present, zero-length byte sequence.
// Base64 is standard padded base64; null has the sole representation
// {"null":true,"base64":""}. Neither field may be omitted when decoding.
type NullableBytes struct {
	Null   bool   `json:"null"`
	Base64 string `json:"base64"`
}

func NewNullableBytes(value []byte) NullableBytes {
	return NullableBytes{Null: value == nil, Base64: base64.StdEncoding.EncodeToString(value)}
}

func decodeBase64(text string) ([]byte, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(value) != text {
		return nil, fmt.Errorf("invalid canonical base64 %q", text)
	}
	if value == nil {
		value = []byte{}
	}
	return value, nil
}

// Bytes returns nil only for a null value. Present empty bytes return a non-nil
// slice, so callers can preserve Kafka's distinction without another flag.
func (b NullableBytes) Bytes() ([]byte, error) {
	if b.Null {
		if b.Base64 != "" {
			return nil, fmt.Errorf("null bytes cannot carry a payload")
		}
		return nil, nil
	}
	return decodeBase64(b.Base64)
}

func (b NullableBytes) MarshalJSON() ([]byte, error) {
	if _, err := b.Bytes(); err != nil {
		return nil, err
	}
	type wire NullableBytes
	return json.Marshal(wire(b))
}

func (b *NullableBytes) UnmarshalJSON(data []byte) error {
	var wire struct {
		Null   *bool   `json:"null"`
		Base64 *string `json:"base64"`
	}
	if err := decodeFields(data, &wire, "null", "base64"); err != nil {
		return err
	}
	if wire.Null == nil || wire.Base64 == nil {
		return fmt.Errorf("nullable bytes require null and base64 fields")
	}
	value := NullableBytes{Null: *wire.Null, Base64: *wire.Base64}
	if _, err := value.Bytes(); err != nil {
		return err
	}
	*b = value
	return nil
}

// Header keeps binary keys and nullable values in an ordered array. KeyBase64
// represents a non-null binary key; it is never a JSON object key or UTF-8 text.
type Header struct {
	KeyBase64 string        `json:"key_base64"`
	Value     NullableBytes `json:"value"`
}

func NewHeader(key, value []byte) Header {
	return Header{KeyBase64: base64.StdEncoding.EncodeToString(key), Value: NewNullableBytes(value)}
}

func (h Header) KeyBytes() ([]byte, error) { return decodeBase64(h.KeyBase64) }

func (h Header) MarshalJSON() ([]byte, error) {
	if _, err := h.KeyBytes(); err != nil {
		return nil, err
	}
	type wire Header
	return json.Marshal(wire(h))
}

func (h *Header) UnmarshalJSON(data []byte) error {
	var wire struct {
		KeyBase64 *string        `json:"key_base64"`
		Value     *NullableBytes `json:"value"`
	}
	if err := decodeFields(data, &wire, "key_base64", "value"); err != nil {
		return err
	}
	if wire.KeyBase64 == nil || wire.Value == nil {
		return fmt.Errorf("header requires key_base64 and value fields")
	}
	value := Header{KeyBase64: *wire.KeyBase64, Value: *wire.Value}
	if _, err := value.KeyBytes(); err != nil {
		return err
	}
	*h = value
	return nil
}

// Record contains fidelity bytes only. In particular, no test ID header is
// inserted into no-header or size-boundary fixtures. TimestampKind records
// unknown, create_time, or log_append_time as independently observed.
type Record struct {
	Key           NullableBytes `json:"key"`
	Value         NullableBytes `json:"value"`
	Headers       []Header      `json:"headers"`
	TimestampMS   *Int64        `json:"timestamp_ms"`
	TimestampKind string        `json:"timestamp_kind"`
}

func (r Record) MarshalJSON() ([]byte, error) {
	if r.Headers == nil {
		r.Headers = []Header{}
	}
	type wire Record
	return json.Marshal(wire(r))
}

// SourcePosition is a Kafka source identity. TopicID is the canonical lowercase
// 32-character hex topic ID; a name alone cannot distinguish topic recreation.
// A destination offset is a different position and never replaces this one.
type SourcePosition struct {
	Cluster   string `json:"cluster"`
	Topic     string `json:"topic"`
	TopicID   string `json:"topic_id"`
	Partition int32  `json:"partition"`
	Offset    Int64  `json:"offset"`
}

// ArchiveCursor addresses the next record within an OCF block. Block is an
// absolute byte offset and Record a zero-based physical index within the block.
type ArchiveCursor struct {
	Block  Int64 `json:"block"`
	Record Int64 `json:"record"`
}

// ArchivePosition identifies one physical occurrence. Ordinal is zero based
// within a file; equal provenance offsets remain separate obligations. Cursor
// refers to this occurrence, rather than an inferred virtual Kafka offset.
type ArchivePosition struct {
	WriterID   string         `json:"writer_id"`
	FileID     string         `json:"file_id"`
	Ordinal    Int64          `json:"ordinal"`
	Cursor     ArchiveCursor  `json:"cursor"`
	Provenance SourcePosition `json:"provenance"`
}

// LogicalStressID is optional lab identity for uniquely identifiable stress
// records. Byte-fidelity fixtures do not need one. Extracting it from a record
// is scenario-specific and never changes the record bytes.
type LogicalStressID string

type Observation struct {
	LogicalID *LogicalStressID `json:"logical_id,omitempty"`
	Record    Record           `json:"record"`
	Source    *SourcePosition  `json:"source,omitempty"`
	Archive   *ArchivePosition `json:"archive,omitempty"`
}

// decodeFields rejects duplicate/unknown fields and trailing values. The
// containing bundle checker owns broader schema/version/event validation.
func decodeFields(data []byte, value any, names ...string) error {
	fields := json.NewDecoder(bytes.NewReader(data))
	first, err := fields.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("expected a JSON object")
	}
	seen := make(map[string]bool)
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for fields.More() {
		key, err := fields.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] || !allowed[name] {
			return fmt.Errorf("invalid, unknown, or duplicate JSON field")
		}
		seen[name] = true
		if err := fields.Decode(new(json.RawMessage)); err != nil {
			return err
		}
	}
	if _, err := fields.Token(); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return nil
}
