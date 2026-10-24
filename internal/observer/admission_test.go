package observer

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
)

// This input is intentionally not a valid record payload. The admission budget
// must reject decompression before any record parser or client allocation runs.
func TestAdmissionBoundsCompressedExpansion(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, e := writer.Write(make([]byte, maxDecodedBatch+1)); e != nil {
		t.Fatal(e)
	}
	if e := writer.Close(); e != nil {
		t.Fatal(e)
	}
	batch := make([]byte, 61+compressed.Len())
	binary.BigEndian.PutUint32(batch[8:12], uint32(len(batch)-12))
	batch[16] = 2
	binary.BigEndian.PutUint16(batch[21:23], 1)
	binary.BigEndian.PutUint32(batch[57:61], 1)
	copy(batch[61:], compressed.Bytes())
	binary.BigEndian.PutUint32(batch[17:21], crc32.Checksum(batch[21:], crc32.MakeTable(crc32.Castagnoli)))
	if _, e := admitRecordSet(batch); e == nil || !strings.Contains(e.Error(), "decompression exceeds") {
		t.Fatalf("expansion budget was not enforced before record parsing: %v", e)
	}
}
func TestAdmissionBoundsResponseFrame(t *testing.T) {
	if _, e := decodeFetchV11(make([]byte, maxFetchFrame+1), 1, "a", 0); e == nil {
		t.Fatal("oversized frame accepted")
	}
}
