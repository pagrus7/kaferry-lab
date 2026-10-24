package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// extract validates the entire compressed stream before interpreting the bounded
// tar. Only the three regular top-level release members are accepted; no path is
// ever passed to the filesystem. Links, duplicates and extra members fail closed.
func extract(data []byte) (map[string][]byte, error) {
	input := bytes.NewReader(data)
	gz, err := gzip.NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", ErrIntegrity, err)
	}
	gz.Multistream(false)
	raw, err := io.ReadAll(io.LimitReader(gz, (128<<20)+1))
	closeErr := gz.Close()
	if err != nil || closeErr != nil || len(raw) > 128<<20 || input.Len() != 0 {
		return nil, fmt.Errorf("%w: gzip framing/checksum/budget", ErrIntegrity)
	}
	if len(raw) < 1024 || len(raw)%512 != 0 || !allZero(raw[len(raw)-1024:]) {
		return nil, fmt.Errorf("%w: tar terminator", ErrIntegrity)
	}
	remaining := bytes.NewReader(raw)
	tr := tar.NewReader(remaining)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrIntegrity, err)
		}
		limit := int64(1 << 20)
		switch h.Name {
		case "kaferry":
			limit = 64 << 20
		case "LICENSE", "THIRD_PARTY_NOTICES.txt":
		default:
			return nil, fmt.Errorf("%w: unexpected tar path/type", ErrIntegrity)
		}
		if (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || h.Size <= 0 || h.Size > limit || h.Linkname != "" || len(h.PAXRecords) > 0 {
			return nil, fmt.Errorf("%w: tar member", ErrIntegrity)
		}
		if _, ok := files[h.Name]; ok {
			return nil, fmt.Errorf("%w: duplicate tar member", ErrIntegrity)
		}
		if h.Name == "kaferry" && h.Mode&0111 == 0 {
			return nil, fmt.Errorf("%w: executable mode", ErrIntegrity)
		}
		b, err := io.ReadAll(tr)
		if err != nil || int64(len(b)) != h.Size {
			return nil, fmt.Errorf("%w: short member", ErrIntegrity)
		}
		files[h.Name] = b
	}
	if len(files) != 3 || !allZero(raw[len(raw)-remaining.Len():]) {
		return nil, fmt.Errorf("%w: missing member/trailing tar data", ErrIntegrity)
	}
	return files, nil
}
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
