// Package calibration runs visibly separate faulty/healthy stand-ins. It cannot
// produce a Kaferry release qualification.
package calibration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

type Barrier struct {
	Saved identity.Int64 `json:"saved"`
	Mode  string         `json:"mode"`
}

func checkpoint(path string, next identity.Int64) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func readCheckpoint(path string) (identity.Int64, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var next identity.Int64
	err = json.Unmarshal(raw, &next)
	return next, err
}

// Standin deliberately exposes a deterministic commit-before-produce window in
// faulty mode. The parent confirms the durable checkpoint/output files and kills
// this real child at the stdin barrier. This is never the subject under test.
func Standin(input, output, state, mode string, stdin io.Reader, stdout io.Writer) error {
	if mode != "faulty" && mode != "healthy-pause" && mode != "healthy" {
		return fmt.Errorf("invalid calibration mode")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var records []identity.Record
	if err = json.Unmarshal(raw, &records); err != nil {
		return err
	}
	next, err := readCheckpoint(state)
	if err != nil {
		return err
	}
	if next < 0 || int64(next) > int64(len(records)) {
		return fmt.Errorf("invalid saved input cursor")
	}
	out, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	barrier := func(saved identity.Int64) error {
		if err := json.NewEncoder(stdout).Encode(Barrier{saved, mode}); err != nil {
			return err
		}
		var b [1]byte
		_, err := io.ReadFull(stdin, b[:])
		return err
	}
	for i := int(next); i < len(records); i++ {
		if mode == "faulty" {
			if err = checkpoint(state, identity.Int64(i+1)); err != nil {
				return err
			}
			if err = barrier(identity.Int64(i + 1)); err != nil {
				return err
			}
		}
		if err = json.NewEncoder(out).Encode(records[i]); err != nil {
			return err
		}
		if err = out.Sync(); err != nil {
			return err
		}
		if mode != "faulty" {
			if err = checkpoint(state, identity.Int64(i+1)); err != nil {
				return err
			}
		}
		if mode == "healthy-pause" {
			if err = barrier(identity.Int64(i + 1)); err != nil {
				return err
			}
		}
	}
	return nil
}
