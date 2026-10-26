package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pagrus7/kaferry-lab/internal/identity"
)

// WritePhaseBundle reserves one new flat version3 bundle, retaining incomplete
// writes and never replacing an earlier attempt. A closed stream is not a
// mechanism observation or a passing verdict. Callers retain failed histories.
func WritePhaseBundle(dir string, m PhaseManifest, artifact ArtifactMetadata, events []PhaseEvent) (reserved bool, err error) {
	if m.SchemaVersion != PhaseSchemaVersion || m.CheckerVersion != PhaseCheckerVersion || len(events) == 0 || len(events) > maxEvents || events[len(events)-1].Kind != "run_finished" {
		return false, fmt.Errorf("version3 writer requires a supported manifest and a bounded closed event stream")
	}
	artifactRaw, err := json.Marshal(artifact)
	if err != nil || len(artifactRaw) > (4<<20)-1 {
		return false, fmt.Errorf("artifact metadata cannot be encoded within its bound: %v", err)
	}
	artifactRaw = append(artifactRaw, '\n')
	var stream bytes.Buffer
	for i, event := range events {
		raw, encodeErr := json.Marshal(event)
		if encodeErr != nil || len(raw) > maxEventBytes {
			return false, fmt.Errorf("version3 event %d cannot be encoded within its bound: %v", i+1, encodeErr)
		}
		if stream.Len()+len(raw)+1 > maxEventsBytes {
			return false, fmt.Errorf("version3 stream exceeds its byte bound")
		}
		var decoded PhaseEvent
		if err := strictJSON(raw, &decoded); err != nil {
			return false, err
		}
		stream.Write(raw)
		stream.WriteByte('\n')
	}
	m.Artifact = FileHash{Path: ArtifactName, SHA256: digest(artifactRaw), Bytes: identity.Int64(len(artifactRaw))}
	m.Events = FileHash{Path: EventsName, SHA256: digest(stream.Bytes()), Bytes: identity.Int64(stream.Len())}
	m.EventCount = identity.Int64(len(events))
	manifestRaw, err := json.Marshal(m)
	if err != nil || len(manifestRaw) > (1<<20)-1 {
		return false, fmt.Errorf("version3 manifest cannot be encoded within its bound: %v", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	var decoded PhaseManifest
	if err := strictJSON(manifestRaw, &decoded); err != nil {
		return false, err
	}
	completion := M2Completion{SchemaVersion: PhaseSchemaVersion, RunID: m.RunID, ManifestSHA256: digest(manifestRaw), EventsSHA256: m.Events.SHA256, EventCount: m.EventCount}
	completeRaw, err := json.Marshal(completion)
	if err != nil {
		return false, err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return false, fmt.Errorf("reserve version3 evidence bundle: %w", err)
	}
	reserved = true
	// Only our exclusively reserved directory is touched. A late persistence
	// error removes its completion marker while preserving the other bytes.
	defer func() {
		if err != nil {
			removeErr := os.Remove(filepath.Join(dir, CompleteName))
			if !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	for _, item := range []struct {
		name string
		raw  []byte
	}{{ArtifactName, artifactRaw}, {EventsName, stream.Bytes()}, {ManifestName, manifestRaw}, {CompleteName, append(completeRaw, '\n')}} {
		if err = writePhaseFile(dir, item.name, item.raw); err != nil {
			return reserved, err
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		return reserved, err
	}
	err = errors.Join(f.Sync(), f.Close())
	return reserved, err
}

// Keep each actual write/sync/close failure instead of replacing an earlier
// cause with later cleanup. This does not introduce a retry or another path.
func writePhaseFile(dir, name string, raw []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(raw)
	if n != len(raw) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, f.Sync(), f.Close())
}
