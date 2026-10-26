package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPhaseWriterOfflineRecheckAndCorruptionControl(t *testing.T) {
	// Given closed, independently specified phase history, when it is written
	// and rechecked using only four files, then missing mechanisms stay
	// Unsupported. A changed event byte cannot inherit the closed verdict.
	c := completePhaseControl()
	dir := filepath.Join(t.TempDir(), "attempt")
	reserved, err := WritePhaseBundle(dir, c.m, c.a, c.e)
	if !reserved || err != nil {
		t.Fatalf("write phase history: reserved=%v err=%v", reserved, err)
	}
	first, second := LoadAndCheck(dir), LoadAndCheck(dir)
	if first.Verdict != Unsupported || !phaseFinding(first, "phase_admission_complete") || !phaseFinding(second, "phase_admission_complete") || !reflect.DeepEqual(first, second) {
		t.Fatalf("closed phase history acquired another meaning: first=%+v second=%+v", first, second)
	}
	streamPath := filepath.Join(dir, EventsName)
	raw, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	// Appending valid whitespace preserves JSON interpretation but changes
	// the admitted stream bytes and count. The manifest must detect this.
	if err := os.WriteFile(streamPath, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	result := LoadAndCheck(dir)
	if result.Verdict != HarnessError || !phaseFinding(result, "events_integrity") || phaseFinding(result, "phase_admission_complete") {
		t.Fatalf("altered stream retained admission: %+v", result)
	}
}

func TestPhaseWriterCollisionPreservesPriorAttempt(t *testing.T) {
	// Given an existing attempt, when another writer targets its directory,
	// then it neither owns that attempt nor changes any recorded byte.
	c := completePhaseControl()
	dir := filepath.Join(t.TempDir(), "attempt")
	if reserved, err := WritePhaseBundle(dir, c.m, c.a, c.e); !reserved || err != nil {
		t.Fatalf("initial write: reserved=%v err=%v", reserved, err)
	}
	before := map[string][]byte{}
	for _, name := range []string{ManifestName, EventsName, ArtifactName, CompleteName} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = raw
	}
	c.m.RunID = "different-attempt"
	reserved, err := WritePhaseBundle(dir, c.m, c.a, c.e)
	if reserved || err == nil {
		t.Fatalf("collision took ownership: reserved=%v err=%v", reserved, err)
	}
	for name, expected := range before {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(raw, expected) {
			t.Fatalf("collision modified %s: %v", name, err)
		}
	}
}

func TestPhaseWriterRejectsOpenAndOversizedStreamsBeforeReservation(t *testing.T) {
	for _, name := range []string{"open-stream", "oversized-event"} {
		t.Run(name, func(t *testing.T) {
			// Given an unfinished or unbounded history, when a writer is
			// requested, then no bundle directory or completion is created.
			c := completePhaseControl()
			if name == "open-stream" {
				c.e = c.e[:len(c.e)-1]
			} else {
				c.e[len(c.e)-1].Finished.Proof = strings.Repeat("x", maxEventBytes)
			}
			dir := filepath.Join(t.TempDir(), "attempt")
			reserved, err := WritePhaseBundle(dir, c.m, c.a, c.e)
			if reserved || err == nil {
				t.Fatalf("invalid stream reserved output: reserved=%v err=%v", reserved, err)
			}
			if _, statErr := os.Lstat(dir); !os.IsNotExist(statErr) {
				t.Fatalf("rejected stream left a bundle directory: %v", statErr)
			}
		})
	}
}

func TestPhaseWriterRetainsViolationHistory(t *testing.T) {
	// Given an observed save beyond the published warmup, when the closed
	// attempt is retained, then serialization cannot replace the violation
	// with the phase preparation's usual Unsupported result.
	c := completePhaseControl()
	for _, event := range c.e {
		if event.Audit != nil && event.Audit.Observation.ID == "warmup-progress" {
			event.Audit.Observation.Saved[0].Source.Offset = 2
		}
	}
	dir := filepath.Join(t.TempDir(), "failed-attempt")
	if reserved, err := WritePhaseBundle(dir, c.m, c.a, c.e); !reserved || err != nil {
		t.Fatalf("retain violation: reserved=%v err=%v", reserved, err)
	}
	result := LoadAndCheck(dir)
	if result.Verdict != Violation || !phaseFinding(result, "saved_beyond_published") || result.ReleaseQualified {
		t.Fatalf("retained violation changed meaning: %+v", result)
	}
}
