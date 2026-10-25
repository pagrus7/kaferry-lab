package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func TestScenarioCLIRejectsUnownedAndUnsupportedPreparation(t *testing.T) {
	// Given an empty directory with no run-owned fixture or release.
	t.Chdir(t.TempDir())
	out := filepath.Join(t.TempDir(), "unreserved")
	for _, tc := range []struct {
		args   []string
		status int
	}{
		{[]string{"scenario"}, 2},
		{[]string{"scenario", "synthetic-only", "unknown", "PRESERVE", out}, 3},
		{[]string{"scenario", "synthetic-only", "healthy", "unknown", out}, 2},
		{[]string{"scenario", "../foreign", "healthy", "PRESERVE", out}, 2},
		{[]string{"scenario", "synthetic-absent", "healthy", "PRESERVE", out}, 2},
	} {
		// When preparation cannot identify a supported owned run, no subject starts.
		runCLI(t, tc.status, tc.args...)
		// Then even its output reservation has not been created.
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rejected scenario created output: %v", err)
		}
	}
}

func TestScenarioCLIRefusesExistingEvidenceDirectory(t *testing.T) {
	// Given a synthetic manifest and a directory containing retained evidence.
	t.Chdir(t.TempDir())
	id := "synthetic-owned"
	path, err := fixture.StatePath(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	state := fixture.State{RunID: id, Network: "kaferry-lab-" + id,
		Containers: []string{"kaferry-lab-" + id + "-source", "kaferry-lab-" + id + "-dest"}}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	marker := filepath.Join(out, "retained")
	if err := os.WriteFile(marker, []byte("first attempt"), 0600); err != nil {
		t.Fatal(err)
	}
	// When asked to reuse it, the CLI fails before release acquisition or faults.
	runCLI(t, 2, "scenario", id, "healthy", "PRESERVE", out)
	// Then the prior attempt is unchanged and no release directory exists.
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "first attempt" {
		t.Fatalf("prior evidence changed: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(out, "release")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("existing run reached release acquisition: %v", err)
	}
}
