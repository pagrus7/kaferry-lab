package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLinkContainerLogOriginalSuccessRetainedBeforeReturn(t *testing.T) {
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	linkTestDirectory(t, s)
	id := strings.Repeat("e", 64)
	original := []byte("PRIVATE synthetic application config open failed\x00\xff\n")
	args := []string{"container", "logs", "--tail", "64", "--timestamps", id}
	wrapped, err := LinkExecutor(s, func(_ context.Context, got ...string) ([]byte, error) {
		if !reflect.DeepEqual(got, args) {
			t.Fatal(got)
		}
		return original, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapped(context.Background(), args...)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("log command result changed", err)
	}
	paths, err := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "operation-*", "docker-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range paths {
		body, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var receipt struct {
			PrivateReadbackKind, CombinedSHA256, SemanticAdmission, Stream string
			Combined                                                       []byte
			Argv                                                           []string
			CombinedComplete, CommandSucceeded                             bool
			CapturedCombinedBytes                                          int
			ObservedCombinedBytes                                          int64
		}
		if json.Unmarshal(body, &receipt) == nil && receipt.PrivateReadbackKind == "linked-docker-container-log-readback" && bytes.Equal(receipt.Combined, original) && receipt.CombinedSHA256 == linkDigest(original) && receipt.CapturedCombinedBytes == len(original) && receipt.ObservedCombinedBytes == int64(len(original)) && receipt.CombinedComplete && receipt.CommandSucceeded && receipt.SemanticAdmission == "not-observed-by-executor" && receipt.Stream == "combined stdout/stderr" && reflect.DeepEqual(receipt.Argv, append([]string{"docker"}, args...)) {
			found = true
		}
	}
	if !found {
		t.Fatal("successful log original or bounded success facts discarded")
	}
}

func TestStopLinkEvidenceRequiresExistingPrivateAuthority(t *testing.T) {
	for _, kind := range []string{"valid", "invalid-state", "missing-root", "missing-marker", "wrong-run", "missing-class", "wrong-mode", "symlink-marker"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := linkTestState(true)
			if kind != "missing-root" {
				if err := reserveLinkEvidence(s.RunID); err != nil {
					t.Fatal(err)
				}
			}
			root := linkPrivateDirectory(s.RunID)
			marker := filepath.Join(root, "PRIVATE.json")
			switch kind {
			case "invalid-state":
				s.Image = "foreign"
			case "missing-marker":
				if err := os.Rename(marker, marker+".preserved"); err != nil {
					t.Fatal(err)
				}
			case "wrong-run":
				if err := os.WriteFile(marker, []byte(`{"RunID":"other","Classification":"PRIVATE RAW EVIDENCE"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-class":
				if err := os.WriteFile(marker, []byte(`{"RunID":"test"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-mode":
				if err := os.Chmod(marker, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-marker":
				if err := os.Rename(marker, marker+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("PRIVATE.json.preserved", marker); err != nil {
					t.Fatal(err)
				}
			}
			err := StopLinkEvidence(s, "synthetic selected receipt incomplete")
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				before, e := os.ReadFile(filepath.Join(root, "STOPPED.json"))
				if e != nil {
					t.Fatal(e)
				}
				if err = StopLinkEvidence(s, "later event"); err != nil {
					t.Fatal(err)
				}
				after, e := os.ReadFile(filepath.Join(root, "STOPPED.json"))
				if e != nil || !bytes.Equal(before, after) {
					t.Fatal("existing stop was replaced/cleared")
				}
			} else {
				if err == nil {
					t.Fatal("missing/invalid authority admitted stop write")
				}
				if _, e := os.Lstat(filepath.Join(root, "STOPPED.json")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("invalid authority created marker", e)
				}
				if kind == "missing-root" {
					if _, e := os.Lstat(root); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("missing private root synthesized")
					}
				}
			}
		})
	}
}
