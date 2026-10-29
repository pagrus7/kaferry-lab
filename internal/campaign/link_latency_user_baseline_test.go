package campaign

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

func TestLinkCalibrationExecutorConstructorCauseUsesPrimarySink(t *testing.T) {
	s, _, _, _, _ := driverLatencyCleanupFixture(t, true)
	_, sink := driverProofFiles(t) // selected before the failed constructor
	root := filepath.Join(".cache", "fixtures-private", s.RunID+"-links")
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cleanupLinkCalibrationLatency(context.Background(), s, nil)
	if err == nil || got.Attempted || got.Resolved || got.Removed || got.LogsRetained || strings.Contains(err.Error(), "linked Docker executor missing") {
		t.Fatal("constructor failure claimed work, success or exposed its private cause", got, err)
	}
	if !retainLinkCalibrationError(sink, []string{"latency_resource_cleanup", s.RunID}, err) {
		t.Fatal("existing primary sink lost constructor failure")
	}
	if err = closeLinkCalibrationSink(sink); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(sink.Name())
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Errors []struct {
			Cause    []byte
			Complete bool
		}
	}
	if json.Unmarshal(body, &receipt) != nil || len(receipt.Errors) != 1 || !receipt.Errors[0].Complete || string(receipt.Errors[0].Cause) != "linked Docker executor missing" {
		t.Fatal("exact constructor cause was not retained once in the preallocated primary sink")
	}
	after, err := os.ReadDir(root)
	if err != nil || len(after) != len(before) {
		t.Fatal("constructor failure tried another fixture operation or notice sink", err)
	}
	for i := range before {
		if before[i].Name() != after[i].Name() {
			t.Fatal("constructor failure changed fixture evidence routes")
		}
	}
}

// These controls deliberately use only APIs present before the repair, so the
// same control source can demonstrate the frozen baseline's missing guards.
func TestLinkLatencyRejectsUnboundExecutionUser(t *testing.T) {
	for _, user := range []string{"missing", "", "0:0", "root", "999999:999999"} {
		t.Run(user, func(t *testing.T) {
			s, p, id, raw, _ := driverLatencyCleanupFixture(t, true)
			var facts map[string]any
			if err := json.Unmarshal(raw, &facts); err != nil {
				t.Fatal(err)
			}
			config := facts["Config"].(map[string]any)
			if user == "missing" {
				delete(config, "User")
			} else {
				config["User"] = user
			}
			bad, err := json.Marshal(facts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = validateLinkCalibrationLatencyContainer(bad, s, p, id); err == nil {
				t.Fatal("unbound/root execution user admitted before start/removal")
			}
		})
	}
}

func retainedLatencyLog(root string, want []byte, id string) (bool, error) {
	found, files := false, 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files++
		if files > 128 {
			return errors.New("private log control file bound exceeded")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(body) > 256<<10 {
			return errors.New("private log control receipt bound exceeded")
		}
		var record struct {
			PrivateReadbackKind, Stream, CombinedSHA256, SemanticAdmission string
			Argv                                                           []string
			Combined                                                       []byte
			CapturedCombinedBytes                                          int
			ObservedCombinedBytes                                          int64
			CombinedComplete, CommandSucceeded                             bool
		}
		if json.Unmarshal(body, &record) == nil && record.PrivateReadbackKind == "linked-docker-container-log-readback" && reflect.DeepEqual(record.Argv, []string{"docker", "container", "logs", "--tail", "64", "--timestamps", id}) && record.Stream == "combined stdout/stderr" && record.CommandSucceeded && record.CombinedComplete && record.SemanticAdmission == "not-observed-by-executor" && record.CombinedSHA256 == processDigest(want) && record.CapturedCombinedBytes == len(want) && record.ObservedCombinedBytes == int64(len(want)) && bytes.Equal(record.Combined, want) {
			found = true
		}
		return nil
	})
	return found, err
}

func TestLinkLatencyRetainsStartupLogsBeforeRemoval(t *testing.T) {
	s, _, id, raw, _ := driverLatencyCleanupFixture(t, true)
	log := []byte("PRIVATE synthetic application startup error: open /calibration.json: denied\x00\xff\n")
	var actions []string
	logs := false
	run := func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] != "container" {
			t.Fatal("foreign Docker route", args)
		}
		actions = append(actions, args[1])
		switch args[1] {
		case "inspect":
			if args[2] != id {
				t.Fatal("wrong ownership target")
			}
			return raw, nil
		case "logs":
			if !reflect.DeepEqual(args, []string{"container", "logs", "--tail", "64", "--timestamps", id}) {
				t.Fatal("unbounded/foreign logs", args)
			}
			logs = true
			return log, nil
		case "rm":
			if !logs {
				t.Fatal("latency container removed before startup logs were requested")
			}
			found, err := retainedLatencyLog(filepath.Join(".cache", "fixtures-private", s.RunID+"-links"), log, id)
			if err != nil || !found {
				t.Fatal("latency container removed before exact log success bytes/metadata were retained", err)
			}
			if !reflect.DeepEqual(args, []string{"container", "rm", "-f", id}) {
				t.Fatal("removal target changed")
			}
			return nil, nil
		default:
			t.Fatal("unexpected Docker route", args)
		}
		return nil, nil
	}
	got, err := cleanupLinkCalibrationLatency(context.Background(), s, run)
	if err != nil || !got.Resolved || !got.Removed || got.ContainerID != id || !reflect.DeepEqual(actions, []string{"inspect", "logs", "rm"}) {
		t.Fatal("healthy owned log custody/removal failed", got, err)
	}
}
