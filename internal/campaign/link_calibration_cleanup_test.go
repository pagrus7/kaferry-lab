package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func driverLatencyCleanupFixture(t *testing.T, withID bool) (fixture.State, linkCalibrationLatencyPlan, string, []byte, string) {
	t.Helper()
	return driverLatencyCleanupFixtureForPlatform(t, withID, "linux/amd64")
}
func driverLatencyCleanupFixtureForPlatform(t *testing.T, withID bool, platform string) (fixture.State, linkCalibrationLatencyPlan, string, []byte, string) {
	t.Helper()
	s := latencyNoticeState(t)
	if os.Geteuid() == 0 {
		t.Skip("latency startup ownership requires a nonroot file owner")
	}
	s.DockerPlatform = platform
	s.Proxy.ImageID = "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa"
	if platform == "linux/arm64" {
		s.Proxy.Image = "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"
		s.Proxy.ImageID = "sha256:b0e75e62fcf0abd5c8aea482fd4aa00ff5052fd24d8d0b4103c94668a95b8c99"
	}
	s.Proxy.ContainerID = strings.Repeat("8", 64)
	s.Proxy.NetworkID = strings.Repeat("9", 64)
	s.Proxy.BrokerIDs = []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	s.Proxy.BrokerImageID = "sha256:" + strings.Repeat("3", 64)
	name := s.Proxy.Container + "-latency-0123456789abcdef"
	dir := filepath.Join(".cache", "fixtures", s.RunID+"-links", name)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	config, e := filepath.Abs(filepath.Join(dir, "startup.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(config, []byte("[]"), 0600); e != nil {
		t.Fatal(e)
	}
	configIdentity, e := readLinkLatencyStartup(config, []byte("[]"))
	if e != nil {
		t.Fatal(e)
	}
	p := linkCalibrationLatencyPlan{RunID: s.RunID, Name: name, Role: "latency-calibration", Image: s.Proxy.Image, ExpectedImageID: s.Proxy.ImageID, Network: "host", API: "127.0.0.1:18475", Endpoint: "127.0.0.1:18476", Upstream: "127.0.0.1:18477", ConfigPath: config, User: configIdentity.user(), ConfigFile: configIdentity, Command: []string{"-host=127.0.0.1", "-port=18475", "-config=/calibration.json"}, MemoryBytes: 128 << 20, NanoCPUs: 500000000, PIDs: 64, LogBytes: 1 << 20}
	id := strings.Repeat("4", 64)
	var rows []byte
	appendRow := func(kind string, fact any) {
		b, e := json.Marshal(struct {
			Kind      string
			ElapsedNS int64
			Facts     any
		}{kind, 1, fact})
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, append(b, '\n')...)
	}
	appendRow("resource_plan", p)
	appendRow("create_intent", struct{ Name string }{name})
	if withID {
		appendRow("container_ownership", struct{ ID, Name, ImageID, User string }{id, name, s.Proxy.ImageID, p.User})
	}
	// A proved active toxic is precisely the state t.Cleanup can fail to restore.
	appendRow("api", struct{ Method, Path string }{"POST", "/proxies/echo/toxics"})
	path := filepath.Join(dir, "observations.jsonl")
	if e = os.WriteFile(path, rows, 0600); e != nil {
		t.Fatal(e)
	}
	facts := map[string]any{
		"ID": id, "Name": "/" + name, "Image": s.Proxy.ImageID,
		"Config":     map[string]any{"Image": s.Proxy.Image, "User": p.User, "Labels": map[string]string{brokerOwnerLabel: s.RunID, "io.kaferry-lab.role": "latency-calibration"}, "Cmd": p.Command, "Entrypoint": []string{"/toxiproxy"}},
		"State":      map[string]bool{"Running": true, "Paused": false},
		"HostConfig": map[string]any{"NetworkMode": "host", "CapAdd": []string{}, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges"}, "Memory": 128 << 20, "NanoCPUs": 500000000, "PidsLimit": 64, "Privileged": false, "ReadonlyRootfs": true, "PortBindings": map[string]any{}, "LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1m", "max-file": "1"}}},
		"Mounts":     []map[string]any{{"Type": "bind", "Source": config, "Destination": "/calibration.json", "RW": false}},
	}
	raw, e := json.Marshal(facts)
	if e != nil {
		t.Fatal(e)
	}
	return s, p, id, raw, path
}
func TestLinkCalibrationRestoresExactLatencyContainerAfterLostTestCleanup(t *testing.T) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		t.Run(platform, func(t *testing.T) {
			for _, withID := range []bool{false, true} {
				t.Run(map[bool]string{false: "partial-create-no-ID", true: "toxic-active-known-ID"}[withID], func(t *testing.T) {
					s, p, id, raw, _ := driverLatencyCleanupFixtureForPlatform(t, withID, platform)
					var calls [][]string
					run := func(_ context.Context, args ...string) ([]byte, error) {
						calls = append(calls, append([]string(nil), args...))
						if args[1] == "inspect" {
							target := p.Name
							if withID {
								target = id
							}
							if args[2] != target {
								t.Fatal("cleanup searched a different resource")
							}
							return raw, nil
						}
						if len(args) == 6 && args[0] == "container" && args[1] == "logs" && args[2] == "--tail" && args[3] == "64" && args[4] == "--timestamps" && args[5] == id {
							return []byte("synthetic startup log"), nil
						}
						if len(args) != 4 || args[0] != "container" || args[1] != "rm" || args[2] != "-f" || args[3] != id {
							t.Fatal("cleanup removed by name/label or changed route")
						}
						// The exact immutable ownership evidence must exist BEFORE destruction.
						b, e := os.ReadFile(filepath.Join(".cache", "fixtures-private", s.RunID+"-links", "latency-cleanup-owner.json"))
						if e != nil || !bytes.Contains(b, []byte(id)) {
							t.Fatal("resource removed before ownership evidence")
						}
						return nil, nil
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					got, err := cleanupLinkCalibrationLatency(ctx, s, run)
					if err != nil || !got.Resolved || !got.Removed || !got.JournalComplete || got.ContainerID != id || !got.LogsRetained || len(calls) != 3 {
						t.Fatal("available exact cleanup did not restore killed-test resource", err)
					}
				})
			}
		})
	}
}
func TestLinkCalibrationLatencyCleanupHonorsStopAndExactAbsence(t *testing.T) {
	for _, kind := range []string{"STOPPED", "exact-absence", "exact-leading-LF-absence", "permission-mixed-absence", "leading-LF-permission-mixed-absence"} {
		t.Run(kind, func(t *testing.T) {
			s, p, _, _, _ := driverLatencyCleanupFixture(t, false)
			if kind == "STOPPED" {
				if e := os.WriteFile(filepath.Join(".cache", "fixtures-private", s.RunID+"-links", "STOPPED.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				raw := []byte("Error response from daemon: No such object: " + p.Name + "\n")
				if kind == "exact-leading-LF-absence" || kind == "leading-LF-permission-mixed-absence" {
					raw = []byte("\nError response from daemon: No such container: " + p.Name + "\n")
				}
				if kind == "permission-mixed-absence" || kind == "leading-LF-permission-mixed-absence" {
					return raw, errors.Join(syscall.EPERM, errors.New("unknown-PRIVATE-refusal"))
				}
				return raw, errors.New("exit1")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := cleanupLinkCalibrationLatency(ctx, s, run)
			if kind == "exact-absence" || kind == "exact-leading-LF-absence" {
				if err != nil || !got.Resolved || !got.Absent || calls != 1 {
					t.Fatal("exact retained absence lost idempotence")
				}
			} else {
				if err == nil || got.Resolved || got.Removed || (kind == "STOPPED" && calls != 0) || (kind != "STOPPED" && calls != 1) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("denial bypassed or exact reason leaked")
				}
				if kind == "permission-mixed-absence" || kind == "leading-LF-permission-mixed-absence" {
					want := errors.Join(syscall.EPERM, errors.New("unknown-PRIVATE-refusal")).Error()
					found, files := false, 0
					root := filepath.Join(".cache", "fixtures-private", s.RunID+"-links")
					if walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
						if e != nil {
							return e
						}
						if d.IsDir() {
							return nil
						}
						files++
						if files > 64 {
							return errors.New("private control file bound")
						}
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						if len(b) > 256<<10 {
							return errors.New("private control receipt bound")
						}
						var receipt struct{ CauseText []byte }
						if json.Unmarshal(b, &receipt) == nil && string(receipt.CauseText) == want {
							found = true
						}
						return nil
					}); walkErr != nil || !found {
						t.Fatal("original mixed permission cause lost before safe wrapper")
					}
				}

			}
		})
	}
}
func TestLinkCalibrationLatencyOwnershipMismatchNeverRemoves(t *testing.T) {
	for _, field := range []string{"run", "role", "image", "id", "command", "mount"} {
		t.Run(field, func(t *testing.T) {
			s, _, _, raw, _ := driverLatencyCleanupFixture(t, true)
			var object map[string]any
			if e := json.Unmarshal(raw, &object); e != nil {
				t.Fatal(e)
			}
			config := object["Config"].(map[string]any)
			switch field {
			case "run":
				config["Labels"].(map[string]any)[brokerOwnerLabel] = "PRIVATE-other-run"
			case "role":
				config["Labels"].(map[string]any)["io.kaferry-lab.role"] = "PRIVATE-other-role"
			case "image":
				object["Image"] = "sha256:" + strings.Repeat("6", 64)
			case "id":
				object["ID"] = strings.Repeat("5", 64)
			case "command":
				config["Cmd"] = []string{"PRIVATE-command"}
			case "mount":
				object["Mounts"].([]any)[0].(map[string]any)["RW"] = true
			}
			bad, e := json.Marshal(object)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if args[1] != "inspect" {
					t.Fatal("mismatched ownership mutated Docker")
				}
				return bad, nil
			}
			got, err := cleanupLinkCalibrationLatency(context.Background(), s, run)
			if err == nil || got.Removed || got.Resolved || calls != 1 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("mismatch admitted/leaked cleanup")
			}
			retained, ok := err.(*linkCalibrationCleanupError)
			if !ok || !retained.retentionComplete {
				t.Fatal("original inspect response not retained")
			}
			b, e := os.ReadFile(retained.reference)
			if e != nil {
				t.Fatal(e)
			}
			var receipt struct{ Notice []byte }
			if e = json.Unmarshal(b, &receipt); e != nil || !bytes.Equal(receipt.Notice, bad) {
				t.Fatal("exact rejected inspect bytes lost")
			}
		})
	}
}
func TestLinkCalibrationLatencyJournalAuthorityAndTail(t *testing.T) {
	for _, kind := range []string{"tail", "duplicate-plan", "conflicting-ID", "missing-plan", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			s, _, id, raw, path := driverLatencyCleanupFixture(t, true)
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "tail":
				original = append(original, []byte(`{"Kind":"exchange","Facts":"PRIVATE-partial`)...)
			case "duplicate-plan":
				first := bytes.Split(original, []byte{'\n'})[0]
				original = append(original, append(first, '\n')...)
			case "conflicting-ID":
				row, _ := json.Marshal(struct {
					Kind  string
					Facts any
				}{"container_ownership", struct{ ID, Name, ImageID string }{strings.Repeat("5", 64), s.Proxy.Container + "-latency-0123456789abcdef", s.Proxy.ImageID}})
				original = append(original, append(row, '\n')...)
			case "missing-plan":
				original = []byte("{}\n")
			case "oversize":
				original = bytes.Repeat([]byte{'x'}, (128<<10)+1)
			}
			if e = os.WriteFile(path, original, 0600); e != nil {
				t.Fatal(e)
			}
			calls := 0
			run := func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if args[1] == "inspect" {
					return raw, nil
				}
				if len(args) == 6 && args[0] == "container" && args[1] == "logs" && args[5] == id {
					return []byte("synthetic startup log"), nil
				}
				if args[3] != id {
					t.Fatal("wrong cleanup ID")
				}
				return nil, nil
			}
			got, err := cleanupLinkCalibrationLatency(context.Background(), s, run)
			if kind == "tail" {
				if err != nil || !got.Resolved || !got.Removed || !got.LogsRetained || got.JournalComplete || calls != 3 {
					t.Fatal("retained partial observation prevented safe exact restoration or became complete", err)
				}
			} else if err == nil || got.Resolved || calls != 0 {
				t.Fatal("missing/ambiguous journal authorized Docker")
			}
		})
	}
}
func TestLinkCalibrationLatencyOwnerReceiptFailureStopsBeforeRemoval(t *testing.T) {
	s, _, _, raw, _ := driverLatencyCleanupFixture(t, true)
	if e := os.WriteFile(filepath.Join(".cache", "fixtures-private", s.RunID+"-links", "latency-cleanup-owner.json"), []byte("prior-owned-receipt"), 0600); e != nil {
		t.Fatal(e)
	}
	calls := 0
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if args[1] != "inspect" {
			t.Fatal("owner evidence failure followed by mutation")
		}
		return raw, nil
	}
	got, err := cleanupLinkCalibrationLatency(context.Background(), s, run)
	if err == nil || got.Resolved || calls != 1 {
		t.Fatal("ownership evidence failure admitted removal")
	}
}

func TestLinkCalibrationCleanupRejectsCrossPlatformProxyAuthority(t *testing.T) {
	// Given an ARM64 fixture, When state, journal or inspected proxy identity is
	// borrowed from AMD64, Then no removal can be authorized by that evidence.
	for _, kind := range []string{"engine", "state-reference", "state-config", "journal-reference", "container-reference"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, raw, path := driverLatencyCleanupFixtureForPlatform(t, true, "linux/arm64")
			expectedCalls := 0
			switch kind {
			case "engine":
				s.DockerPlatform = "linux/arm64/v8"
			case "state-reference":
				s.Proxy.Image = fixture.ProxyImage
			case "state-config":
				s.Proxy.ImageID = "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa"
			case "journal-reference":
				body, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				body = bytes.ReplaceAll(body, []byte(s.Proxy.Image), []byte(fixture.ProxyImage))
				if e = os.WriteFile(path, body, 0600); e != nil {
					t.Fatal(e)
				}
			case "container-reference":
				var f map[string]any
				if e := json.Unmarshal(raw, &f); e != nil {
					t.Fatal(e)
				}
				f["Config"].(map[string]any)["Image"] = fixture.ProxyImage
				var e error
				raw, e = json.Marshal(f)
				if e != nil {
					t.Fatal(e)
				}
				expectedCalls = 1
			}
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			got, err := cleanupLinkCalibrationLatency(context.Background(), s, func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if args[0] != "container" || args[1] != "inspect" {
					t.Fatal("cross-platform cleanup mutation", args)
				}
				return raw, nil
			})
			if err == nil || got.Removed || got.Resolved || calls != expectedCalls {
				t.Fatalf("cross-platform authority admitted: calls=%d result=%+v err=%v", calls, got, err)
			}
			retained, ok := err.(*linkCalibrationCleanupError)
			// Invalid engine/reference state cannot authorize even the fixture's private
			// retention route. Keep it explicitly incomplete; never normalize authority
			// or switch sinks to turn this refusal into evidence of a completed notice.
			complete := kind != "engine" && kind != "state-reference"
			if !ok || retained.retentionComplete != complete {
				t.Fatal("invalid authority or incomplete notice became complete", err)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(original, after) {
				t.Fatal("original journal changed after refusal", e)
			}
		})
	}
}
