package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func TestLinkLatencyInitialCreateUsesExactPrivateFileOwner(t *testing.T) {
	s, p, _, _, _ := driverLatencyCleanupFixture(t, true)
	info, err := os.Stat(p.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("native file owner unavailable")
	}
	if owner.Uid == 0 || info.Mode().Perm() != 0600 || p.ConfigFile.UID != owner.Uid || p.ConfigFile.GID != owner.Gid {
		t.Fatal("fixture lacks actual private nonroot file precondition")
	}
	args, err := linkLatencyCreateArguments(s, p, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	wantUser := strconv.FormatUint(uint64(owner.Uid), 10) + ":" + strconv.FormatUint(uint64(owner.Gid), 10)
	counts := map[string]int{}
	for i, arg := range args {
		counts[arg]++
		if arg == "--user" && (i+1 >= len(args) || args[i+1] != wantUser) {
			t.Fatal("initial user differs from actual file owner")
		}
		if arg == "--mount" && (i+1 >= len(args) || args[i+1] != "type=bind,src="+p.ConfigPath+",dst=/calibration.json,readonly") {
			t.Fatal("private startup bind changed")
		}
		if arg == "--cap-add" {
			t.Fatal("capability fallback introduced")
		}
	}
	if counts["--user"] != 1 || counts["--read-only"] != 1 || counts["ALL"] != 1 || counts["no-new-privileges"] != 1 {
		t.Fatal("initial user/security contract missing", args)
	}
	if counts["128m"] != 1 || counts["0.5"] != 1 || counts["64"] != 1 || counts["max-size=1m"] != 1 || counts["max-file=1"] != 1 {
		t.Fatal("resource/log budgets changed")
	}
}

func TestLinkLatencyStartupAuthorityRefusesBeforeFirstCreate(t *testing.T) {
	for _, kind := range []string{"missing-user", "root-user", "wrong-user", "wrong-owner", "wrong-mode-fact", "changed-mode", "changed-bytes", "changed-inode", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, p, _, _, _ := driverLatencyCleanupFixture(t, true)
			switch kind {
			case "missing-user":
				p.User = ""
			case "root-user":
				p.User = "0:0"
			case "wrong-user":
				p.User = "999999:999999"
			case "wrong-owner":
				p.ConfigFile.UID = 0
			case "wrong-mode-fact":
				p.ConfigFile.Mode = 0644
			case "changed-mode":
				if err := os.Chmod(p.ConfigPath, 0640); err != nil {
					t.Fatal(err)
				}
			case "changed-bytes":
				if err := os.WriteFile(p.ConfigPath, []byte("[{}]"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-inode":
				if err := os.Rename(p.ConfigPath, p.ConfigPath+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p.ConfigPath, []byte("[]"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(p.ConfigPath, p.ConfigPath+".owned-link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(p.ConfigPath, p.ConfigPath+".preserved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.ConfigPath+".preserved", p.ConfigPath); err != nil {
					t.Fatal(err)
				}
			}
			if args, err := linkLatencyCreateArguments(s, p, "linux/amd64"); err == nil || args != nil {
				t.Fatal("invalid startup authority produced a create command")
			}
		})
	}
}

func TestLinkLatencyUserAndSecurityMismatchNeverLogsOrRemoves(t *testing.T) {
	for _, kind := range []string{"missing-user", "root-user", "wrong-user", "cap-add", "missing-cap-drop", "missing-no-new-privileges"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, raw, _ := driverLatencyCleanupFixture(t, true)
			var f map[string]any
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			config, host := f["Config"].(map[string]any), f["HostConfig"].(map[string]any)
			switch kind {
			case "missing-user":
				delete(config, "User")
			case "root-user":
				config["User"] = "0:0"
			case "wrong-user":
				config["User"] = "999999:999999"
			case "cap-add":
				host["CapAdd"] = []string{"DAC_OVERRIDE"}
			case "missing-cap-drop":
				host["CapDrop"] = []string{}
			case "missing-no-new-privileges":
				host["SecurityOpt"] = []string{}
			}
			bad, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			got, err := cleanupLinkCalibrationLatency(context.Background(), s, func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if args[0] != "container" || args[1] != "inspect" {
					t.Fatal("unproved user/security authorized logs or removal", args)
				}
				return bad, nil
			})
			if err == nil || got.Resolved || got.Removed || got.LogsRetained || calls != 1 {
				t.Fatal("unproved execution user/security admitted cleanup")
			}
		})
	}
}

func TestLinkLatencyLogFailureStopsChildAndLostCleanup(t *testing.T) {
	for _, route := range []string{"child", "lost-child"} {
		for _, kind := range []string{"denial", "overflow", "sink", "owner-sink"} {
			t.Run(route+"/"+kind, func(t *testing.T) {
				s, p, id, raw, _ := driverLatencyCleanupFixture(t, true)
				root := filepath.Join(".cache", "fixtures-private", s.RunID+"-links")
				if kind == "owner-sink" {
					if err := os.WriteFile(filepath.Join(root, "latency-cleanup-owner.json"), []byte("preserved prior ownership receipt"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				calls, logs, removed := 0, 0, 0
				original := []byte("PRIVATE exact synthetic startup/log refusal\x00\xff")
				fake := func(_ context.Context, args ...string) ([]byte, error) {
					calls++
					switch args[1] {
					case "inspect":
						return raw, nil
					case "logs":
						logs++
						if !reflect.DeepEqual(args, []string{"container", "logs", "--tail", "64", "--timestamps", id}) {
							t.Fatal("log target/bound changed", args)
						}
						if kind == "denial" {
							return original, errors.Join(syscall.EPERM, errors.New("PRIVATE-first-log-refusal"))
						}
						if kind == "overflow" {
							return bytes.Repeat([]byte("x"), (64<<10)+1), nil
						}
						if kind == "sink" {
							ops, err := filepath.Glob(filepath.Join(root, "operation-*"))
							if err != nil || len(ops) != 1 {
								t.Fatal("operation reservation missing")
							}
							if err = os.Rename(ops[0], ops[0]+"-preserved"); err != nil {
								t.Fatal(err)
							}
							if err = os.WriteFile(ops[0], []byte("synthetic selected-sink obstruction"), 0600); err != nil {
								t.Fatal(err)
							}
							return original, nil
						}
						t.Fatal("owner sink failure reached log command")
					case "rm":
						removed++
						t.Fatal("log/receipt failure followed by removal")
					default:
						t.Fatal("unexpected Docker route", args)
					}
					return nil, nil
				}
				if route == "child" {
					wrapped, err := fixture.LinkExecutor(s, fake)
					if err != nil {
						t.Fatal(err)
					}
					_, _, captured, err := cleanupLinkCalibrationLatencyContainer(context.Background(), s, p, id, wrapped)
					if err == nil || captured {
						t.Fatal("incomplete child log cleanup admitted")
					}
				} else {
					got, err := cleanupLinkCalibrationLatency(context.Background(), s, fake)
					if err == nil || got.Resolved || got.Removed || got.LogsRetained {
						t.Fatal("incomplete lost-child log cleanup admitted")
					}
				}
				want := 2
				if kind == "owner-sink" {
					want = 1
				}
				if calls != want || removed != 0 || logs != want-1 {
					t.Fatal("failure path issued extra commands")
				}
				before, err := os.ReadFile(filepath.Join(root, "STOPPED.json"))
				if err != nil {
					t.Fatal("evidence/log refusal did not stop facility")
				}
				if _, err = cleanupLinkCalibrationLatency(context.Background(), s, fake); err == nil || calls != want {
					t.Fatal("stopped cleanup retried Docker")
				}
				after, err := os.ReadFile(filepath.Join(root, "STOPPED.json"))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("stop marker changed after refusal")
				}
				if kind == "denial" || kind == "overflow" {
					found := false
					err = filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
						if e != nil {
							return e
						}
						if d.IsDir() {
							return nil
						}
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						var rec struct {
							Combined, CauseText   []byte
							CombinedComplete      bool
							ReportedCauseBytes    int
							ObservedCombinedBytes int64
						}
						if json.Unmarshal(b, &rec) == nil {
							if kind == "denial" && bytes.Equal(rec.Combined, original) && bytes.Contains(rec.CauseText, []byte("PRIVATE-first-log-refusal")) {
								found = true
							}
							if kind == "overflow" && len(rec.Combined) == 64<<10 && !rec.CombinedComplete && rec.ObservedCombinedBytes == (64<<10)+1 {
								found = true
							}
						}
						return nil
					})
					if err != nil || !found {
						t.Fatal("available first log notice/prefix lost", err)
					}
				}
			})
		}
	}
}

func TestLinkLatencyStartupExpectedBytesAndRootOwnerRefuse(t *testing.T) {
	directory, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Chdir(directory)
	path, err := filepath.Abs("startup.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if _, err = readLinkLatencyStartup(path, []byte("[]")); err == nil {
			t.Fatal("root-owned startup selected nonroot execution")
		}
		return
	}
	if _, err = readLinkLatencyStartup(path, []byte("[{}]")); err == nil {
		t.Fatal("changed generated startup bytes admitted")
	}
	got, err := readLinkLatencyStartup(path, []byte("[]"))
	if err != nil || got.UID == 0 || !strings.Contains(got.user(), ":") {
		t.Fatal("actual private owner unavailable", err)
	}
}
