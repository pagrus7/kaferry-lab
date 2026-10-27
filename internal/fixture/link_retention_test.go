package fixture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func linkRetentionState(t *testing.T) State {
	t.Helper()
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	linkTestDirectory(t, s)
	return s
}
func readLinkPrivateFailure(t *testing.T, err error) (string, []byte) {
	t.Helper()
	var failure *linkDockerFailure
	if !errors.As(err, &failure) || failure.PersistenceFailed || failure.Reference == "" {
		t.Fatalf("missing complete private failure receipt: %v", err)
	}
	body, e := os.ReadFile(failure.Reference)
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(failure.Reference)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private receipt permissions: %v %v", info, e)
	}
	return failure.Reference, body
}
func assertLinkPublicWithholds(t *testing.T, s State, secrets ...[]byte) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(linkDirectory(s.RunID), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(body, secret) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(secret))) {
				t.Fatalf("raw failure/log bytes entered public receipt %s", file)
			}
		}
	}
}

func TestLinkedDockerRetainsExactPrivateFailureAndStopsAllRoutes(t *testing.T) {
	// Given failed fixed Docker actions containing unsafe Env and notice text,
	// when retained, then exact bounded bytes/argv/cause stay private and neither
	// another target/command nor a fresh wrapper can retry the Docker facility.
	for _, tc := range []struct {
		name  string
		args  []string
		cause error
	}{
		{"launch access", []string{"info", "--format", "{{.OSType}}/{{.Architecture}}"}, syscall.EACCES},
		{"launch operation", []string{"run", "-d", "--name", "kaferry-lab-test-links", ProxyImage}, syscall.EPERM},
		{"inspect unknown", []string{"container", "inspect", "kaferry-lab-test-links", "--format", "{{json .}}"}, errors.New("unknown control failure")},
		{"image", []string{"image", "inspect", ProxyImage, "--format", "{{.Id}}"}, syscall.EACCES},
		{"logs", []string{"logs", "--tail", "200", strings.Repeat("c", 64)}, syscall.EPERM},
		{"remove", []string{"container", "rm", "-f", strings.Repeat("c", 64)}, errors.New("unknown removal failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := linkRetentionState(t)
			notice := []byte(`{"Config":{"Env":["PRIVATE_ENV=retain-only-in-private"]},"notice":"exact failed action notice"}` + "\n")
			cause := errors.Join(tc.cause, errors.New("PRIVATE_CAUSE=unreviewed-secret"))
			calls := 0
			run, err := LinkExecutor(s, func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				if !reflect.DeepEqual(args, tc.args) {
					t.Fatalf("action changed: %v", args)
				}
				if _, e := os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); e != nil {
					t.Fatal("acted before durable stop reservation", e)
				}
				return notice, cause
			})
			if err != nil {
				t.Fatal(err)
			}
			out, err := run(context.Background(), tc.args...)
			if err == nil || out != nil || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatalf("unsafe public failure: %q %v", out, err)
			}
			_, body := readLinkPrivateFailure(t, err)
			var receipt struct {
				Argv                            []string
				Combined, CauseText             []byte
				CombinedComplete, CauseComplete bool
				Cause                           linkDockerCause
			}
			if e := json.Unmarshal(body, &receipt); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(receipt.Argv, append([]string{"docker"}, tc.args...)) || !bytes.Equal(receipt.Combined, notice) || string(receipt.CauseText) != cause.Error() || !receipt.CombinedComplete || !receipt.CauseComplete {
				t.Fatal("exact failure action/notice/cause lost")
			}
			if tc.cause == syscall.EACCES || tc.cause == syscall.EPERM {
				if receipt.Cause.Errno == nil || *receipt.Cause.Errno != uint64(tc.cause.(syscall.Errno)) {
					t.Fatal("typed OS cause lost")
				}
			}
			assertLinkPublicWithholds(t, s, notice, []byte(cause.Error()), []byte("PRIVATE_ENV"), []byte("PRIVATE_CAUSE"))
			if _, e := run(context.Background(), "network", "rm", strings.Repeat("d", 64)); e == nil || calls != 1 {
				t.Fatal("failed facility used another command/target", calls, e)
			}
			if _, e := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) {
				t.Fatal("fresh wrapper reached Docker")
				return nil, nil
			}); e == nil {
				t.Fatal("persistent stop bypassed by fresh wrapper")
			}
		})
	}
}

func TestLinkedSuccessfulInspectDiscardsEnvironmentRatherThanRetainingRawSuccess(t *testing.T) {
	// Given successful inspect responses with an unrelated secret Env, when the
	// selected identity is checked, then neither public nor private success
	// receipts retain its raw JSON/Env; callers still receive enough to validate.
	s := linkRetentionState(t)
	run, err := LinkExecutor(s, linkTestDocker(t, s, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inspectLinkResources(context.Background(), s, run); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(".cache", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		body, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if bytes.Contains(body, []byte("never-retain-this-value")) || bytes.Contains(body, []byte("UNRELATED_SECRET")) {
			t.Fatalf("successful inspect Env retained: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful action left facility stopped", err)
	}
}

func TestLinkedPreflightReservesEvidenceBeforeDockerInfo(t *testing.T) {
	// Given a fresh linked run, when the very first Docker info action fails,
	// then its exact failure already has a run-bound private evidence location.
	t.Chdir(t.TempDir())
	calls := 0
	notice := []byte("synthetic first-info control notice\n")
	_, err := up(context.Background(), "test", func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if args[0] != "info" {
			t.Fatal("unexpected post-failure action", args)
		}
		if _, e := os.Stat(filepath.Join(linkPrivateDirectory("test"), "PRIVATE.json")); e != nil {
			t.Fatal("info preceded private reservation", e)
		}
		return notice, syscall.EACCES
	}, true, func(context.Context, string, string, string, []byte) (int, []byte, error) {
		t.Fatal("HTTP after failed preflight")
		return 0, nil, nil
	}, kafkaLinkBrokerProbe)
	if err == nil || calls != 1 {
		t.Fatal("preflight did not stop", calls, err)
	}
	_, body := readLinkPrivateFailure(t, err)
	var receipt struct {
		RunID    string
		Combined []byte
	}
	if e := json.Unmarshal(body, &receipt); e != nil || receipt.RunID != "test" || !bytes.Equal(receipt.Combined, notice) {
		t.Fatal("missing first failure receipt", e)
	}
	// A repeated run ID must fail exclusive reservation before another action.
	if _, e := up(context.Background(), "test", func(context.Context, ...string) ([]byte, error) { calls++; return nil, nil }, true, linkHTTP, kafkaLinkBrokerProbe); e == nil || calls != 1 {
		t.Fatal("duplicate run reused failed evidence", calls, e)
	}
}

func TestLinkedReceiptPersistenceFailureStopsEvenExactAbsence(t *testing.T) {
	// Given literal exact absence (normally idempotent), when either the private
	// outcome or public summary cannot persist, then the incomplete evidence is
	// fatal, the absence cannot pass, and no further Docker action is sent.
	for _, target := range []string{"private", "public"} {
		t.Run(target, func(t *testing.T) {
			s := linkRetentionState(t)
			calls := 0
			run, err := LinkExecutor(s, func(_ context.Context, args ...string) ([]byte, error) {
				calls++
				path := linkDirectory(s.RunID)
				if target == "private" {
					dirs, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "operation-*"))
					if e != nil || len(dirs) != 1 {
						t.Fatal("operation not reserved", dirs, e)
					}
					path = dirs[0]
				}
				// A regular file in place of the retained pathname produces ENOTDIR.
				// This is an offline storage-shape control, not a permission workaround.
				if e := os.Rename(path, path+".retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte("path occupied"), 0600); e != nil {
					t.Fatal(e)
				}
				return []byte("Error: No such container: " + args[2] + "\n"), errors.New("exit 1")
			})
			if err != nil {
				t.Fatal(err)
			}
			var object linkContainer
			present, err := linkInspect(context.Background(), run, "container", s.Proxy.Container, &object)
			var failure *linkDockerFailure
			if present || !errors.As(err, &failure) || !failure.PersistenceFailed {
				t.Fatalf("missing evidence accepted as absence: %v %v", present, err)
			}
			if _, e := run(context.Background(), "network", "inspect", s.Network, "--format", "{{json .}}"); e == nil || calls != 1 {
				t.Fatal("receipt failure retried", calls, e)
			}
			if _, e := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { t.Fatal("receipt failure bypassed"); return nil, nil }); e == nil {
				t.Fatal("persistent stop absent after receipt failure")
			}
		})
	}
}

func TestLinkedIntentFailurePreventsFirstActionAndPersistsStop(t *testing.T) {
	// Given an executor with an exclusively reserved operation, when its intent
	// pathname becomes unavailable, then it cannot act or select a new route.
	s := linkRetentionState(t)
	calls := 0
	run, err := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { calls++; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "operation-*"))
	if err != nil || len(dirs) != 1 {
		t.Fatal(dirs, err)
	}
	if err = os.Rename(dirs[0], dirs[0]+".retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dirs[0], []byte("path occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = run(context.Background(), "info", "--format", "{{.OSType}}/{{.Architecture}}"); err == nil || calls != 0 {
		t.Fatal("action preceded intent", calls, err)
	}
	if _, err = LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { calls++; return nil, nil }); err == nil || calls != 0 {
		t.Fatal("new evidence route after intent failure", calls, err)
	}
}

func TestLinkedCleanupExactAbsenceIsIdempotentWithPrivateFailureReceipts(t *testing.T) {
	// Given every exact owned target is absent, when cleanup is repeated, then no
	// log/image/remove action is sent, each absence is retained, and no stop remains.
	s := linkRetentionState(t)
	calls := 0
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) != 5 || args[1] != "inspect" || args[0] != "network" && args[0] != "container" {
			t.Fatal("absence triggered another route", args)
		}
		return []byte("Error: No such " + args[0] + ": " + args[2] + "\n"), errors.New("exit 1")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := Down(context.Background(), s, run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 8 {
		t.Fatal("absence cleanup incomplete or retried", calls)
	}
	if _, err := os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("exact absence stopped facility", err)
	}
	files, err := filepath.Glob(filepath.Join(linkDirectory(s.RunID), "docker-failure-*.json"))
	if err != nil || len(files) != 8 {
		t.Fatal("missing exact absence summaries", files, err)
	}
}

func TestLinkedAbsenceNeverGuessesFromControlNoticeOrTypedPermission(t *testing.T) {
	// Given an absence phrase mixed with an unknown control notice, a different
	// target, or a typed permission cause, when inspected, then it remains fatal.
	for _, tc := range []struct {
		name, notice string
		cause        error
	}{
		{"prefixed control", "approval refused; Error: No such container: kaferry-lab-test-links", errors.New("unknown")},
		{"other target", "Error: No such container: another-target", errors.New("exit 1")},
		{"permission with absence", "Error: No such container: kaferry-lab-test-links", syscall.EACCES},
		{"context with absence", "Error: No such container: kaferry-lab-test-links", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := linkRetentionState(t)
			run, err := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { return []byte(tc.notice), tc.cause })
			if err != nil {
				t.Fatal(err)
			}
			var info linkContainer
			if present, e := linkInspect(context.Background(), run, "container", s.Proxy.Container, &info); present || e == nil {
				t.Fatal("control notice treated as absence", present, e)
			}
		})
	}
}

func TestLinkedExactLeadingLFContainerAbsenceRetainsOriginalFraming(t *testing.T) {
	// Given the exact combined stdout/stderr observed from an already removed
	// owned container, when inspected, then absence is retained without a retry,
	// another target or discarded formatting bytes.
	s := linkRetentionState(t)
	raw := []byte("\nError response from daemon: No such container: " + s.Proxy.Container + "\n")
	calls := 0
	run, err := LinkExecutor(s, func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if !reflect.DeepEqual(args, []string{"container", "inspect", s.Proxy.Container, "--format", "{{json .}}"}) {
			t.Fatal("unexpected absence route")
		}
		return raw, errors.New("exit 1")
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := run(context.Background(), "container", "inspect", s.Proxy.Container, "--format", "{{json .}}")
	var absent *linkDockerFailure
	if !errors.As(err, &absent) || !absent.ExactAbsence || absent.PersistenceFailed || calls != 1 || !bytes.Equal(got, raw) {
		t.Fatal("exact retained leading-LF absence was not admitted")
	}
	_, body := readLinkPrivateFailure(t, err)
	var receipt struct {
		Combined     []byte
		ExactAbsence bool
	}
	if e := json.Unmarshal(body, &receipt); e != nil || !receipt.ExactAbsence || !bytes.Equal(receipt.Combined, raw) {
		t.Fatal("original absence framing lost")
	}
	if _, e := os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("complete exact absence retained a stop")
	}
}

func TestLinkedLeadingLFAbsenceDoesNotStripWarningsOrBypassDenial(t *testing.T) {
	for _, kind := range []string{"extra-leading-LF", "warning-prefix", "warning-suffix", "other-target", "permission", "context"} {
		t.Run(kind, func(t *testing.T) {
			s := linkRetentionState(t)
			raw := "\nError response from daemon: No such container: " + s.Proxy.Container + "\n"
			cause := error(errors.New("exit 1"))
			switch kind {
			case "extra-leading-LF":
				raw = "\n" + raw
			case "warning-prefix":
				raw = "approval refused\n" + raw
			case "warning-suffix":
				raw += "unreviewed control notice\n"
			case "other-target":
				raw = "\nError response from daemon: No such container: another-target\n"
			case "permission":
				cause = syscall.EPERM
			case "context":
				cause = context.Canceled
			}
			calls := 0
			run, e := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { calls++; return []byte(raw), cause })
			if e != nil {
				t.Fatal(e)
			}
			_, e = run(context.Background(), "container", "inspect", s.Proxy.Container, "--format", "{{json .}}")
			var failure *linkDockerFailure
			if !errors.As(e, &failure) || failure.ExactAbsence || calls != 1 {
				t.Fatal("unknown notice or denial became absence")
			}
			if _, e = LinkExecutor(s, func(context.Context, ...string) ([]byte, error) {
				t.Fatal("new executor bypassed the retained stop")
				return nil, nil
			}); e == nil {
				t.Fatal("retained failure did not stop the facility")
			}
		})
	}
}

func TestLinkedCaptureLimitCancelsAndMarksNoticeIncomplete(t *testing.T) {
	// Given more output than the hard bound, when copied into the linked capture,
	// then memory stays bounded, the child cancellation is requested and the
	// retained prefix is explicitly incomplete; the action is never rerun.
	canceled := false
	writer := &linkBoundedOutput{cancel: func() { canceled = true }}
	body := bytes.Repeat([]byte{'x'}, linkOutputLimit+17)
	n, err := writer.Write(body)
	if n != linkOutputLimit || err == nil || !canceled || !writer.overflow || len(writer.bytes) != linkOutputLimit || writer.observed != int64(len(body)) {
		t.Fatal("capture is not bounded", n, err)
	}
	s := linkRetentionState(t)
	calls := 0
	run, err := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) {
		calls++
		return writer.bytes, &linkOutputOverflow{ObservedBytes: writer.observed}
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = run(context.Background(), "logs", "--tail", "200", s.Proxy.ContainerID)
	_, receipt := readLinkPrivateFailure(t, err)
	var outcome struct {
		Combined              []byte
		CombinedComplete      bool
		ObservedCombinedBytes int64
	}
	if e := json.Unmarshal(receipt, &outcome); e != nil || outcome.CombinedComplete || len(outcome.Combined) != linkOutputLimit || outcome.ObservedCombinedBytes != int64(len(body)) {
		t.Fatal("truncated notice claimed complete", e)
	}
	if _, e := run(context.Background(), "logs", "--tail", "200", s.Proxy.ContainerID); e == nil || calls != 1 {
		t.Fatal("overflow retried", calls, e)
	}
}

func TestLinkedCleanupStopsAtEachFailedDockerBoundaryAndRetainsPrivateLogs(t *testing.T) {
	// Given freshly owned resources, when any cleanup Docker boundary fails, then
	// its exact private receipt survives, no later resource/command is attempted,
	// and successful logs already retained never appear in public summaries.
	for _, boundary := range []string{"network inspect", "container inspect", "image inspect", "logs", "container rm", "network rm"} {
		t.Run(boundary, func(t *testing.T) {
			s := linkRetentionState(t)
			inspect := linkTestDocker(t, s, nil)
			failed, calls := false, 0
			notice := []byte("PRIVATE_CLEANUP_NOTICE=exact-action-failure\n")
			logs := []byte("PRIVATE_LOG_BODY=synthetic-broker-log\n")
			run := func(ctx context.Context, args ...string) ([]byte, error) {
				if failed {
					t.Fatal("cleanup used failed facility again", args)
				}
				calls++
				action := args[0]
				if len(args) > 1 && (args[0] == "network" || args[0] == "container" || args[0] == "image") {
					action += " " + args[1]
				}
				if action == boundary {
					failed = true
					return notice, syscall.EPERM
				}
				if args[0] == "logs" {
					return logs, nil
				}
				if len(args) > 1 && args[1] == "rm" {
					return nil, nil
				}
				return inspect(ctx, args...)
			}
			err := Down(context.Background(), s, run)
			if err == nil || !failed {
				t.Fatal("failure boundary not reached", boundary, err)
			}
			_, body := readLinkPrivateFailure(t, err)
			var receipt struct{ Combined []byte }
			if e := json.Unmarshal(body, &receipt); e != nil || !bytes.Equal(receipt.Combined, notice) {
				t.Fatal("cleanup failure notice lost", e)
			}
			assertLinkPublicWithholds(t, s, notice, logs, []byte("PRIVATE_LOG_BODY"), []byte("PRIVATE_CLEANUP_NOTICE"))
			before := calls
			if err = Down(context.Background(), s, run); err == nil || calls != before {
				t.Fatal("cleanup reentered stopped facility", calls, before, err)
			}
		})
	}
}

func TestLinkedCleanupPublicReceiptFailurePreventsRemoval(t *testing.T) {
	// Given owned containers and successfully read logs, when the public cleanup
	// receipt pathname becomes unavailable, then no removal is attempted even
	// though the preceding Docker read itself succeeded and its private bytes exist.
	s := linkRetentionState(t)
	inspect := linkTestDocker(t, s, nil)
	removed := false
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "rm" {
			removed = true
			t.Fatal("removed without mandatory cleanup receipt")
		}
		if args[0] == "logs" {
			path := linkDirectory(s.RunID)
			if e := os.Rename(path, path+".retained"); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(path, []byte("path occupied"), 0600); e != nil {
				t.Fatal(e)
			}
			return []byte("private successful log body"), nil
		}
		return inspect(ctx, args...)
	}
	if err := Down(context.Background(), s, run); err == nil || removed {
		t.Fatal("receipt persistence failure accepted", removed, err)
	}
	if _, err := LinkExecutor(s, run); err == nil {
		t.Fatal("receipt persistence failure did not stop a later cleanup invocation")
	}
	files, err := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatal("successful raw logs not retained privately before failed public summary", files, err)
	}
	var log struct{ Bytes []byte }
	body, err := os.ReadFile(files[0])
	if err != nil || json.Unmarshal(body, &log) != nil || string(log.Bytes) != "private successful log body" {
		t.Fatal("private successful log bytes lost", err)
	}
}

func TestPrivateLinkReceiptCapIncludesFinalNewline(t *testing.T) {
	// Given independently sized JSON string specimens at the complete-file bound,
	// when the production writer appends its newline, then exactly256KiB is
	// admitted and the adjacent256KiB+1 specimen is rejected before reservation.
	for _, tc := range []struct {
		name       string
		characters int
		accepted   bool
	}{
		{"exact file limit", 262141, true},
		{"one byte beyond complete file limit", 262142, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			reference, err := writeLinkPrivate(directory, "", strings.Repeat("x", tc.characters))
			if tc.accepted {
				if err != nil || reference == "" {
					t.Fatal("exact private file bound rejected", err)
				}
				info, e := os.Stat(reference)
				if e != nil || info.Size() != 262144 {
					t.Fatal("actual private receipt size differs from bound", e)
				}
			} else {
				if err == nil || reference != "" {
					t.Fatal("private receipt exceeding complete-file cap admitted")
				}
				files, e := os.ReadDir(directory)
				if e != nil || len(files) != 0 {
					t.Fatal("over-bound receipt reserved/written bytes", e)
				}
			}
		})
	}
}

// Match the literal retained bytes, not a marker or the executor's output hash.
func assertLinkedMetadataReadback(t *testing.T, id, kind string, argv []string, want []byte) {
	t.Helper()
	root := linkPrivateDirectory(id)
	info, e := os.Stat(root)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("metadata private root unavailable", e)
	}
	found, files := 0, 0
	e = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		files++
		if files > 128 {
			return errors.New("metadata private file bound")
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode().Perm() != 0600 || info.Size() > 256<<10 {
			return errors.New("metadata private file mode/size")
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var receipt struct {
			RunID, PrivateReadbackKind, SemanticAdmission, CombinedSHA256 string
			Argv                                                          []string
			Combined                                                      []byte
			CommandSucceeded, CombinedComplete                            bool
			CapturedCombinedBytes                                         int
			ObservedCombinedBytes                                         int64
		}
		if json.Unmarshal(raw, &receipt) != nil || receipt.PrivateReadbackKind == "" {
			return nil
		}
		if receipt.PrivateReadbackKind == kind && reflect.DeepEqual(receipt.Argv, argv) && bytes.Equal(receipt.Combined, want) {
			if receipt.RunID != id || !receipt.CommandSucceeded || receipt.SemanticAdmission != "not-observed-by-executor" || !receipt.CombinedComplete || receipt.CombinedSHA256 != linkDigest(want) || receipt.CapturedCombinedBytes != len(want) || receipt.ObservedCombinedBytes != int64(len(want)) {
				return errors.New("metadata readback completion or identity claim mismatch")
			}
			found++
		}
		return nil
	})
	if e != nil || found != 1 {
		t.Fatalf("exact private metadata readback missing/ambiguous: matches=%d err=%v", found, e)
	}
}

// Isolated error injection at the same three-method writer used by real receipts.
// There is no context policy, global hook or alternate evidence destination.
type metadataReceiptFaultFile struct {
	body                        []byte
	calls                       []string
	writeErr, syncErr, closeErr error
	short                       bool
}

func (f *metadataReceiptFaultFile) Write(body []byte) (int, error) {
	f.calls = append(f.calls, "write")
	f.body = append([]byte(nil), body...)
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(body) - 1, nil
	}
	return len(body), nil
}
func (f *metadataReceiptFaultFile) Sync() error { f.calls = append(f.calls, "sync"); return f.syncErr }
func (f *metadataReceiptFaultFile) Close() error {
	f.calls = append(f.calls, "close")
	return f.closeErr
}

func TestLinkedMetadataReceiptWriterRequiresWriteSyncAndClose(t *testing.T) {
	// Given command-success metadata, When any actual persistence stage fails,
	// Then success cannot replace the primary or secondary write/Sync/Close errors.
	body := []byte(`{"CommandSucceeded":true,"SemanticAdmission":"not-observed-by-executor","Combined":"PRIVATE_SYNTHETIC_METADATA"}` + "\n")
	primary, syncFailure, closeFailure := errors.New("TEST ONLY write failure"), errors.New("TEST ONLY sync failure"), errors.New("TEST ONLY close failure")
	for _, kind := range []string{"healthy", "write", "sync", "close", "joined", "short-write"} {
		t.Run(kind, func(t *testing.T) {
			f := &metadataReceiptFaultFile{}
			switch kind {
			case "write":
				f.writeErr = primary
			case "sync":
				f.syncErr = syncFailure
			case "close":
				f.closeErr = closeFailure
			case "joined":
				f.writeErr = primary
				f.syncErr = syncFailure
				f.closeErr = closeFailure
			case "short-write":
				f.short = true
			}
			err := persistLinkPrivateReceipt(f, body)
			if !reflect.DeepEqual(f.calls, []string{"write", "sync", "close"}) || !bytes.Equal(f.body, body) {
				t.Fatal("receipt persistence omitted/reordered a stage or changed bytes")
			}
			if (err == nil) != (kind == "healthy") {
				t.Fatal("failed persistence became success", err)
			}
			for _, cause := range []error{f.writeErr, f.syncErr, f.closeErr} {
				if cause != nil && !errors.Is(err, cause) {
					t.Fatal("primary/secondary persistence error lost", err)
				}
			}
			if kind == "short-write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("silent short write accepted", err)
			}
		})
	}
}

func TestLinkedSuccessfulRawRetentionIsLimitedToExactMetadataCommands(t *testing.T) {
	// Given successful bounded bytes, When the fixed command identity differs,
	// Then it keeps the old hash-only policy and cannot broaden raw success capture.
	for _, tc := range []struct {
		name, kind string
		args       []string
	}{
		{"engine", "linked-docker-engine-info", []string{"info", "--format", "{{.OSType}}/{{.Architecture}}"}},
		{"broker", "linked-docker-image-inspect", []string{"image", "inspect", Image, "--format", "{{json .}}"}},
		{"amd64-proxy", "linked-docker-image-inspect", []string{"image", "inspect", ProxyImage, "--format", "{{json .}}"}},
		{"arm64-proxy", "linked-docker-image-inspect", []string{"image", "inspect", arm64ProxyImage, "--format", "{{json .}}"}},
		{"other-image", "", []string{"image", "inspect", "unreviewed/image:tag", "--format", "{{json .}}"}},
		{"other-format", "", []string{"image", "inspect", Image, "--format", "{{.Id}}"}},
		{"extra-image-arg", "", []string{"image", "inspect", Image, "--format", "{{json .}}", "extra"}},
		{"other-info-format", "", []string{"info", "--format", "{{json .}}"}},
		{"container", "", []string{"container", "inspect", "synthetic-owned", "--format", "{{json .}}"}},
		{"logs", "", []string{"logs", "--tail", "200", "synthetic-owned"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := linkRetentionState(t)
			raw := []byte("PRIVATE_SUCCESS_METADATA_SYNTHETIC\n")
			run, e := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) { return raw, nil })
			if e != nil {
				t.Fatal(e)
			}
			got, e := run(context.Background(), tc.args...)
			if e != nil || !bytes.Equal(got, raw) {
				t.Fatal("successful command changed", e)
			}
			if _, e = os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("successful persisted command remained pending", e)
			}
			if tc.kind != "" {
				assertLinkedMetadataReadback(t, s.RunID, tc.kind, append([]string{"docker"}, tc.args...), raw)
			} else {
				e = filepath.WalkDir(linkPrivateDirectory(s.RunID), func(path string, d os.DirEntry, cause error) error {
					if cause != nil {
						return cause
					}
					if d.IsDir() {
						return nil
					}
					b, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					if bytes.Contains(b, raw) || bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString(raw))) {
						return errors.New("unselected successful raw output retained")
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			assertLinkPublicWithholds(t, s, raw)
		})
	}
}
