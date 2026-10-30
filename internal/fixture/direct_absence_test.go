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
	"syscall"
	"testing"
)

func TestDirectAbsenceLeadingLFNetworkNotice(t *testing.T) {
	// Given a returned cleanup and exact retained IDs on an inert backend, When
	// the final network inspect returns the native single-LF notice, Then its
	// complete original is retained and absence passes only with every guard.
	for _, fault := range []string{"none", "wrong-id", "multiple-leading-LF", "extra-output", "missing-terminal-LF", "EACCES", "EPERM", "canceled-error", "deadline-error", "canceled-context", "incomplete-output", "truncated-output", "truncated-cause", "persistence"} {
		t.Run(fault, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newDirectDockerControl(t)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			if err = Down(context.Background(), s, f.execute); err != nil {
				t.Fatal(err)
			}
			root := directPrivateDirectory(s.RunID)
			oldOperations, err := filepath.Glob(filepath.Join(root, "operation-*"))
			if err != nil {
				t.Fatal(err)
			}
			prior := map[string]bool{}
			for _, path := range oldOperations {
				prior[path] = true
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := [][]string{}
			for _, target := range s.Direct.BrokerIDs {
				want = append(want, []string{"container", "inspect", target, "--format", "{{json .}}"})
			}
			want = append(want, []string{"network", "inspect", s.Direct.NetworkID, "--format", "{{json .}}"})
			calls := 0
			notice := "\nError response from daemon: network " + s.Direct.NetworkID + " not found\n"
			raw := []byte(notice)
			cause := error(errors.New("SYNTHETIC exit status 1"))
			switch fault {
			case "wrong-id":
				raw = []byte("\nError response from daemon: network " + strings.Repeat("e", 64) + " not found\n")
			case "multiple-leading-LF":
				raw = append([]byte{'\n'}, raw...)
			case "extra-output":
				raw = append(raw, []byte("SYNTHETIC additional notice\n")...)
			case "missing-terminal-LF":
				raw = raw[:len(raw)-1]
			case "EACCES":
				cause = syscall.EACCES
			case "EPERM":
				cause = syscall.EPERM
			case "canceled-error":
				cause = context.Canceled
			case "deadline-error":
				cause = context.DeadlineExceeded
			case "incomplete-output":
				cause = &linkOutputOverflow{ObservedBytes: int64(len(raw) + 1)}
			case "truncated-output":
				raw = append(raw, bytes.Repeat([]byte{'x'}, linkOutputLimit)...)
			case "truncated-cause":
				cause = errors.New(strings.Repeat("x", linkOutputLimit+1))
			}
			backend := func(ctx context.Context, args ...string) ([]byte, error) {
				if calls >= len(want) || !reflect.DeepEqual(args, want[calls]) {
					t.Fatal("absence issued another target, action or retry", args)
				}
				calls++
				if calls < len(want) {
					return f.execute(ctx, args...)
				}
				if fault == "canceled-context" {
					cancel()
				}
				if fault == "persistence" {
					operations, e := filepath.Glob(filepath.Join(root, "operation-*"))
					if e != nil {
						t.Fatal(e)
					}
					changed := 0
					for _, path := range operations {
						if !prior[path] {
							// Preserve the actual intent/first two container receipts,
							// then make only this operation's outcome path ENOTDIR.
							if e = os.Rename(path, path+".retained"); e != nil {
								t.Fatal(e)
							}
							if e = os.WriteFile(path, []byte("SYNTHETIC occupied outcome path"), 0600); e != nil {
								t.Fatal(e)
							}
							changed++
						}
					}
					if changed != 1 {
						t.Fatal("persistence failure did not reach exactly the current operation", changed)
					}
				}
				return raw, cause
			}
			r, err := ObserveDirectAbsence(ctx, s, backend)
			if calls != 3 || r.ContainersAbsent != [2]bool{true, true} {
				t.Fatal("network boundary not reached after two exact container absences", calls, r, err)
			}
			if fault != "none" {
				var failure *linkDockerFailure
				if err == nil || r.Complete || r.NetworkAbsent || !errors.As(err, &failure) || failure.ExactAbsence || failure.PersistenceFailed != (fault == "persistence") {
					t.Fatal("incomplete network evidence became absence", r, err)
				}
				if _, e := os.Stat(filepath.Join(root, "STOPPED.json")); e != nil {
					t.Fatal("network failure did not preserve facility stop", e)
				}
				if _, e := ObserveDirectAbsence(context.Background(), s, backend); e == nil || calls != 3 {
					t.Fatal("network failure retried through another observer", calls, e)
				}
				return
			}
			if err != nil || !r.Complete || !r.NetworkAbsent || r.PrivateReference == "" {
				t.Fatal("complete exact leading-LF network absence rejected", r, err)
			}
			if _, e := os.Stat(filepath.Join(root, "STOPPED.json")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("complete network absence retained a stop", e)
			}
			outcomes, e := filepath.Glob(filepath.Join(root, "operation-*", "docker-*.json"))
			if e != nil {
				t.Fatal(e)
			}
			matches := 0
			for _, path := range outcomes {
				body, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var receipt struct {
					Argv                                          []string
					Combined                                      []byte
					ExactAbsence, CombinedComplete, CauseComplete bool
				}
				if e = json.Unmarshal(body, &receipt); e != nil {
					t.Fatal(e)
				}
				if bytes.Equal(receipt.Combined, []byte(notice)) {
					if !receipt.ExactAbsence || !receipt.CombinedComplete || !receipt.CauseComplete || !reflect.DeepEqual(receipt.Argv, append([]string{"docker"}, want[2]...)) {
						t.Fatal("network original or completion facts changed", path)
					}
					matches++
				}
			}
			if matches != 1 {
				t.Fatal("exact network original missing or duplicated", matches)
			}
		})
	}
}

func TestDirectAbsenceAfterCleanupOnlyReadsThreeRetainedIDs(t *testing.T) {
	// Given a genuinely returned strict cleanup on an inert backend, When the
	// read-only witness runs, Then exactly its three retained IDs are inspected.
	t.Chdir(t.TempDir())
	f := newDirectDockerControl(t)
	s, err := upDirectControl(context.Background(), f.execute)
	if err != nil {
		t.Fatal(err)
	}
	if err = Down(context.Background(), s, f.execute); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	r, err := ObserveDirectAbsence(context.Background(), s, f.execute)
	if err != nil || !r.Complete || !r.NetworkAbsent || r.ContainersAbsent != [2]bool{true, true} || r.PrivateReference == "" {
		t.Fatal("absence witness incomplete", r, err)
	}
	want := [][]string{}
	for _, target := range s.Direct.BrokerIDs {
		want = append(want, []string{"container", "inspect", target, "--format", "{{json .}}"})
	}
	want = append(want, []string{"network", "inspect", s.Direct.NetworkID, "--format", "{{json .}}"})
	if !reflect.DeepEqual(f.calls[before:], want) {
		t.Fatal("absence witness issued another route", f.calls[before:])
	}
}

func TestDirectAbsenceRefusesPresentWarningAndMissingAuthorityWithoutRemoving(t *testing.T) {
	// Given retained direct identity, When absence is contradicted or its
	// authority is missing, Then there is no rm, retry or name-based discovery.
	for _, fault := range []string{"present", "warning", "typed-permission", "missing-identity", "stopped"} {
		t.Run(fault, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newDirectDockerControl(t)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "missing-identity" {
				if err = os.Remove(filepath.Join(directPrivateDirectory(s.RunID), "identity.json")); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "stopped" {
				if err = StopFixtureEvidence(s, "literal refused operation"); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			raw := func(ctx context.Context, args ...string) ([]byte, error) {
				calls++
				if args[0] != "container" || args[1] != "inspect" || args[2] != s.Direct.BrokerIDs[0] {
					t.Fatal("unexpected route", args)
				}
				if fault == "warning" {
					return []byte("warning: No such container; SYNTHETIC original"), errors.New("exit 1")
				}
				if fault == "typed-permission" {
					return []byte("Error response from daemon: No such container: " + args[2] + "\n"), syscall.EPERM
				}
				return f.execute(ctx, args...)
			}
			r, err := ObserveDirectAbsence(context.Background(), s, raw)
			if err == nil || r.Complete || len(f.removed) != 0 || f.networkRemoved {
				t.Fatal("failed absence became destructive/successful", r, err)
			}
			wantCalls := 1
			if fault == "missing-identity" || fault == "stopped" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("absence refusal retried", calls)
			}
			if wantCalls == 1 {
				if _, e := os.Stat(filepath.Join(directPrivateDirectory(s.RunID), "STOPPED.json")); e != nil {
					t.Fatal(e)
				}
				before := calls
				if _, e := ObserveDirectAbsence(context.Background(), s, raw); e == nil || calls != before {
					t.Fatal("absence STOP bypassed")
				}
			}
			for _, command := range f.calls {
				if strings.Join(command[:min(2, len(command))], " ") == "container rm" {
					t.Fatal("absence removed a resource")
				}
			}
		})
	}
}
