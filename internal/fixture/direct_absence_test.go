package fixture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

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
