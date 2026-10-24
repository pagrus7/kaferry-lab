package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerificationRejectsUnavailableTrustBeforeFetching(t *testing.T) {
	for _, fixture := range []string{"missing", "invalid"} {
		t.Run(fixture, func(t *testing.T) {
			// Given a missing or invalid explicitly configured trust bundle.
			path := filepath.Join(t.TempDir(), "roots.pem")
			if fixture == "invalid" {
				if err := os.WriteFile(path, []byte("synthetic invalid CA bundle"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("SSL_CERT_FILE", path)
			out := filepath.Join(t.TempDir(), "attempt")
			// When verification is requested, then it refuses the trust setup
			// before downloading or creating an executable output directory.
			got, err := verify(context.Background(), out)
			if err == nil || got.BinarySHA256 != "" {
				t.Fatalf("unavailable trust accepted: %+v / %v", got, err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("verification proceeded past invalid trust: %v", err)
			}
		})
	}
}

func TestVerificationPreservesExistingAttempt(t *testing.T) {
	// Given a retained attempt with independently known bytes.
	t.Setenv("SSL_CERT_FILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "FAILED.json")
	want := []byte("retained synthetic first failure\n")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	// When another verification names the same directory, then the original
	// evidence survives and the command cannot claim a fresh verified result.
	got, err := verify(context.Background(), dir)
	if err == nil || got.BinarySHA256 != "" {
		t.Fatalf("existing attempt reused: %+v / %v", got, err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatalf("retained attempt changed: %q / %v", actual, err)
	}
}

func TestVersionOutputBudgetRejectsOverflow(t *testing.T) {
	// Given a version process filling the exact 64 KiB collection budget.
	var out boundedOutput
	if n, err := out.Write(bytes.Repeat([]byte{'x'}, 64<<10)); err != nil || n != 64<<10 {
		t.Fatalf("bounded output rejected exact limit: %d / %v", n, err)
	}
	// When another byte arrives, then collection fails and stays bounded.
	if n, err := out.Write([]byte{'y'}); n != 0 || err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("overflow accepted: %d / %v", n, err)
	}
	if out.buffer.Len() != 64<<10 {
		t.Fatalf("version output grew beyond budget: %d", out.buffer.Len())
	}
}
