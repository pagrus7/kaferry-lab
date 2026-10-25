package campaign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWireReceiptRejectsUnboundedAndLinkedInputs(t *testing.T) {
	// Given public synthetic dependency receipts outside the capture process.
	dir := t.TempDir()
	ordinary := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(ordinary, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if body, err := wireReadReceipt(ordinary); err != nil || string(body) != "{}" {
		t.Fatalf("regular receipt unavailable: %q %v", body, err)
	}
	oversized := filepath.Join(dir, "oversized")
	if err := os.WriteFile(oversized, make([]byte, 16385), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(ordinary, link); err != nil {
		t.Fatal(err)
	}
	// When input is oversized, linked, missing or a directory, reject before capture.
	for _, path := range []string{oversized, link, dir, filepath.Join(dir, "missing")} {
		// Then no invalid receipt can authorize or block the bounded tool boundary.
		if _, err := wireReadReceipt(path); err == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
}
