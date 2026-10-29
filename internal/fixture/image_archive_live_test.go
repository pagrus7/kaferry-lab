package fixture

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestNativeOwnedSavedImageArchiveMetadata(t *testing.T) {
	path := os.Getenv("LAB_NATIVE_IMAGE_ARCHIVE")
	if path == "" {
		t.Skip("explicit owned native image archive data opt-in absent")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		t.Fatal("CALIBRATION DATA ONLY: requires selected native LinuxARM64 reader")
	}
	kernel, err := exec.Command("uname", "-m").Output()
	if err != nil || strings.TrimSpace(string(kernel)) != "aarch64" {
		t.Fatal("native AArch64 kernel required for this dependency-data control", err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || real != path {
		t.Fatal("canonical owned archive data path required", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || native.Uid != uint32(os.Getuid()) || native.Nlink != 1 || before.Size() <= 0 || before.Size() > 512<<20 {
		t.Fatal("bounded private single-link owned archive required")
	}
	var archiveHash string
	for _, ref := range []string{Image, arm64ProxyImage} {
		fixed, err := modernImage(State{DockerPlatform: "linux/arm64"}, ref)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		result, readErr := readImageArchive(file, imageArchiveExpected{Manifest: fixed.manifest, Config: fixed.config, OS: "linux", Architecture: "arm64"})
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || !result.Complete || result.ArchiveBytes != before.Size() {
			t.Fatal("native dependency-data proof incomplete", readErr, closeErr, result.Complete, result.ArchiveBytes)
		}
		if archiveHash != "" && result.ArchiveSHA256 != archiveHash {
			t.Fatal("archive changed between selected-image checks")
		}
		archiveHash = result.ArchiveSHA256
		t.Log("DEPENDENCY DATA ONLY; no container/process/fault qualification", ref, result.ManifestDescriptor.Digest, result.ConfigDescriptor.Digest, result.ArchiveSHA256, result.Entries, result.Blobs)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		t.Fatal("archive data changed during read", err)
	}
}
