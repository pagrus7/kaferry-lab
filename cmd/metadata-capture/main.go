package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func main() { os.Exit(execute(os.Args[1:])) }

func execute(args []string) int {
	// Only the reviewed caller may launch this utility; it must pre-reserve and
	// privately bound both pipes. stdout is fixed; stderr may carry private
	// bounded base64 causes. Flag parsing cannot echo arbitrary arguments.
	fail := func() int { _, _ = io.WriteString(os.Stderr, "metadata diagnostic incomplete\n"); return 1 }
	flags := flag.NewFlagSet("metadata-capture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var id Identity
	var output string
	flags.StringVar(&id.RunID, "run-id", "", "")
	flags.StringVar(&id.SourceHead, "source-head", "", "")
	flags.StringVar(&id.Job, "job", "", "")
	flags.StringVar(&id.Attempt, "attempt", "", "")
	flags.StringVar(&output, "output", "", "")
	id.GitHubRunID = os.Getenv("GITHUB_RUN_ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !validIdentity(id) {
		return fail()
	}
	if output != filepath.Join(".cache", "fixtures-private", id.RunID+"-links", "metadata.json") {
		return fail()
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !validContext(id, os.Getenv) {
		return fail()
	}
	sink, err := reserve(id)
	if err != nil {
		privateFailure(os.Stderr, id, "output-reservation", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	client, setupErr := productionClient()
	r := observe(ctx, id, client, setupErr)
	cancel()
	if err := persist(sink, r); err != nil {
		privateFailure(os.Stderr, id, "receipt-write-sync-close", err)
		return 1
	}
	if _, err := io.WriteString(os.Stdout, "metadata diagnostic observation closed\n"); err != nil {
		privateFailure(os.Stderr, id, "fixed-stdout", err)
		return 1
	}
	if !r.CaptureComplete {
		return 2
	}
	return 0
}

func validContext(id Identity, get func(string) string) bool {
	return get("GITHUB_REPOSITORY") == "pagrus7/kaferry-lab" &&
		get("GITHUB_REPOSITORY_ID") == "1432555755" &&
		get("GITHUB_EVENT_NAME") == "workflow_dispatch" &&
		get("GITHUB_REF") == "refs/heads/codex/resilience-release-lab" &&
		get("GITHUB_SHA") == id.SourceHead && get("GITHUB_RUN_ID") == id.GitHubRunID &&
		get("GITHUB_RUN_ATTEMPT") == id.Attempt && get("GITHUB_JOB") == id.Job
}

// The caller creates the fixture-v1 root and PRIVATE.json, both owner-only.
// No creation, append, replacement, alternate destination, or error fallback.
func reserve(id Identity) (*os.File, error) {
	root := filepath.Join(".cache", "fixtures-private", id.RunID+"-links")
	var rootInfo os.FileInfo
	for _, path := range []string{".cache", filepath.Join(".cache", "fixtures-private"), root} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != uint32(os.Getuid()) || (path == root && info.Mode().Perm() != 0700) {
			return nil, os.ErrPermission
		}
		if path == root {
			rootInfo = info
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	heldInfo, statErr := r.Stat(".")
	if statErr != nil {
		return nil, errors.Join(statErr, r.Close())
	}
	if !os.SameFile(rootInfo, heldInfo) {
		return nil, errors.Join(os.ErrPermission, r.Close())
	}
	f, openErr := r.OpenFile("metadata.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	rootCloseErr := r.Close()
	if openErr != nil {
		return nil, errors.Join(openErr, rootCloseErr)
	}
	if rootCloseErr != nil {
		return nil, errors.Join(rootCloseErr, f.Close())
	}
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, errors.Join(statErr, f.Close())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != uint32(os.Getuid()) {
		return nil, errors.Join(os.ErrPermission, f.Close())
	}
	return f, nil
}
