package campaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

const nativeCheckOutputLimit = 16 << 20
const nativeCheckInputLimit = 1 << 20
const nativeCheckSourceLimit = 16 << 20
const nativeCheckSDK = "bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd"
const nativeCheckMachine = "kaferry-lab-arm64-20261026"
const nativeCheckMachineID = "01M5XVQQ4GRX6H79K1SE76R0X1"

var nativeCheckIncomplete = errors.New("native harness check incomplete; private originals and external wait/readback required")
var nativeCheckHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var nativeCheckHead = regexp.MustCompile(`^[0-9a-f]{40}$`)
var nativeCheckRun = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// NativeCheckPlan admits one source-only checkout and one fixed command. The
// external parent authenticates these inputs and this prebuilt controller.
type NativeCheckPlan struct {
	Repository, RunID, ReviewedHead, InputSHA256 string
}

type NativeCheckSourceFile struct {
	Path, SHA256 string
	Bytes        int64
	Mode         uint32
}

// NativeCheckInput is a bounded source catalog, not an executable job plan.
// GuestMachineID is an externally authenticated ownership assertion; the native
// controller cannot discover an OrbStack machine ID from its Linux hostname.
type NativeCheckInput struct {
	Version, RunID, SourceHead, Repository                      string
	GuestName, GuestMachineID, SDKArchiveSHA256, GoBinarySHA256 string
	Files                                                       []NativeCheckSourceFile
}

type NativeCheckResult struct {
	Version, Namespace, RunID, SourceHead, InputSHA256, Status string
	Argv, Environment                                          []string
	Wait                                                       LinkCalibrationWait
	Tree                                                       LinkCalibrationTree
	SourceAdmitted, SourceUnchanged, StdoutEOF, StderrEOF      bool
	CommandWritersStopped, NativeHarnessChecksPassed           bool
	CommandReturnedSuccessfully                                bool
	PriorPayloadFilesClosed, OwnFinalCloseProven               bool
	RequiresExternalWaitAndMacReadback, ReleaseQualified       bool
}

// RunNativeCheck owns only the fixed scripts/check.sh process tree. Its returned
// value is not a receipt of its own process exit, final close, or Mac custody.
func RunNativeCheck(ctx context.Context, p NativeCheckPlan) (r NativeCheckResult, err error) {
	r = NativeCheckResult{Version: "1", Namespace: "harness/native-unit-check", RunID: p.RunID,
		SourceHead: p.ReviewedHead, InputSHA256: p.InputSHA256, Status: "INCOMPLETE",
		RequiresExternalWaitAndMacReadback: true}
	directory, sink, reserveErr := reserveNativeCheck(p)
	if reserveErr != nil {
		return r, nativeCheckIncomplete // before the first sink, exact cause may be unavailable
	}
	capture := true
	retain := func(action string, cause error) {
		if cause != nil && !retainLinkCalibrationError(sink, []string{action}, cause) {
			capture = false
		}
	}
	finish := func() (NativeCheckResult, error) { return finishNativeCheck(directory, sink, r, capture) }
	if err = nativeCheckPlatform(); err != nil {
		retain("native_platform", err)
		return finish()
	}
	if p.Repository != filepath.Join("/home/labrunner", "kaferry-native-ci-"+p.RunID, "source") {
		retain("owned_source_root", errors.New("fixed fresh native check source root required"))
		return finish()
	}
	if err = nativeCheckControllerBuild(p.ReviewedHead); err != nil {
		retain("controller_build", err)
		return finish()
	}
	if err = nativeCheckInitialCache(p); err != nil {
		retain("fresh_attempt_cache", err)
		return finish()
	}
	_, raw, inputErr := readNativeCheckInput(p)
	if inputErr != nil {
		retain("source_admission", inputErr)
		return finish()
	}
	if err = nativeCheckWrite(directory, "inputs.json", raw, nativeCheckInputLimit); err != nil {
		retain("retain_inputs", err)
		return finish()
	}
	r.SourceAdmitted = true
	r.Argv = []string{"/bin/sh", "scripts/check.sh"}
	r.Environment = nativeCheckEnvironment()
	if err = nativeCheckAmbient(); err != nil {
		retain("default_home_and_caches", err)
		return finish()
	}
	r.Tree, err = prepareLinkCalibrationTree()
	if err != nil {
		retain("prepare_dedicated_tree", err)
		return finish()
	}
	command := exec.Command(r.Argv[0], r.Argv[1:]...)
	command.Dir, command.Env = p.Repository, r.Environment
	anchor := exec.Command("/proc/self/exe", "--owned-native-check-anchor")
	anchor.Env = []string{"LC_ALL=C"}
	group, groupErr := startLinkCalibrationGroup(anchor, r.Tree)
	var stdout, stderr []byte
	if group != nil {
		if groupErr == nil {
			checkCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
			r.Wait, stdout, stderr, _, err = waitOwnedHarnessCommand(checkCtx, command, group, nativeCheckOutputLimit)
			cancel()
		} else {
			// Even a failed anchor membership observation keeps its sole Wait owner.
			stopErr := group.beginStop()
			if stopErr == nil {
				stopErr = group.lastSignal()
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, closeErr := group.close(closeCtx, true)
			cancel()
			err = errors.Join(stopErr, closeErr)
		}
		r.Tree = group.result
	}
	retain("fixed_check_and_tree", errors.Join(groupErr, err))
	r.CommandReturnedSuccessfully = groupErr == nil && err == nil
	// exec.Cmd.Wait joins its copy goroutines. A nil/ExitError wait with no
	// ErrWaitDelay or copy error proves natural EOF for BOTH copied streams.
	// On a nonzero exit exec.Wait may prioritize ExitError over ErrWaitDelay.
	// Be conservative: only a nil command wait can prove both natural EOFs here.
	r.StdoutEOF, r.StderrEOF = r.CommandReturnedSuccessfully && r.Wait.OutputComplete && r.Wait.StreamCopiesJoined, r.CommandReturnedSuccessfully && r.Wait.OutputComplete && r.Wait.StreamCopiesJoined
	r.CommandWritersStopped = nativeCheckStopped(r.Wait, r.Tree)
	for _, output := range []struct {
		name string
		body []byte
	}{{"stdout.bin", stdout}, {"stderr.bin", stderr}} {
		if e := nativeCheckWrite(directory, output.name, output.body, nativeCheckOutputLimit); e != nil {
			retain("retain_"+output.name, e)
			capture = false
		}
	}
	if e := nativeCheckJSON(directory, "command.json", struct {
		Argv, Environment []string
		Wait              LinkCalibrationWait
	}{r.Argv, r.Environment, r.Wait}); e != nil {
		retain("retain_command", e)
		capture = false
	}
	if e := nativeCheckJSON(directory, "tree.json", r.Tree); e != nil {
		retain("retain_tree", e)
		capture = false
	}
	if r.CommandWritersStopped {
		_, postRaw, postErr := readNativeCheckInput(p)
		r.SourceUnchanged = postErr == nil && bytes.Equal(raw, postRaw)
		if !r.SourceUnchanged {
			retain("source_postcheck", errors.Join(postErr, errors.New("admitted tracked source changed")))
		}
	}
	r.PriorPayloadFilesClosed = capture
	return finish()
}

func nativeCheckStopped(w LinkCalibrationWait, tree LinkCalibrationTree) bool {
	if !(w.Started && w.WaitReturned && w.Reaped && w.StreamCopiesJoined && w.PID > 0 && w.StartTicks != "" &&
		tree.SubreaperEnabled && tree.AnchorStarted && tree.AnchorWaitReturned && tree.AnchorReaped &&
		tree.AnchorPID > 0 && tree.AnchorStartTicks != "" && tree.SignalsClosed && tree.Closed && tree.NoChildren && !tree.ControlFailed) {
		return false
	}
	anchor := syscall.WaitStatus(tree.AnchorStatus)
	if !anchor.Signaled() || (anchor.Signal() != syscall.SIGTERM && anchor.Signal() != syscall.SIGKILL) {
		return false
	}
	for _, adopted := range tree.Adopted {
		status := syscall.WaitStatus(adopted.Status)
		if adopted.PID <= 0 || !adopted.Terminal || !(status.Exited() || status.Signaled()) {
			return false
		}
	}
	return true
}

func nativeCheckPass(r NativeCheckResult, capture bool) bool {
	return capture && r.SourceAdmitted && r.SourceUnchanged && r.PriorPayloadFilesClosed && r.CommandReturnedSuccessfully &&
		r.StdoutEOF && r.StderrEOF && nativeCheckStopped(r.Wait, r.Tree) && r.Wait.OutputComplete &&
		r.Wait.ExitCode == 0 && r.Wait.SignalNumber == 0 && r.Wait.StdoutBytes <= nativeCheckOutputLimit &&
		r.Wait.StderrBytes <= nativeCheckOutputLimit && r.Wait.StdoutBytes == r.Wait.CapturedStdoutBytes &&
		r.Wait.StderrBytes == r.Wait.CapturedStderrBytes && r.Wait.DroppedObservedStdoutBytes == 0 && r.Wait.DroppedObservedStderrBytes == 0
}

func finishNativeCheck(directory string, sink *linkCalibrationSink, r NativeCheckResult, capture bool) (NativeCheckResult, error) {
	r.Status = "INCOMPLETE"
	r.OwnFinalCloseProven, r.ReleaseQualified = false, false
	r.RequiresExternalWaitAndMacReadback = true
	r.NativeHarnessChecksPassed = nativeCheckPass(r, capture && !sink.broken && !sink.finalized && sink.records == 0)
	if r.NativeHarnessChecksPassed {
		r.Status = "HARNESS_CHECKS_PASSED_EXTERNAL_CUSTODY_REQUIRED"
	}
	// Stage while the first exact-error sink is alive. No serialized assertion
	// claims this writer's own final close or the external parent's actual Wait.
	if err := nativeCheckJSON(directory, "result.pending.json", r); err != nil {
		retainLinkCalibrationError(sink, []string{"stage_native_result"}, err)
		closeLinkCalibrationSink(sink)
		r.NativeHarnessChecksPassed = false
		return r, nativeCheckIncomplete
	}
	if err := closeLinkCalibrationSink(sink); err != nil {
		r.NativeHarnessChecksPassed = false
		r.Status = "INCOMPLETE"
		return r, nativeCheckIncomplete // no replacement final-close error sink
	}
	if err := os.Rename(filepath.Join(directory, "result.pending.json"), filepath.Join(directory, "result.json")); err != nil {
		r.NativeHarnessChecksPassed = false
		r.Status = "INCOMPLETE"
		return r, nativeCheckIncomplete // original pending file remains
	}
	if !r.NativeHarnessChecksPassed {
		return r, nativeCheckIncomplete
	}
	return r, nil
}

func nativeCheckEnvironment() []string {
	// No inherited credentials, opt-ins, loader/coverage hooks or Go overrides.
	// Normal HOME and absent overrides preserve the ordinary default caches.
	return []string{"PATH=/usr/local/go/bin:/usr/bin:/bin", "HOME=/home/labrunner", "LC_ALL=C"}
}

func nativeCheckInitialCache(p NativeCheckPlan) error {
	for path, expected := range map[string]map[string]bool{
		filepath.Join(p.Repository, ".cache"):                         {"native-check-input.json": true, "native-check-private": true},
		filepath.Join(p.Repository, ".cache", "native-check-private"): {p.RunID: true},
	} {
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(4)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if len(entries) != len(expected) {
			return errors.New("fresh native source cache has unexpected entries")
		}
		for _, entry := range entries {
			if !expected[entry.Name()] {
				return errors.New("fresh native source cache contains another attempt")
			}
		}
	}
	return nil
}

func nativeCheckAmbient() error {
	if os.Getenv("HOME") != "/home/labrunner" {
		return errors.New("normal native HOME required")
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOENV", "GOROOT", "XDG_CACHE_HOME"} {
		if _, present := os.LookupEnv(key); present {
			return errors.New("default Go cache/environment overrides must be absent")
		}
	}
	info, err := os.Lstat("/home/labrunner")
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&0022 != 0 || !nativeCheckOwned(info) {
		return errors.New("existing canonical owned native home required")
	}
	real, err := filepath.EvalSymlinks("/home/labrunner")
	if err != nil || real != "/home/labrunner" {
		return errors.Join(err, errors.New("native home alias rejected"))
	}
	return nil
}

func nativeCheckControllerBuild(head string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Path != "github.com/pagrus7/kaferry-lab/cmd/native-check" || info.GoVersion != "go1.26.0" {
		return errors.New("prebuilt reviewed native controller required")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return errors.New("duplicate controller build setting")
		}
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" || settings["vcs.revision"] != head || settings["vcs.modified"] != "false" {
		return errors.New("clean reviewed Linux ARM64 controller build required")
	}
	return nil
}

func reserveNativeCheck(p NativeCheckPlan) (string, *linkCalibrationSink, error) {
	if !nativeCheckRun.MatchString(p.RunID) || !nativeCheckHead.MatchString(p.ReviewedHead) || !nativeCheckHex.MatchString(p.InputSHA256) ||
		!filepath.IsAbs(p.Repository) || filepath.Clean(p.Repository) != p.Repository {
		return "", nil, nativeCheckIncomplete
	}
	if real, err := filepath.EvalSymlinks(p.Repository); err != nil || real != p.Repository {
		return "", nil, nativeCheckIncomplete
	}
	rootInfo, err := os.Lstat(p.Repository)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 || !nativeCheckOwned(rootInfo) {
		return "", nil, nativeCheckIncomplete
	}
	directory := filepath.Join(p.Repository, ".cache", "native-check-private", p.RunID)
	for _, path := range []string{filepath.Join(p.Repository, ".cache"), filepath.Dir(directory)} {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !nativeCheckOwned(info) {
			return "", nil, nativeCheckIncomplete
		}
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", nil, err
	}
	f, err := os.OpenFile(filepath.Join(directory, "errors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return directory, nil, err
	}
	sink, err := newLinkCalibrationSink(f, p.RunID)
	return directory, sink, err
}

func nativeCheckOwned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && (info.IsDir() || s.Nlink == 1)
}

func nativeCheckRead(path string, limit int64) (body []byte, err error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Mode().Perm()&0200 == 0 || !nativeCheckOwned(before) || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("bounded owner-only single-link regular native input required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	opened, err := f.Stat()
	if err != nil || !nativeCheckSameFile(before, opened) {
		return nil, errors.Join(err, errors.New("native input changed before read"))
	}
	body, err = io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	final, finalErr := os.Lstat(path)
	if err != nil || statErr != nil || finalErr != nil || int64(len(body)) != before.Size() || !nativeCheckSameFile(opened, after) || !nativeCheckSameFile(after, final) {
		return nil, errors.Join(err, statErr, finalErr, errors.New("native input changed during read"))
	}
	return body, nil
}

func nativeCheckSameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() &&
		a.ModTime().Equal(b.ModTime()) && nativeCheckOwned(b)
}

func readNativeCheckInput(p NativeCheckPlan) (input NativeCheckInput, raw []byte, err error) {
	raw, err = nativeCheckRead(filepath.Join(p.Repository, ".cache", "native-check-input.json"), nativeCheckInputLimit)
	if err != nil {
		return
	}
	if processDigest(raw) != p.InputSHA256 {
		return input, raw, errors.New("native input digest mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		return
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return input, raw, errors.New("native input trailing data")
	}
	if input.Version != "1" || input.RunID != p.RunID || input.SourceHead != p.ReviewedHead || input.Repository != p.Repository ||
		input.GuestName != nativeCheckMachine || input.GuestMachineID != nativeCheckMachineID || input.SDKArchiveSHA256 != nativeCheckSDK || !nativeCheckHex.MatchString(input.GoBinarySHA256) {
		return input, raw, errors.New("native input ownership/source/SDK binding mismatch")
	}
	if err = checkNativeSource(p.Repository, input.Files); err != nil {
		return
	}
	goPath := "/usr/local/go/bin/go"
	if real, e := filepath.EvalSymlinks(goPath); e != nil || real != goPath {
		return input, raw, errors.Join(e, errors.New("normal Go executable path alias rejected"))
	}
	before, e := os.Lstat(goPath)
	if e != nil {
		return input, raw, e
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || owner.Uid != 0 || owner.Nlink != 1 || before.Size() <= 0 || before.Size() > 32<<20 {
		return input, raw, errors.New("normal root-owned Go executable required")
	}
	goFile, e := os.Open(goPath)
	if e != nil {
		return input, raw, e
	}
	h := sha256.New()
	opened, openStatErr := goFile.Stat()
	n, readErr := io.Copy(h, io.LimitReader(goFile, (32<<20)+1))
	info, buildErr := buildinfo.Read(goFile)
	after, statErr := goFile.Stat()
	closeErr := goFile.Close()
	final, finalErr := os.Lstat(goPath)
	stable := func(a, b os.FileInfo) bool {
		return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
	}
	if openStatErr != nil || readErr != nil || buildErr != nil || statErr != nil || closeErr != nil || finalErr != nil {
		return input, raw, errors.Join(openStatErr, readErr, buildErr, statErr, closeErr, finalErr)
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if !stable(before, opened) || !stable(opened, after) || !stable(after, final) || n != before.Size() ||
		hex.EncodeToString(h.Sum(nil)) != input.GoBinarySHA256 || info.GoVersion != "go1.26.0" || info.Path != "cmd/go" || settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" {
		return input, raw, errors.New("exact normal native Go executable binding mismatch")
	}
	return input, raw, nil
}

func checkNativeSource(root string, files []NativeCheckSourceFile) error {
	if len(files) < 3 || len(files) > 1024 {
		return errors.New("bounded complete native source catalog required")
	}
	expected := make(map[string]NativeCheckSourceFile, len(files))
	var total int64
	last := ""
	for _, row := range files {
		if row.Path <= last || !fs.ValidPath(row.Path) || strings.HasPrefix(row.Path, ".cache/") || row.Path == ".cache" ||
			strings.HasPrefix(row.Path, ".git/") || row.Path == ".git" || !nativeCheckHex.MatchString(row.SHA256) || row.Bytes < 0 || row.Bytes > nativeCheckSourceLimit || (row.Mode != 0600 && row.Mode != 0700) {
			return errors.New("canonical ordered native source catalog required")
		}
		expected[row.Path], last = row, row.Path
		total += row.Bytes
	}
	if total > nativeCheckSourceLimit {
		return errors.New("native source byte budget exceeded")
	}
	for _, required := range []string{"go.mod", "go.sum", "scripts/check.sh"} {
		if _, ok := expected[required]; !ok {
			return errors.New("fixed check source absent from catalog")
		}
	}
	visited, count := []string{}, 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".cache" {
			info, err := entry.Info()
			if err != nil || !entry.IsDir() || info.Mode().Perm() != 0700 || !nativeCheckOwned(info) {
				return errors.Join(err, errors.New("native cache root identity mismatch"))
			}
			return filepath.SkipDir
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
			return errors.New("source-only native checkout must not contain Git metadata")
		}
		count++
		if count > 2048 || strings.Count(rel, "/") > 12 || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("native source tree shape exceeds fixed bounds")
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil || info.Mode().Perm() != 0700 || !nativeCheckOwned(info) {
				return errors.Join(err, errors.New("native source directory identity mismatch"))
			}
			return nil
		}
		row, ok := expected[rel]
		if !ok {
			return errors.New("unlisted native source entry")
		}
		body, err := nativeCheckRead(path, row.Bytes)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil || uint32(info.Mode().Perm()) != row.Mode || int64(len(body)) != row.Bytes || processDigest(body) != row.SHA256 {
			return errors.Join(err, errors.New("native source file binding mismatch"))
		}
		visited = append(visited, rel)
		return nil
	})
	if err != nil {
		return err
	}
	if len(visited) != len(files) {
		return errors.New("native source catalog membership mismatch")
	}
	return nil
}

func nativeCheckWrite(directory, name string, body []byte, limit int) error {
	if len(body) > limit {
		return errors.New("native output file exceeds fixed byte budget")
	}
	f, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(body)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}

func nativeCheckJSON(directory, name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return nativeCheckWrite(directory, name, append(body, '\n'), 256<<10)
}
