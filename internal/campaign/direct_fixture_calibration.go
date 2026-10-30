package campaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

const directFixtureModule = "github.com/pagrus7/kaferry-lab/cmd/direct-fixture-calibration"
const directFixtureModernMode = "native-arm64-manifest-v1"

var directFixtureIncomplete = errors.New("direct fixture calibration incomplete; private originals and external wait/Mac readback required")

// DirectFixtureCalibrationPlan selects one fixed direct lifecycle. It accepts
// no executable, image, command, environment, timeout or cleanup override.
type DirectFixtureCalibrationPlan struct {
	Repository, RunID, ReviewedHead, InputSHA256 string
}

// Machine/SDK archive identities are externally authenticated bindings. The
// controller also checks actual kernel/UID, installed Go bytes/build metadata,
// its own running prebuilt image and every catalogued source file locally.
type DirectFixtureCalibrationInput struct {
	Version, RunID, SourceHead, Repository                      string
	GuestName, GuestMachineID, SDKArchiveSHA256, GoBinarySHA256 string
	ControllerSHA256                                            string
	ControllerBytes                                             int64
	Files                                                       []NativeCheckSourceFile
}

type DirectFixtureCalibrationResult struct {
	Version, Namespace, RunID, SourceHead, InputSHA256, Status             string
	PrivateDirectory, FixturePrivate, ImageArchive                         string
	Synthetic, SourceAdmitted, SourceUnchanged                             bool
	MachineIDExternallyBound, SDKArchiveExternallyBound                    bool
	UpAttempted, UpReturned, ReloadReturned, IdentityAdmitted              bool
	DownAttempted, DownReturned, AbsenceAttempted                          bool
	CleanupSucceeded, ResourcesAbsent                                      bool
	PriorPayloadFilesClosed, NativeDirectFixturePassed                     bool
	OwnFinalCloseProven, ReleaseQualified                                  bool
	RequiresExternalWaitAndMacReadback                                     bool
	ExternalImageOutletProfileImplemented                                  bool
	PlannedExternalImageMaximumBytes, PlannedExternalReceiptAggregateBytes int64
	State                                                                  *fixture.State `json:",omitempty"`
	Absence                                                                fixture.DirectAbsence
	Tree                                                                   LinkCalibrationTree
}

// RunDirectFixtureCalibration builds and launches no lab/test/product image.
// All Docker operations are the existing synchronous fixed fixture functions.
func RunDirectFixtureCalibration(ctx context.Context, p DirectFixtureCalibrationPlan) (r DirectFixtureCalibrationResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	r = newDirectFixtureResult(p)
	directory, sink, reserveErr := reserveDirectFixtureCalibration(p)
	r.PrivateDirectory = directory
	if reserveErr != nil {
		return r, directFixtureIncomplete
	}
	capture := true
	retain := func(action string, cause error) {
		if cause != nil && !retainLinkCalibrationError(sink, []string{action}, cause) {
			capture = false
		}
	}
	finish := func() (DirectFixtureCalibrationResult, error) {
		return finishDirectFixtureCalibration(ctx, directory, sink, r, capture)
	}
	if err = nativeCheckPlatform(); err != nil {
		retain("native_platform", err)
		return finish()
	}
	if err = directFixtureAmbient(); err != nil {
		retain("normal_home_and_default_caches", err)
		return finish()
	}
	if err = directFixtureFreshCache(p); err != nil {
		retain("fresh_attempt_cache", err)
		return finish()
	}
	input, original, err := readDirectFixtureInput(p)
	if err != nil {
		retain("native_source_sdk_and_prebuilt_admission", err)
		capture = false
		return finish()
	}
	if err = nativeCheckWrite(directory, "inputs.json", original, nativeCheckInputLimit); err != nil {
		retain("retain_inputs", err)
		capture = false
		return finish()
	}
	r.SourceAdmitted, r.MachineIDExternallyBound, r.SDKArchiveExternallyBound = true, true, true
	if err = ctx.Err(); err != nil {
		retain("cancelled_before_fixture", err)
		return finish()
	}
	r.Tree, err = prepareLinkCalibrationTree()
	if err != nil {
		retain("dedicated_child_ownership", err)
		return finish()
	}
	steps := directFixtureLifecycleSteps{
		up: func(ctx context.Context, id string) (fixture.State, error) {
			return fixture.Up(ctx, id, fixture.Docker)
		},
		load: fixture.Load, image: fixture.ValidatedBrokerImage,
		down: func(ctx context.Context, s fixture.State) error { return fixture.Down(ctx, s, fixture.Docker) },
		absent: func(ctx context.Context, s fixture.State) (fixture.DirectAbsence, error) {
			return fixture.ObserveDirectAbsence(ctx, s, fixture.Docker)
		},
	}
	err = directFixtureLifecycle(ctx, p.RunID, &r, steps, func(name string, value any) error {
		e := persistLinkCalibrationJSON(directory, name, value)
		if e != nil {
			capture = false
		}
		return e
	})
	retain("direct_fixture_lifecycle", err)
	if err != nil {
		capture = false
	}
	if err != nil && r.State != nil && r.State.RunID == p.RunID && r.State.Proxy == nil {
		e := fixture.StopFixtureEvidence(*r.State, "direct lifecycle controller evidence incomplete")
		retain("stop_incomplete_fixture_evidence", e)
		if e != nil {
			capture = false
		}
	}
	// No synchronous fixture Cmd.Wait owner is active past this boundary. This
	// is the one adopted-drain attempt, including after failed/partial setup.
	deadline, _ := ctx.Deadline()
	end := time.Now().Add(20 * time.Second)
	if deadline.Before(end) {
		end = deadline
	}
	drain, stop := context.WithDeadline(context.Background(), end)
	r.Tree, err = drainLinkCalibrationChildren(drain, r.Tree)
	stop()
	retain("final_dedicated_child_drain", err)
	if e := persistLinkCalibrationJSON(directory, "tree.json", r.Tree); e != nil {
		retain("retain_tree", e)
		capture = false
	}
	if r.Tree.Closed && r.Tree.NoChildren && !r.Tree.ControlFailed {
		post, raw, e := readDirectFixtureInput(p)
		r.SourceUnchanged = e == nil && bytes.Equal(raw, original) && reflect.DeepEqual(post, input)
		if !r.SourceUnchanged {
			retain("source_sdk_prebuilt_postcheck", errors.Join(e, errors.New("admitted source/input or executable changed")))
			capture = false
		}
	}
	return finish()
}

func directFixtureAmbient() error {
	if err := nativeCheckAmbient(); err != nil {
		return err
	}
	return validateDirectFixtureEnvironment(os.Environ())
}

func validateDirectFixtureEnvironment(environment []string) error {
	wanted := map[string]string{"HOME": "/home/labrunner", "PATH": "/usr/local/go/bin:/usr/bin:/bin", "LC_ALL": "C"}
	if len(environment) != len(wanted) {
		return errors.New("fixed normal direct controller environment required")
	}
	seen := map[string]bool{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		want, known := wanted[key]
		if !ok || !known || seen[key] || value != want {
			return errors.New("direct controller environment override rejected")
		}
		seen[key] = true
	}
	return nil
}

func newDirectFixtureResult(p DirectFixtureCalibrationPlan) DirectFixtureCalibrationResult {
	return DirectFixtureCalibrationResult{Version: "1", Namespace: "calibration/native-direct-fixture", RunID: p.RunID, SourceHead: p.ReviewedHead, InputSHA256: p.InputSHA256,
		Status: "INCOMPLETE", Synthetic: true, RequiresExternalWaitAndMacReadback: true,
		FixturePrivate: filepath.Join(p.Repository, ".cache", "fixtures-private", p.RunID+"-brokers"), ImageArchive: filepath.Join(p.Repository, ".cache", "image-identity-data", p.RunID, "images.tar"),
		PlannedExternalImageMaximumBytes: 512 << 20, PlannedExternalReceiptAggregateBytes: 32 << 20}
}

// This private seam tests orchestration connections, not alternative runtime
// backends. Production above supplies only the five fixed fixture functions.
type directFixtureLifecycleSteps struct {
	up     func(context.Context, string) (fixture.State, error)
	load   func(string) (fixture.State, error)
	image  func(fixture.State) (fixture.LinkImageIdentity, error)
	down   func(context.Context, fixture.State) error
	absent func(context.Context, fixture.State) (fixture.DirectAbsence, error)
}

func directFixtureLifecycle(ctx context.Context, runID string, r *DirectFixtureCalibrationResult, steps directFixtureLifecycleSteps, persist func(string, any) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.UpAttempted = true
	s, err := steps.up(ctx, runID)
	r.UpReturned = true
	r.State = &s // even a partial returned plan remains a fact, never authority
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = persist("up.json", s); err != nil {
		return err
	}
	loaded, err := steps.load(runID)
	r.ReloadReturned = true
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s, loaded) || loaded.RunID != runID || loaded.Proxy != nil || loaded.Direct == nil || loaded.WorkerSource != "" || loaded.WorkerDestination != "" {
		return errors.New("direct fixture reload differs from returned complete identity")
	}
	image, err := steps.image(loaded)
	if err != nil {
		return err
	}
	if image.Mode != directFixtureModernMode || image.Manifest == nil || !reflect.DeepEqual(image, loaded.Direct.Image) || !nativeCheckHex.MatchString(image.ProofSHA256) {
		return errors.New("same-run modern stock-save/selected-manifest authority required")
	}
	r.IdentityAdmitted = true
	if err = persist("identity.json", loaded.Direct); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	r.DownAttempted = true
	err = steps.down(ctx, loaded) // exactly one, never a cleanup retry
	r.DownReturned, r.CleanupSucceeded = true, err == nil
	if err != nil {
		return err
	}
	if err = persist("cleanup.json", struct {
		RunID                string
		Identity             *fixture.DirectIdentity
		ReturnedSuccessfully bool
	}{runID, loaded.Direct, true}); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	r.AbsenceAttempted = true
	r.Absence, err = steps.absent(ctx, loaded)
	if err != nil {
		return err
	}
	a := r.Absence
	if !a.Complete || !a.NetworkAbsent || a.ContainersAbsent != [2]bool{true, true} || a.RunID != runID || a.NetworkID != loaded.Direct.NetworkID || !reflect.DeepEqual(a.BrokerIDs, loaded.Direct.BrokerIDs) || a.PrivateReference == "" {
		return errors.New("exact-ID read-only absence witness incomplete or foreign")
	}
	r.ResourcesAbsent = true
	return persist("absence.json", a)
}

func directFixturePass(r DirectFixtureCalibrationResult, capture bool) bool {
	return capture && r.SourceAdmitted && r.SourceUnchanged && r.UpAttempted && r.UpReturned && r.ReloadReturned && r.IdentityAdmitted &&
		r.DownAttempted && r.DownReturned && r.CleanupSucceeded && r.AbsenceAttempted && r.ResourcesAbsent && r.Tree.SubreaperEnabled &&
		r.Tree.Closed && r.Tree.NoChildren && !r.Tree.ControlFailed && !r.Tree.AnchorStarted
}

func finishDirectFixtureCalibration(ctx context.Context, directory string, sink *linkCalibrationSink, r DirectFixtureCalibrationResult, capture bool) (DirectFixtureCalibrationResult, error) {
	if err := ctx.Err(); err != nil {
		capture = retainLinkCalibrationError(sink, []string{"whole_lifecycle_context"}, err) && capture
	}
	r.Status = "INCOMPLETE"
	r.OwnFinalCloseProven, r.ReleaseQualified, r.ExternalImageOutletProfileImplemented = false, false, false
	r.RequiresExternalWaitAndMacReadback = true
	r.PriorPayloadFilesClosed = capture && !sink.broken && !sink.finalized
	r.NativeDirectFixturePassed = directFixturePass(r, r.PriorPayloadFilesClosed && sink.records == 0)
	if r.NativeDirectFixturePassed {
		r.Status = "DIRECT_FIXTURE_PASSED_EXTERNAL_CUSTODY_REQUIRED"
	}
	if err := persistLinkCalibrationJSON(directory, "result.pending.json", r); err != nil {
		retainLinkCalibrationError(sink, []string{"stage_direct_fixture_result"}, err)
		closeLinkCalibrationSink(sink)
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	late := ctx.Err()
	if late != nil {
		retainLinkCalibrationError(sink, []string{"cancellation_after_result_staging"}, late)
	}
	closeErr := closeLinkCalibrationSink(sink)
	if late != nil || closeErr != nil || ctx.Err() != nil {
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	// Publish without replacing an earlier original. Both names are fixed;
	// failed link/unlink/directory sync leaves incomplete bytes for readback.
	pending := filepath.Join(directory, "result.pending.json")
	if err := os.Link(pending, filepath.Join(directory, "result.json")); err != nil {
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	if err := os.Remove(pending); err != nil {
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	if err := syncProcessDirectory(directory); err != nil {
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	// A late cancellation rejects the already serialized candidate through this
	// actual return. It never rewrites a closed result or reopens the error sink.
	if ctx.Err() != nil {
		r.NativeDirectFixturePassed, r.Status = false, "INCOMPLETE"
		return r, directFixtureIncomplete
	}
	if !r.NativeDirectFixturePassed {
		return r, directFixtureIncomplete
	}
	return r, nil
}

func directFixtureDirectory(path string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if real != path || !info.IsDir() || info.Mode().Perm() != 0700 || !nativeCheckOwned(info) {
		return errors.New("canonical owned0700 direct lifecycle directory required")
	}
	return nil
}

func reserveDirectFixtureCalibration(p DirectFixtureCalibrationPlan) (string, *linkCalibrationSink, error) {
	if _, err := fixture.StatePath(p.RunID); err != nil {
		return "", nil, err
	}
	if !nativeCheckHead.MatchString(p.ReviewedHead) || !nativeCheckHex.MatchString(p.InputSHA256) || p.Repository != filepath.Join("/home/labrunner", "kaferry-direct-"+p.RunID, "source") {
		return "", nil, directFixtureIncomplete
	}
	if err := directFixtureDirectory(filepath.Dir(p.Repository)); err != nil {
		return "", nil, err
	}
	if err := directFixtureDirectory(p.Repository); err != nil {
		return "", nil, err
	}
	wd, err := os.Getwd()
	if err != nil || wd != p.Repository {
		return "", nil, errors.Join(err, errors.New("fixed direct source working directory required"))
	}
	return reserveDirectFixturePrivate(p.Repository, p.RunID)
}

func reserveDirectFixturePrivate(repository, runID string) (string, *linkCalibrationSink, error) {
	if _, err := fixture.StatePath(runID); err != nil {
		return "", nil, err
	}
	parent := filepath.Join(repository, ".cache", "direct-fixture-calibration-private")
	for _, path := range []string{filepath.Join(repository, ".cache"), parent} {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
		if err := directFixtureDirectory(path); err != nil {
			return "", nil, err
		}
	}
	directory := filepath.Join(parent, runID)
	if err := os.Mkdir(directory, 0700); err != nil {
		return directory, nil, err
	}
	f, err := os.OpenFile(filepath.Join(directory, "errors.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return directory, nil, err
	}
	sink, err := newLinkCalibrationSink(f, runID)
	return directory, sink, err
}

func directFixtureFreshCache(p DirectFixtureCalibrationPlan) error {
	for path, want := range map[string]map[string]bool{
		filepath.Join(p.Repository, ".cache"):                                       {"direct-fixture-input.json": true, "direct-fixture-calibration-private": true},
		filepath.Join(p.Repository, ".cache", "direct-fixture-calibration-private"): {p.RunID: true},
	} {
		if err := directFixtureDirectory(path); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		entries, readErr := f.ReadDir(4)
		closeErr := f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if len(entries) != len(want) {
			return errors.New("fresh direct source cache has unexpected entries")
		}
		for _, entry := range entries {
			if !want[entry.Name()] {
				return errors.New("fresh direct cache contains another attempt")
			}
		}
	}
	return nil
}

func readDirectFixtureInput(p DirectFixtureCalibrationPlan) (input DirectFixtureCalibrationInput, raw []byte, err error) {
	raw, err = nativeCheckRead(filepath.Join(p.Repository, ".cache", "direct-fixture-input.json"), nativeCheckInputLimit)
	if err != nil {
		return
	}
	if processDigest(raw) != p.InputSHA256 {
		return input, raw, errors.New("direct input digest mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&input); err != nil {
		return
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return input, raw, errors.New("direct input trailing data")
	}
	if input.Version != "1" || input.RunID != p.RunID || input.SourceHead != p.ReviewedHead || input.Repository != p.Repository || input.GuestName != nativeCheckMachine || input.GuestMachineID != nativeCheckMachineID || input.SDKArchiveSHA256 != nativeCheckSDK || !nativeCheckHex.MatchString(input.GoBinarySHA256) || !nativeCheckHex.MatchString(input.ControllerSHA256) || input.ControllerBytes <= 0 || input.ControllerBytes > 32<<20 {
		return input, raw, errors.New("fixed direct input identity mismatch")
	}
	if err = checkNativeSource(p.Repository, input.Files); err != nil {
		return
	}
	required := map[string]bool{"cmd/direct-fixture-calibration/main.go": false, "internal/campaign/direct_fixture_calibration.go": false, "internal/fixture/direct_absence.go": false, "internal/fixture/image_save.go": false}
	for _, row := range input.Files {
		if _, ok := required[row.Path]; ok {
			required[row.Path] = true
		}
	}
	for _, found := range required {
		if !found {
			return input, raw, errors.New("direct source catalog omits a fixed lifecycle source")
		}
	}
	var program *debug.BuildInfo
	program, err = readDirectFixtureProgram("/usr/local/go/bin/go", input.GoBinarySHA256, 0, true)
	if err != nil {
		return
	}
	if err = validateDirectSDKBuild(program); err != nil {
		return
	}
	path := filepath.Join(filepath.Dir(p.Repository), "controller", "direct-fixture-calibration")
	if err = directFixtureDirectory(filepath.Dir(path)); err != nil {
		return
	}
	program, err = readDirectFixtureProgram(path, input.ControllerSHA256, input.ControllerBytes, false)
	if err != nil {
		return
	}
	if err = validateDirectFixtureBuild(program, p.ReviewedHead); err != nil {
		return
	}
	self, ok := debug.ReadBuildInfo()
	if !ok {
		return input, raw, errors.New("running prebuilt metadata unavailable")
	}
	if err = validateDirectFixtureBuild(self, p.ReviewedHead); err != nil {
		return
	}
	var actual, expected os.FileInfo
	actual, err = os.Stat("/proc/self/exe")
	if err != nil {
		return
	}
	expected, err = os.Lstat(path)
	if err != nil {
		return
	}
	if !os.SameFile(actual, expected) {
		return input, raw, errors.New("running controller differs from admitted prebuilt image")
	}
	return
}

func directBuildSettings(info *debug.BuildInfo) (map[string]string, error) {
	if info == nil {
		return nil, errors.New("native executable build information missing")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return nil, errors.New("duplicate native executable build setting")
		}
		settings[setting.Key] = setting.Value
	}
	return settings, nil
}

func validateDirectFixtureBuild(info *debug.BuildInfo, head string) error {
	settings, err := directBuildSettings(info)
	if err != nil {
		return err
	}
	if !nativeCheckHead.MatchString(head) || info.Path != directFixtureModule || info.Main.Path != "github.com/pagrus7/kaferry-lab" || info.GoVersion != "go1.26.0" || settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" || settings["vcs"] != "git" || settings["vcs.revision"] != head || settings["vcs.modified"] != "false" {
		return errors.New("clean reviewed native direct prebuilt module/source required")
	}
	return nil
}

func validateDirectSDKBuild(info *debug.BuildInfo) error {
	settings, err := directBuildSettings(info)
	if err != nil {
		return err
	}
	if info.Path != "cmd/go" || info.GoVersion != "go1.26.0" || settings["GOOS"] != "linux" || settings["GOARCH"] != "arm64" {
		return errors.New("normal reviewed installed native Go required")
	}
	return nil
}

// Exactly two compiled image uses: root-owned normal SDK or this run's owned
// prebuilt driver. No executable is launched by this bounded byte/metadata read.
func readDirectFixtureProgram(path, digest string, expectedBytes int64, sdk bool) (*debug.BuildInfo, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	wantOwner := uint32(os.Geteuid())
	if sdk {
		wantOwner = 0
	}
	if !ok || real != path || !before.Mode().IsRegular() || owner.Uid != wantOwner || owner.Nlink != 1 || before.Size() <= 0 || before.Size() > 32<<20 || before.Mode()&0111 == 0 || before.Mode()&0022 != 0 || !sdk && before.Mode().Perm() != 0700 || expectedBytes > 0 && before.Size() != expectedBytes {
		return nil, errors.New("fixed native executable identity/bound rejected")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened, openErr := f.Stat()
	var header [64]byte
	_, headerErr := f.ReadAt(header[:], 0)
	if headerErr == nil && (!bytes.Equal(header[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) || binary.LittleEndian.Uint16(header[16:18]) != 2 && binary.LittleEndian.Uint16(header[16:18]) != 3 || binary.LittleEndian.Uint16(header[18:20]) != 183) {
		headerErr = errors.New("native Linux ARM64 ELF image required")
	}
	h := sha256.New()
	count, readErr := io.Copy(h, io.LimitReader(f, (32<<20)+1))
	info, buildErr := buildinfo.Read(f)
	after, statErr := f.Stat()
	closeErr := f.Close()
	final, pathErr := os.Lstat(path)
	if err = errors.Join(openErr, headerErr, readErr, buildErr, statErr, closeErr, pathErr); err != nil {
		return nil, err
	}
	stable := func(a, b os.FileInfo) bool {
		if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
			return false
		}
		x, xok := a.Sys().(*syscall.Stat_t)
		y, yok := b.Sys().(*syscall.Stat_t)
		return xok && yok && x.Uid == y.Uid && x.Nlink == y.Nlink
	}
	if !stable(before, opened) || !stable(opened, after) || !stable(after, final) || count != before.Size() || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, errors.New("admitted native executable changed or hash differs")
	}
	return info, nil
}
