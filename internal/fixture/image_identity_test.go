package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeImageState(t *testing.T) State {
	t.Helper()
	s := linkTestState(false)
	s.DockerPlatform = "linux/aarch64"
	s.Proxy.Image = arm64ProxyImage
	s.Proxy.BrokerImageID = arm64BrokerConfigID
	s.Proxy.ImageID = arm64ProxyConfigID
	return s
}

func fixedInspectLiteral(f fixedModernImage, selected bool) []byte {
	d := f.target
	if selected {
		d = f.manifest
	}
	descriptor := map[string]any{"mediaType": d.MediaType, "digest": d.Digest, "size": d.Size}
	if selected && f.role == "broker" {
		descriptor["platform"] = map[string]string{"os": "linux", "architecture": "arm64"}
	}
	b, _ := json.Marshal(map[string]any{"Id": d.Digest, "Os": "linux", "Architecture": "arm64", "RepoDigests": []string{f.reference}, "Descriptor": descriptor})
	return b
}

func TestImageIdentityFixedNativeInspectionDomains(t *testing.T) {
	// Given independently pinned target/child/config tuples, When Docker returns
	// exact generic and selected metadata, Then they remain distinct identities.
	s := nativeImageState(t)
	for _, ref := range []string{Image, arm64ProxyImage} {
		fixed, err := modernImage(s, ref)
		if err != nil {
			t.Fatal(err)
		}
		for _, selected := range []bool{false, true} {
			raw := fixedInspectLiteral(fixed, selected)
			if err := inspectModernImage(raw, fixed, selected); err != nil {
				t.Fatal(err)
			}
			var valid map[string]any
			if json.Unmarshal(raw, &valid) != nil {
				t.Fatal("literal")
			}
			for _, change := range []string{"id", "config-as-runtime", "reference", "platform", "digest", "size", "media", "missing"} {
				t.Run(fixed.role+fmt.Sprint(selected)+change, func(t *testing.T) {
					var object map[string]any
					_ = json.Unmarshal(raw, &object)
					d := object["Descriptor"].(map[string]any)
					switch change {
					case "id":
						object["Id"] = "sha256:" + strings.Repeat("e", 64)
					case "config-as-runtime":
						object["Id"] = fixed.config.Digest
					case "reference":
						object["RepoDigests"] = []string{arm64ProxyImage, Image}
					case "platform":
						d["platform"] = map[string]string{"os": "linux", "architecture": "amd64"}
					case "digest":
						d["digest"] = fixed.config.Digest
					case "size":
						d["size"] = float64(d["size"].(float64)) + 1
					case "media":
						d["mediaType"] = "application/octet-stream"
					case "missing":
						delete(object, "Descriptor")
					}
					bad, _ := json.Marshal(object)
					if inspectModernImage(bad, fixed, selected) == nil {
						t.Fatal("wrong identity admitted")
					}
				})
			}
		}
	}
}

func TestImageIdentityClassicRemainsExactAndRejectsModernFields(t *testing.T) {
	for _, s := range []State{linkTestState(true), nativeImageState(t)} {
		for _, proxy := range []bool{false, true} {
			id, err := ValidatedLinkImage(s, proxy)
			if err != nil {
				t.Fatal(err)
			}
			if id.Mode != classicImageMode || id.Manifest != nil {
				t.Fatal("classic domain changed")
			}
			if err = ValidateLinkContainerImage(s, proxy, id.RuntimeImageID, nil); err != nil {
				t.Fatal(err)
			}
			if ValidateLinkContainerImage(s, proxy, id.RuntimeImageID, &ImageManifestIdentity{}) == nil {
				t.Fatal("classic admitted manifest domain")
			}
		}
	}
	s := nativeImageState(t)
	s.Proxy.ImageIdentity = &LinkImageIdentity{Mode: manifestImageMode, RuntimeImageID: s.Proxy.ImageID, ConfigDigest: arm64ProxyConfigID}
	if _, err := ValidatedLinkImage(s, true); err == nil {
		t.Fatal("conflicting typed state admitted")
	}
	// Selecting proxy does not grant authority over unrelated broker IDs.
	s = linkTestState(true)
	s.Proxy.BrokerImageID = "sha256:" + strings.Repeat("e", 64)
	if _, err := ValidatedLinkImage(s, true); err != nil {
		t.Fatal(err)
	}
}

func TestImageIdentityModernCannotUseAmbiguousJournalOrSelfAssertion(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	fixed, _ := modernImage(s, arm64ProxyImage)
	s.Proxy.ImageID = fixed.runtime
	if _, err := ValidatedLinkImage(s, true); err == nil {
		t.Fatal("untyped modern journal admitted")
	}
	s.Proxy.ImageIdentity = &LinkImageIdentity{Mode: manifestImageMode, RuntimeImageID: fixed.runtime, ConfigDigest: fixed.config.Digest, Manifest: nativeManifest(fixed.manifest), ProofSHA256: strings.Repeat("a", 64)}
	if _, err := ValidatedLinkImage(s, true); err == nil {
		t.Fatal("self-asserted modern journal admitted without original proof")
	}
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatedLinkImage(s, true); err == nil {
		t.Fatal("reservation substituted for raw proof")
	}
	if err := stopLinkOperation(s.RunID, "literal"); err != nil {
		t.Fatal(err)
	}
	if _, err := imagePrivateAuthority(s); err == nil {
		t.Fatal("stop ignored")
	}
}

func TestImageIdentityUnlinkedModernRefusesBeforeCreateOrCleanup(t *testing.T) {
	t.Chdir(t.TempDir())
	var calls []string
	s := nativeImageState(t)
	fixed, _ := modernImage(s, Image)
	run := func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "info":
			return []byte("linux/aarch64"), nil
		case "pull":
			return nil, nil
		case "image":
			return fixedInspectLiteral(fixed, false), nil
		default:
			t.Fatalf("mutation after missing authority: %v", args)
		}
		return nil, nil
	}
	if _, err := Up(context.Background(), "test", run); err == nil {
		t.Fatal("modern M0 without private authority admitted")
	}
	if len(calls) != 3 {
		t.Fatal(calls)
	}
}

func TestImageIdentitySelectedReadbackRetainedBeforeSemanticRefusal(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	fixed, _ := modernImage(s, Image)
	raw := fixedInspectLiteral(fixed, true)
	bad := bytes.Replace(raw, []byte(`"architecture":"arm64"`), []byte(`"architecture":"amd64"`), 1)
	calls := 0
	run, err := linkExecutor(s.RunID, func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) != 7 {
			t.Fatal(args)
		}
		return bad, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admitModernImage(context.Background(), run, s, Image, fixedInspectLiteral(fixed, false)); err == nil {
		t.Fatal("wrong native child admitted")
	}
	if calls != 1 {
		t.Fatal("selected inspection retried")
	}
	files, err := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "operation-*", "docker-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range files {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var receipt struct {
			Combined            []byte
			PrivateReadbackKind string
			CommandSucceeded    bool
		}
		_ = json.Unmarshal(b, &receipt)
		if receipt.PrivateReadbackKind == "linked-docker-selected-native-image-inspect" && receipt.CommandSucceeded && bytes.Equal(receipt.Combined, bad) {
			found = true
		}
	}
	if !found {
		t.Fatal("selected original discarded before semantic refusal")
	}
	if _, err = os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); err != nil {
		t.Fatal("semantic refusal did not stop")
	}
	if _, err = run(context.Background(), "info"); err == nil || calls != 1 {
		t.Fatal("stopped facility reused")
	}
}

// The helper is the current Go test binary. No Docker executable or daemon is
// selected by these process-controller controls.
func TestImageSaveProcessHelper(t *testing.T) {
	mode := os.Getenv("KAFERRY_IMAGE_SAVE_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "success":
		_, _ = os.Stdout.Write([]byte("synthetic archive prefix"))
		_, _ = os.Stderr.Write([]byte("PRIVATE-stderr\x00\xff"))
	case "exit":
		_, _ = os.Stderr.Write([]byte("PRIVATE-original-denial\x00\xff"))
		os.Exit(23)
	case "stderr-overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("e"), linkOutputLimit*3))
	case "wait":
		time.Sleep(5 * time.Second)
	default:
		os.Exit(24)
	}
	os.Exit(0)
}

func imageHelperCommand(mode string) imageSaveCommand {
	return func(ctx context.Context, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestImageSaveProcessHelper$")
		cmd.Env = append(os.Environ(), "KAFERRY_IMAGE_SAVE_HELPER="+mode)
		return cmd
	}
}

func TestImageSaveControllerDirectWaitStreamsAndFailureControls(t *testing.T) {
	for _, mode := range []string{"success", "exit", "stderr-overflow", "wait", "sink-closed", "start-failure"} {
		t.Run(mode, func(t *testing.T) {
			f, err := os.OpenFile(filepath.Join(t.TempDir(), "archive"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			factory := imageHelperCommand(mode)
			ctx := context.Background()
			var cancel context.CancelFunc
			if mode == "wait" {
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			if mode == "sink-closed" {
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				factory = imageHelperCommand("success")
			}
			if mode == "start-failure" {
				factory = func(ctx context.Context, _ ...string) *exec.Cmd {
					return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing-selected-command"))
				}
			}
			r, err := executeImageSave(ctx, State{RunID: "test"}, f, factory)
			if mode == "success" {
				if err != nil || !r.Started || !r.WaitReturned || !r.TerminalWait || !r.StdoutEOF || !r.StderrEOF || !r.PipesClosed || r.ArchiveBytes != int64(len("synthetic archive prefix")) || !bytes.Equal(r.Stderr, []byte("PRIVATE-stderr\x00\xff")) {
					t.Fatalf("actual success accounting missing: %+v %v", r, err)
				}
			} else if err == nil {
				t.Fatal("failure detector admitted failed controller")
			}
			if mode != "start-failure" && (!r.WaitReturned || !r.TerminalWait) {
				t.Fatal("actual direct terminal wait missing")
			}
			if mode == "exit" && (!bytes.Equal(r.Stderr, []byte("PRIVATE-original-denial\x00\xff")) || r.ExitCode == nil || *r.ExitCode != 23) {
				t.Fatal("exact denial/exit lost")
			}
			if mode == "stderr-overflow" && (len(r.Stderr) != linkOutputLimit || r.ObservedStderrBytes <= linkOutputLimit) {
				t.Fatal("stderr bound not reached/retained")
			}
			if mode == "sink-closed" && !errors.Is(err, os.ErrClosed) {
				t.Fatal("original archive sink cause lost")
			}
			if mode == "wait" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline cause lost")
			}
		})
	}
}

func TestImageSaveBoundStopsWriterAtFirstOverflow(t *testing.T) {
	var saved bytes.Buffer
	canceled := 0
	w := &imageSaveWriter{writer: &saved, limit: 7, cancel: func() { canceled++ }}
	if n, e := w.Write([]byte("12345")); e != nil || n != 5 {
		t.Fatal(n, e)
	}
	if n, e := w.Write([]byte("6789")); e == nil || n != 2 || canceled != 1 || saved.String() != "1234567" || w.observed != 9 {
		t.Fatal("overflow not reached and bounded")
	}
}

func TestImageSaveFailureRetainsCauseAndStopsAllLaterCommands(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	factory := imageSaveCommand(func(ctx context.Context, args ...string) *exec.Cmd {
		calls++
		return imageHelperCommand("exit")(ctx, args...)
	})
	ctx := context.WithValue(context.Background(), imageSaveCommandKey{}, factory)
	if err := ensureSavedImages(ctx, s); err == nil {
		t.Fatal("failed save admitted")
	}
	b, err := os.ReadFile(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-attempt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r imageSaveReceipt
	if json.Unmarshal(b, &r) != nil || r.Complete || !r.WaitReturned || !r.TerminalWait || !r.ArchiveClosed || !bytes.Equal(r.Stderr, []byte("PRIVATE-original-denial\x00\xff")) || !r.CauseComplete || len(r.Cause) == 0 {
		t.Fatal("actual failure evidence incomplete", string(b))
	}
	if err = ensureSavedImages(ctx, s); err == nil || calls != 1 {
		t.Fatal("failed selected save retried")
	}
	run, err := linkExecutor(s.RunID, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("Docker after save failure")
		return nil, nil
	})
	if err == nil || run != nil {
		t.Fatal("save stop did not gate ordinary Docker")
	}
}

func TestImageSaveMissingReservationAndPartialArchiveNeverRetry(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	calls := 0
	ctx := context.WithValue(context.Background(), imageSaveCommandKey{}, imageSaveCommand(func(ctx context.Context, args ...string) *exec.Cmd {
		calls++
		return imageHelperCommand("success")(ctx, args...)
	}))
	if ensureSavedImages(ctx, s) == nil || calls != 0 {
		t.Fatal("invented private authority")
	}
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(imageDataDirectory(s), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(savedImageArchivePath(s), []byte("retained partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if ensureSavedImages(ctx, s) == nil || calls != 0 {
		t.Fatal("partial archive replaced or command retried")
	}
	b, err := os.ReadFile(savedImageArchivePath(s))
	if err != nil || string(b) != "retained partial" {
		t.Fatal("partial original changed")
	}
}

func TestImageIdentityContainerCandidateOriginalSurvivesRefusal(t *testing.T) {
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"Id":"` + s.Proxy.ContainerID + `","Image":"wrong-runtime","ImageManifestDescriptor":{"digest":"wrong-child"},"PRIVATE":"original"}`)
	calls := 0
	run, err := linkExecutor(s.RunID, func(context.Context, ...string) ([]byte, error) { calls++; return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = inspectLinkContainer(context.Background(), s, run, 2, s.Proxy.NetworkID, s.Proxy.ImageID, true); err == nil {
		t.Fatal("wrong container image admitted")
	}
	files, _ := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "operation-*", "docker-*.json"))
	found := false
	for _, name := range files {
		body, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		var got struct {
			PrivateReadbackKind string
			Combined            []byte
			CommandSucceeded    bool
			SemanticAdmission   string
		}
		_ = json.Unmarshal(body, &got)
		if got.PrivateReadbackKind == "linked-docker-container-candidate-inspect" && got.CommandSucceeded && got.SemanticAdmission == "not-observed-by-executor" && bytes.Equal(got.Combined, raw) {
			found = true
		}
	}
	if calls != 1 || !found {
		t.Fatal("candidate original discarded")
	}
}

func TestImageIdentityPartialArchiveReservationFailureStopsBeforeCreation(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(imageDataDirectory(s), 0700); err != nil {
		t.Fatal(err)
	}
	// A retained partial archive is never overwritten by save or converted into
	// a complete receipt merely because the next selected inspections succeed.
	if err := os.WriteFile(savedImageArchivePath(s), []byte("PRIVATE-original-partial"), 0600); err != nil {
		t.Fatal(err)
	}
	fixed, _ := modernImage(s, Image)
	calls := 0
	run := func(context.Context, ...string) ([]byte, error) {
		calls++
		return fixedInspectLiteral(fixed, true), nil
	}
	if _, err := admitModernImage(context.Background(), run, s, Image, fixedInspectLiteral(fixed, false)); err == nil {
		t.Fatal("partial selected archive admitted")
	}
	files, _ := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-control-*.json"))
	if len(files) != 1 {
		t.Fatal("missing pre-reserved original cause")
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var notice struct {
		Cause         []byte
		CauseComplete bool
	}
	if json.Unmarshal(body, &notice) != nil || !notice.CauseComplete || !bytes.Contains(notice.Cause, []byte("file exists")) {
		t.Fatal("exact filesystem cause lost", string(body))
	}
	if _, err = os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "STOPPED.json")); err != nil {
		t.Fatal("sink failure did not gate")
	}
	if calls != 1 {
		t.Fatal("selected inspection repeated")
	}
}

func literalImageSaveCompletion(s State) imageSaveReceipt {
	zero := 0
	argv := []string{"docker", "image", "save", "--platform=linux/arm64", Image, arm64ProxyImage}
	return imageSaveReceipt{RunID: s.RunID, Argv: argv, ExecutedArgv: append([]string{}, argv...), ExecutablePath: "/usr/bin/docker", Started: true, WaitReturned: true, TerminalWait: true, StdoutEOF: true, StderrEOF: true, PipesClosed: true, ArchiveClosed: true, Complete: true, ArchiveBytes: 2048, ObservedArchiveBytes: 2048, ExitCode: &zero}
}

func TestImageProofReuseRequiresActualSaveLifecycleFields(t *testing.T) {
	// These independent literal records challenge the reader; they are synthetic
	// fixtures, never asserted to be native waits or executed save receipts.
	for _, kind := range []string{"literal", "wait", "terminal", "stdout", "stderr-eof", "pipes", "archive", "exit", "partial", "count", "stderr-notice", "cause", "argv", "executed-argv", "executable", "run"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := nativeImageState(t)
			if err := reserveLinkEvidence(s.RunID); err != nil {
				t.Fatal(err)
			}
			r := literalImageSaveCompletion(s)
			switch kind {
			case "wait":
				r.WaitReturned = false
			case "terminal":
				r.TerminalWait = false
			case "stdout":
				r.StdoutEOF = false
			case "stderr-eof":
				r.StderrEOF = false
			case "pipes":
				r.PipesClosed = false
			case "archive":
				r.ArchiveClosed = false
			case "exit":
				code := 23
				r.ExitCode = &code
			case "partial":
				r.Complete = false
			case "count":
				r.ObservedArchiveBytes++
			case "stderr-notice":
				r.Stderr = []byte("PRIVATE-notice")
				r.ObservedStderrBytes = int64(len(r.Stderr))
			case "cause":
				r.Cause = []byte("PRIVATE-original-refusal")
			case "argv":
				r.Argv[3] = "--platform=linux/amd64"
			case "executed-argv":
				r.ExecutedArgv = r.ExecutedArgv[:len(r.ExecutedArgv)-1]
			case "executable":
				r.ExecutablePath = "/other/oci-client"
			case "run":
				r.RunID = "other"
			}
			if _, err := writeLinkPrivate(linkPrivateDirectory(s.RunID), "image-save-complete.json", r); err != nil {
				t.Fatal(err)
			}
			_, err := validatedImageSaveReceipt(s)
			if (err == nil) != (kind == "literal") {
				t.Fatal("save lifecycle sensitivity", kind, err)
			}
			calls := 0
			ctx := context.WithValue(context.Background(), imageSaveCommandKey{}, imageSaveCommand(func(context.Context, ...string) *exec.Cmd { calls++; t.Fatal("reuse failure retried save"); return nil }))
			if err = ensureSavedImages(ctx, s); (err == nil) != (kind == "literal") || calls != 0 {
				t.Fatal("reuse selected an alternate execution", err)
			}
		})
	}
}

func TestImageProofReusePreservesReadAndJSONCauses(t *testing.T) {
	t.Chdir(t.TempDir())
	s := nativeImageState(t)
	if err := reserveLinkEvidence(s.RunID); err != nil {
		t.Fatal(err)
	}
	fixed, _ := modernImage(s, Image)
	if _, err := loadImageProof(s, fixed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original proof read cause lost", err)
	}
	path := imageProofPath(s, fixed)
	if err := os.WriteFile(path, []byte(`{"RunID":!}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadImageProof(s, fixed)
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatal("original proof JSON cause lost", err)
	}
	if err = os.WriteFile(filepath.Join(linkPrivateDirectory(s.RunID), "image-save-complete.json"), []byte(`{"RunID":!}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = validatedImageSaveReceipt(s)
	if !errors.As(err, &syntax) {
		t.Fatal("original save JSON cause lost", err)
	}
}
