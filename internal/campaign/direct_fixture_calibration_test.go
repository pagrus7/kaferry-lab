package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func directLifecycleLiteral() fixture.State {
	id := "direct-inert"
	prefix := "kaferry-lab-" + id
	image := fixture.LinkImageIdentity{Mode: directFixtureModernMode, RuntimeImageID: "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02", ConfigDigest: "sha256:5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f", ProofSHA256: strings.Repeat("e", 64), Manifest: &fixture.ImageManifestIdentity{Digest: "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", MediaType: "application/vnd.oci.image.manifest.v1+json", Size: 2201}}
	image.Manifest.Platform.OS, image.Manifest.Platform.Architecture = "linux", "arm64"
	return fixture.State{RunID: id, Image: fixture.Image, Network: prefix, Containers: []string{prefix + "-source", prefix + "-dest"}, Source: "127.0.0.1:21092", Destination: "127.0.0.1:22092", DockerPlatform: "linux/arm64", ClusterIDs: []string{"AAAAAAAAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEBAQEBAQ"}, Created: "2026-10-29T01:02:03Z", Direct: &fixture.DirectIdentity{RunID: id, ManifestSHA256: strings.Repeat("f", 64), NetworkID: strings.Repeat("d", 64), BrokerIDs: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}, Image: image}}
}

func cloneDirectLifecycle(t *testing.T, s fixture.State) fixture.State {
	t.Helper()
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var copy fixture.State
	if err = json.Unmarshal(body, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func literalDirectSteps(t *testing.T, s fixture.State, calls *[]string) directFixtureLifecycleSteps {
	t.Helper()
	return directFixtureLifecycleSteps{
		up: func(ctx context.Context, id string) (fixture.State, error) {
			*calls = append(*calls, "up")
			if id != s.RunID {
				t.Fatal("wrong Up identity")
			}
			return cloneDirectLifecycle(t, s), nil
		},
		load: func(id string) (fixture.State, error) {
			*calls = append(*calls, "load")
			if id != s.RunID {
				t.Fatal("wrong reload identity")
			}
			return cloneDirectLifecycle(t, s), nil
		},
		image: func(got fixture.State) (fixture.LinkImageIdentity, error) {
			*calls = append(*calls, "image")
			return got.Direct.Image, nil
		},
		down: func(_ context.Context, got fixture.State) error {
			*calls = append(*calls, "down")
			if !reflect.DeepEqual(got, s) {
				t.Fatal("cleanup gained foreign authority")
			}
			return nil
		},
		absent: func(_ context.Context, got fixture.State) (fixture.DirectAbsence, error) {
			*calls = append(*calls, "absence")
			return fixture.DirectAbsence{RunID: got.RunID, NetworkID: got.Direct.NetworkID, BrokerIDs: append([]string{}, got.Direct.BrokerIDs...), ContainersAbsent: [2]bool{true, true}, NetworkAbsent: true, Complete: true, PrivateReference: "inert-private-absence-receipt"}, nil
		},
	}
}

func TestDirectFixtureLifecycleOrderUsesOneCleanupThenReadOnlyAbsence(t *testing.T) {
	// Given visibly literal modern identities and inert synchronous operations,
	// When lifecycle orchestration runs, Then it reloads/admit proof before its
	// sole cleanup and obtains separate absence evidence, never a second Down.
	s := directLifecycleLiteral()
	var calls, receipts []string
	r := newDirectFixtureResult(DirectFixtureCalibrationPlan{RunID: s.RunID})
	err := directFixtureLifecycle(context.Background(), s.RunID, &r, literalDirectSteps(t, s, &calls), func(name string, _ any) error { receipts = append(receipts, name); return nil })
	if err != nil || !reflect.DeepEqual(calls, []string{"up", "load", "image", "down", "absence"}) || !r.ResourcesAbsent || !r.CleanupSucceeded {
		t.Fatal("wrong lifecycle boundary", calls, r, err)
	}
	if !reflect.DeepEqual(receipts, []string{"up.json", "identity.json", "cleanup.json", "absence.json"}) {
		t.Fatal("mandatory evidence ordering", receipts)
	}
	if r.NativeDirectFixturePassed || r.OwnFinalCloseProven || r.ReleaseQualified || r.ExternalImageOutletProfileImplemented || !r.RequiresExternalWaitAndMacReadback {
		t.Fatal("literal operations claimed native/external completion")
	}
}

func TestDirectFixtureLifecycleFailuresNeverRetryCleanupOrBypassEvidence(t *testing.T) {
	// Given the exact orchestration seam, When a specific upstream operation,
	// identity, evidence sink or post-cleanup witness fails, Then later commands
	// are absent and the returned lifecycle cannot pass. No Docker runs here.
	for _, fault := range []string{"up", "reload", "changed-reload", "missing-identity", "proof", "classic", "up-sink", "identity-sink", "down", "cleanup-sink", "absence", "foreign-absence", "absence-sink", "cancel-before-down"} {
		t.Run(fault, func(t *testing.T) {
			s := directLifecycleLiteral()
			var calls []string
			steps := literalDirectSteps(t, s, &calls)
			cause := errors.New("SYNTHETIC reached " + fault)
			switch fault {
			case "up":
				steps.up = func(context.Context, string) (fixture.State, error) {
					calls = append(calls, "up")
					return fixture.State{RunID: s.RunID}, cause
				}
			case "reload":
				steps.load = func(string) (fixture.State, error) { calls = append(calls, "load"); return fixture.State{}, cause }
			case "changed-reload", "missing-identity":
				steps.load = func(string) (fixture.State, error) {
					calls = append(calls, "load")
					copy := cloneDirectLifecycle(t, s)
					if fault == "changed-reload" {
						copy.Destination = "127.0.0.1:24092"
					} else {
						copy.Direct = nil
					}
					return copy, nil
				}
			case "proof":
				steps.image = func(fixture.State) (fixture.LinkImageIdentity, error) {
					calls = append(calls, "image")
					return fixture.LinkImageIdentity{}, cause
				}
			case "classic":
				s.Direct.Image.Mode = "exact-config-v1"
				steps = literalDirectSteps(t, s, &calls)
			case "down":
				steps.down = func(context.Context, fixture.State) error { calls = append(calls, "down"); return cause }
			case "absence":
				steps.absent = func(context.Context, fixture.State) (fixture.DirectAbsence, error) {
					calls = append(calls, "absence")
					return fixture.DirectAbsence{}, cause
				}
			case "foreign-absence":
				steps.absent = func(context.Context, fixture.State) (fixture.DirectAbsence, error) {
					calls = append(calls, "absence")
					return fixture.DirectAbsence{RunID: "foreign", Complete: true, ContainersAbsent: [2]bool{true, true}, NetworkAbsent: true}, nil
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := newDirectFixtureResult(DirectFixtureCalibrationPlan{RunID: s.RunID})
			err := directFixtureLifecycle(ctx, s.RunID, &r, steps, func(name string, _ any) error {
				if fault == "cancel-before-down" && name == "identity.json" {
					cancel()
				}
				if fault == strings.TrimSuffix(name, ".json")+"-sink" {
					return cause
				}
				return nil
			})
			if err == nil || r.ResourcesAbsent && fault != "absence-sink" {
				t.Fatal("reached failure passed", fault, calls, r, err)
			}
			want := []string{"up", "load", "image", "down", "absence"}
			switch fault {
			case "up", "up-sink":
				want = want[:1]
			case "reload", "changed-reload", "missing-identity":
				want = want[:2]
			case "proof", "classic", "identity-sink", "cancel-before-down":
				want = want[:3]
			case "down", "cleanup-sink":
				want = want[:4]
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatal("upstream refusal reached later operation/retry", fault, calls, want)
			}
			if r.NativeDirectFixturePassed || r.OwnFinalCloseProven || r.ReleaseQualified {
				t.Fatal("failure claimed completion")
			}
		})
	}
}

func directBuildLiteral() *debug.BuildInfo {
	return &debug.BuildInfo{Path: directFixtureModule, GoVersion: "go1.26.0", Main: debug.Module{Path: "github.com/pagrus7/kaferry-lab"}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "arm64"}, {Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.modified", Value: "false"}}}
}

func TestDirectFixtureAmbientCannotRedirectDockerOrDefaultCaches(t *testing.T) {
	// Given the fixed parent's three-entry environment, When an inherited Docker,
	// loader or cache override is added, Then it refuses instead of using another
	// facility. The production check reads values but never prints credentials.
	good := []string{"HOME=/home/labrunner", "PATH=/usr/local/go/bin:/usr/bin:/bin", "LC_ALL=C"}
	if err := validateDirectFixtureEnvironment(good); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"DOCKER_HOST=unix:///SYNTHETIC-other.sock", "DOCKER_CONFIG=/SYNTHETIC-other", "GOCACHE=/SYNTHETIC-other", "LD_PRELOAD=/SYNTHETIC-other", "HOME=/SYNTHETIC-other"} {
		if err := validateDirectFixtureEnvironment(append(append([]string{}, good...), entry)); err == nil {
			t.Fatal("environment redirect admitted", entry)
		}
	}
	changed := append([]string{}, good...)
	changed[1] = "PATH=/SYNTHETIC-other"
	if err := validateDirectFixtureEnvironment(changed); err == nil {
		t.Fatal("another executable search path admitted")
	}
}

func TestDirectFixturePrebuiltAdmissionIsModuleSourceAndNativeSpecific(t *testing.T) {
	// Given literal embedded build data, When module/source/native settings
	// change, Then the direct driver cannot borrow native-check/link build facts.
	for _, fault := range []string{"good", "native-check", "test", "dirty", "head", "arch", "sdk", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			info := directBuildLiteral()
			switch fault {
			case "native-check":
				info.Path = "github.com/pagrus7/kaferry-lab/cmd/native-check"
			case "test":
				info.Path = "github.com/pagrus7/kaferry-lab/internal/campaign.test"
			case "dirty":
				info.Settings[4].Value = "true"
			case "head":
				info.Settings[3].Value = strings.Repeat("b", 40)
			case "arch":
				info.Settings[1].Value = "amd64"
			case "sdk":
				info.GoVersion = "go1.27.2"
			case "duplicate":
				info.Settings = append(info.Settings, info.Settings[0])
			}
			if err := validateDirectFixtureBuild(info, strings.Repeat("a", 40)); (err == nil) != (fault == "good") {
				t.Fatal("wrong direct prebuilt identity admitted", fault, err)
			}
		})
	}
}

func TestDirectFixtureFreshReservationAndCacheCannotReuseAnAttempt(t *testing.T) {
	// Given a canonical private source root, When a prior fixture/archive or
	// run reservation exists, Then it is rejected rather than granting reuse.
	for _, fault := range []string{"healthy", "fixture-plan", "archive", "reservation-collision", "private-symlink"} {
		t.Run(fault, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			p := DirectFixtureCalibrationPlan{Repository: root, RunID: "direct-inert"}
			if err = os.Mkdir(filepath.Join(root, ".cache"), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, ".cache", "direct-fixture-input.json"), []byte("literal only"), 0600); err != nil {
				t.Fatal(err)
			}
			if fault == "private-symlink" {
				target := filepath.Join(root, "original-private")
				if err = os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(target, filepath.Join(root, ".cache", "direct-fixture-calibration-private")); err != nil {
					t.Fatal(err)
				}
			}
			directory, sink, err := reserveDirectFixturePrivate(root, p.RunID)
			if fault == "private-symlink" {
				if err == nil {
					t.Fatal("private symlink admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if !sink.finalized {
					_ = closeLinkCalibrationSink(sink)
				}
			}()
			body, err := os.ReadFile(filepath.Join(directory, "errors.json"))
			if err != nil || len(body) == 0 {
				t.Fatal("missing first sink before admission", err)
			}
			if fault == "reservation-collision" {
				if _, _, err = reserveDirectFixturePrivate(root, p.RunID); err == nil {
					t.Fatal("run reservation reused")
				}
				after, _ := os.ReadFile(filepath.Join(directory, "errors.json"))
				if string(after) != string(body) {
					t.Fatal("first prefix replaced")
				}
				return
			}
			if fault == "fixture-plan" {
				if err = os.Mkdir(filepath.Join(root, ".cache", "fixtures"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "archive" {
				if err = os.Mkdir(filepath.Join(root, ".cache", "image-identity-data"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err = directFixtureFreshCache(p); (err == nil) != (fault == "healthy") {
				t.Fatal("prior fixture/save authority reused", fault, err)
			}
		})
	}
}

func directPassedLiteral() DirectFixtureCalibrationResult {
	r := newDirectFixtureResult(DirectFixtureCalibrationPlan{RunID: "direct-inert"})
	r.SourceAdmitted, r.SourceUnchanged, r.UpAttempted, r.UpReturned, r.ReloadReturned, r.IdentityAdmitted = true, true, true, true, true, true
	r.DownAttempted, r.DownReturned, r.CleanupSucceeded, r.AbsenceAttempted, r.ResourcesAbsent = true, true, true, true, true
	r.Tree = LinkCalibrationTree{SubreaperEnabled: true, Closed: true, NoChildren: true}
	return r
}

// This literal Context fires at a selected finalization observation. It never
// runs a process; it makes loss of a newly observed late cancel deterministic.
type directLateContext struct {
	context.Context
	calls, at int
	cancel    context.CancelFunc
}

func (c *directLateContext) Err() error {
	c.calls++
	if c.calls == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestDirectFixtureFinalizationRejectsMissingWaitSinkAndLateCancellation(t *testing.T) {
	// Given literal completed inner facts, When an original error/tree witness,
	// sink/publication or late cancellation refuses, Then actual return stays failed
	// without replacing a serialized candidate or reopening the primary sink.
	for _, fault := range []string{"good", "live-child", "wait-uncertain", "primary-error", "staging-collision", "sink-close", "publication-collision", "late-stage", "late-close", "late-publication"} {
		t.Run(fault, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			directory, sink, err := reserveDirectFixturePrivate(root, "direct-inert")
			if err != nil {
				t.Fatal(err)
			}
			r := directPassedLiteral()
			ctx := context.Context(context.Background())
			cancelAt := func(at int) context.Context {
				base, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				return &directLateContext{Context: base, at: at, cancel: cancel}
			}
			switch fault {
			case "live-child":
				r.Tree.NoChildren = false
			case "wait-uncertain":
				r.Tree.ControlFailed = true
			case "primary-error":
				if !retainLinkCalibrationError(sink, []string{"literal refusal"}, errors.New("SYNTHETIC private refusal")) {
					t.Fatal("sink failed")
				}
			case "staging-collision":
				if err = os.WriteFile(filepath.Join(directory, "result.pending.json"), []byte("prior original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "sink-close":
				if err = sink.Close(); err != nil {
					t.Fatal(err)
				}
			case "publication-collision":
				if err = os.WriteFile(filepath.Join(directory, "result.json"), []byte("prior final original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "late-stage":
				ctx = cancelAt(2)
			case "late-close":
				ctx = cancelAt(3)
			case "late-publication":
				ctx = cancelAt(4)
			}
			got, err := finishDirectFixtureCalibration(ctx, directory, sink, r, true)
			if (err == nil) != (fault == "good") || got.NativeDirectFixturePassed != (fault == "good") {
				t.Fatal("failed finalization admitted", fault, got, err)
			}
			if got.OwnFinalCloseProven || got.ReleaseQualified || got.ExternalImageOutletProfileImplemented || !got.RequiresExternalWaitAndMacReadback {
				t.Fatal("self-asserted external custody")
			}
			if !sink.finalized {
				t.Fatal("primary sink not finalized")
			}
			if fault == "staging-collision" {
				body, _ := os.ReadFile(filepath.Join(directory, "result.pending.json"))
				if string(body) != "prior original" {
					t.Fatal("prior pending original replaced")
				}
			}
			if fault == "publication-collision" {
				body, _ := os.ReadFile(filepath.Join(directory, "result.json"))
				if string(body) != "prior final original" {
					t.Fatal("prior final original replaced")
				}
			}
		})
	}
}

func TestDirectFixtureWholeCancellationPreventsFirstOperation(t *testing.T) {
	// Given an already cancelled controller context, When orchestration begins,
	// Then not even Up is attempted; there is no fresh cleanup context fallback.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := directLifecycleLiteral()
	calls := []string{}
	r := newDirectFixtureResult(DirectFixtureCalibrationPlan{RunID: s.RunID})
	err := directFixtureLifecycle(ctx, s.RunID, &r, literalDirectSteps(t, s, &calls), func(string, any) error { t.Fatal("cancelled operation wrote a stage"); return nil })
	if !errors.Is(err, context.Canceled) || len(calls) != 0 || r.UpAttempted {
		t.Fatal("cancelled operation reached a route", calls, r, err)
	}
}
