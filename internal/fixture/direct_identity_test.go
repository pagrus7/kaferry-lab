package fixture

import (
	"archive/tar"
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

// Every Docker response below is inert literal data; no daemon/image/product
// runs. The actual fixed broker-only image-save format remains a native control.
func directPlanLiteral(id, platform string) State {
	prefix := "kaferry-lab-" + id
	return State{RunID: id, Image: Image, Network: prefix, Containers: []string{prefix + "-source", prefix + "-dest"}, Source: "127.0.0.1:21092", Destination: "127.0.0.1:22092", DockerPlatform: platform, ClusterIDs: []string{"AAAAAAAAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEBAQEBAQ"}, Created: "2026-10-29T01:02:03Z"}
}

func TestDirectReservationCanonicalizesOnlyCurrentDirectoryAlias(t *testing.T) {
	// Given a logical PWD alias for the actual workspace, When its direct root
	// is reserved, Then canonical admission binds the same directory and allows
	// the first info command. The old Abs-vs-Eval comparison rejects this input.
	workspace := t.TempDir()
	alias := filepath.Join(t.TempDir(), "workspace-alias")
	if err := os.Symlink(workspace, alias); err != nil {
		t.Fatal(err)
	}
	t.Chdir(alias)
	t.Setenv("PWD", alias)
	if err := reservePrivateFixtureEvidence("test", directPrivateDirectory("test")); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directPrivateDirectory("test"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil || absolute == canonical {
		t.Fatal("logical current-directory alias was not reached", absolute, canonical, err)
	}
	calls := 0
	run, err := privateFixtureExecutor("test", directPrivateDirectory("test"), func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if !reflect.DeepEqual(args, []string{"info", "--format", "{{.OSType}}/{{.Architecture}}"}) {
			t.Fatal("unexpected command", args)
		}
		return []byte("linux/arm64"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = run(context.Background(), "info", "--format", "{{.OSType}}/{{.Architecture}}"); err != nil || calls != 1 {
		t.Fatal("canonical workspace alias refused before first info", err, calls)
	}
}

func TestDirectReservationStillRejectsSymlinkInsideRunOwnedPath(t *testing.T) {
	// Given a valid reserved root, When an owned path component is replaced by
	// a symlink to its unchanged original, Then canonical admission still refuses
	// before any executor call; canonicalizing the workspace grants no redirect.
	for _, component := range []string{"cache", "private-parent", "run-root"} {
		t.Run(component, func(t *testing.T) {
			t.Chdir(t.TempDir())
			root := directPrivateDirectory("test")
			if err := reservePrivateFixtureEvidence("test", root); err != nil {
				t.Fatal(err)
			}
			path := root
			if component == "private-parent" {
				path = filepath.Dir(root)
			} else if component == "cache" {
				path = ".cache"
			}
			original := path + "-original"
			if err := os.Rename(path, original); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(original), path); err != nil {
				t.Fatal(err)
			}
			if _, err := privateFixtureExecutor("test", root, func(context.Context, ...string) ([]byte, error) {
				t.Fatal("owned path symlink reached Docker")
				return nil, nil
			}); err == nil {
				t.Fatal("symlinked owned reservation admitted", component)
			}
		})
	}
}

type directDockerControl struct {
	t              *testing.T
	state          State
	calls          [][]string
	removed        map[string]bool
	networkRemoved bool
	change         func(string, map[string]any)
	modern         bool
	archive        []byte // inert metadata-only specimen, never a runnable saved image
}

func newDirectDockerControl(t *testing.T) *directDockerControl {
	return &directDockerControl{t: t, state: directPlanLiteral("test", "linux/amd64"), removed: map[string]bool{}}
}

func directInertProbe(context.Context, string) (linkBrokerProbeResult, error) {
	return linkBrokerProbeResult{Opened: true, Closed: true, Version: 0, APIKeys: 1}, nil
}

func upDirectControl(ctx context.Context, run Executor) (State, error) {
	return up(ctx, "test", run, false, nil, directInertProbe)
}

func directContainerLiteral(s State, i int, image LinkImageIdentity) map[string]any {
	name, endpoint := s.Containers[i], []string{s.Source, s.Destination}[i]
	port, _ := loopbackPort(endpoint)
	bindings := map[string]any{"19092/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": port}}}
	result := map[string]any{
		"Id": strings.Repeat([]string{"a", "b"}[i], 64), "Name": "/" + name, "Image": image.RuntimeImageID,
		"Config":          map[string]any{"Image": Image, "Labels": map[string]string{ownerLabel: s.RunID, linkRoleLabel: []string{"source", "destination"}[i]}, "Env": []string{"CLUSTER_ID=" + s.ClusterIDs[i], "KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092", "KAFKA_ADVERTISED_LISTENERS=INTERNAL://" + name + ":9092,EXTERNAL://" + endpoint, "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT", "SYNTHETIC_PRIVATE_ENV=retained-only"}},
		"State":           map[string]any{"Running": true, "Paused": false, "StartedAt": "2026-10-29T01:02:04Z"},
		"HostConfig":      map[string]any{"NetworkMode": s.Network, "Memory": int64(768 << 20), "NanoCpus": int64(1500000000), "PidsLimit": int64(256), "PortBindings": bindings, "LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1m", "max-file": "1"}}},
		"NetworkSettings": map[string]any{"Ports": bindings, "Networks": map[string]any{s.Network: map[string]string{"NetworkID": strings.Repeat("d", 64)}}},
	}
	if image.Manifest != nil {
		result["ImageManifestDescriptor"] = image.Manifest
	}
	return result
}

func (f *directDockerControl) execute(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if args[0] == "info" {
		return []byte(f.state.DockerPlatform), nil
	}
	path, _ := StatePath(f.state.RunID)
	if body, err := os.ReadFile(path); err == nil {
		if err = json.Unmarshal(body, &f.state); err != nil {
			f.t.Fatal(err)
		}
	}
	profile, _ := fixedImageProfile(f.state.DockerPlatform)
	image := LinkImageIdentity{Mode: classicImageMode, RuntimeImageID: profile.brokerConfig, ConfigDigest: profile.brokerConfig}
	if f.modern {
		fixed, err := modernImage(f.state, Image)
		if err != nil {
			f.t.Fatal(err)
		}
		image = LinkImageIdentity{Mode: manifestImageMode, RuntimeImageID: fixed.runtime, ConfigDigest: fixed.config.Digest, Manifest: nativeManifest(fixed.manifest)}
	}
	var value map[string]any
	switch args[0] {
	case "pull", "run", "exec":
		return nil, nil
	case "image":
		if f.modern {
			fixed, _ := modernImage(f.state, Image)
			selected := args[2] == "--platform"
			if selected && f.archive != nil {
				f.installLiteralSave()
			}
			if err := json.Unmarshal(fixedInspectLiteral(fixed, selected), &value); err != nil {
				f.t.Fatal(err)
			}
		} else {
			value = map[string]any{"Id": profile.brokerConfig, "Os": "linux", "Architecture": profile.architecture}
		}
	case "network":
		if args[1] == "create" {
			return []byte(strings.Repeat("d", 64)), nil
		}
		if args[1] == "rm" {
			f.networkRemoved = true
			return nil, nil
		}
		if f.networkRemoved {
			return []byte("Error response from daemon: No such network: " + args[2] + "\n"), errors.New("SYNTHETIC exit1")
		}
		attached := map[string]any{}
		for i, name := range f.state.Containers {
			id := strings.Repeat([]string{"a", "b"}[i], 64)
			if !f.removed[id] {
				attached[id] = map[string]string{"Name": name}
			}
		}
		value = map[string]any{"Id": strings.Repeat("d", 64), "Name": f.state.Network, "Labels": map[string]string{ownerLabel: f.state.RunID}, "Containers": attached}
	case "container":
		if args[1] == "rm" {
			f.removed[args[len(args)-1]] = true
			return nil, nil
		}
		if f.removed[args[2]] {
			return []byte("Error response from daemon: No such container: " + args[2] + "\n"), errors.New("SYNTHETIC exit1")
		}
		i := 0
		if args[2] == f.state.Containers[1] || args[2] == strings.Repeat("b", 64) {
			i = 1
		} else if args[2] != f.state.Containers[0] && args[2] != strings.Repeat("a", 64) {
			f.t.Fatal("unowned target", args)
		}
		value = directContainerLiteral(f.state, i, image)
	case "logs":
		return []byte("SYNTHETIC-PRIVATE-LOG\x00\xff"), nil
	default:
		f.t.Fatal("unexpected direct Docker route", args)
	}
	if f.change != nil {
		f.change(strings.Join(args, " "), value)
	}
	return json.Marshal(value)
}

func (f *directDockerControl) installLiteralSave() {
	f.t.Helper()
	if _, err := os.Lstat(savedImageArchivePath(f.state)); err == nil {
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll(imageDataDirectory(f.state), 0700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(savedImageArchivePath(f.state), f.archive, 0600); err != nil {
		f.t.Fatal(err)
	}
	// These lifecycle fields are literal calibration input. They do not claim
	// an actual Docker save, producer wait, stream EOF or archive close.
	receipt := literalImageSaveCompletion(f.state)
	receipt.Argv = []string{"docker", "image", "save", "--platform=linux/arm64", Image}
	receipt.ExecutedArgv = append([]string{}, receipt.Argv...)
	receipt.ArchiveBytes = int64(len(f.archive))
	receipt.ObservedArchiveBytes = receipt.ArchiveBytes
	if _, err := writeLinkPrivate(directPrivateDirectory(f.state.RunID), "image-save-complete.json", receipt); err != nil {
		f.t.Fatal(err)
	}
}

func directPinnedMetadataSpecimen(t *testing.T) []byte {
	t.Helper()
	// Public selected metadata copied from retained native evidence, then hash
	// checked here independently. This small archive omits filesystem layers;
	// it is strictly an offline admission specimen, never an executable image.
	config, err := os.ReadFile("testdata/direct-kafka-selected-config.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("testdata/direct-kafka-selected-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(config) != 8254 || archiveDigest(config) != "sha256:5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f" || len(manifest) != 2201 || archiveDigest(manifest) != "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0" {
		t.Fatal("public selected metadata fixture changed")
	}
	specimen := archiveSpecimen{members: []archiveMember{
		{"blobs", nil, tar.TypeDir, tar.FormatUSTAR}, {"blobs/sha256", nil, tar.TypeDir, tar.FormatUSTAR},
		{"blobs/sha256/5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f", config, tar.TypeReg, tar.FormatUSTAR},
		{"blobs/sha256/ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", manifest, tar.TypeReg, tar.FormatUSTAR},
		{"index.json", []byte(`{"schemaVersion":2}`), tar.TypeReg, tar.FormatUSTAR},
		{"manifest.json", []byte(`[]`), tar.TypeReg, tar.FormatUSTAR},
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`), tar.TypeReg, tar.FormatUSTAR},
	}}
	return specimen.bytes(t)
}

func newModernDirectControl(t *testing.T, archive []byte) *directDockerControl {
	f := newDirectDockerControl(t)
	f.state.DockerPlatform = "linux/arm64"
	f.modern, f.archive = true, archive
	return f
}

func TestDirectModernMetadataAdmissionReloadAndCleanupWithoutProxy(t *testing.T) {
	// Given exact pinned metadata and explicitly literal save lifecycle fields,
	// When direct Up/Load/Down use the real private proof and container readers,
	// Then the selected manifest/config/whole archive bind every retained ID.
	archive := directPinnedMetadataSpecimen(t)
	t.Chdir(t.TempDir())
	f := newModernDirectControl(t, archive)
	probes := 0
	s, err := up(context.Background(), "test", f.execute, false, nil, func(ctx context.Context, endpoint string) (linkBrokerProbeResult, error) {
		probes++
		return directInertProbe(ctx, endpoint)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Proxy != nil || s.Direct == nil || s.Direct.Image.Mode != manifestImageMode || s.Direct.Image.ProofSHA256 == "" || probes != 2 {
		t.Fatal("inert modern direct route incomplete", s.Direct, probes)
	}
	loaded, err := Load(s.RunID)
	if err != nil || !reflect.DeepEqual(loaded, s) {
		t.Fatal("modern typed identity reload", err)
	}
	if err = Down(context.Background(), loaded, f.execute); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 2 || !f.networkRemoved {
		t.Fatal("exact modern resources not removed")
	}
	for _, args := range f.calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "toxiproxy") || strings.Contains(joined, "WORKER") || args[0] == "exec" {
			t.Fatal("direct route acquired another topology/readiness path", args)
		}
	}
}

func TestDirectModernSelectedRefusalPreservesOriginalBeforeCreate(t *testing.T) {
	// Given a complete direct reservation, When the selected child metadata
	// differs from the exact pin, Then its successful raw candidate survives and
	// neither network/container creation nor an independent readiness probe runs.
	for _, kind := range []string{"target", "selected-id", "selected-size", "selected-platform", "selected-reference"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newModernDirectControl(t, nil)
			var refused []byte
			f.change = func(command string, row map[string]any) {
				if !strings.HasPrefix(command, "image inspect") {
					return
				}
				selected := strings.Contains(command, "--platform")
				if kind == "target" && !selected {
					row["Id"] = "sha256:" + strings.Repeat("e", 64)
					refused, _ = json.Marshal(row)
				}
				if !selected {
					return
				}
				switch kind {
				case "selected-id":
					row["Id"] = "sha256:" + strings.Repeat("e", 64)
				case "selected-size":
					row["Descriptor"].(map[string]any)["size"] = 2202
				case "selected-platform":
					row["Descriptor"].(map[string]any)["platform"] = map[string]string{"os": "linux", "architecture": "amd64"}
				case "selected-reference":
					row["RepoDigests"] = []string{arm64ProxyImage}
				}
				refused, _ = json.Marshal(row)
			}
			_, err := up(context.Background(), "test", f.execute, false, nil, func(context.Context, string) (linkBrokerProbeResult, error) {
				t.Fatal("probe after selected refusal")
				return linkBrokerProbeResult{}, nil
			})
			if err == nil {
				t.Fatal("wrong modern metadata admitted")
			}
			for _, args := range f.calls {
				if args[0] == "network" || args[0] == "run" || args[0] == "logs" {
					t.Fatal("action after selected metadata refusal", args)
				}
			}
			found := false
			for _, body := range privateDirectBodies(t, "test") {
				var row struct {
					Combined            []byte
					PrivateReadbackKind string
				}
				_ = json.Unmarshal(body, &row)
				if len(refused) > 0 && bytes.Equal(row.Combined, refused) && strings.Contains(row.PrivateReadbackKind, "image-inspect") {
					found = true
				}
			}
			if !found {
				t.Fatal("selected successful raw candidate discarded")
			}
			if _, err = os.Stat(filepath.Join(directPrivateDirectory("test"), "STOPPED.json")); err != nil {
				t.Fatal("missing selected refusal STOP", err)
			}
		})
	}
}

func TestDirectModernReuseRejectsProofLifecycleAndUnrelatedArchiveMutation(t *testing.T) {
	archive := directPinnedMetadataSpecimen(t)
	// Given an admitted literal modern fixture, When retained proof, actual
	// archive bytes, or required save lifecycle fields change, Then no later
	// executor or cleanup can issue even a discovery command.
	for _, kind := range []string{"proof-config", "proof-run", "save-wait", "archive-byte", "archive-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newModernDirectControl(t, archive)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			root := directPrivateDirectory(s.RunID)
			switch kind {
			case "proof-config", "proof-run":
				fixed, _ := modernImage(s, Image)
				path := imageProofPath(s, fixed)
				body, _ := os.ReadFile(path)
				var proof imageProof
				if err = json.Unmarshal(body, &proof); err != nil {
					t.Fatal(err)
				}
				if kind == "proof-config" {
					proof.Config[100] ^= 1
				} else {
					proof.RunID = "foreign"
				}
				body, err = json.Marshal(proof)
				if err == nil {
					err = os.WriteFile(path, body, 0600)
				}
			case "save-wait":
				path := filepath.Join(root, "image-save-complete.json")
				body, _ := os.ReadFile(path)
				var receipt imageSaveReceipt
				if err = json.Unmarshal(body, &receipt); err != nil {
					t.Fatal(err)
				}
				receipt.WaitReturned = false
				body, err = json.Marshal(receipt)
				if err == nil {
					err = os.WriteFile(path, body, 0600)
				}
			case "archive-byte":
				body := append([]byte(nil), archive...)
				body[len(body)-1] = 1
				err = os.WriteFile(savedImageArchivePath(s), body, 0600)
			case "archive-hardlink":
				err = os.Link(savedImageArchivePath(s), filepath.Join(root, "foreign-archive-link"))
			}
			if err != nil {
				t.Fatal(err)
			}
			before := len(f.calls)
			if _, err = FixtureExecutor(s, f.execute); err == nil {
				t.Fatal("changed modern retained evidence authorized executor", kind)
			}
			if err = Down(context.Background(), s, f.execute); err == nil || len(f.calls) != before {
				t.Fatal("changed modern evidence authorized cleanup", kind, err)
			}
		})
	}
}

func privateDirectBodies(t *testing.T, id string) [][]byte {
	t.Helper()
	var result [][]byte
	err := filepath.WalkDir(directPrivateDirectory(id), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			result = append(result, b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDirectFixtureClassicIdentityReloadAndExactCleanup(t *testing.T) {
	// Given a finite inert classic backend, When direct Up/Load/Down run through
	// real private persistence, Then all IDs are bound and only those IDs removed.
	t.Chdir(t.TempDir())
	f := newDirectDockerControl(t)
	s, err := upDirectControl(context.Background(), f.execute)
	if err != nil {
		t.Fatal(err)
	}
	if s.Proxy != nil || s.WorkerSource != "" || s.WorkerDestination != "" || s.Direct == nil {
		t.Fatal("direct topology invented proxy/missing identity")
	}
	loaded, err := Load("test")
	if err != nil || !reflect.DeepEqual(s, loaded) {
		t.Fatal("exclusive identity not reloaded", err)
	}
	if err = Down(context.Background(), loaded, f.execute); err != nil {
		t.Fatal(err)
	}
	if !f.removed[strings.Repeat("a", 64)] || !f.removed[strings.Repeat("b", 64)] || !f.networkRemoved {
		t.Fatal("exact resources not removed")
	}
	if err = Down(context.Background(), loaded, f.execute); err != nil {
		t.Fatal("exact retained absence not idempotent", err)
	}
	for _, args := range f.calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "toxiproxy") || strings.Contains(joined, "WORKER") {
			t.Fatal("direct route used links", args)
		}
		if len(args) > 1 && args[1] == "rm" && !linkID(args[len(args)-1]) {
			t.Fatal("removal targeted mutable name", args)
		}
	}
}

func TestDirectFirstInfoFailureAndReusedAttemptPreserveOriginalBeforeAnyCreate(t *testing.T) {
	// Given no resources, When the first info refuses, Then a primary private
	// sink already exists, exact bytes survive and no retry/cleanup is attempted.
	t.Chdir(t.TempDir())
	calls := 0
	notice := []byte("SYNTHETIC-first-info\x00\xff")
	_, err := Up(context.Background(), "test", func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if args[0] != "info" {
			t.Fatal("post-refusal action", args)
		}
		if _, e := os.Stat(filepath.Join(directPrivateDirectory("test"), "startup-control.json")); e != nil {
			t.Fatal("first action preceded primary sink", e)
		}
		return notice, syscall.EPERM
	})
	if err == nil || calls != 1 {
		t.Fatal("first refusal passed", err, calls)
	}
	found := false
	for _, body := range privateDirectBodies(t, "test") {
		var row struct{ Combined []byte }
		_ = json.Unmarshal(body, &row)
		found = found || bytes.Equal(row.Combined, notice)
	}
	if !found {
		t.Fatal("exact original missing")
	}
	stop, err := os.ReadFile(filepath.Join(directPrivateDirectory("test"), "STOPPED.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Up(context.Background(), "test", func(context.Context, ...string) ([]byte, error) {
		calls++
		t.Fatal("reused failed run")
		return nil, nil
	}); err == nil {
		t.Fatal("reused attempt admitted")
	}
	after, _ := os.ReadFile(filepath.Join(directPrivateDirectory("test"), "STOPPED.json"))
	if !bytes.Equal(stop, after) || calls != 1 {
		t.Fatal("original refusal replaced")
	}
}

func TestDirectMissingIdentityCannotAuthorizeCleanupOrExecutor(t *testing.T) {
	// Given a reserved partial plan, When the final identity is absent, Then
	// even matching names/labels cannot authorize one Docker inspection/removal.
	t.Chdir(t.TempDir())
	s := directPlanLiteral("test", "linux/arm64")
	if err := reservePrivateFixtureEvidence(s.RunID, directPrivateDirectory(s.RunID)); err != nil {
		t.Fatal(err)
	}
	if err := save(s); err != nil {
		t.Fatal(err)
	}
	never := func(context.Context, ...string) ([]byte, error) {
		t.Fatal("action without complete identity")
		return nil, nil
	}
	if _, err := FixtureExecutor(s, never); err == nil {
		t.Fatal("missing receipt gained executor")
	}
	if err := Down(context.Background(), s, never); err == nil {
		t.Fatal("missing receipt gained cleanup")
	}
}

func TestDirectModernContainerNeedsExactManifestAndFiniteOwnedTopology(t *testing.T) {
	// Given literal modern typed fields (not authenticated proof), When each
	// ownership/manifest/configuration field changes, Then the pure predicate
	// rejects. Full modern source/save authority is tested separately below.
	s := directPlanLiteral("test", "linux/arm64")
	fixed, err := modernImage(s, Image)
	if err != nil {
		t.Fatal(err)
	}
	image := LinkImageIdentity{Mode: manifestImageMode, RuntimeImageID: fixed.runtime, ConfigDigest: fixed.config.Digest, Manifest: nativeManifest(fixed.manifest)}
	for _, kind := range []string{"good", "owner", "role", "runtime", "manifest", "manifest-platform", "network", "port", "cluster", "log", "pids", "missing-state"} {
		t.Run(kind, func(t *testing.T) {
			v := directContainerLiteral(s, 0, image)
			switch kind {
			case "owner":
				v["Config"].(map[string]any)["Labels"] = map[string]string{ownerLabel: "foreign", linkRoleLabel: "source"}
			case "role":
				v["Config"].(map[string]any)["Labels"] = map[string]string{ownerLabel: s.RunID, linkRoleLabel: "destination"}
			case "runtime":
				v["Image"] = fixed.config.Digest
			case "manifest":
				v["ImageManifestDescriptor"] = nativeManifest(fixed.target)
			case "manifest-platform":
				m := nativeManifest(fixed.manifest)
				m.Platform.Architecture = "amd64"
				v["ImageManifestDescriptor"] = m
			case "network":
				v["HostConfig"].(map[string]any)["NetworkMode"] = "foreign"
			case "port":
				v["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{}
			case "cluster":
				v["Config"].(map[string]any)["Env"] = []string{"CLUSTER_ID=other"}
			case "log":
				v["HostConfig"].(map[string]any)["LogConfig"] = map[string]any{}
			case "pids":
				v["HostConfig"].(map[string]any)["PidsLimit"] = 257
			case "missing-state":
				v["State"] = map[string]any{"Running": true}
			}
			raw, _ := json.Marshal(v)
			_, err := validateDirectContainer(raw, s, 0, strings.Repeat("d", 64), image, strings.Repeat("a", 64), true)
			if (err == nil) != (kind == "good") {
				t.Fatal("pure container predicate insensitive", kind, err)
			}
		})
	}
}

func TestDirectSaveSelectionIsExactlyBrokerOnlyAndCannotReuseLinkedCompletion(t *testing.T) {
	// Given fixed direct/linked selections, When lifecycle completion carries
	// the other selection, Then direct reuse refuses without spawning a child.
	t.Chdir(t.TempDir())
	s := directPlanLiteral("test", "linux/arm64")
	want := []string{"docker", "image", "save", "--platform=linux/arm64", "apache/kafka@sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02"}
	if !reflect.DeepEqual(imageSaveArgv(s), want) {
		t.Fatal("direct selection changed", imageSaveArgv(s))
	}
	linked := nativeImageState(t)
	if !reflect.DeepEqual(imageSaveArgv(linked), append(append([]string{}, want...), arm64ProxyImage)) {
		t.Fatal("linked selection changed")
	}
	if err := reservePrivateFixtureEvidence(s.RunID, directPrivateDirectory(s.RunID)); err != nil {
		t.Fatal(err)
	}
	r := literalImageSaveCompletion(linked)
	r.RunID = s.RunID
	if _, err := writeLinkPrivate(directPrivateDirectory(s.RunID), "image-save-complete.json", r); err != nil {
		t.Fatal(err)
	}
	if _, err := validatedImageSaveReceipt(s); err == nil {
		t.Fatal("linked argv authorized direct save")
	}
}

func TestDirectAuthorityPlanProofAndArchiveRefusalsPrecedeActions(t *testing.T) {
	for _, kind := range []string{"missing", "mode", "marker-run", "stopped", "plan-change", "proof-self-assertion"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newDirectDockerControl(t)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			root := directPrivateDirectory(s.RunID)
			switch kind {
			case "missing":
				if err = os.Remove(filepath.Join(root, "identity.json")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err = os.Chmod(filepath.Join(root, "identity.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "marker-run":
				if err = os.WriteFile(filepath.Join(root, "PRIVATE.json"), []byte(`{"RunID":"foreign","Classification":"PRIVATE RAW EVIDENCE"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				if err = stopPrivateFixtureOperation(s.RunID, root, "SYNTHETIC refused"); err != nil {
					t.Fatal(err)
				}
			case "plan-change":
				path, _ := StatePath(s.RunID)
				b, _ := os.ReadFile(path)
				if err = os.WriteFile(path, append(b, ' '), 0600); err != nil {
					t.Fatal(err)
				}
			case "proof-self-assertion":
				s.Direct.Image.Mode = manifestImageMode
				s.Direct.Image.ProofSHA256 = strings.Repeat("e", 64)
			}
			before := len(f.calls)
			if _, err = FixtureExecutor(s, f.execute); err == nil {
				t.Fatal("invalid authority gained executor", kind)
			}
			if err = Down(context.Background(), s, f.execute); err == nil {
				t.Fatal("invalid authority authorized cleanup", kind)
			}
			if len(f.calls) != before {
				t.Fatal("authority failure reached Docker")
			}
		})
	}
}

func TestDirectCleanupForeignCandidateRetainsRawAndNeverRemoves(t *testing.T) {
	for _, kind := range []string{"owner", "manifest", "network-foreign", "daemon-warning", "log-refusal"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			f := newDirectDockerControl(t)
			s, err := upDirectControl(context.Background(), f.execute)
			if err != nil {
				t.Fatal(err)
			}
			f.change = func(command string, v map[string]any) {
				if kind == "owner" && strings.HasPrefix(command, "container inspect") {
					v["Config"].(map[string]any)["Labels"] = map[string]string{ownerLabel: "foreign", linkRoleLabel: "source"}
				}
				if kind == "manifest" && strings.HasPrefix(command, "container inspect") {
					v["ImageManifestDescriptor"] = &ImageManifestIdentity{Digest: "foreign"}
				}
				if kind == "network-foreign" && strings.HasPrefix(command, "network inspect") {
					v["Containers"] = map[string]any{strings.Repeat("e", 64): map[string]string{"Name": "foreign"}}
				}
			}
			raw := Executor(f.execute)
			if kind == "daemon-warning" {
				raw = func(ctx context.Context, args ...string) ([]byte, error) {
					if args[0] == "network" && args[1] == "inspect" {
						return []byte("SYNTHETIC warning: No such network\nPRIVATE-original"), syscall.EPERM
					}
					return f.execute(ctx, args...)
				}
			}
			if kind == "log-refusal" {
				raw = func(ctx context.Context, args ...string) ([]byte, error) {
					if args[0] == "logs" {
						return []byte("SYNTHETIC denied logs\x00\xff"), syscall.EACCES
					}
					return f.execute(ctx, args...)
				}
			}
			if err = Down(context.Background(), s, raw); err == nil {
				t.Fatal("foreign/refused cleanup passed", kind)
			}
			if len(f.removed) != 0 || f.networkRemoved {
				t.Fatal("destruction after refusal", kind)
			}
			if _, err = os.Stat(filepath.Join(directPrivateDirectory(s.RunID), "STOPPED.json")); err != nil {
				t.Fatal("missing cleanup latch", err)
			}
			before := len(f.calls)
			if err = Down(context.Background(), s, f.execute); err == nil || len(f.calls) != before {
				t.Fatal("stopped cleanup retried")
			}
			if kind == "owner" || kind == "manifest" || kind == "network-foreign" {
				found := false
				for _, body := range privateDirectBodies(t, s.RunID) {
					var row struct {
						Combined            []byte
						PrivateReadbackKind string
					}
					_ = json.Unmarshal(body, &row)
					found = found || bytes.Contains(row.Combined, []byte("foreign")) && strings.Contains(row.PrivateReadbackKind, "candidate")
				}
				if !found {
					t.Fatal("semantic failure lost raw candidate", kind)
				}
			}
		})
	}
}
