package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func linkTestState(retained bool) State {
	p := &ProxyState{Image: ProxyImage, Container: "kaferry-lab-test-links", API: "127.0.0.1:20300", Source: ProxyMapping{"kaferry-lab-test-source-worker", "0.0.0.0:8666", "kaferry-lab-test-source:29092"}, Destination: ProxyMapping{"kaferry-lab-test-dest-worker", "0.0.0.0:8667", "kaferry-lab-test-dest:29092"}}
	if retained {
		p.ContainerID = strings.Repeat("c", 64)
		p.NetworkID = strings.Repeat("d", 64)
		p.ImageID = proxyConfigID
		p.BrokerImageID = amd64BrokerConfigID
		p.BrokerIDs = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	}
	return State{RunID: "test", Image: Image, Network: "kaferry-lab-test", Containers: []string{"kaferry-lab-test-source", "kaferry-lab-test-dest"}, ClusterIDs: []string{"source-cluster", "dest-cluster"}, Source: "127.0.0.1:20101", Destination: "127.0.0.1:20102", WorkerSource: "127.0.0.1:20201", WorkerDestination: "127.0.0.1:20202", Proxy: p, DockerPlatform: "linux/amd64"}
}
func linkTestDocker(t *testing.T, s State, change func(string, map[string]any)) Executor {
	t.Helper()
	profile, err := fixedImageProfile(s.DockerPlatform)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) < 3 {
			t.Fatalf("unexpected Docker command: %v", args)
		}
		if args[0] == "image" && args[1] == "inspect" {
			id := profile.brokerConfig
			if args[2] == profile.proxyImage {
				id = profile.proxyConfig
			} else if args[2] != Image {
				t.Fatalf("foreign image: %v", args)
			}
			object := map[string]any{"Id": id, "Os": "linux", "Architecture": profile.architecture}
			if change != nil {
				change(args[2], object)
			}
			return json.Marshal(object)
		}
		var object map[string]any
		if args[0] == "network" && args[1] == "inspect" {
			object = map[string]any{"Id": strings.Repeat("d", 64), "Name": s.Network, "Labels": map[string]string{ownerLabel: s.RunID}}
		} else if args[0] == "container" && args[1] == "inspect" {
			index := -1
			names := append(append([]string{}, s.Containers...), s.Proxy.Container)
			for i, name := range names {
				if args[2] == name || args[2] == strings.Repeat(string(rune('a'+i)), 64) {
					index = i
				}
			}
			if index < 0 {
				return []byte("No such container"), errors.New("absent")
			}
			name, role, reference, image := names[index], "proxy", s.Proxy.Image, profile.proxyConfig
			bindings := map[string][]linkBinding{}
			if index < 2 {
				role = []string{"source", "destination"}[index]
				reference = Image
				image = profile.brokerConfig
				port, _ := loopbackPort([]string{s.Source, s.Destination}[index])
				bindings["19092/tcp"] = []linkBinding{{"127.0.0.1", port}}
			} else {
				for port, endpoint := range map[string]string{"8474/tcp": s.Proxy.API, "8666/tcp": s.WorkerSource, "8667/tcp": s.WorkerDestination} {
					p, _ := loopbackPort(endpoint)
					bindings[port] = []linkBinding{{"127.0.0.1", p}}
				}
			}
			env := []string{"UNRELATED_SECRET=never-retain-this-value"}
			if index < 2 {
				env = append(env, "CLUSTER_ID="+s.ClusterIDs[index], "KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092,WORKER://:29092", "KAFKA_ADVERTISED_LISTENERS=INTERNAL://"+name+":9092,EXTERNAL://"+[]string{s.Source, s.Destination}[index]+",WORKER://"+[]string{s.WorkerSource, s.WorkerDestination}[index], "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT,WORKER:PLAINTEXT")
			}
			object = map[string]any{"Id": strings.Repeat(string(rune('a'+index)), 64), "Name": "/" + name, "Image": image, "Config": map[string]any{"Image": reference, "Labels": map[string]string{ownerLabel: s.RunID, linkRoleLabel: role}, "Env": env}, "State": map[string]bool{"Running": true, "Paused": false}, "HostConfig": map[string]any{"NetworkMode": s.Network, "PortBindings": bindings}, "NetworkSettings": map[string]any{"Ports": bindings, "Networks": map[string]any{s.Network: map[string]string{"NetworkID": strings.Repeat("d", 64)}}}}
		} else {
			t.Fatalf("unexpected Docker mutation: %v", args)
		}
		if change != nil {
			change(args[2], object)
		}
		return json.Marshal(object)
	}
}
func linkTestDirectory(t *testing.T, s State) {
	t.Helper()
	if e := os.MkdirAll(linkDirectory(s.RunID), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(linkPrivateDirectory(s.RunID), "PRIVATE.json")); errors.Is(e, os.ErrNotExist) {
		if e = reserveLinkEvidence(s.RunID); e != nil {
			t.Fatal(e)
		}
	}
}
func linkTestProxy(m ProxyMapping) map[string]any {
	return map[string]any{"name": m.Name, "listen": m.Listen, "upstream": m.Upstream, "enabled": true, "toxics": []any{}}
}

func TestLinkedSetupRejectsOwnershipAndRoutingAmbiguityBeforeHTTP(t *testing.T) {
	// Given a mismatched owner, image, network, binding or advertised worker
	// endpoint, when setup asks to create a proxy, then no HTTP mutation is sent.
	cases := []struct {
		name   string
		change func(string, map[string]any)
	}{
		{"wrong owner", func(_ string, o map[string]any) {
			if config, ok := o["Config"].(map[string]any); ok {
				config["Labels"].(map[string]string)[ownerLabel] = "foreign"
			}
		}},
		{"wrong image", func(_ string, o map[string]any) {
			if _, ok := o["Config"]; ok {
				o["Image"] = "sha256:" + strings.Repeat("0", 64)
			}
		}},
		{"wrong network", func(_ string, o map[string]any) {
			if _, ok := o["Config"]; !ok {
				o["Name"] = "foreign-network"
			}
		}},
		{"public management binding", func(_ string, o map[string]any) {
			if config, ok := o["Config"].(map[string]any); ok && config["Image"] == ProxyImage {
				ports := o["HostConfig"].(map[string]any)["PortBindings"].(map[string][]linkBinding)
				ports["8474/tcp"] = []linkBinding{{"0.0.0.0", "20300"}}
			}
		}},
		{"worker metadata bypasses proxy", func(_ string, o map[string]any) {
			if config, ok := o["Config"].(map[string]any); ok && config["Image"] == Image {
				env := config["Env"].([]string)
				for i, v := range env {
					if strings.HasPrefix(v, "KAFKA_ADVERTISED_LISTENERS=") {
						env[i] = strings.Replace(v, "WORKER://", "WORKER://bypass-", 1)
					}
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := linkTestState(true)
			linkTestDirectory(t, s)
			called := false
			request := func(context.Context, string, string, string, []byte) (int, []byte, error) {
				called = true
				return 200, nil, nil
			}
			err := linkAPICall(context.Background(), s, linkTestDocker(t, s, tc.change), request, "POST", "/proxies", &s.Proxy.Source, 0)
			if err == nil || called {
				t.Fatalf("unsafe setup reached HTTP: called=%v err=%v", called, err)
			}
		})
	}
}
func TestLinkedSetupRejectsForeignMappingAndGlobalReset(t *testing.T) {
	// Given fixed owned proxy topology, when an arbitrary endpoint or global reset
	// is requested, then it is rejected before even inspecting or calling HTTP.
	s := linkTestState(true)
	mapping := ProxyMapping{"foreign", "0.0.0.0:9999", "production:9092"}
	run := func(context.Context, ...string) ([]byte, error) { t.Fatal("unexpected Docker access"); return nil, nil }
	request := func(context.Context, string, string, string, []byte) (int, []byte, error) {
		t.Fatal("unexpected HTTP access")
		return 0, nil, nil
	}
	if err := linkAPICall(context.Background(), s, run, request, "POST", "/proxies", &mapping, 0); err == nil {
		t.Fatal("foreign mapping accepted")
	}
	if err := linkAPICall(context.Background(), s, run, request, "POST", "/reset", nil, 0); err == nil {
		t.Fatal("global reset accepted")
	}
}
func TestLinkedAPIFailuresKeepBodiesPrivateAndOmitInspectEnvironment(t *testing.T) {
	// Given an owned endpoint that returns an unsafe error body, when setup fails,
	// then public receipts retain operation/status without body or inspect Env,
	// while the original failed body/cause remain private.
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	linkTestDirectory(t, s)
	request := func(context.Context, string, string, string, []byte) (int, []byte, error) {
		return 500, []byte("HTTP_SECRET=do-not-retain"), errors.New("TRANSPORT_SECRET")
	}
	err := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "POST", "/proxies", &s.Proxy.Source, 0)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
	files, e := filepath.Glob(filepath.Join(linkDirectory(s.RunID), "*.json"))
	if e != nil || len(files) != 3 {
		t.Fatalf("missing intent/outcome receipts: %v %v", files, e)
	}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "never-retain") {
			t.Fatal("unsafe receipt", string(b))
		}
	}
}
func TestLinkedStartupRetriesOnlyRequestSocketAvailability(t *testing.T) {
	// Given literal errors, when startup considers another read, then permission,
	// unknown, ownership and joined fatal failures never permit another request.
	refused := &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"request refused", refused, true},
		{"request reset", &linkSocketError{cause: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}, true},
		{"ownership transport", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"access denied", &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EACCES}}, false},
		{"operation forbidden", &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EPERM}}, false},
		{"unknown transport", &linkSocketError{cause: &net.OpError{Op: "read", Net: "tcp", Err: errors.New("unknown failure")}}, false},
		{"version", errors.New("proxy version mismatch"), false},
		{"authorization", errors.New("HTTP status 403"), false},
		{"canceled", &linkSocketError{cause: context.Canceled}, false},
		{"deadline", &linkSocketError{cause: context.DeadlineExceeded}, false},
		{"joined receipt", errors.Join(refused, errors.New("receipt persistence failed")), false},
		{"joined ownership", errors.Join(refused, errors.New("owner mismatch")), false},
		{"joined context", errors.Join(refused, context.Canceled), false},
		{"nested permission", &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(syscall.ECONNREFUSED, syscall.EPERM)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := linkStartupRetryable(tc.err); got != tc.want {
				t.Fatalf("retry=%v want=%v: %v", got, tc.want, tc.err)
			}
		})
	}
}

func TestLinkedSocketDenialRetainsExactPrivateNoticeAndCause(t *testing.T) {
	// Given a literal marked denial, when the production API path records it,
	// then typed classification remains but raw notice/body never become public.
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	linkTestDirectory(t, s)
	denial := &linkSocketError{cause: &url.Error{Op: "Get", URL: "http://127.0.0.1:20300/version", Err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20300}, Err: &os.SyscallError{Syscall: "connect", Err: syscall.EACCES}}}}
	notice := []byte("HTTP_SECRET=private-body")
	request := func(context.Context, string, string, string, []byte) (int, []byte, error) { return 0, notice, denial }
	err := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "GET", "/version", nil, 0)
	if !errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), denial.cause.Error()) || linkStartupRetryable(err) {
		t.Fatal("denial leaked or allowed retry")
	}
	assertLinkPublicWithholds(t, s, notice, []byte(denial.cause.Error()))
	files, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
	if e != nil || len(files) != 1 {
		t.Fatal("private failure missing", e)
	}
	body, e := os.ReadFile(files[0])
	var receipt struct {
		Action                        []string
		Notice, CauseText             []byte
		NoticeComplete, CauseComplete bool
	}
	if e != nil || json.Unmarshal(body, &receipt) != nil || string(receipt.CauseText) != denial.cause.Error() || string(receipt.Notice) != string(notice) || !receipt.NoticeComplete || !receipt.CauseComplete || len(receipt.Action) != 3 {
		t.Fatal("exact private action/notice/cause lost")
	}
}

func TestLinkedStartupStopsBeforeAnotherRequestAfterFatalOutcome(t *testing.T) {
	// Given startup's receipt/ownership path and a fake HTTP executor, when a
	// response or receipt fails, then no second request or POST can be sent.
	for _, kind := range []string{"version", "malformed", "authorization", "unknown", "permission", "marked PRIVATE", "marked joined fatal", "receipt beside refused", "ownership"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := linkTestState(false)
			if e := save(s); e != nil {
				t.Fatal(e)
			}
			linkTestDirectory(t, s)
			inspect := linkTestDocker(t, s, func(_ string, object map[string]any) {
				if kind == "ownership" {
					if _, e := os.Stat(filepath.Join(linkDirectory(s.RunID), "identity.json")); e == nil {
						if labels, ok := object["Labels"].(map[string]string); ok {
							labels[ownerLabel] = "foreign"
						}
					}
				}
			})
			run := func(ctx context.Context, args ...string) ([]byte, error) {
				if args[0] == "run" {
					return nil, nil
				}
				return inspect(ctx, args...)
			}
			calls := 0
			request := func(_ context.Context, _ string, method, path string, _ []byte) (int, []byte, error) {
				calls++
				if method != "GET" || path != "/version" {
					t.Fatalf("unexpected follow-up: %s %s", method, path)
				}
				switch kind {
				case "version":
					return 200, []byte(`{"version":"2.11.0"}`), nil
				case "malformed":
					return 200, []byte(`{"version":`), nil
				case "authorization":
					return 403, []byte("SECRET"), nil
				case "unknown":
					return 0, nil, errors.New("unknown failure")
				case "marked PRIVATE":
					return 0, []byte("PRIVATE_BODY"), &linkSocketError{cause: &net.OpError{Op: "read", Net: "tcp", Err: errors.New("PRIVATE_CAUSE=unknown")}}
				case "marked joined fatal":
					return 0, nil, &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(syscall.ECONNREFUSED, errors.New("PRIVATE_CAUSE=joined fatal"))}}
				case "permission":
					return 0, nil, &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EPERM}}
				case "receipt beside refused":
					// Preserve written evidence but replace its pathname with a
					// regular file: ENOTDIR, without changing permissions.
					dir := linkDirectory(s.RunID)
					if e := os.Rename(dir, dir+"-preserved"); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(dir, nil, 0600); e != nil {
						t.Fatal(e)
					}
					return 0, nil, &linkSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
				default:
					t.Fatal("ownership failure reached HTTP")
					return 0, nil, nil
				}
			}
			err := setupLinks(context.Background(), &s, run, request)
			wantCalls := 1
			if kind == "ownership" {
				wantCalls = 0
			}
			if err == nil || calls != wantCalls || linkStartupRetryable(err) {
				t.Fatalf("fatal startup retried: calls=%d want=%d err=%v", calls, wantCalls, err)
			}
			if strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("private marked cause leaked through startup")
			}
			if kind == "marked PRIVATE" || kind == "marked joined fatal" {
				assertLinkPublicWithholds(t, s, []byte("PRIVATE_CAUSE"), []byte("PRIVATE_BODY"))
			}
			if kind == "receipt beside refused" && (!errors.Is(err, syscall.ECONNREFUSED) || !errors.Is(err, syscall.ENOTDIR)) {
				t.Fatalf("joined causes lost: %v", err)
			}
		})
	}
}

func TestLinkedFinalConfigurationRequiresBothMappingsAndNoToxics(t *testing.T) {
	// Given incomplete, changed or already faulted proxy state, when final setup
	// checks it, then configuration cannot be reported ready.
	for _, kind := range []string{"empty", "missing", "changed", "toxic"} {
		t.Run(kind, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := linkTestState(true)
			linkTestDirectory(t, s)
			proxies := map[string]any{s.Proxy.Source.Name: linkTestProxy(s.Proxy.Source), s.Proxy.Destination.Name: linkTestProxy(s.Proxy.Destination)}
			switch kind {
			case "empty":
				proxies = map[string]any{}
			case "missing":
				delete(proxies, s.Proxy.Source.Name)
			case "changed":
				proxies[s.Proxy.Source.Name].(map[string]any)["upstream"] = "foreign:9092"
			case "toxic":
				proxies[s.Proxy.Source.Name].(map[string]any)["toxics"] = []any{map[string]any{"name": "unrequested"}}
			}
			body, _ := json.Marshal(proxies)
			request := func(context.Context, string, string, string, []byte) (int, []byte, error) { return 200, body, nil }
			if e := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "GET", "/proxies", nil, 2); e == nil {
				t.Fatal("incomplete/faulted fixture accepted")
			}
		})
	}
}
func TestLinkedIdentityIsExclusiveAndBoundToReservedManifest(t *testing.T) {
	// Given an initial manifest, when identities are recorded, then Load returns
	// those exact IDs; neither replacement nor a changed manifest is accepted.
	t.Chdir(t.TempDir())
	s := linkTestState(false)
	if e := save(s); e != nil {
		t.Fatal(e)
	}
	linkTestDirectory(t, s)
	resources, e := inspectLinkResources(context.Background(), s, linkTestDocker(t, s, nil))
	if e != nil {
		t.Fatal(e)
	}
	if e = saveLinkIdentity(&s, resources); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(s.RunID)
	if e != nil || loaded.Proxy.ContainerID != strings.Repeat("c", 64) || !reflect.DeepEqual(loaded.Proxy.BrokerIDs, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}) {
		t.Fatalf("lost identities: %+v %v", loaded.Proxy, e)
	}
	before, _ := os.ReadFile(filepath.Join(linkDirectory(s.RunID), "identity.json"))
	if e = saveLinkIdentity(&s, resources); e == nil {
		t.Fatal("identity overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(linkDirectory(s.RunID), "identity.json"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("prior identity changed")
	}
	path, _ := StatePath(s.RunID)
	manifest, _ := os.ReadFile(path)
	if e = os.WriteFile(path, append(manifest, ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(s.RunID); e == nil {
		t.Fatal("identity accepted changed manifest")
	}
}
func TestLinkedCleanupTargetsIDsAfterEvidenceAndKeepsForeignResources(t *testing.T) {
	// Given fully owned resources, when cleanup runs, then logs/facts are saved
	// before exact immutable IDs are removed, followed by the owned network.
	t.Chdir(t.TempDir())
	s := linkTestState(true)
	linkTestDirectory(t, s)
	var removed []string
	inspect := linkTestDocker(t, s, nil)
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "logs" {
			return []byte("owned synthetic logs"), nil
		}
		if len(args) > 1 && args[1] == "rm" {
			target := args[len(args)-1]
			files, _ := filepath.Glob(filepath.Join(linkDirectory(s.RunID), "cleanup-*.json"))
			found := false
			for _, f := range files {
				b, _ := os.ReadFile(f)
				if strings.Contains(string(b), target) {
					found = true
				}
			}
			if !found {
				t.Fatal("removed before evidence", args)
			}
			removed = append(removed, target)
			return nil, nil
		}
		return inspect(ctx, args...)
	}
	if e := Down(context.Background(), s, run); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(removed, []string{strings.Repeat("c", 64), strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 64)}) {
		t.Fatal(removed)
	}
	// Given a mismatched network owner, then no resource removal is attempted.
	removed = nil
	inspect = linkTestDocker(t, s, func(_ string, o map[string]any) {
		if labels, ok := o["Labels"].(map[string]string); ok {
			labels[ownerLabel] = "foreign"
		}
	})
	if e := Down(context.Background(), s, run); e == nil || len(removed) != 0 {
		t.Fatalf("foreign cleanup: removed=%v err=%v", removed, e)
	}
}
func TestUpLinksKeepsDirectObserversAndAllWorkerAdvertisementsProxied(t *testing.T) {
	// Given the optional fixture mode, when setup creates its three containers,
	// then only workers use the two proxy mappings; old direct endpoints survive.
	for _, tc := range []struct{ engine, platform, proxy string }{
		{"linux/amd64", "linux/amd64", "ghcr.io/shopify/toxiproxy@sha256:a3e244375123dad8849091bcc59775e188624d3f602db01901f9af855682fef8"},
		{"linux/x86_64", "linux/amd64", "ghcr.io/shopify/toxiproxy@sha256:a3e244375123dad8849091bcc59775e188624d3f602db01901f9af855682fef8"},
		{"linux/arm64", "linux/arm64", "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"},
		{"linux/aarch64", "linux/arm64", "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			t.Chdir(t.TempDir())
			var starts, pulls [][]string
			run := func(ctx context.Context, args ...string) ([]byte, error) {
				if args[0] == "info" {
					return []byte(tc.engine), nil
				}
				if args[0] == "run" {
					starts = append(starts, append([]string{}, args...))
					return nil, nil
				}
				if args[0] == "exec" {
					t.Fatal("linked readiness used Docker exec", args)
				}
				if args[0] == "pull" {
					pulls = append(pulls, append([]string{}, args...))
					return nil, nil
				}
				if args[0] == "network" && args[1] == "create" {
					return nil, nil
				}
				path, _ := StatePath("test")
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var state State
				if e = json.Unmarshal(raw, &state); e != nil {
					t.Fatal(e)
				}
				return linkTestDocker(t, state, nil)(ctx, args...)
			}
			proxies := map[string]any{}
			request := func(_ context.Context, _ string, method, path string, body []byte) (int, []byte, error) {
				if path == "/version" {
					return 200, []byte(`{"version":"2.12.0"}`), nil
				}
				if method == "POST" {
					var p map[string]any
					if e := json.Unmarshal(body, &p); e != nil {
						t.Fatal(e)
					}
					if len(p) != 4 || p["enabled"] != true || p["name"] == nil || p["listen"] == nil || p["upstream"] == nil {
						t.Fatalf("unexpected stock API payload: %s", body)
					}
					p["toxics"] = []any{}
					proxies[p["name"].(string)] = p
					b, e := json.Marshal(p)
					return 200, b, e
				}
				b, e := json.Marshal(proxies)
				return 200, b, e
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			s, e := up(ctx, "test", run, true, request, func(context.Context, string) (linkBrokerProbeResult, error) {
				return linkBrokerProbeResult{Opened: true, Closed: true, APIKeys: 1}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if s.DockerPlatform != tc.engine || s.Proxy.Image != tc.proxy {
				t.Fatalf("selected state: %+v", s)
			}
			for _, args := range append(append([][]string{}, starts...), pulls...) {
				found := false
				for i, arg := range args {
					if arg == "--platform" && i+1 < len(args) && args[i+1] == tc.platform {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing native platform: %v", args)
				}
			}
			if len(pulls) != 2 || pulls[0][len(pulls[0])-1] != tc.proxy || pulls[1][len(pulls[1])-1] != Image {
				t.Fatalf("unpinned pull: %v", pulls)
			}
			if len(starts) != 3 || len(s.Containers) != 2 || s.Source == s.WorkerSource || s.Destination == s.WorkerDestination || s.Proxy.ContainerID == "" || len(proxies) != 2 {
				t.Fatalf("fixture lost isolation: %+v starts=%d", s, len(starts))
			}
			for i := 0; i < 2; i++ {
				args := strings.Join(starts[i], " ")
				direct := []string{s.Source, s.Destination}[i]
				worker := []string{s.WorkerSource, s.WorkerDestination}[i]
				if !strings.Contains(args, ",EXTERNAL://"+direct+",WORKER://"+worker) || !strings.Contains(args, "WORKER://:29092") || !strings.Contains(args, "WORKER:PLAINTEXT") {
					t.Fatalf("metadata route escapes proxy: %s", args)
				}
			}
			proxy := strings.Join(starts[2], " ")
			for _, required := range []string{tc.proxy, "--memory 128m", "--cpus 1", "--pids-limit 128", "--read-only", "--cap-drop ALL", "--log-opt max-size=1m", "-proxy-metrics"} {
				if !strings.Contains(proxy, required) {
					t.Fatalf("missing bounded stock-proxy setting %q", required)
				}
			}
			for i, arg := range starts[2] {
				if arg == "-p" && !strings.HasPrefix(starts[2][i+1], "127.0.0.1:") {
					t.Fatal("public port binding", starts[2])
				}
			}
		})
	}
}
func TestLegacyManifestLoadsWithoutProxyFields(t *testing.T) {
	t.Chdir(t.TempDir())
	s := linkTestState(false)
	s.Proxy = nil
	s.WorkerSource = ""
	s.WorkerDestination = ""
	if e := save(s); e != nil {
		t.Fatal(e)
	}
	got, e := Load(s.RunID)
	if e != nil || got.Proxy != nil || got.WorkerSource != "" || got.WorkerDestination != "" {
		t.Fatalf("legacy fixture changed: %+v %v", got, e)
	}
}

func TestStoppedPartialContainerRequiresConfiguredOwnershipAndCannotBeReady(t *testing.T) {
	// Given a correctly configured stopped proxy left by a failed Docker start,
	// when live bindings are absent, then cleanup can identify it but setup cannot
	// call its API. A conflicting network attachment is never accepted.
	s := linkTestState(true)
	partial := func(target string, o map[string]any) {
		if target == s.Proxy.ContainerID || target == s.Proxy.Container {
			o["State"] = map[string]bool{"Running": false, "Paused": false}
			settings := o["NetworkSettings"].(map[string]any)
			settings["Ports"] = map[string][]linkBinding{}
			settings["Networks"] = map[string]any{}
		}
	}
	run := linkTestDocker(t, s, partial)
	fact, present, err := inspectLinkContainer(context.Background(), s, run, 2, strings.Repeat("d", 64), proxyConfigID, false)
	if err != nil || !present || fact.ID != s.Proxy.ContainerID || fact.Running {
		t.Fatalf("safe partial cleanup identity: %+v %v", fact, err)
	}
	if _, err = inspectLinkResources(context.Background(), s, run); err == nil {
		t.Fatal("stopped partial container accepted as ready")
	}
	conflict := linkTestDocker(t, s, func(target string, o map[string]any) {
		partial(target, o)
		if target == s.Proxy.ContainerID {
			o["NetworkSettings"].(map[string]any)["Networks"] = map[string]any{"foreign": map[string]string{"NetworkID": strings.Repeat("0", 64)}}
		}
	})
	if _, _, err = inspectLinkContainer(context.Background(), s, conflict, 2, strings.Repeat("d", 64), proxyConfigID, false); err == nil {
		t.Fatal("conflicting live attachment accepted for cleanup")
	}
}

func TestLinkedInspectionAcceptsOnlyExactDockerAbsence(t *testing.T) {
	// Given an inspect failure, when Docker reports absence of this exact object,
	// then cleanup is idempotent; daemon failures or another name remain errors.
	target := "kaferry-lab-test-links"
	for _, tc := range []struct {
		name, message string
		absent        bool
	}{
		{"exact absence", "Error: No such object: " + target, true},
		{"different object", "Error: No such object: another-container", false},
		{"daemon message containing absence phrase", "Cannot connect to Docker daemon; No such object: " + target, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(context.Context, ...string) ([]byte, error) {
				return []byte(tc.message), errors.New("inspect failed")
			}
			var out linkContainer
			present, err := linkInspect(context.Background(), run, "container", target, &out)
			if present || ((err == nil) != tc.absent) {
				t.Fatalf("misclassified inspect failure: present=%v err=%v", present, err)
			}
		})
	}
}

func TestIncompleteIdentityTemporaryFileDoesNotBlockRestartableLoad(t *testing.T) {
	// Given interrupted identity preparation with no canonical receipt, when the
	// initial manifest is reloaded, then cleanup can still use its exact planned
	// names and perform fresh ownership checks instead of trusting partial IDs.
	t.Chdir(t.TempDir())
	s := linkTestState(false)
	if err := save(s); err != nil {
		t.Fatal(err)
	}
	linkTestDirectory(t, s)
	if err := os.WriteFile(filepath.Join(linkDirectory(s.RunID), "identity-interrupted.tmp"), []byte(`{"ContainerID":`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(s.RunID)
	if err != nil || loaded.Proxy.ContainerID != "" || len(loaded.Proxy.BrokerIDs) != 0 {
		t.Fatalf("interrupted identity blocked intended cleanup: %+v %v", loaded.Proxy, err)
	}
}

func TestLinkedImageProfilesRejectSubstitutedBackendMetadata(t *testing.T) {
	// Given the recorded ARM64 engine and fixed published subject, When an image
	// claims another config or OS/architecture, Then no proxy request is issued.
	for _, reference := range []string{Image, "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"} {
		for _, tc := range []struct {
			name   string
			mutate func(map[string]any)
		}{
			{"amd64 architecture", func(o map[string]any) { o["Architecture"] = "amd64" }},
			{"foreign OS", func(o map[string]any) { o["Os"] = "darwin" }},
			{"missing architecture", func(o map[string]any) { delete(o, "Architecture") }},
			{"missing OS", func(o map[string]any) { delete(o, "Os") }},
			{"missing config", func(o map[string]any) { delete(o, "Id") }},
			{"arbitrary config", func(o map[string]any) { o["Id"] = "sha256:" + strings.Repeat("e", 64) }},
			{"amd64 config with arm64 label", func(o map[string]any) {
				if reference == Image {
					o["Id"] = "sha256:41abbd7d7f05d1ea7918ce2539d04a334c597943a53dbc1812a572af136c6df1"
				} else {
					o["Id"] = "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa"
				}
			}},
		} {
			t.Run(reference+"/"+tc.name, func(t *testing.T) {
				t.Chdir(t.TempDir())
				s := linkTestState(false)
				s.DockerPlatform = "linux/aarch64"
				s.Proxy.Image = "ghcr.io/shopify/toxiproxy@sha256:5ab4b4e8f476fd5452eb9584a608dd7cf8c11135878a8f7953722a9fcb9b3d87"
				linkTestDirectory(t, s)
				inspect := linkTestDocker(t, s, func(target string, o map[string]any) {
					if target == reference {
						tc.mutate(o)
					}
				})
				requests := 0
				err := linkAPICall(context.Background(), s, inspect, func(context.Context, string, string, string, []byte) (int, []byte, error) {
					requests++
					return 200, nil, nil
				}, "POST", "/proxies", &s.Proxy.Source, 0)
				if err == nil || requests != 0 {
					t.Fatalf("foreign image admitted: requests=%d err=%v", requests, err)
				}
			})
		}
	}
}

func TestLinkedPlanRejectsCrossPlatformProxyBeforeDocker(t *testing.T) {
	// Given ARM64 state carrying the AMD64 subject, When inspecting resources,
	// Then no Docker action can turn that cross-platform tuple into ownership.
	s := linkTestState(false)
	s.DockerPlatform = "linux/arm64"
	_, err := inspectLinkResources(context.Background(), s, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("Docker called for mixed tuple")
		return nil, nil
	})
	if err == nil {
		t.Fatal("cross-platform proxy reference admitted")
	}
}

func TestLinkedImageInspectionPreservesJoinedFailure(t *testing.T) {
	// Given an actual executor error with joined causes, When checking the image,
	// Then its classification survives and no retry or alternative action occurs.
	cause := errors.Join(syscall.EACCES, errors.New("TEST ONLY image inspection cause"))
	calls := 0
	_, err := inspectLinkImage(context.Background(), func(context.Context, ...string) ([]byte, error) { calls++; return nil, cause }, linkTestState(false), Image)
	if calls != 1 || !errors.Is(err, syscall.EACCES) || err != cause {
		t.Fatalf("failure changed: calls=%d err=%v", calls, err)
	}
}
