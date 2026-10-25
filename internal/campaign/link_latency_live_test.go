package campaign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

const linkLatencyImageID = "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa"

// These are one-host monotonic offsets, never comparisons of serialized UTC
// timestamps. First-byte observations also catch an early partial delivery.
type linkLatencyExchange struct {
	Phase, Socket, Nonce, ClientLocal, ClientRemote, ServerPeer string
	ServerConnection                                            int
	RequestStartNS, ClientWriteStartNS, ClientWriteEndNS        int64
	ServerFirstByteNS, ServerReceiveNS                          int64
	ServerWriteStartNS, ServerWriteEndNS                        int64
	ClientFirstByteNS, ClientReadEndNS                          int64
	ExactBytes, Closed                                          bool
	Error                                                       string `json:",omitempty"`
}
type linkLatencyServerReceipt struct {
	Nonce, Peer, Error                               string
	Connection                                       int
	FirstByteNS, ReceiveNS, WriteStartNS, WriteEndNS int64
}
type linkLatencyToxic struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Stream     string  `json:"stream"`
	Toxicity   float64 `json:"toxicity"`
	Attributes struct {
		Latency int `json:"latency"`
		Jitter  int `json:"jitter"`
	} `json:"attributes"`
}
type linkLatencyProxy struct {
	Name     string             `json:"name"`
	Listen   string             `json:"listen"`
	Upstream string             `json:"upstream"`
	Enabled  bool               `json:"enabled"`
	Toxics   []linkLatencyToxic `json:"toxics"`
}

func TestLiveOwnedLinkDirectionalLatency(t *testing.T) {
	if os.Getenv("LAB_LINKS") == "" {
		t.Skip("LAB_LINKS=1 owned proxy calibration opt-in absent")
	}
	if os.Getenv("LAB_LINKS") != "1" || os.Getenv("LAB_RUN_ID") == "" || os.Getenv("LAB_SOURCE_ADDR") == "" || os.Getenv("LAB_DEST_ADDR") == "" {
		t.Fatal("incomplete explicit LAB_LINKS fixture opt-in")
	}
	// Given a real UpLinks fixture, reuse its private Docker failure boundary.
	// The extra echo container tests stock proxy mechanics, not these brokers,
	// Kafka semantics, a released Kaferry process or qualification.
	state := liveCampaignState(t)
	if state.Proxy == nil || state.Proxy.ContainerID == "" || state.Proxy.NetworkID == "" || len(state.Proxy.BrokerIDs) != 2 {
		t.Fatal("completed genuine UpLinks immutable setup identities required")
	}
	if err := nativeProcessPlatform(); err != nil {
		t.Fatal(err)
	}
	run, err := fixture.LinkExecutor(state, fixture.Docker)
	if err != nil {
		t.Fatal(err)
	}
	origin := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(70*time.Second))
	defer cancel()
	var salt [8]byte
	if _, err = rand.Read(salt[:]); err != nil {
		t.Fatal("calibration identity unavailable")
	}
	name := state.Proxy.Container + "-latency-" + hex.EncodeToString(salt[:])
	directory := filepath.Join(".cache", "fixtures", state.RunID+"-links", name)
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal("exclusive calibration evidence reservation failed")
	}
	journal, err := os.OpenFile(filepath.Join(directory, "observations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("calibration journal reservation failed")
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error("calibration journal close failed")
		}
	})
	written, records := 0, 0
	retain := func(kind string, value any) error {
		body, err := json.Marshal(struct {
			Kind      string
			ElapsedNS int64
			Facts     any
		}{kind, time.Since(origin).Nanoseconds(), value})
		if err != nil || len(body) > 16<<10 || written+len(body)+1 > 128<<10 || records >= 128 {
			return errors.New("calibration selected-fact evidence bound exceeded")
		}
		n, err := journal.Write(append(body, '\n'))
		written += n
		records++
		return errors.Join(err, journal.Sync())
	}
	mustRetain := func(kind string, value any) {
		t.Helper()
		if err := retain(kind, value); err != nil {
			t.Fatal("calibration evidence incomplete")
		}
	}
	// Keep the two chosen ports reserved until the exact container is created.
	// Startup configuration carries an unguessable mapping identity, so no API
	// mutation is made before its readback matches this run's mapping.
	mustRetain("loopback_reservation_intent", struct {
		Bind      string
		Listeners int
	}{"127.0.0.1:0", 3})
	listeners := make([]net.Listener, 0, 3)
	for i := 0; i < 3; i++ {
		listener, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			t.Fatal("calibration loopback reservation failed")
		}
		listeners = append(listeners, listener)
	}
	t.Cleanup(func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	api, endpoint, upstream := listeners[0].Addr().String(), listeners[1].Addr().String(), listeners[2].Addr().String()
	_, apiPort, _ := net.SplitHostPort(api)
	mapping := linkLatencyProxy{Name: "echo-" + hex.EncodeToString(salt[:]), Listen: endpoint, Upstream: upstream, Enabled: true, Toxics: []linkLatencyToxic{}}
	config, _ := json.Marshal([]linkLatencyProxy{mapping})
	configPath, err := filepath.Abs(filepath.Join(directory, "startup.json"))
	if err != nil {
		t.Fatal("calibration startup path unavailable")
	}
	if err = os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal("calibration startup configuration persistence failed")
	}
	command := []string{"-host=127.0.0.1", "-port=" + apiPort, "-config=/calibration.json"}
	mustRetain("resource_plan", struct {
		RunID, Name, Role, Image, ExpectedImageID, Network, API, Endpoint, Upstream, ConfigPath              string
		Command                                                                                              []string
		BudgetSeconds, WorkSeconds, MemoryBytes, NanoCPUs, PIDs, LogBytes, Connections, Requests, NonceBytes int64
		LatencyMS, GranularityMS, DelayedMinimumMS, PromptMaximumMS, RequestBoundMS                          int
	}{state.RunID, name, "latency-calibration", fixture.ProxyImage, linkLatencyImageID, "host", api, endpoint, upstream, configPath, command, 90, 70, 128 << 20, 500000000, 64, 1 << 20, 8, 14, 32, 400, 100, 300, 200, 4000})
	t.Log("STOCK PROXY ECHO CALIBRATION ONLY; selected synthetic facts: " + filepath.Join(directory, "observations.jsonl"))

	serverEvents := make(chan linkLatencyServerReceipt, 16)
	stopEcho := startLinkLatencyEcho(ctx, origin, listeners[2], serverEvents)
	var persistent net.Conn
	var containerID string
	created, dockerStopped := false, false
	docker := func(ctx context.Context, args ...string) ([]byte, error) {
		if dockerStopped {
			return nil, errors.New("retained Docker facility stop; calibration action prohibited")
		}
		one, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		raw, err := run(one, args...)
		if err != nil {
			dockerStopped = true
		}
		return raw, err
	}
	inspect := func(ctx context.Context, running bool) error {
		target := containerID
		if target == "" {
			target = name
		}
		raw, err := docker(ctx, "container", "inspect", target, "--format", "{{json .}}")
		if err != nil {
			return err
		}
		var facts struct {
			ID, Name, Image string
			Config          struct {
				Image           string
				Labels          map[string]string
				Cmd, Entrypoint []string
			}
			State      struct{ Running, Paused *bool }
			HostConfig struct {
				NetworkMode                 string
				Memory, NanoCPUs, PidsLimit int64
				Privileged, ReadonlyRootfs  bool
				PortBindings                map[string]json.RawMessage
				LogConfig                   struct {
					Type   string
					Config map[string]string
				}
			}
			Mounts []struct {
				Type, Source, Destination string
				RW                        bool
			}
		}
		if len(raw) > 64<<10 || json.Unmarshal(raw, &facts) != nil {
			return errors.New("calibration ownership inspection malformed or oversized")
		}
		if !linkLatencyContainerID(facts.ID) || facts.Name != "/"+name || containerID != "" && facts.ID != containerID || facts.Image != linkLatencyImageID || facts.Config.Image != fixture.ProxyImage || facts.Config.Labels[brokerOwnerLabel] != state.RunID || facts.Config.Labels["io.kaferry-lab.role"] != "latency-calibration" {
			return errors.New("calibration immutable ownership/image mismatch")
		}
		if !reflect.DeepEqual(facts.Config.Cmd, command) || !reflect.DeepEqual(facts.Config.Entrypoint, []string{"/toxiproxy"}) || facts.State.Running == nil || facts.State.Paused == nil || *facts.State.Paused || running && !*facts.State.Running {
			return errors.New("calibration command or required process state mismatch")
		}
		if facts.HostConfig.NetworkMode != "host" || facts.HostConfig.Memory != 128<<20 || facts.HostConfig.NanoCPUs != 500000000 || facts.HostConfig.PidsLimit != 64 || facts.HostConfig.Privileged || !facts.HostConfig.ReadonlyRootfs || len(facts.HostConfig.PortBindings) != 0 {
			return errors.New("calibration network/resource configuration mismatch")
		}
		if facts.HostConfig.LogConfig.Type != "json-file" || facts.HostConfig.LogConfig.Config["max-size"] != "1m" || facts.HostConfig.LogConfig.Config["max-file"] != "1" {
			return errors.New("calibration container log bound mismatch")
		}
		if len(facts.Mounts) != 1 || facts.Mounts[0].Type != "bind" || facts.Mounts[0].Source != configPath || facts.Mounts[0].Destination != "/calibration.json" || facts.Mounts[0].RW {
			return errors.New("calibration exact read-only startup configuration mismatch")
		}
		containerID = facts.ID
		return retain("container_ownership", struct {
			ID, Name, ImageID string
			Running           bool
		}{facts.ID, name, facts.Image, *facts.State.Running})
	}
	// Restoration/removal is registered before the first Docker mutation. A
	// latched facility failure forbids even alternate cleanup commands or HTTP;
	// unresolved exact resources are recorded, never silently declared reaped.
	t.Cleanup(func() {
		clientClosed := true
		if persistent != nil {
			clientClosed = persistent.Close() == nil
			if !clientClosed {
				t.Error("calibration persistent socket close failed")
			}
		}
		for _, listener := range listeners[:2] {
			_ = listener.Close()
		}
		echoReaped := stopEcho() == nil
		if !echoReaped {
			t.Error("echo connections or goroutines not reaped")
		}
		cleanup, done := context.WithDeadline(context.Background(), origin.Add(90*time.Second))
		defer done()
		status := "no container created"
		if created {
			status = "unresolved container and any active toxic; no unsafe cleanup attempted"
			if !dockerStopped {
				if err := inspect(cleanup, false); err != nil {
					t.Errorf("calibration cleanup ownership failed: %v", err)
				} else if _, err := docker(cleanup, "container", "rm", "-f", containerID); err != nil {
					t.Errorf("calibration cleanup removal failed: %v", err)
				} else {
					status = "exact owned container removed; its toxic chains destroyed"
				}
			} else {
				t.Error("retained Docker facility failure prohibits cleanup; exact calibration resource unresolved")
			}
		}
		if err := retain("cleanup", struct {
			Name, ID, Status                        string
			DockerStopped, ClientClosed, EchoReaped bool
		}{name, containerID, status, dockerStopped, clientClosed, echoReaped}); err != nil {
			t.Error("calibration cleanup evidence incomplete")
		}
	})
	mustRetain("create_intent", struct{ Name string }{name})
	raw, err := docker(ctx, "container", "create", "--name", name, "--network", "host", "--platform", "linux/amd64", "--pull=never", "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--label", brokerOwnerLabel+"="+state.RunID, "--label", "io.kaferry-lab.role=latency-calibration", "--mount", "type=bind,src="+configPath+",dst=/calibration.json,readonly", fixture.ProxyImage, command[0], command[1], command[2])
	created = true // even a failed create may have left its planned owned resource
	if err != nil {
		t.Fatal(err) // LinkExecutor returns only a safe private-receipt reference.
	}
	containerID = strings.TrimSpace(string(raw))
	if !linkLatencyContainerID(containerID) {
		containerID = "" // cleanup must inspect the planned name, then prove its ID
		t.Fatal("calibration create did not return an immutable ID")
	}
	if err = inspect(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err = errors.Join(listeners[0].Close(), listeners[1].Close()); err != nil {
		t.Fatal("calibration reserved-port release failed")
	}
	if _, err = docker(ctx, "container", "start", containerID); err != nil {
		t.Fatal(err)
	}
	if err = inspect(ctx, true); err != nil {
		t.Fatal(err)
	}

	apiCall := func(method, path string, body any, out any) error {
		if dockerStopped {
			return errors.New("Docker facility stopped; calibration API action prohibited")
		}
		start := time.Now()
		status, data, err := linkLatencyHTTP(ctx, api, method, path, body)
		if e := retain("api", struct {
			Method, Path   string
			Status         int
			StartNS, EndNS int64
			Successful     bool
		}{method, path, status, start.Sub(origin).Nanoseconds(), time.Since(origin).Nanoseconds(), err == nil}); e != nil {
			return e
		}
		if err != nil {
			return err
		}
		if out != nil && json.Unmarshal(data, out) != nil {
			return errors.New("calibration API response malformed")
		}
		return nil
	}
	// Only exact refusal at the just-started API socket may retry. HTTP status,
	// malformed/version/configuration and unknown failures cannot retry.
	for attempt := 1; ; attempt++ {
		var version struct{ Version string }
		err = apiCall("GET", "/version", nil, &version)
		if err == nil {
			if version.Version != "2.12.0" {
				t.Fatal("calibration stock proxy version mismatch")
			}
			break
		}
		if !errors.Is(err, syscall.ECONNREFUSED) || attempt >= 20 || ctx.Err() != nil {
			t.Fatal("calibration stock proxy API not independently ready")
		}
		select {
		case <-ctx.Done():
			t.Fatal("calibration API readiness budget expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	checkMapping := func(want []linkLatencyToxic) error {
		if err := inspect(ctx, true); err != nil {
			return err
		}
		var proxies map[string]linkLatencyProxy
		if err := apiCall("GET", "/proxies", nil, &proxies); err != nil {
			return err
		}
		got, ok := proxies[mapping.Name]
		if len(proxies) != 1 || !ok || got.Name != mapping.Name || got.Listen != mapping.Listen || got.Upstream != mapping.Upstream || !got.Enabled || !reflect.DeepEqual(got.Toxics, want) {
			return errors.New("calibration unique mapping/toxic readback mismatch")
		}
		return retain("mapping", got)
	}
	if err = checkMapping([]linkLatencyToxic{}); err != nil {
		t.Fatal(err)
	}
	persistent, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		t.Fatal("calibration persistent socket unavailable")
	}
	local, remote := persistent.LocalAddr().String(), persistent.RemoteAddr().String()
	persistentID, persistentPeer := 0, ""
	newIDs := map[int]bool{}
	seenNonces := map[string]bool{}
	probeBoth := func(phase, delayedDirection string) {
		t.Helper()
		for _, socket := range []string{"existing", "new"} {
			one, done := context.WithTimeout(ctx, 4*time.Second)
			conn := persistent
			if socket == "new" {
				var e error
				conn, e = (&net.Dialer{Timeout: time.Second}).DialContext(one, "tcp4", endpoint)
				if e != nil {
					done()
					t.Fatal("calibration fresh socket unavailable")
				}
			}
			observed, e := exchangeLinkLatency(one, origin, conn, serverEvents)
			done()
			observed.Phase, observed.Socket = phase, socket
			if socket == "new" {
				closeErr := conn.Close()
				observed.Closed = closeErr == nil
				e = errors.Join(e, closeErr)
			}
			mustRetain("exchange", observed)
			if e != nil || !observed.ExactBytes || seenNonces[observed.Nonce] {
				t.Fatal("calibration unique exact-nonce exchange failed")
			}
			seenNonces[observed.Nonce] = true
			if socket == "existing" {
				if observed.ClientLocal != local || observed.ClientRemote != remote || persistentID != 0 && (observed.ServerConnection != persistentID || observed.ServerPeer != persistentPeer) {
					t.Fatal("calibration replaced its established socket")
				}
				persistentID, persistentPeer = observed.ServerConnection, observed.ServerPeer
			} else {
				if observed.ServerConnection == persistentID || newIDs[observed.ServerConnection] || observed.ClientLocal == local {
					t.Fatal("calibration fresh socket reused an earlier connection")
				}
				newIDs[observed.ServerConnection] = true
			}
			up := time.Duration(observed.ServerFirstByteNS - observed.ClientWriteStartNS)
			down := time.Duration(observed.ClientFirstByteNS - observed.ServerWriteStartNS)
			prompt := 200 * time.Millisecond
			minimum := 300 * time.Millisecond // configured 400ms minus one 100ms granule
			if up < 0 || down < 0 || observed.ClientWriteEndNS-observed.ClientWriteStartNS > int64(prompt) || observed.ServerWriteStartNS-observed.ServerReceiveNS > int64(prompt) || delayedDirection == "upstream" && (up < minimum || down > prompt) || delayedDirection == "downstream" && (down < minimum || up > prompt) || delayedDirection == "" && (up > prompt || down > prompt) {
				t.Fatalf("calibration directional effect not independently reached: phase=%s socket=%s up=%s down=%s", phase, socket, up, down)
			}
		}
	}
	// When latency is added to the existing stock proxy, both its established
	// link and a later new link must exhibit the independently observed direction.
	probeBoth("healthy", "")
	for _, setting := range []struct {
		direction string
		toxicity  float64
	}{{"downstream", 1}, {"upstream", 1}, {"downstream", 0}} {
		toxic := linkLatencyToxic{Name: "latency", Type: "latency", Stream: setting.direction, Toxicity: setting.toxicity}
		toxic.Attributes.Latency = 400
		if err = checkMapping([]linkLatencyToxic{}); err != nil {
			t.Fatal(err)
		}
		var added linkLatencyToxic
		if err = apiCall("POST", "/proxies/"+mapping.Name+"/toxics", toxic, &added); err != nil || !reflect.DeepEqual(added, toxic) {
			t.Fatal("calibration latency activation response mismatch")
		}
		if err = checkMapping([]linkLatencyToxic{toxic}); err != nil {
			t.Fatal(err)
		}
		direction := setting.direction
		phase := setting.direction
		if setting.toxicity == 0 {
			direction, phase = "", "toxicity-zero"
		}
		probeBoth(phase, direction)
		if err = apiCall("DELETE", "/proxies/"+mapping.Name+"/toxics/latency", nil, nil); err != nil {
			t.Fatal(err)
		}
		if err = checkMapping([]linkLatencyToxic{}); err != nil {
			t.Fatal(err)
		}
		// Then removal must independently restore prompt exact-byte exchange on
		// both socket lifetimes. Nothing is pending when this toxic is removed;
		// this control does not claim to calibrate pending-byte early flush.
		probeBoth("removed-"+phase, "")
	}
	if err = ctx.Err(); err != nil {
		t.Fatal("calibration work budget expired")
	}
}

func linkLatencyContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func linkLatencyHTTP(ctx context.Context, endpoint, method, path string, value any) (int, []byte, error) {
	var body []byte
	if value != nil {
		body, _ = json.Marshal(value)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("calibration HTTP request unavailable")
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return 0, nil, syscall.ECONNREFUSED
		}
		return 0, nil, errors.New("calibration HTTP transport failed; nonpublic details withheld")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<10)+1))
	if err != nil || len(data) > 8<<10 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, nil, errors.New("calibration HTTP response failed or exceeded bound; body withheld")
	}
	return response.StatusCode, data, nil
}

func exchangeLinkLatency(ctx context.Context, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt) (result linkLatencyExchange, err error) {
	result.RequestStartNS = time.Since(origin).Nanoseconds()
	result.ClientLocal, result.ClientRemote = conn.LocalAddr().String(), conn.RemoteAddr().String()
	defer func() {
		if err != nil {
			result.Error = "bounded exact-nonce exchange failed"
		}
	}()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, errors.New("calibration nonce unavailable")
	}
	result.Nonce = hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return result, err
	}
	result.ClientWriteStartNS = time.Since(origin).Nanoseconds()
	n, err := conn.Write(nonce[:])
	result.ClientWriteEndNS = time.Since(origin).Nanoseconds()
	if err != nil || n != len(nonce) {
		return result, errors.New("calibration nonce write incomplete")
	}
	var reply [32]byte
	_, err = io.ReadFull(conn, reply[:1])
	result.ClientFirstByteNS = time.Since(origin).Nanoseconds()
	if err == nil {
		_, err = io.ReadFull(conn, reply[1:])
	}
	result.ClientReadEndNS = time.Since(origin).Nanoseconds()
	select {
	case received := <-events:
		result.ServerConnection, result.ServerPeer = received.Connection, received.Peer
		result.ServerFirstByteNS, result.ServerReceiveNS = received.FirstByteNS, received.ReceiveNS
		result.ServerWriteStartNS, result.ServerWriteEndNS = received.WriteStartNS, received.WriteEndNS
		if received.Nonce != result.Nonce || received.Error != "" {
			err = errors.Join(err, errors.New("calibration independent server receipt mismatch"))
		}
	case <-ctx.Done():
		err = errors.Join(err, errors.New("calibration independent server receipt missing"))
	}
	result.ExactBytes = bytes.Equal(reply[:], nonce[:]) && err == nil
	return result, err
}

func startLinkLatencyEcho(ctx context.Context, origin time.Time, listener net.Listener, events chan<- linkLatencyServerReceipt) func() error {
	var mu sync.Mutex
	connections := make([]net.Conn, 0, 8)
	stopping := false
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for id := 1; id <= 8; id++ {
			conn, err := listener.Accept()
			if err != nil {
				return // cleanup closes the listener and every accepted connection
			}
			mu.Lock()
			if stopping {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			connections = append(connections, conn)
			mu.Unlock()
			workers.Add(1)
			go func(id int, conn net.Conn) {
				defer workers.Done()
				defer conn.Close()
				deadline, _ := ctx.Deadline()
				if conn.SetDeadline(deadline) != nil {
					return
				}
				for request := 0; request < 14; request++ {
					var nonce [32]byte
					if _, err := io.ReadFull(conn, nonce[:1]); err != nil {
						return
					}
					r := linkLatencyServerReceipt{Connection: id, Peer: conn.RemoteAddr().String(), FirstByteNS: time.Since(origin).Nanoseconds()}
					if _, err := io.ReadFull(conn, nonce[1:]); err != nil {
						return
					}
					r.ReceiveNS, r.Nonce = time.Since(origin).Nanoseconds(), hex.EncodeToString(nonce[:])
					r.WriteStartNS = time.Since(origin).Nanoseconds()
					n, err := conn.Write(nonce[:])
					r.WriteEndNS = time.Since(origin).Nanoseconds()
					if err != nil || n != len(nonce) {
						r.Error = "server exact-nonce write incomplete"
					}
					select {
					case events <- r:
					case <-ctx.Done():
						return
					}
				}
			}(id, conn)
		}
	}()
	return func() error {
		mu.Lock()
		stopping = true
		_ = listener.Close()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
			return nil
		case <-time.After(time.Second):
			return errors.New("bounded echo cleanup did not reap goroutines")
		}
	}
}
