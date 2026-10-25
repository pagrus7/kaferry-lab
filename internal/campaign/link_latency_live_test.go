package campaign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	Nonce, Peer                                      string
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
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_identity", "rand.Read"}, nil, err, false))
	}
	name := state.Proxy.Container + "-latency-" + hex.EncodeToString(salt[:])
	directory := filepath.Join(".cache", "fixtures", state.RunID+"-links", name)
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_journal", "Mkdir", directory}, nil, err, false))
	}
	journal, err := os.OpenFile(filepath.Join(directory, "observations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_journal", "OpenFile", filepath.Join(directory, "observations.jsonl")}, nil, err, false))
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(linkLatencyRetainFailure(state, []string{"latency_journal", "Close", journal.Name()}, nil, err, false))
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
			return errors.Join(err, errors.New("calibration selected-fact evidence bound exceeded"))
		}
		n, err := journal.Write(append(body, '\n'))
		written += n
		records++
		return errors.Join(err, journal.Sync())
	}
	mustRetain := func(kind string, value any) {
		t.Helper()
		if err := retain(kind, value); err != nil {
			t.Fatal(linkLatencyRetainFailure(state, []string{"latency_journal", "Persist", kind, journal.Name()}, nil, err, false))
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
	listenerCloseResults := map[string]error{}
	echoOwnsListener := false
	closeListener := func(listener net.Listener) error {
		address := listener.Addr().String()
		if previous, attempted := listenerCloseResults[address]; attempted {
			return previous
		}
		var result error
		if cause := listener.Close(); cause != nil && !linkLatencyClosed(cause) {
			result = linkLatencyRetainFailure(state, []string{"latency_listener", "Close", address}, nil, cause, false)
		}
		listenerCloseResults[address] = result
		return result
	}
	for i := 0; i < 3; i++ {
		listener, e := listenLinkLatency(state, net.Listen)
		if e != nil {
			for _, opened := range listeners {
				if closeErr := closeListener(opened); closeErr != nil {
					t.Error(closeErr)
				}
			}
			t.Fatal(e)
		}
		listeners = append(listeners, listener)
	}
	t.Cleanup(func() {
		for index, listener := range listeners {
			if index == 2 && echoOwnsListener {
				continue
			}
			if closeErr := closeListener(listener); closeErr != nil {
				t.Error(closeErr)
			}
		}
	})
	api, endpoint, upstream := listeners[0].Addr().String(), listeners[1].Addr().String(), listeners[2].Addr().String()
	_, apiPort, _ := net.SplitHostPort(api)
	mapping := linkLatencyProxy{Name: "echo-" + hex.EncodeToString(salt[:]), Listen: endpoint, Upstream: upstream, Enabled: true, Toxics: []linkLatencyToxic{}}
	config, _ := json.Marshal([]linkLatencyProxy{mapping})
	configPath, err := filepath.Abs(filepath.Join(directory, "startup.json"))
	if err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_configuration", "Abs"}, nil, err, false))
	}
	if err = os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_configuration", "WriteFile", configPath}, nil, err, false))
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
	serverFailures := make(chan linkLatencyNetworkFailure, 32)
	stopEcho := startLinkLatencyEcho(ctx, origin, listeners[2], serverEvents, serverFailures)
	echoOwnsListener = true
	drainServerFailures := func() error {
		return retainLinkLatencyServerFailures(state, serverFailures)
	}
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
		if cause := retain("container_ownership", struct {
			ID, Name, ImageID string
			Running           bool
		}{facts.ID, name, facts.Image, *facts.State.Running}); cause != nil {
			return linkLatencyRetainFailure(state, []string{"latency_journal", "Persist", "container_ownership", journal.Name()}, nil, cause, false)
		}
		return nil
	}
	// Restoration/removal is registered before the first Docker mutation. A
	// latched facility failure forbids even alternate cleanup commands or HTTP;
	// unresolved exact resources are recorded, never silently declared reaped.
	t.Cleanup(func() {
		clientClosed := true
		if persistent != nil {
			closeErr := closeLinkLatencyClient(state, persistent)
			clientClosed = closeErr == nil
			if closeErr != nil {
				t.Error(closeErr)
			}
		}
		for _, listener := range listeners[:2] {
			if closeErr := closeListener(listener); closeErr != nil {
				t.Error(closeErr)
			}
		}
		echoErr := stopEcho()
		echoReaped := echoErr == nil
		if echoErr != nil {
			t.Error(linkLatencyRetainFailure(state, []string{"latency_echo", "Wait"}, nil, echoErr, false))
		}
		if err := drainServerFailures(); err != nil {
			t.Error(err)
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
			t.Error(linkLatencyRetainFailure(state, []string{"latency_journal", "Persist", "cleanup", journal.Name()}, nil, err, false))
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
	if err = errors.Join(closeListener(listeners[0]), closeListener(listeners[1])); err != nil {
		t.Fatal(err)
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
		if err := drainServerFailures(); err != nil {
			return err
		}
		status, data, err := linkLatencyHTTP(ctx, state, api, method, path, body)
		if e := retain("api", struct {
			Method, Path   string
			Status         int
			StartNS, EndNS int64
			Successful     bool
		}{method, path, status, start.Sub(origin).Nanoseconds(), time.Since(origin).Nanoseconds(), err == nil}); e != nil {
			return linkLatencyRetainFailure(state, []string{"latency_http", "PublicReceipt", method, api, path}, nil, e, false)
		}
		if err != nil {
			return err
		}
		if out != nil {
			if cause := json.Unmarshal(data, out); cause != nil {
				return linkLatencyRetainFailure(state, []string{"latency_http", "Decode", method, api, path}, data, cause, false)
			}
		}
		return nil
	}
	// Only exact refusal at the just-started API socket may retry. HTTP status,
	// malformed/version/configuration and unknown failures cannot retry.
	if err = readyLinkLatencyAPI(ctx, func() (string, error) {
		var version struct{ Version string }
		err := apiCall("GET", "/version", nil, &version)
		return version.Version, err
	}); err != nil {
		t.Fatal(err)
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
		if cause := retain("mapping", got); cause != nil {
			return linkLatencyRetainFailure(state, []string{"latency_journal", "Persist", "mapping", journal.Name()}, nil, cause, false)
		}
		return nil
	}
	if err = checkMapping([]linkLatencyToxic{}); err != nil {
		t.Fatal(err)
	}
	persistent, err = dialLinkLatency(ctx, state, endpoint, (&net.Dialer{Timeout: time.Second}).DialContext)
	if err != nil {
		t.Fatal(err)
	}
	local, remote := persistent.LocalAddr().String(), persistent.RemoteAddr().String()
	persistentID, persistentPeer := 0, ""
	newIDs := map[int]bool{}
	seenNonces := map[string]bool{}
	probeBoth := func(phase, delayedDirection string) {
		t.Helper()
		for _, socket := range []string{"existing", "new"} {
			if err := drainServerFailures(); err != nil {
				t.Fatal(err)
			}
			one, done := context.WithTimeout(ctx, 4*time.Second)
			conn := persistent
			if socket == "new" {
				var e error
				conn, e = dialLinkLatency(one, state, endpoint, (&net.Dialer{Timeout: time.Second}).DialContext)
				if e != nil {
					done()
					t.Fatal(e)
				}
			}
			observed, e := exchangeLinkLatency(one, state, origin, conn, serverEvents)
			done()
			observed.Phase, observed.Socket = phase, socket
			if socket == "new" {
				closeErr := closeLinkLatencyClient(state, conn)
				observed.Closed = closeErr == nil
				e = errors.Join(e, closeErr)
			}
			e = errors.Join(e, drainServerFailures())
			mustRetain("exchange", observed)
			if e != nil {
				t.Fatal(e)
			}
			if !observed.ExactBytes || seenNonces[observed.Nonce] {
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
		if err = apiCall("POST", "/proxies/"+mapping.Name+"/toxics", toxic, &added); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(added, toxic) {
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

func linkLatencyHTTP(ctx context.Context, state fixture.State, endpoint, method, path string, value any) (int, []byte, error) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return requestLinkLatencyHTTP(ctx, state, endpoint, method, path, value, client.Do)
}

// This callback is only the actual HTTP request boundary. It permits literal
// response/transport controls without a network server or transport framework.
func requestLinkLatencyHTTP(ctx context.Context, state fixture.State, endpoint, method, path string, value any, do func(*http.Request) (*http.Response, error)) (int, []byte, error) {
	action := []string{"latency_http", method, endpoint, path}
	var body []byte
	if value != nil {
		var err error
		body, err = json.Marshal(value)
		if err != nil {
			return 0, nil, linkLatencyRetainFailure(state, action, nil, err, false)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, cause := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, bytes.NewReader(body))
	if cause != nil {
		return 0, nil, linkLatencyRetainFailure(state, action, nil, cause, false)
	}
	request.Header.Set("Content-Type", "application/json")
	response, cause := do(request)
	// A bare errno or non-request failure cannot acquire this origin marker.
	requestOrigin := false
	var socket *net.OpError
	if response == nil && cause != nil && errors.As(cause, &socket) {
		requestOrigin = true
	}
	status := 0
	var data []byte
	if response != nil {
		status = response.StatusCode
		if response.Body == nil {
			cause = errors.Join(cause, errors.New("HTTP response body missing"))
		} else {
			var readErr error
			data, readErr = io.ReadAll(io.LimitReader(response.Body, (8<<10)+1))
			cause = errors.Join(cause, readErr)
			if readErr != nil || len(data) > 8<<10 {
				action = append(action, "response_prefix_incomplete", "capture_limit_bytes=8192", fmt.Sprintf("observed_prefix_bytes=%d", len(data)))
			}
			if len(data) > 8<<10 {
				cause = errors.Join(cause, errors.New("HTTP response prefix incomplete: exceeded 8KiB capture bound"))
			}
			// This raw close outcome is mandatory and participates in the same
			// whole error tree before retry classification and private retention.
			closeErr := response.Body.Close()
			if closeErr != nil {
				requestOrigin = false
			}
			cause = errors.Join(cause, closeErr)
		}
		if status < 200 || status >= 300 {
			reportedStatus := response.Status
			if reportedStatus == "" {
				reportedStatus = "HTTP non-success status"
			}
			cause = errors.Join(cause, errors.New(reportedStatus))
		}
	} else if cause == nil {
		cause = errors.New("HTTP response missing")
	}
	cause = errors.Join(cause, ctx.Err())
	if cause != nil {
		retry := requestOrigin && linkLatencyRefusalOnly(cause)
		return status, nil, linkLatencyRetainFailure(state, action, data, cause, retry)
	}
	return status, data, nil
}

type linkLatencyRetainedFailure struct {
	Reference string
	Retryable bool
}

func (e *linkLatencyRetainedFailure) Error() string {
	return "calibration network action failed; private receipt " + e.Reference
}

func linkLatencyRetainFailure(state fixture.State, action []string, notice []byte, cause error, retry bool) error {
	reference, err := fixture.RetainLinkNetworkFailure(state, action, notice, cause)
	if err != nil {
		return err // shared helper returns only safe fatal persistence/bound errors
	}
	return &linkLatencyRetainedFailure{Reference: reference, Retryable: retry}
}

// Only the already-proved actual request scope may use this all-leaf rule.
// Wrappers preserve the original error; any other leaf rejects the whole tree.
func linkLatencyRefusalOnly(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if len(joined.Unwrap()) == 0 {
			return false
		}
		for _, leaf := range joined.Unwrap() {
			if !linkLatencyRefusalOnly(leaf) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return linkLatencyRefusalOnly(wrapped.Unwrap())
	}
	return err == syscall.ECONNREFUSED
}

func readyLinkLatencyAPI(ctx context.Context, read func() (string, error)) error {
	for attempt := 1; attempt <= 20; attempt++ {
		version, err := read()
		if err == nil {
			if version != "2.12.0" {
				return errors.New("calibration stock proxy version mismatch")
			}
			return nil
		}
		// Exact type avoids promoting a joined receipt/close/other fatal error
		// merely because one nested retained error permits a retry.
		failure, ok := err.(*linkLatencyRetainedFailure)
		if !ok || !failure.Retryable || attempt == 20 || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("calibration API sample bound exhausted")
}

func exchangeLinkLatency(ctx context.Context, state fixture.State, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt) (result linkLatencyExchange, err error) {
	result.RequestStartNS = time.Since(origin).Nanoseconds()
	result.ClientLocal, result.ClientRemote = conn.LocalAddr().String(), conn.RemoteAddr().String()
	operation := "rand.Read"
	defer func() {
		if err != nil {
			err = linkLatencyRetainFailure(state, []string{"latency_exchange", operation, result.ClientLocal, result.ClientRemote, result.Nonce}, nil, err, false)
			result.Error = err.Error()
		}
	}()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, err
	}
	result.Nonce = hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	operation = "SetDeadline"
	if err = conn.SetDeadline(deadline); err != nil {
		return result, err
	}
	operation = "Write"
	result.ClientWriteStartNS = time.Since(origin).Nanoseconds()
	n, err := conn.Write(nonce[:])
	result.ClientWriteEndNS = time.Since(origin).Nanoseconds()
	if err != nil {
		return result, err
	}
	if n != len(nonce) {
		return result, io.ErrShortWrite
	}
	var reply [32]byte
	operation = "ReadFirstByte"
	_, err = io.ReadFull(conn, reply[:1])
	result.ClientFirstByteNS = time.Since(origin).Nanoseconds()
	if err == nil {
		operation = "ReadRemainingBytes"
		_, err = io.ReadFull(conn, reply[1:])
	}
	result.ClientReadEndNS = time.Since(origin).Nanoseconds()
	if err != nil {
		return result, err
	}
	operation = "server_receipt"
	select {
	case received := <-events:
		result.ServerConnection, result.ServerPeer = received.Connection, received.Peer
		result.ServerFirstByteNS, result.ServerReceiveNS = received.FirstByteNS, received.ReceiveNS
		result.ServerWriteStartNS, result.ServerWriteEndNS = received.WriteStartNS, received.WriteEndNS
		if received.Nonce != result.Nonce {
			err = errors.Join(err, errors.New("calibration independent server receipt mismatch"))
		}
	case <-ctx.Done():
		err = errors.Join(err, ctx.Err())
	}
	result.ExactBytes = bytes.Equal(reply[:], nonce[:]) && err == nil
	return result, err
}

type linkLatencyNetworkFailure struct {
	Action []string
	Cause  error
}

func linkLatencyClosed(err error) bool {
	if err == net.ErrClosed {
		return true
	}
	socket, ok := err.(*net.OpError)
	return ok && socket.Err == net.ErrClosed
}

func startLinkLatencyEcho(ctx context.Context, origin time.Time, listener net.Listener, events chan<- linkLatencyServerReceipt, failures chan<- linkLatencyNetworkFailure) func() error {
	var mu sync.Mutex
	connections := make([]net.Conn, 0, 8)
	stopping := false
	failed := func(operation, endpoint string, cause error) {
		// At most 19 terminal/close failures: eight worker failures,
		// eight single-attempt connection closes, listener/accept and one race.
		// The fixed 32-entry owner handoff never drops or redacts a cause.
		failures <- linkLatencyNetworkFailure{[]string{"latency_echo", operation, endpoint}, cause}
	}
	var closeMu sync.Mutex
	closeAttempted := map[net.Conn]bool{} // at most eight owned TCP connections
	closeConn := func(conn net.Conn) {
		closeMu.Lock()
		if closeAttempted[conn] {
			closeMu.Unlock()
			return
		}
		closeAttempted[conn] = true
		closeMu.Unlock()
		if err := conn.Close(); err != nil && !linkLatencyClosed(err) {
			failed("Close", conn.RemoteAddr().String(), err)
		}
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for id := 1; id <= 8; id++ {
			conn, err := listener.Accept()
			if err != nil {
				mu.Lock()
				expected := stopping && linkLatencyClosed(err)
				mu.Unlock()
				if !expected {
					failed("Accept", listener.Addr().String(), err)
				}
				return
			}
			mu.Lock()
			if stopping {
				mu.Unlock()
				closeConn(conn)
				return
			}
			connections = append(connections, conn)
			mu.Unlock()
			workers.Add(1)
			go func(id int, conn net.Conn) {
				defer workers.Done()
				defer closeConn(conn)
				endpoint := conn.RemoteAddr().String()
				deadline, _ := ctx.Deadline()
				if err := conn.SetDeadline(deadline); err != nil {
					failed("SetDeadline", endpoint, err)
					return
				}
				for request := 0; request < 14; request++ {
					var nonce [32]byte
					n, err := io.ReadFull(conn, nonce[:1])
					if err != nil {
						mu.Lock()
						expected := stopping && linkLatencyClosed(err)
						mu.Unlock()
						if !expected && !(request > 0 && n == 0 && err == io.EOF) {
							failed("ReadFirstByte", endpoint, err)
						}
						return
					}
					r := linkLatencyServerReceipt{Connection: id, Peer: endpoint, FirstByteNS: time.Since(origin).Nanoseconds()}
					if _, err := io.ReadFull(conn, nonce[1:]); err != nil {
						failed("ReadRemainingBytes", endpoint, err)
						return
					}
					r.ReceiveNS, r.Nonce = time.Since(origin).Nanoseconds(), hex.EncodeToString(nonce[:])
					r.WriteStartNS = time.Since(origin).Nanoseconds()
					n, err = conn.Write(nonce[:])
					r.WriteEndNS = time.Since(origin).Nanoseconds()
					if err != nil || n != len(nonce) {
						if err == nil {
							err = io.ErrShortWrite
						}
						failed("Write", endpoint, err)
						return
					}
					select {
					case events <- r:
					case <-ctx.Done():
						failed("ReceiptHandoff", endpoint, ctx.Err())
						return
					}
				}
			}(id, conn)
		}
	}()
	return func() error {
		mu.Lock()
		stopping = true
		if err := listener.Close(); err != nil && !linkLatencyClosed(err) {
			failed("ListenerClose", listener.Addr().String(), err)
		}
		for _, conn := range connections {
			closeConn(conn)
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

// Fixed opening/closing boundaries keep literal failure controls on the same
// path as the real socket calls; no alternate network route is introduced.
func listenLinkLatency(state fixture.State, listen func(string, string) (net.Listener, error)) (net.Listener, error) {
	listener, cause := listen("tcp4", "127.0.0.1:0")
	if cause != nil {
		return nil, linkLatencyRetainFailure(state, []string{"latency_listener", "Listen", "tcp4", "127.0.0.1:0"}, nil, cause, false)
	}
	return listener, nil
}

func dialLinkLatency(ctx context.Context, state fixture.State, endpoint string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	conn, cause := dial(ctx, "tcp4", endpoint)
	if cause != nil {
		return nil, linkLatencyRetainFailure(state, []string{"latency_client", "Dial", "tcp4", endpoint}, nil, cause, false)
	}
	return conn, nil
}

func closeLinkLatencyClient(state fixture.State, conn net.Conn) error {
	cause := conn.Close()
	if cause == nil || linkLatencyClosed(cause) {
		return nil
	}
	return linkLatencyRetainFailure(state, []string{"latency_client", "Close", conn.LocalAddr().String(), conn.RemoteAddr().String()}, nil, cause, false)
}

func retainLinkLatencyServerFailures(state fixture.State, failures <-chan linkLatencyNetworkFailure) error {
	var result error
	for {
		select {
		case failure := <-failures:
			result = errors.Join(result, linkLatencyRetainFailure(state, failure.Action, nil, failure.Cause, false))
		default:
			return result
		}
	}
}
