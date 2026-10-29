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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

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

type linkLatencyMappingReadback struct {
	PrivateRecordKind   string
	Matched             bool
	ObservationComplete bool
	Expected            linkLatencyProxy
	ResponseBytes       []byte
	DecodedMappings     map[string]json.RawMessage
	DecodedMatch        *linkLatencyProxy
	ToxicsFieldPresent  bool
	Components          map[string]bool
	DecodeCause         []byte
}

// The selected zero-active-toxic predicate concerns collection membership:
// explicitly present null and [] both contain no entries. Missing is unknown.
// Nonempty entries must still contain every reviewed field and exact value.
func validateLinkLatencyMapping(raw []byte, mapping linkLatencyProxy, want []linkLatencyToxic) linkLatencyMappingReadback {
	mapping.Toxics = want
	r := linkLatencyMappingReadback{PrivateRecordKind: "latency-mapping-readback", Expected: mapping, ResponseBytes: bytes.Clone(raw), Components: map[string]bool{}}
	for _, field := range []string{"bounded_response", "json_object", "unique_mapping", "mapping_fields", "name", "listen", "upstream", "enabled", "toxics_present", "toxics_fields", "toxics_values"} {
		r.Components[field] = false
	}
	r.Components["bounded_response"] = len(raw) > 0 && len(raw) <= 8<<10
	r.ObservationComplete = r.Components["bounded_response"] // returned body only; actual HTTP path owns read/close
	if !r.Components["bounded_response"] {
		return r
	}
	if err := json.Unmarshal(raw, &r.DecodedMappings); err != nil {
		r.DecodeCause = []byte(err.Error())
		return r
	}
	r.Components["json_object"] = r.DecodedMappings != nil
	match, ok := r.DecodedMappings[mapping.Name]
	r.Components["unique_mapping"] = len(r.DecodedMappings) == 1 && ok
	if !ok {
		return r
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(match, &fields); err != nil {
		r.DecodeCause = []byte(err.Error())
		return r
	}
	r.Components["mapping_fields"] = exactLatencyFields(fields, "name", "listen", "upstream", "enabled", "toxics")
	// Pinned Toxiproxy2.12.0 also serializes its exported diagnostic Logger
	// as {}. Admit only that exact extra member; it proves no mapping fact.
	if exactLatencyFields(fields, "name", "listen", "upstream", "enabled", "toxics", "Logger") {
		var logger map[string]json.RawMessage
		r.Components["mapping_fields"] = json.Unmarshal(fields["Logger"], &logger) == nil && logger != nil && len(logger) == 0
	}
	toxics, present := fields["toxics"]
	r.ToxicsFieldPresent, r.Components["toxics_present"] = present, present
	var got linkLatencyProxy
	if err := json.Unmarshal(match, &got); err != nil {
		r.DecodeCause = []byte(err.Error())
		return r
	}
	r.DecodedMatch = &got
	r.Components["name"] = got.Name == mapping.Name
	r.Components["listen"] = got.Listen == mapping.Listen
	r.Components["upstream"] = got.Upstream == mapping.Upstream
	r.Components["enabled"] = got.Enabled && mapping.Enabled
	if !present {
		return r
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(toxics, &entries); err != nil {
		r.DecodeCause = []byte(err.Error())
		return r
	}
	fieldsExact := true
	for _, entry := range entries {
		var toxic, attributes map[string]json.RawMessage
		if err := json.Unmarshal(entry, &toxic); err != nil {
			r.DecodeCause = []byte(err.Error())
			return r
		}
		if err := json.Unmarshal(toxic["attributes"], &attributes); err != nil {
			r.DecodeCause = []byte(err.Error())
			return r
		}
		fieldsExact = fieldsExact && exactLatencyFields(toxic, "name", "type", "stream", "toxicity", "attributes") && exactLatencyFields(attributes, "latency", "jitter") && nonNullLatencyFields(toxic) && nonNullLatencyFields(attributes)
	}
	r.Components["toxics_fields"] = fieldsExact
	equal := len(got.Toxics) == len(want)
	for index := range got.Toxics {
		if index >= len(want) || got.Toxics[index] != want[index] {
			equal = false
		}
	}
	r.Components["toxics_values"] = equal
	return r
}

func exactLatencyFields(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func nonNullLatencyFields(fields map[string]json.RawMessage) bool {
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

// The actual bounded HTTP layer has already finished read/close. Persist this
// private readback before either semantic acceptance or rejection. The existing
// helper creates only a safe public reference; raw bytes/decoded values stay in
// its fixed private fixture JSON, including successful response observations.
func checkLinkLatencyMapping(state fixture.State, raw []byte, mapping linkLatencyProxy, want []linkLatencyToxic) (linkLatencyProxy, error) {
	r := validateLinkLatencyMapping(raw, mapping, want)
	matched := true
	for _, exact := range r.Components {
		matched = matched && exact
	}
	r.Matched = matched
	var cause error
	if !matched {
		cause = errors.New("calibration unique mapping/toxic readback mismatch")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return linkLatencyProxy{}, linkLatencyRetainFailure(state, []string{"latency_mapping_readback", "Encode"}, raw, err, false)
	}
	if len(body) > 64<<10 {
		return linkLatencyProxy{}, linkLatencyRetainFailure(state, []string{"latency_mapping_readback", "SerializedNoticeOverflow"}, body, errors.New("mapping readback serialized notice exceeds 64KiB; evidence incomplete"), false)
	}
	reference, err := fixture.RetainLinkNetworkFailure(state, []string{"latency_mapping_readback", "GET", "/proxies"}, body, cause)
	if err != nil {
		return linkLatencyProxy{}, err
	}
	if cause != nil {
		return linkLatencyProxy{}, &linkLatencyRetainedFailure{Reference: reference}
	}
	return *r.DecodedMatch, nil
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
	platform, proxyImage, proxyImageID, err := selectedLinkCalibrationProxy(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateScenarioFixturePlatform(platform, runtime.GOOS+"/"+runtime.GOARCH, state); err != nil {
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
	configFile, openErr := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if openErr != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_configuration", "OpenFile", configPath}, nil, openErr, false))
	}
	n, writeErr := configFile.Write(config)
	if writeErr == nil && n != len(config) {
		writeErr = io.ErrShortWrite
	}
	err = errors.Join(writeErr, configFile.Sync(), configFile.Close())
	if err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_configuration", "WriteFile", configPath}, nil, err, false))
	}
	configIdentity, err := readLinkLatencyStartup(configPath, config)
	if err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_configuration", "ValidateOwnerBytes", configPath}, nil, err, false))
	}
	command := []string{"-host=127.0.0.1", "-port=" + apiPort, "-config=/calibration.json"}
	resourcePlan := linkCalibrationLatencyPlan{RunID: state.RunID, Name: name, Role: "latency-calibration", Image: proxyImage, ExpectedImageID: proxyImageID, Network: "host", API: api, Endpoint: endpoint, Upstream: upstream, ConfigPath: configPath, User: configIdentity.user(), ConfigFile: configIdentity, Command: command, MemoryBytes: 128 << 20, NanoCPUs: 500000000, PIDs: 64, LogBytes: 1 << 20}
	mustRetain("resource_plan", struct {
		linkCalibrationLatencyPlan
		BudgetSeconds, WorkSeconds, Connections, Requests, NonceBytes, CleanupDockerCommands int64
		LatencyMS, GranularityMS, DelayedMinimumMS, PromptMaximumMS, RequestBoundMS          int
		LongLatencyMS, LongMinimumMS, LongRequestBoundMS, PendingTriggerMaximumMS            int
	}{resourcePlan, 90, 70, 10, 19, 32, 3, 400, 100, 300, 200, 4000, 20000, 19900, 25000, 1000})
	t.Log("STOCK PROXY ECHO CALIBRATION ONLY; selected synthetic facts: " + filepath.Join(directory, "observations.jsonl"))

	serverEvents := make(chan linkLatencyServerReceipt, 16)
	serverFailures := make(chan linkLatencyNetworkFailure, 32)
	stopEcho := startLinkLatencyEcho(ctx, origin, listeners[2], serverEvents, serverFailures)
	echoOwnsListener = true
	drainServerFailures := func() error {
		return retainLinkLatencyServerFailures(state, serverFailures)
	}
	var persistent net.Conn
	persistentCloseAttempted := false
	var persistentCloseError error
	closePersistent := func() error {
		if persistent == nil {
			return nil
		}
		if !persistentCloseAttempted {
			persistentCloseAttempted = true
			persistentCloseError = closeLinkLatencyClient(state, persistent)
		}
		return persistentCloseError
	}
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
		facts, err := inspectLinkCalibrationLatencyContainer(raw, state, resourcePlan, containerID, running)
		if err != nil {
			return err
		}
		containerID = facts.ID
		if cause := retain("container_ownership", struct {
			ID, Name, ImageID, User string
			Running                 bool
		}{facts.ID, name, facts.Image, facts.Config.User, *facts.State.Running}); cause != nil {
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
			closeErr := closePersistent()
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
				if actual, absent, _, err := cleanupLinkCalibrationLatencyContainer(cleanup, state, resourcePlan, containerID, docker); err != nil {
					dockerStopped = true
					t.Errorf("calibration cleanup failed: %v", err)
				} else if absent {
					status = "exact planned calibration container absent"
				} else {
					containerID = actual
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
	createArgs, err := linkLatencyCreateArguments(state, resourcePlan, platform)
	if err != nil {
		t.Fatal(linkLatencyRetainFailure(state, []string{"latency_create", "ValidateInitialUser"}, nil, err, false))
	}
	raw, err := docker(ctx, createArgs...)
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

	var mappingResponse []byte // serial successful GET/proxies only; cleared before every call
	apiCall := func(method, path string, body any, out any) error {
		mappingResponse = nil
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
			return linkLatencyRetainFailure(state, []string{"latency_http", "PublicReceipt", method, api, path}, data, e, false)
		}
		if err != nil {
			return err
		}
		if method == "GET" && path == "/proxies" {
			mappingResponse = bytes.Clone(data)
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
		if err := apiCall("GET", "/proxies", nil, nil); err != nil {
			return err
		}
		got, err := checkLinkLatencyMapping(state, mappingResponse, mapping, want)
		if err != nil {
			return err
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
	probeBoth := func(phase, delayedDirection string, longDownstream bool) {
		t.Helper()
		for _, socket := range []string{"existing", "new"} {
			if err := drainServerFailures(); err != nil {
				t.Fatal(err)
			}
			requestBound := 4 * time.Second
			if longDownstream {
				requestBound = 25 * time.Second
			}
			one, done := context.WithTimeout(ctx, requestBound)
			conn := persistent
			if socket == "new" {
				var e error
				conn, e = dialLinkLatency(one, state, endpoint, (&net.Dialer{Timeout: time.Second}).DialContext)
				if e != nil {
					done()
					t.Fatal(e)
				}
			}
			var observed linkLatencyExchange
			var e error
			if longDownstream {
				observed, e = exchangeLongLinkLatency(one, state, origin, conn, serverEvents)
			} else {
				observed, e = exchangeLinkLatency(one, state, origin, conn, serverEvents)
			}
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
			if longDownstream {
				if !linkLatencyLongDownstreamObserved(observed) {
					t.Fatal("20s downstream server-write-to-client-first-byte interval not independently observed")
				}
				continue
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
	probeBoth("healthy", "", false)
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
		probeBoth(phase, direction, false)
		if err = apiCall("DELETE", "/proxies/"+mapping.Name+"/toxics/latency", nil, nil); err != nil {
			t.Fatal(err)
		}
		if err = checkMapping([]linkLatencyToxic{}); err != nil {
			t.Fatal(err)
		}
		// Then removal must independently restore prompt exact-byte exchange on
		// both socket lifetimes. Nothing is pending when this toxic is removed;
		// this control does not claim to calibrate pending-byte early flush.
		probeBoth("removed-"+phase, "", false)
	}
	// The 20s toxic is a separate measurement, never an extrapolation from the
	// 400ms controls. Each complete exchange records its own server write end.
	longToxic := linkLatencyToxic{Name: "latency", Type: "latency", Stream: "downstream", Toxicity: 1}
	longToxic.Attributes.Latency = 20000
	if err = checkMapping([]linkLatencyToxic{}); err != nil {
		t.Fatal(err)
	}
	var addedLong linkLatencyToxic
	if err = apiCall("POST", "/proxies/"+mapping.Name+"/toxics", longToxic, &addedLong); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(addedLong, longToxic) {
		t.Fatal("20s toxic activation response mismatch")
	}
	if err = checkMapping([]linkLatencyToxic{longToxic}); err != nil {
		t.Fatal(err)
	}
	probeBoth("downstream-20s", "downstream", true)
	if err = checkMapping([]linkLatencyToxic{longToxic}); err != nil {
		t.Fatal(err)
	}
	// Unlike the short quiescent removals, this request removes the toxic while
	// a matching server-written nonce has no observed first-byte read completion.
	pending, pendingErr := pendingLinkLatencyRemoval(ctx, state, origin, persistent, serverEvents, closePersistent, func() (int64, int64, error) {
		start := time.Since(origin).Nanoseconds()
		e := apiCall("DELETE", "/proxies/"+mapping.Name+"/toxics/latency", nil, nil)
		return start, time.Since(origin).Nanoseconds(), e
	})
	pending.Exchange.Phase, pending.Exchange.Socket = "pending-removal-20s", "existing"
	if pendingErr == nil {
		pending.Effect, pendingErr = linkLatencyPendingEffect(pending)
	}
	mustRetain("pending_removal", pending)
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	if pending.Exchange.ClientLocal != local || pending.Exchange.ClientRemote != remote || pending.Exchange.ServerConnection != persistentID || pending.Exchange.ServerPeer != persistentPeer || seenNonces[pending.Exchange.Nonce] {
		t.Fatal("pending-removal nonce or established socket identity mismatch")
	}
	seenNonces[pending.Exchange.Nonce] = true
	if err = checkMapping([]linkLatencyToxic{}); err != nil {
		t.Fatal(err)
	}
	// Exact bytes and prompt new/existing responses establish recovery; no
	// aggregate zero counter or inferred quiescence is used for that decision.
	probeBoth("removed-pending-20s", "", false)

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

func exchangeLinkLatency(ctx context.Context, state fixture.State, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt) (linkLatencyExchange, error) {
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return exchangeLinkLatencyInWindow(bounded, state, origin, conn, events)
}

func exchangeLongLinkLatency(ctx context.Context, state fixture.State, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt) (linkLatencyExchange, error) {
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return exchangeLinkLatencyInWindow(bounded, state, origin, conn, events)
}

func exchangeLinkLatencyInWindow(ctx context.Context, state fixture.State, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt) (result linkLatencyExchange, err error) {
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
	deadline, ok := ctx.Deadline()
	if !ok {
		return result, errors.New("calibration exchange requires its fixed request deadline")
	}
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
	connections := make([]net.Conn, 0, 10)
	stopping := false
	failed := func(operation, endpoint string, cause error) {
		// At most 23 terminal/close failures: ten worker failures,
		// ten single-attempt connection closes, listener/accept and one race.
		// The fixed 32-entry owner handoff never drops or redacts a cause.
		failures <- linkLatencyNetworkFailure{[]string{"latency_echo", operation, endpoint}, cause}
	}
	var closeMu sync.Mutex
	closeAttempted := map[net.Conn]bool{} // at most ten owned TCP connections
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
		for id := 1; id <= 10; id++ {
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

// Long-delay comparisons use the independent server write END, not request
// start or configured toxic presence, as the lower observation boundary.
func linkLatencyServerWriteObserved(v linkLatencyExchange) bool {
	const prompt = int64(200 * time.Millisecond)
	return v.ExactBytes && v.Error == "" && v.RequestStartNS > 0 &&
		v.ClientWriteStartNS >= v.RequestStartNS && v.ClientWriteEndNS >= v.ClientWriteStartNS && v.ClientWriteEndNS-v.ClientWriteStartNS <= prompt &&
		v.ServerFirstByteNS >= v.ClientWriteStartNS && v.ServerFirstByteNS-v.ClientWriteStartNS <= prompt &&
		v.ServerReceiveNS >= v.ServerFirstByteNS && v.ServerWriteStartNS >= v.ServerReceiveNS && v.ServerWriteStartNS-v.ServerReceiveNS <= prompt &&
		v.ServerWriteEndNS >= v.ServerWriteStartNS && v.ServerWriteEndNS-v.ServerWriteStartNS <= int64(100*time.Millisecond) &&
		v.ClientReadEndNS >= v.ClientFirstByteNS && v.ClientReadEndNS-v.RequestStartNS <= int64(25*time.Second)
}

func linkLatencyLongDownstreamObserved(v linkLatencyExchange) bool {
	return linkLatencyServerWriteObserved(v) &&
		v.ClientFirstByteNS-v.ServerWriteEndNS >= int64(19900*time.Millisecond) &&
		v.ClientFirstByteNS-v.ServerWriteEndNS <= int64(25*time.Second)
}

type linkLatencyPendingRemoval struct {
	Exchange                                          linkLatencyExchange
	ClientReadStartedNS, ClientReadOutstandingCheckNS int64
	RemovalStartNS, RemovalEndNS                      int64
	ReaderReaped                                      bool
	Effect                                            string
}

type linkLatencyPendingRead struct {
	FirstByteNS, ReadEndNS int64
	ExactBytes             bool
	Error                  error // already privately retained before leaving the reader goroutine
}

// This finite observation has exactly one reader, one matching server-write
// receipt and one remove operation. Its callbacks own only this already-open
// persistent socket and this one toxic; they are not a transport/retry policy.
func pendingLinkLatencyRemoval(ctx context.Context, state fixture.State, origin time.Time, conn net.Conn, events <-chan linkLatencyServerReceipt, closeOnce func() error, remove func() (int64, int64, error)) (result linkLatencyPendingRemoval, err error) {
	bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	deadline, _ := bounded.Deadline()
	v := &result.Exchange
	v.RequestStartNS = time.Since(origin).Nanoseconds()
	v.ClientLocal, v.ClientRemote = conn.LocalAddr().String(), conn.RemoteAddr().String()
	operation, safeFailure := "rand.Read", false
	started, firstByte := make(chan int64, 1), make(chan int64, 1)
	readResult, readerDone := make(chan linkLatencyPendingRead, 1), make(chan struct{})
	readerStarted, outcomeConsumed := false, false
	apply := func(read linkLatencyPendingRead) {
		v.ClientFirstByteNS, v.ClientReadEndNS, v.ExactBytes = read.FirstByteNS, read.ReadEndNS, read.ExactBytes
	}
	defer func() {
		var closeErr error
		if readerStarted {
			if err != nil {
				closeErr = closeOnce()
			}
			// Even cancellation cannot abandon a reader or its original notice.
			// Initial SetDeadline bounds this wait by request end + one second;
			// that is <=71s from the campaign origin, before the90s cleanup cap.
			timer := time.NewTimer(max(0, time.Until(deadline)) + time.Second)
			defer timer.Stop()
			select {
			case <-readerDone:
				result.ReaderReaped = true
				if !outcomeConsumed {
					read := <-readResult
					apply(read)
					err = errors.Join(err, read.Error)
				}
			case <-timer.C:
				err = errors.Join(err, errors.New("pending-removal client reader not reaped within its fixed deadline"))
			}
		}
		if err != nil {
			if !safeFailure {
				err = linkLatencyRetainFailure(state, []string{"latency_pending_removal", operation, v.ClientLocal, v.ClientRemote, v.Nonce}, nil, err, false)
			}
			err = errors.Join(err, closeErr)
			v.Error = err.Error()
		}
	}()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, err
	}
	v.Nonce = hex.EncodeToString(nonce[:])
	operation = "SetDeadline"
	if err = conn.SetDeadline(deadline); err != nil {
		return result, err
	}
	operation = "Write"
	v.ClientWriteStartNS = time.Since(origin).Nanoseconds()
	n, writeErr := conn.Write(nonce[:])
	v.ClientWriteEndNS = time.Since(origin).Nanoseconds()
	if writeErr != nil {
		return result, writeErr
	}
	if n != len(nonce) {
		return result, io.ErrShortWrite
	}
	readerStarted = true
	go func() {
		defer close(readerDone)
		started <- time.Since(origin).Nanoseconds()
		var reply [32]byte
		_, cause := io.ReadFull(conn, reply[:1])
		read := linkLatencyPendingRead{FirstByteNS: time.Since(origin).Nanoseconds()}
		firstByte <- read.FirstByteNS
		readOperation := "ReadFirstByte"
		if cause == nil {
			readOperation = "ReadRemainingBytes"
			_, cause = io.ReadFull(conn, reply[1:])
		}
		read.ReadEndNS = time.Since(origin).Nanoseconds()
		read.ExactBytes = cause == nil && bytes.Equal(reply[:], nonce[:])
		if cause != nil {
			read.Error = linkLatencyRetainFailure(state, []string{"latency_pending_removal", readOperation, v.ClientLocal, v.ClientRemote, v.Nonce}, nil, cause, false)
		}
		readResult <- read
	}()
	operation = "ReadStartedHandoff"
	select {
	case result.ClientReadStartedNS = <-started:
	case <-bounded.Done():
		return result, bounded.Err()
	}
	operation = "ServerWriteHandoff"
	select {
	case receipt := <-events:
		v.ServerConnection, v.ServerPeer = receipt.Connection, receipt.Peer
		v.ServerFirstByteNS, v.ServerReceiveNS = receipt.FirstByteNS, receipt.ReceiveNS
		v.ServerWriteStartNS, v.ServerWriteEndNS = receipt.WriteStartNS, receipt.WriteEndNS
		if receipt.Nonce != v.Nonce {
			return result, errors.New("pending-removal server nonce mismatch")
		}
	case <-bounded.Done():
		return result, bounded.Err()
	}
	operation = "PendingTrigger"
	select {
	case <-firstByte:
		return result, errors.New("pending-removal trigger unreached: client first-byte read already completed")
	default:
		result.ClientReadOutstandingCheckNS = time.Since(origin).Nanoseconds()
	}
	if v.ServerWriteEndNS <= 0 || result.ClientReadOutstandingCheckNS-v.ServerWriteEndNS < 0 || result.ClientReadOutstandingCheckNS-v.ServerWriteEndNS > int64(time.Second) {
		return result, errors.New("pending-removal server-write trigger not fresh within one second")
	}
	operation = "RemoveToxic"
	result.RemovalStartNS, result.RemovalEndNS, err = remove()
	if err != nil {
		safeFailure = true
		return result, err
	}
	operation = "ReadCompletedHandoff"
	select {
	case read := <-readResult:
		outcomeConsumed = true
		apply(read)
		if read.Error != nil {
			safeFailure = true
			return result, read.Error
		}
		if !read.ExactBytes {
			return result, errors.New("pending-removal response nonce changed")
		}
	case <-bounded.Done():
		return result, bounded.Err()
	}
	return result, nil
}

// Return observations, never an inferred Kafka ACK or a claim that removal
// necessarily flushes. RemovalStartNS/EndNS enclose the removal callback,
// including API receipt retention. HTTP return has a separate API journal time;
// this classification distinguishes callback placement, not HTTP placement.
func linkLatencyPendingEffect(v linkLatencyPendingRemoval) (string, error) {
	e := v.Exchange
	if !v.ReaderReaped || !linkLatencyServerWriteObserved(e) || e.ServerWriteEndNS <= 0 ||
		v.ClientReadStartedNS < e.ClientWriteEndNS || v.ClientReadStartedNS > v.ClientReadOutstandingCheckNS ||
		v.ClientReadOutstandingCheckNS < e.ServerWriteEndNS || v.ClientReadOutstandingCheckNS-e.ServerWriteEndNS > int64(time.Second) ||
		v.RemovalStartNS < v.ClientReadOutstandingCheckNS || v.RemovalEndNS < v.RemovalStartNS ||
		v.RemovalStartNS-e.ServerWriteEndNS >= int64(19900*time.Millisecond) ||
		e.ClientFirstByteNS < v.RemovalStartNS || e.ClientReadEndNS < e.ClientFirstByteNS {
		return "", errors.New("pending-removal timing/read-completion evidence is missing, stale or precedes removal")
	}
	if e.ClientFirstByteNS-e.ServerWriteEndNS < int64(19900*time.Millisecond) {
		if e.ClientFirstByteNS <= v.RemovalEndNS {
			return "first_byte_during_removal_before_20s_reference", nil
		}
		return "first_byte_after_removal_before_20s_reference", nil
	}
	return "first_byte_at_or_after_20s_reference", nil
}
