package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ProxyImage = "ghcr.io/shopify/toxiproxy@sha256:a3e244375123dad8849091bcc59775e188624d3f602db01901f9af855682fef8"

// Image config addressed by the pinned Linux AMD64 manifest.
const proxyConfigID = "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa"
const linkRoleLabel = "io.kaferry-lab.role"

// ProxyState records intended resources before creation. Immutable identities
// come from a separate exclusive identity receipt after successful inspection.
// The two broker containers and direct observer endpoints stay in State.
type ProxyState struct {
	Image, Container, API                          string
	Source, Destination                            ProxyMapping
	ContainerID, NetworkID, ImageID, BrokerImageID string   `json:",omitempty"`
	BrokerIDs                                      []string `json:",omitempty"`
}
type ProxyMapping struct {
	Name     string `json:"name"`
	Listen   string `json:"listen"`
	Upstream string `json:"upstream"`
}
type linkIdentity struct {
	RunID, ManifestSHA256, ContainerID, NetworkID, ImageID, BrokerImageID string
	BrokerIDs                                                             []string
}
type linkNetwork struct {
	ID, Name string
	Labels   map[string]string
}
type linkBinding struct{ HostIP, HostPort string }
type linkContainer struct {
	ID, Name, Image string
	Config          struct {
		Image  string
		Labels map[string]string
		Env    []string
	}
	State      struct{ Running, Paused *bool }
	HostConfig struct {
		NetworkMode  string
		PortBindings map[string][]linkBinding
	}
	NetworkSettings struct {
		Ports    map[string][]linkBinding
		Networks map[string]struct{ NetworkID string }
	}
}

// Only selected public fixture facts are persisted, never full inspect Env.
type linkFacts struct {
	ID, Name, ImageID, ImageReference, NetworkID, Role string
	Running, Paused                                    bool
}
type linkResources struct {
	NetworkID, BrokerImageID, ProxyImageID string
	Brokers                                [2]linkFacts
	Proxy                                  linkFacts
}
type linkRequest func(context.Context, string, string, string, []byte) (int, []byte, error)

// Only socket failures from the fixed loopback HTTP request carry this marker.
// HTTP response and unknown error details are discarded before returning.
type linkSocketError struct{ cause error }

func (e *linkSocketError) Error() string { return "proxy HTTP transport failed: " + e.cause.Error() }
func (e *linkSocketError) Unwrap() error { return e.cause }

type linkAPIReceipt struct {
	ContainerID, NetworkID string
	StartedAt              time.Time
	ElapsedNanoseconds     int64
	Method, Path           string
	Status                 int
	Request                *ProxyMapping  `json:",omitempty"`
	Proxies                []ProxyMapping `json:",omitempty"`
	Version                string         `json:",omitempty"`
	Error                  string         `json:",omitempty"`
}

func linkDirectory(id string) string { return filepath.Join(".cache", "fixtures", id+"-links") }
func loopbackPort(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host != "127.0.0.1" || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", errors.New("link endpoint must be an exact IPv4 loopback port")
	}
	return port, nil
}
func planLinks(s *State) error {
	ports := make([]int, 3)
	used := map[string]bool{s.Source: true, s.Destination: true}
	for i := range ports {
		p, e := unusedPort()
		if e != nil {
			return e
		}
		endpoint := fmt.Sprintf("127.0.0.1:%d", p)
		if used[endpoint] {
			return errors.New("link port reservation collision")
		}
		used[endpoint] = true
		ports[i] = p
	}
	s.WorkerSource = fmt.Sprintf("127.0.0.1:%d", ports[0])
	s.WorkerDestination = fmt.Sprintf("127.0.0.1:%d", ports[1])
	prefix := "kaferry-lab-" + s.RunID
	s.Proxy = &ProxyState{Image: ProxyImage, Container: prefix + "-links", API: fmt.Sprintf("127.0.0.1:%d", ports[2]), Source: ProxyMapping{prefix + "-source-worker", "0.0.0.0:8666", prefix + "-source:29092"}, Destination: ProxyMapping{prefix + "-dest-worker", "0.0.0.0:8667", prefix + "-dest:29092"}}
	return validateLinkPlan(*s)
}
func validateLinkPlan(s State) error {
	if _, e := StatePath(s.RunID); e != nil {
		return e
	}
	prefix := "kaferry-lab-" + s.RunID
	if s.Image != Image || s.Network != prefix || len(s.Containers) != 2 || s.Containers[0] != prefix+"-source" || s.Containers[1] != prefix+"-dest" || s.Proxy == nil {
		return errors.New("invalid linked fixture identity")
	}
	if len(s.ClusterIDs) != 2 || s.ClusterIDs[0] == "" || s.ClusterIDs[0] == s.ClusterIDs[1] {
		return errors.New("linked fixture requires two distinct cluster identities")
	}
	p := s.Proxy
	if p.Image != ProxyImage || p.Container != prefix+"-links" || p.Source != (ProxyMapping{prefix + "-source-worker", "0.0.0.0:8666", prefix + "-source:29092"}) || p.Destination != (ProxyMapping{prefix + "-dest-worker", "0.0.0.0:8667", prefix + "-dest:29092"}) {
		return errors.New("invalid fixed proxy topology")
	}
	seen := map[string]bool{}
	for _, endpoint := range []string{s.Source, s.Destination, s.WorkerSource, s.WorkerDestination, p.API} {
		if _, e := loopbackPort(endpoint); e != nil {
			return e
		}
		if seen[endpoint] {
			return errors.New("linked fixture endpoints overlap")
		}
		seen[endpoint] = true
	}
	for _, id := range []string{p.ContainerID, p.NetworkID} {
		if id != "" && !linkID(id) {
			return errors.New("invalid retained link identity")
		}
	}
	if len(p.BrokerIDs) != 0 && (len(p.BrokerIDs) != 2 || !linkID(p.BrokerIDs[0]) || !linkID(p.BrokerIDs[1]) || p.BrokerIDs[0] == p.BrokerIDs[1]) {
		return errors.New("invalid retained broker identities")
	}
	for _, id := range []string{p.ImageID, p.BrokerImageID} {
		if id != "" && !linkImageID(id) {
			return errors.New("invalid retained link image identity")
		}
	}
	return nil
}
func linkBrokerEnvironment(env []string, s State, index int) []string {
	worker := []string{s.WorkerSource, s.WorkerDestination}[index]
	for i, value := range env {
		switch {
		case strings.HasPrefix(value, "KAFKA_LISTENERS="):
			env[i] += ",WORKER://:29092"
		case strings.HasPrefix(value, "KAFKA_ADVERTISED_LISTENERS="):
			env[i] += ",WORKER://" + worker
		case strings.HasPrefix(value, "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP="):
			env[i] += ",WORKER:PLAINTEXT"
		}
	}
	return env
}
func linkID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func linkImageID(id string) bool {
	return strings.HasPrefix(id, "sha256:") && linkID(strings.TrimPrefix(id, "sha256:"))
}
func linkDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func linkReceipt(s State, kind string, value any) error {
	body, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if len(body) > 128<<10 {
		return errors.New("link receipt exceeds evidence bound")
	}
	f, e := os.CreateTemp(linkDirectory(s.RunID), kind+"-*.json")
	if e != nil {
		return e
	}
	_, writeErr := f.Write(append(body, '\n'))
	return errors.Join(writeErr, f.Sync(), f.Close())
}
func loadLinkIdentity(s *State, manifest []byte) error {
	path := filepath.Join(linkDirectory(s.RunID), "identity.json")
	body, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(body) > 8192 {
		return errors.New("link identity receipt oversized")
	}
	var id linkIdentity
	if e = json.Unmarshal(body, &id); e != nil {
		return e
	}
	if id.RunID != s.RunID || id.ManifestSHA256 != linkDigest(manifest) || !linkID(id.ContainerID) || !linkID(id.NetworkID) || !linkImageID(id.ImageID) || !linkImageID(id.BrokerImageID) || len(id.BrokerIDs) != 2 || !linkID(id.BrokerIDs[0]) || !linkID(id.BrokerIDs[1]) || id.BrokerIDs[0] == id.BrokerIDs[1] {
		return errors.New("link identity receipt does not match reserved manifest")
	}
	s.Proxy.ContainerID, s.Proxy.NetworkID, s.Proxy.ImageID, s.Proxy.BrokerImageID = id.ContainerID, id.NetworkID, id.ImageID, id.BrokerImageID
	s.Proxy.BrokerIDs = append([]string{}, id.BrokerIDs...)
	return nil
}
func saveLinkIdentity(s *State, r linkResources) error {
	path, _ := StatePath(s.RunID)
	manifest, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var reserved State
	if e = json.Unmarshal(manifest, &reserved); e != nil {
		return e
	}
	if e = validateLinkPlan(reserved); e != nil {
		return e
	}
	if reserved.RunID != s.RunID || reserved.Source != s.Source || reserved.Destination != s.Destination || reserved.WorkerSource != s.WorkerSource || reserved.WorkerDestination != s.WorkerDestination || reserved.Proxy.API != s.Proxy.API {
		return errors.New("link manifest changed before identity reservation")
	}
	id := linkIdentity{s.RunID, linkDigest(manifest), r.Proxy.ID, r.NetworkID, r.ProxyImageID, r.BrokerImageID, []string{r.Brokers[0].ID, r.Brokers[1].ID}}
	body, e := json.MarshalIndent(id, "", "  ")
	if e != nil {
		return e
	}
	// Publish complete bytes without replacing an existing identity. A crash
	// during the temporary write leaves no canonical receipt, so cleanup can still
	// resolve the intended exact names through fresh ownership inspection.
	f, e := os.CreateTemp(linkDirectory(s.RunID), "identity-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, we := f.Write(append(body, '\n'))
	if e = errors.Join(we, f.Sync(), f.Close()); e != nil {
		return e
	}
	if e = os.Link(f.Name(), filepath.Join(linkDirectory(s.RunID), "identity.json")); e != nil {
		return e
	}
	return loadLinkIdentity(s, manifest)
}

func setupLinks(ctx context.Context, s *State, run Executor, request linkRequest) error {
	p := s.Proxy
	api, _ := loopbackPort(p.API)
	source, _ := loopbackPort(s.WorkerSource)
	dest, _ := loopbackPort(s.WorkerDestination)
	args := []string{"run", "-d", "--platform", "linux/amd64", "--name", p.Container, "--label", ownerLabel + "=" + s.RunID, "--label", linkRoleLabel + "=proxy", "--network", s.Network, "--memory", "128m", "--cpus", "1", "--pids-limit", "128", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-p", "127.0.0.1:" + api + ":8474", "-p", "127.0.0.1:" + source + ":8666", "-p", "127.0.0.1:" + dest + ":8667", ProxyImage, "-host=0.0.0.0", "-proxy-metrics"}
	if _, e := run(ctx, args...); e != nil {
		return e
	}
	resources, e := inspectLinkResources(ctx, *s, run)
	if e != nil {
		return e
	}
	if e = saveLinkIdentity(s, resources); e != nil {
		return e
	}
	// Only known socket availability failures permit bounded startup retries.
	// Ownership, receipts, responses and context failures stop immediately. A
	// failed/ambiguous POST is never retried.
	for attempt := 0; attempt < 5; attempt++ {
		last := linkAPICall(ctx, *s, run, request, "GET", "/version", nil, 0)
		if last == nil {
			break
		}
		if ctx.Err() != nil || !linkStartupRetryable(last) || attempt == 4 {
			return errors.Join(last, ctx.Err())
		}
		select {
		case <-ctx.Done():
			return errors.Join(last, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	if e = linkAPICall(ctx, *s, run, request, "GET", "/proxies", nil, 0); e != nil {
		return e
	}
	for _, mapping := range []ProxyMapping{p.Source, p.Destination} {
		m := mapping
		if e = linkAPICall(ctx, *s, run, request, "POST", "/proxies", &m, 0); e != nil {
			return e
		}
	}
	return linkAPICall(ctx, *s, run, request, "GET", "/proxies", nil, 2)
}

func linkStartupRetryable(err error) bool {
	// Every outcome must permit retry; a failed receipt beside a transient
	// request cannot authorize another request.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !linkStartupRetryable(e) {
				return false
			}
		}
		return len(joined.Unwrap()) > 0
	}
	socket, ok := err.(*linkSocketError)
	return ok && linkSocketAvailability(socket.cause)
}
func linkSocketAvailability(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !linkSocketAvailability(e) {
				return false
			}
		}
		return len(joined.Unwrap()) > 0
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return linkSocketAvailability(wrapped.Unwrap())
	}
	return err == syscall.ECONNREFUSED || err == syscall.ECONNRESET || err == syscall.EPIPE
}
func linkHTTP(ctx context.Context, endpoint, method, path string, body []byte) (int, []byte, error) {
	if _, e := loopbackPort(endpoint); e != nil {
		return 0, nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, bytes.NewReader(body))
	if e != nil {
		return 0, nil, e
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		var socket *net.OpError
		if errors.As(e, &socket) {
			return 0, nil, &linkSocketError{cause: e}
		}
		return 0, nil, errors.New("proxy HTTP transport failed; non-socket details discarded")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil || len(data) > 64<<10 {
		return response.StatusCode, nil, errors.New("proxy HTTP response incomplete or oversized")
	}
	return response.StatusCode, data, nil
}
func linkAPICall(ctx context.Context, s State, run Executor, request linkRequest, method, path string, mapping *ProxyMapping, expectedCount int) (err error) {
	if s.Proxy == nil || request == nil {
		return errors.New("linked fixture API executor missing")
	}
	if s.Proxy.ContainerID == "" || s.Proxy.NetworkID == "" || len(s.Proxy.BrokerIDs) != 2 {
		return errors.New("link identities must be reserved before API access")
	}
	switch method {
	case "GET":
		if (path != "/version" && path != "/proxies") || mapping != nil || (expectedCount != 0 && expectedCount != 2) {
			return errors.New("unsupported proxy setup operation")
		}
	case "POST":
		if path != "/proxies" || mapping == nil || (*mapping != s.Proxy.Source && *mapping != s.Proxy.Destination) {
			return errors.New("unsupported proxy setup operation")
		}
	default:
		return errors.New("unsupported proxy setup operation")
	}
	if _, err = inspectLinkResources(ctx, s, run); err != nil {
		return err
	}
	origin := time.Now()
	receipt := linkAPIReceipt{ContainerID: s.Proxy.ContainerID, NetworkID: s.Proxy.NetworkID, StartedAt: origin.UTC(), Method: method, Path: path, Request: mapping}
	if err = linkReceipt(s, "api-request", receipt); err != nil {
		return err
	}
	defer func() {
		receipt.ElapsedNanoseconds = time.Since(origin).Nanoseconds()
		if err != nil {
			receipt.Error = "owned proxy API/configuration operation failed"
			if socket, ok := err.(*linkSocketError); ok {
				receipt.Error = socket.Error()
			}
		}
		err = errors.Join(err, linkReceipt(s, "api", receipt))
	}()
	var body []byte
	if mapping != nil {
		body, _ = json.Marshal(struct {
			ProxyMapping
			Enabled bool `json:"enabled"`
		}{*mapping, true})
	}
	status, response, e := request(ctx, s.Proxy.API, method, path, body)
	receipt.Status = status
	if socket, ok := e.(*linkSocketError); ok {
		return socket
	}
	if e != nil || status < 200 || status >= 300 {
		return errors.New("proxy HTTP operation failed; response body discarded")
	}
	switch {
	case path == "/version":
		var version struct{ Version string }
		if json.Unmarshal(response, &version) != nil || version.Version != "2.12.0" {
			return errors.New("proxy version mismatch")
		}
		receipt.Version = version.Version
	case method == "POST":
		var proxy linkAPIProxy
		if json.Unmarshal(response, &proxy) != nil || mapping == nil || !proxy.matches(*mapping) {
			return errors.New("proxy creation response does not match owned mapping")
		}
		receipt.Proxies = []ProxyMapping{*mapping}
	default:
		var proxies map[string]linkAPIProxy
		if json.Unmarshal(response, &proxies) != nil {
			return errors.New("proxy configuration response malformed")
		}
		if len(proxies) != expectedCount {
			return errors.New("unexpected proxy configuration membership")
		}
		if s.Proxy.ContainerID == "" {
			return errors.New("proxy identity not reserved")
		}
		if expectedCount == 2 {
			for _, expected := range []ProxyMapping{s.Proxy.Source, s.Proxy.Destination} {
				proxy, ok := proxies[expected.Name]
				if !ok || !proxy.matches(expected) {
					return errors.New("proxy configuration contains an unexpected mapping or toxic")
				}
				receipt.Proxies = append(receipt.Proxies, expected)
			}
		}
	}
	// The same immutable resources must still own the endpoint when the operation
	// completes. This is a bounded ownership check, not a packet/latency claim.
	_, err = inspectLinkResources(ctx, s, run)
	return err
}

type linkAPIProxy struct {
	Name, Listen, Upstream string
	Enabled                *bool
	Toxics                 *[]json.RawMessage
}

func (p linkAPIProxy) matches(expected ProxyMapping) bool {
	host, port, e := net.SplitHostPort(p.Listen)
	_, expectedPort, _ := net.SplitHostPort(expected.Listen)
	return e == nil && (host == "0.0.0.0" || host == "::") && port == expectedPort && p.Name == expected.Name && p.Upstream == expected.Upstream && p.Enabled != nil && *p.Enabled && p.Toxics != nil && len(*p.Toxics) == 0
}

func linkInspect(ctx context.Context, run Executor, kind, target string, out any) (bool, error) {
	raw, e := run(ctx, kind, "inspect", target, "--format", "{{json .}}")
	if e != nil {
		if exactLinkAbsence([]string{kind, "inspect", target, "--format", "{{json .}}"}, raw) {
			var failure *linkDockerFailure
			if errors.As(e, &failure) && failure.PersistenceFailed {
				return false, e
			}
			if errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EPERM) {
				return false, e
			}
			return false, nil
		}
		return false, e
	}
	if len(raw) > 64<<10 || json.Unmarshal(raw, out) != nil {
		return false, errors.New("owned link Docker inspection malformed or oversized")
	}
	return true, nil
}
func inspectLinkNetwork(ctx context.Context, s State, run Executor) (linkNetwork, bool, error) {
	var n linkNetwork
	target := s.Network
	if s.Proxy.NetworkID != "" {
		target = s.Proxy.NetworkID
	}
	present, e := linkInspect(ctx, run, "network", target, &n)
	if e != nil || !present {
		return n, present, e
	}
	if !linkID(n.ID) || n.Name != s.Network || n.Labels[ownerLabel] != s.RunID || s.Proxy.NetworkID != "" && n.ID != s.Proxy.NetworkID {
		return n, true, errors.New("owned link network identity mismatch")
	}
	return n, true, nil
}
func inspectLinkImage(ctx context.Context, run Executor, reference string) (string, error) {
	raw, e := run(ctx, "image", "inspect", reference, "--format", "{{.Id}}")
	id := strings.TrimSpace(string(raw))
	if e != nil {
		return "", e
	}
	if !linkImageID(id) || (reference == ProxyImage && id != proxyConfigID) {
		return "", errors.New("pinned link image identity unavailable")
	}
	return id, nil
}
func inspectLinkContainer(ctx context.Context, s State, run Executor, index int, networkID, imageID string, setup bool) (linkFacts, bool, error) {
	name, role, reference, target := s.Proxy.Container, "proxy", ProxyImage, s.Proxy.ContainerID
	if index < 2 {
		name = s.Containers[index]
		role = []string{"source", "destination"}[index]
		reference = Image
		if len(s.Proxy.BrokerIDs) == 2 {
			target = s.Proxy.BrokerIDs[index]
		} else {
			target = ""
		}
	}
	if target == "" {
		target = name
	}
	var c linkContainer
	present, e := linkInspect(ctx, run, "container", target, &c)
	if e != nil || !present {
		return linkFacts{}, present, e
	}
	if !linkID(c.ID) || c.Name != "/"+name || c.Config.Labels[ownerLabel] != s.RunID || c.Config.Labels[linkRoleLabel] != role || c.Config.Image != reference || c.Image != imageID || target != name && c.ID != target || c.HostConfig.NetworkMode != s.Network || networkID == "" || c.State.Running == nil || c.State.Paused == nil {
		return linkFacts{}, true, errors.New("owned link container identity/image/network mismatch")
	}
	// A failed Docker start can leave only the exact configured network/binds.
	// Such a stopped owned container may be removed, but cannot prove readiness.
	active := *c.State.Running || setup
	networks := c.NetworkSettings.Networks
	if (*c.State.Paused && !*c.State.Running) || len(networks) > 1 || (len(networks) == 1 && networks[s.Network].NetworkID != networkID) || (active && len(networks) != 1) {
		return linkFacts{}, true, errors.New("owned link container network attachment mismatch")
	}
	expected := map[string]string{}
	if index < 2 {
		endpoint := []string{s.Source, s.Destination}[index]
		port, _ := loopbackPort(endpoint)
		expected["19092/tcp"] = port
	} else {
		for port, endpoint := range map[string]string{"8474/tcp": s.Proxy.API, "8666/tcp": s.WorkerSource, "8667/tcp": s.WorkerDestination} {
			p, _ := loopbackPort(endpoint)
			expected[port] = p
		}
	}
	for position, bindings := range []map[string][]linkBinding{c.HostConfig.PortBindings, c.NetworkSettings.Ports} {
		for port, list := range bindings {
			if len(list) == 0 {
				continue
			}
			want, ok := expected[port]
			if !ok || len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != want {
				return linkFacts{}, true, errors.New("owned link container published port mismatch")
			}
		}
		if position == 1 && !active {
			continue
		}
		for port, want := range expected {
			list := bindings[port]
			if len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != want {
				return linkFacts{}, true, errors.New("owned link container binding missing")
			}
		}
	}
	if index < 2 {
		direct := []string{s.Source, s.Destination}[index]
		worker := []string{s.WorkerSource, s.WorkerDestination}[index]
		wanted := map[string]string{"CLUSTER_ID": s.ClusterIDs[index], "KAFKA_LISTENERS": "INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092,WORKER://:29092", "KAFKA_ADVERTISED_LISTENERS": "INTERNAL://" + name + ":9092,EXTERNAL://" + direct + ",WORKER://" + worker, "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT,WORKER:PLAINTEXT"}
		found := map[string]bool{}
		for _, entry := range c.Config.Env {
			key, value, ok := strings.Cut(entry, "=")
			if want, needed := wanted[key]; needed {
				if !ok || value != want || found[key] {
					return linkFacts{}, true, errors.New("owned broker worker listener configuration mismatch")
				}
				found[key] = true
			}
		}
		if len(found) != len(wanted) {
			return linkFacts{}, true, errors.New("owned broker worker listener configuration missing")
		}
	}
	return linkFacts{c.ID, name, c.Image, c.Config.Image, networkID, role, *c.State.Running, *c.State.Paused}, true, nil
}
func inspectLinkResources(ctx context.Context, s State, run Executor) (linkResources, error) {
	var resources linkResources
	if e := validateLinkPlan(s); e != nil {
		return resources, e
	}
	n, present, e := inspectLinkNetwork(ctx, s, run)
	if e != nil || !present {
		return resources, errors.Join(e, errors.New("owned link network unavailable"))
	}
	resources.NetworkID = n.ID
	resources.BrokerImageID, e = inspectLinkImage(ctx, run, Image)
	if e != nil {
		return resources, e
	}
	resources.ProxyImageID, e = inspectLinkImage(ctx, run, ProxyImage)
	if e != nil {
		return resources, e
	}
	if s.Proxy.ImageID != "" && s.Proxy.ImageID != resources.ProxyImageID || s.Proxy.BrokerImageID != "" && s.Proxy.BrokerImageID != resources.BrokerImageID {
		return resources, errors.New("retained link image identity changed")
	}
	for i := 0; i < 3; i++ {
		image := resources.BrokerImageID
		if i == 2 {
			image = resources.ProxyImageID
		}
		fact, present, e := inspectLinkContainer(ctx, s, run, i, n.ID, image, true)
		if e != nil || !present {
			return resources, errors.Join(e, errors.New("owned link container unavailable"))
		}
		if !fact.Running || fact.Paused {
			return resources, errors.New("link setup requires running unpaused owned containers")
		}
		if i < 2 {
			resources.Brokers[i] = fact
		} else {
			resources.Proxy = fact
		}
	}
	return resources, nil
}

func downLinks(ctx context.Context, s State, run Executor) (err error) {
	if e := validateLinkPlan(s); e != nil {
		return e
	}
	if run, err = LinkExecutor(s, run); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, stopLinkOperation(s.RunID, "linked cleanup incomplete"))
		}
	}()
	network, present, networkErr := inspectLinkNetwork(ctx, s, run)
	if networkErr != nil {
		return networkErr
	}
	for _, index := range []int{2, 0, 1} {
		// Absence is checked before image resolution, so interrupted setup with no
		// created containers can still be cleaned after a failed image pull.
		target := s.Proxy.ContainerID
		if target == "" {
			target = s.Proxy.Container
		}
		if index < 2 {
			target = s.Containers[index]
			if len(s.Proxy.BrokerIDs) == 2 {
				target = s.Proxy.BrokerIDs[index]
			}
		}
		var initial linkContainer
		exists, e := linkInspect(ctx, run, "container", target, &initial)
		if e != nil {
			return e
		}
		if !exists {
			continue
		}
		if networkErr != nil || !present {
			return errors.New("cannot prove existing container network ownership")
		}
		image := Image
		if index == 2 {
			image = ProxyImage
		}
		imageID, e := inspectLinkImage(ctx, run, image)
		if e != nil {
			return e
		}
		retained := s.Proxy.BrokerImageID
		if index == 2 {
			retained = s.Proxy.ImageID
		}
		if retained != "" && retained != imageID {
			return errors.New("retained link image identity changed")
		}
		fact, exists, e := inspectLinkContainer(ctx, s, run, index, network.ID, imageID, false)
		if e != nil || !exists {
			return errors.Join(e, errors.New("container changed during cleanup inspection"))
		}
		logs, logErr := run(ctx, "logs", "--tail", "200", fact.ID)
		if logErr != nil {
			return logErr
		}
		if len(logs) > linkOutputLimit {
			return errors.New("owned link logs exceed evidence bound")
		}
		privateRef, e := retainPrivateLinkLogs(s, fact.ID, logs)
		if e != nil {
			return e
		}
		receipt := struct {
			Facts                          linkFacts
			PrivateLogReference, LogSHA256 string
			LogBytes                       int
		}{fact, privateRef, linkDigest(logs), len(logs)}
		if e = linkReceipt(s, "cleanup-container", receipt); e != nil {
			return e
		}
		if _, e = run(ctx, "container", "rm", "-f", fact.ID); e != nil {
			return e
		}
	}
	if present {
		if e := linkReceipt(s, "cleanup-network", struct{ ID, Name string }{network.ID, network.Name}); e != nil {
			return e
		} else if _, e = run(ctx, "network", "rm", network.ID); e != nil {
			return e
		}
	}
	return nil
}
