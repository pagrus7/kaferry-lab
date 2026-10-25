package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
	"github.com/pagrus7/kaferry-lab/internal/observer"
	"github.com/segmentio/kafka-go/protocol"
	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
)

type linkTopologyProbe struct {
	Endpoint, Operation string
	StartedAt           time.Time
	ElapsedNanoseconds  int64
	Opened, Closed      bool
	Metadata            *linkTopologyMetadata    `json:",omitempty"`
	Coordinator         *linkTopologyCoordinator `json:",omitempty"`
	Error               string                   `json:",omitempty"`
}

func TestLiveOwnedWorkerLinkTopology(t *testing.T) {
	if os.Getenv("LAB_LINKS") == "" {
		t.Skip("LAB_LINKS=1 owned proxy topology opt-in absent")
	}
	if os.Getenv("LAB_LINKS") != "1" || os.Getenv("LAB_RUN_ID") == "" || os.Getenv("LAB_SOURCE_ADDR") == "" || os.Getenv("LAB_DEST_ADDR") == "" {
		t.Fatal("incomplete explicit LAB_LINKS fixture opt-in")
	}
	// Given the run's optional standard proxy fixture, with immutable setup
	// receipts and direct broker ownership checked before any bootstrap dial.
	state := liveCampaignState(t)
	if err := nativeProcessPlatform(); err != nil {
		t.Fatal(err)
	}
	if state.Proxy == nil || state.Proxy.ContainerID == "" || state.Proxy.NetworkID == "" || len(state.Proxy.BrokerIDs) != 2 || len(state.ClusterIDs) != 2 || state.ClusterIDs[0] == state.ClusterIDs[1] {
		t.Fatal("fixture up-links identities are required")
	}
	for name, want := range map[string]string{"LAB_WORKER_SOURCE_ADDR": state.WorkerSource, "LAB_WORKER_DEST_ADDR": state.WorkerDestination, "LAB_PROXY_API_ADDR": state.Proxy.API} {
		if value := os.Getenv(name); value != "" && value != want {
			t.Fatal("link environment differs from the owned fixture manifest")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run, err := fixture.LinkExecutor(state, fixture.Docker)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("LINK TOPOLOGY CONTROL ONLY: no Kaferry, records, faults, capture or qualification")
	for i, role := range []string{"source", "destination"} {
		_, ownership, err := openOwnedBroker(ctx, state, role, run)
		logLiveCampaign(t, "link_broker_ownership", ownership)
		if err != nil {
			t.Fatal(err)
		}
		if ownership.Facts.ContainerID != state.Proxy.BrokerIDs[i] || ownership.Facts.ImageID != state.Proxy.BrokerImageID || !ownership.Facts.Running || ownership.Facts.Paused {
			t.Fatal("broker identity/state differs from linked fixture receipt")
		}
	}
	if err := checkLiveLinkProxyOwnership(ctx, state, run); err != nil {
		t.Fatal(err)
	}
	logLiveCampaign(t, "link_proxy_ownership", struct{ ContainerID, NetworkID, ImageID, API string }{state.Proxy.ContainerID, state.Proxy.NetworkID, state.Proxy.ImageID, state.Proxy.API})
	checkLiveLinkSetupReceipts(t, state)
	// When each raw bootstrap is queried with a public Metadata-v8 request whose
	// topic array is allocated empty, no discovery client can follow its response.
	// Sarama's Metadata encoder maps even []string{} to null/all-topics, so the
	// existing kafka-go public request encoder supplies this no-topic request.
	for _, target := range []struct{ role, endpoint, cluster string }{
		{"source_worker", state.WorkerSource, state.ClusterIDs[0]},
		{"destination_worker", state.WorkerDestination, state.ClusterIDs[1]},
		{"source_direct", state.Source, state.ClusterIDs[0]},
		{"destination_direct", state.Destination, state.ClusterIDs[1]},
	} {
		observed, err := readLiveLinkMetadata(ctx, target.endpoint, target.cluster)
		logLiveCampaign(t, "link_metadata_"+target.role, observed)
		if err != nil {
			t.Fatal(err)
		}
	}
	// A named group's coordinator may be cold. Every bounded, read-only attempt
	// is retained; malformed responses and identity/route failures never retry.
	ready, done := context.WithTimeout(ctx, 20*time.Second)
	defer done()
	var coordinator *linkTopologyCoordinator
	for attempt := 1; attempt <= 8; attempt++ {
		observed, retry, err := readLiveLinkCoordinator(ready, state.WorkerSource, "lab-links-"+state.RunID)
		logLiveCampaign(t, "link_coordinator_attempt", struct {
			Attempt     int
			Observation linkTopologyProbe
			Retryable   bool
		}{attempt, observed, retry})
		if err == nil {
			coordinator = observed.Coordinator
			break
		}
		if !retry || ready.Err() != nil || attempt == 8 {
			t.Fatal(err)
		}
		select {
		case <-ready.Done():
			t.Fatal(ready.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if coordinator == nil || coordinator.Node == nil {
		t.Fatal("source coordinator readiness not observed")
	}
	// Then the validated coordinator endpoint can be queried without discovery:
	// it is exactly the source WORKER proxy, while the direct observer remains live.
	for _, target := range []struct{ endpoint, cluster string }{{coordinator.Node.Address, state.ClusterIDs[0]}, {state.Source, state.ClusterIDs[0]}} {
		observed, err := readLiveLinkMetadata(ctx, target.endpoint, target.cluster)
		logLiveCampaign(t, "link_after_coordinator", observed)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := checkLiveLinkProxyOwnership(ctx, state, run); err != nil {
		t.Fatal(err)
	}
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	// This control never stops or removes resources. The fixture owner retains
	// setup receipts/logs and performs its exact-resource cleanup after this test.
}

func readLiveLinkMetadata(ctx context.Context, endpoint, cluster string) (observed linkTopologyProbe, err error) {
	origin := time.Now()
	observed = linkTopologyProbe{Endpoint: endpoint, Operation: "kafka-go Metadata-v8 allocated-empty-topic-array", StartedAt: origin.UTC()}
	defer func() {
		observed.ElapsedNanoseconds = time.Since(origin).Nanoseconds()
		if err != nil {
			observed.Error = "raw metadata request or topology validation failed"
		}
	}()
	if _, err = ownedBrokerPort(endpoint); err != nil {
		return observed, err
	}
	if err = ctx.Err(); err != nil {
		return observed, err
	}
	conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", endpoint)
	if e != nil {
		return observed, e
	}
	observed.Opened = true
	defer func() { closeErr := conn.Close(); observed.Closed = closeErr == nil; err = errors.Join(err, closeErr) }()
	deadline := time.Now().Add(2 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return observed, err
	}
	// This is only an I/O cap. All Kafka request framing and decoding belongs to
	// the existing independent public library; no local protocol parser is added.
	rw := struct {
		io.Reader
		io.Writer
	}{io.LimitReader(conn, 64<<10), conn}
	message, e := protocol.RoundTrip(rw, 8, 1, "kaferry-lab-link-topology", &metadataAPI.Request{TopicNames: []string{}, AllowAutoTopicCreation: false})
	if e != nil {
		return observed, e
	}
	response, ok := message.(*metadataAPI.Response)
	if !ok || response == nil {
		return observed, errors.New("unexpected metadata response type")
	}
	value := &linkTopologyMetadata{ControllerID: response.ControllerID, BrokerCount: len(response.Brokers), TopicCount: len(response.Topics)}
	observed.Metadata = value
	if len(response.ClusterID) > 256 || len(response.Brokers) != 1 {
		return observed, errors.New("metadata identity or broker count exceeds fixture bound")
	}
	value.ClusterID = response.ClusterID
	broker := response.Brokers[0]
	if len(broker.Host) > 256 || broker.Port < 1 || broker.Port > 65535 {
		return observed, errors.New("metadata endpoint exceeds fixture bound")
	}
	value.Nodes = []linkTopologyNode{{ID: broker.NodeID, Address: net.JoinHostPort(broker.Host, strconv.Itoa(int(broker.Port)))}}
	return observed, errors.Join(validateLinkTopologyMetadata(*value, cluster, endpoint), ctx.Err())
}

func readLiveLinkCoordinator(ctx context.Context, endpoint, group string) (observed linkTopologyProbe, retry bool, err error) {
	origin := time.Now()
	observed = linkTopologyProbe{Endpoint: endpoint, Operation: "Sarama raw FindCoordinator-v3", StartedAt: origin.UTC()}
	defer func() {
		observed.ElapsedNanoseconds = time.Since(origin).Nanoseconds()
		if err != nil {
			observed.Error = "raw coordinator request or topology validation failed"
		}
	}()
	if _, err = ownedBrokerPort(endpoint); err != nil {
		return observed, false, err
	}
	if err = ctx.Err(); err != nil {
		return observed, false, err
	}
	broker := sarama.NewBroker(endpoint)
	defer func() {
		e := broker.Close()
		observed.Closed = e == nil || errors.Is(e, sarama.ErrNotConnected)
		if e != nil && !errors.Is(e, sarama.ErrNotConnected) {
			err = errors.Join(err, errors.New("raw coordinator client close failed"))
			retry = false
		}
	}()
	config := observer.Config("kaferry-lab-link-coordinator")
	config.ApiVersionsRequest = false
	config.Net.MaxOpenRequests = 1
	limit := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < limit {
		limit = time.Until(deadline)
	}
	if limit <= 0 {
		return observed, false, context.DeadlineExceeded
	}
	config.Net.DialTimeout, config.Net.ReadTimeout, config.Net.WriteTimeout = limit, limit, limit
	if err = broker.Open(config); err != nil {
		return observed, false, err
	}
	connected, e := broker.Connected()
	if e != nil || !connected {
		if e == nil {
			e = errors.New("raw coordinator bootstrap not connected")
		}
		return observed, linkTopologyTransportRetryable(e), e
	}
	observed.Opened = true
	response, e := broker.FindCoordinator(&sarama.FindCoordinatorRequest{Version: 3, CoordinatorKey: group, CoordinatorType: sarama.CoordinatorGroup})
	if e != nil {
		return observed, linkTopologyTransportRetryable(e), e
	}
	if response == nil {
		return observed, false, errors.New("missing coordinator response")
	}
	value := &linkTopologyCoordinator{Version: response.Version, ErrorCode: int16(response.Err)}
	observed.Coordinator = value
	if response.Coordinator != nil {
		address := response.Coordinator.Addr()
		if len(address) > 256 {
			return observed, false, errors.New("coordinator endpoint exceeds fixture bound")
		}
		value.Node = &linkTopologyNode{ID: response.Coordinator.ID(), Address: address}
	}
	retry, err = validateLinkTopologyCoordinator(*value, endpoint)
	if ctx.Err() != nil {
		return observed, false, errors.Join(err, ctx.Err())
	}
	return observed, retry, err
}

func checkLiveLinkProxyOwnership(ctx context.Context, state fixture.State, run fixture.Executor) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := run(ctx, "container", "inspect", state.Proxy.ContainerID, "--format", "{{json .}}")
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if len(raw) > 64<<10 {
		return errors.New("owned proxy inspect exceeds evidence bound")
	}
	var info struct {
		ID, Name, Image string
		Config          struct {
			Image  string
			Labels map[string]string
		}
		State      struct{ Running, Paused *bool }
		HostConfig struct {
			NetworkMode  string
			PortBindings map[string][]brokerPortBinding
		}
		NetworkSettings struct {
			Ports    map[string][]brokerPortBinding
			Networks map[string]struct{ NetworkID string }
		}
	}
	if json.Unmarshal(raw, &info) != nil {
		return errors.New("owned proxy inspect malformed")
	}
	if info.ID != state.Proxy.ContainerID || info.Name != "/"+state.Proxy.Container || info.Image != state.Proxy.ImageID || info.Image != "sha256:3edf5d14625b9aa8ad71d5dd084da1f8a0eb46ee749457549ae91d29d96546aa" || info.Config.Image != fixture.ProxyImage || info.Config.Labels[brokerOwnerLabel] != state.RunID || info.Config.Labels["io.kaferry-lab.role"] != "proxy" || info.State.Running == nil || info.State.Paused == nil || !*info.State.Running || *info.State.Paused || info.HostConfig.NetworkMode != state.Network || len(info.NetworkSettings.Networks) != 1 || info.NetworkSettings.Networks[state.Network].NetworkID != state.Proxy.NetworkID {
		return errors.New("proxy ownership/image/network/state mismatch")
	}
	expected := map[string]string{"8474/tcp": state.Proxy.API, "8666/tcp": state.WorkerSource, "8667/tcp": state.WorkerDestination}
	for _, bindings := range []map[string][]brokerPortBinding{info.HostConfig.PortBindings, info.NetworkSettings.Ports} {
		for port, list := range bindings {
			if len(list) == 0 {
				continue
			}
			endpoint, ok := expected[port]
			if !ok {
				return errors.New("proxy has unexpected published port")
			}
			p, e := ownedBrokerPort(endpoint)
			if e != nil || len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != p {
				return errors.New("proxy port is not the exact owned loopback mapping")
			}
		}
		for port, endpoint := range expected {
			p, e := ownedBrokerPort(endpoint)
			list := bindings[port]
			if e != nil || len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != p {
				return errors.New("proxy published port missing")
			}
		}
	}
	return nil
}

func readLiveLinkReceipt(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("link setup receipt is not a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("link setup receipt exceeds bound")
	}
	return body, nil
}
func checkLiveLinkSetupReceipts(t *testing.T, state fixture.State) {
	t.Helper()
	directory := filepath.Join(".cache", "fixtures", state.RunID+"-links")
	identity, err := readLiveLinkReceipt(filepath.Join(directory, "identity.json"), 8192)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(identity)
	logLiveCampaign(t, "link_identity_receipt", struct{ SHA256 string }{hex.EncodeToString(sum[:])}) // fixture.Load already verifies its manifest hash and IDs
	files, err := filepath.Glob(filepath.Join(directory, "api-*.json"))
	if err != nil || len(files) == 0 || len(files) > 32 {
		t.Fatal("missing or excessive link API receipts")
	}
	version, source, destination, configuration := false, false, false, false
	for _, path := range files {
		body, err := readLiveLinkReceipt(path, 16<<10)
		if err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			ContainerID, NetworkID, Method, Path, Version, Error string
			Status                                               int
			Proxies                                              []fixture.ProxyMapping
			StartedAt                                            time.Time
			ElapsedNanoseconds                                   int64
		}
		if json.Unmarshal(body, &receipt) != nil || receipt.ContainerID != state.Proxy.ContainerID || receipt.NetworkID != state.Proxy.NetworkID || len(receipt.Proxies) > 2 {
			t.Fatal("link API receipt does not bind the owned proxy")
		}
		successful := receipt.Status >= 200 && receipt.Status < 300 && receipt.Error == "" && !receipt.StartedAt.IsZero() && receipt.ElapsedNanoseconds > 0
		matched := false
		if successful && receipt.Method == "GET" && receipt.Path == "/version" && receipt.Version == "2.12.0" {
			version = true
			matched = true
		}
		if successful && receipt.Method == "POST" && receipt.Path == "/proxies" && len(receipt.Proxies) == 1 {
			if receipt.Proxies[0] == state.Proxy.Source {
				source = true
				matched = true
			}
			if receipt.Proxies[0] == state.Proxy.Destination {
				destination = true
				matched = true
			}
		}
		if successful && receipt.Method == "GET" && receipt.Path == "/proxies" && len(receipt.Proxies) == 2 {
			seen := map[string]bool{}
			for _, p := range receipt.Proxies {
				if p == state.Proxy.Source || p == state.Proxy.Destination {
					seen[p.Name] = true
				}
			}
			if len(seen) == 2 {
				configuration = true
				matched = true
			}
		}
		sum := sha256.Sum256(body)
		logLiveCampaign(t, "link_setup_api_receipt", struct {
			File, SHA256        string
			Status              int
			Successful, Matched bool
		}{filepath.Base(path), hex.EncodeToString(sum[:]), receipt.Status, successful, matched})
	}
	if !version || !source || !destination || !configuration {
		t.Fatal("required stock proxy version/create/configuration receipts missing")
	}
}
