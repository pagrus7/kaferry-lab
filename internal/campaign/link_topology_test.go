package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/fixture"
	"github.com/segmentio/kafka-go/protocol"
	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
)

// These test-only observations retain endpoints/identity, never topic names or
// records. Exactly one node is required by this disposable single-broker fixture.
type linkTopologyNode struct {
	ID      int32
	Address string
}
type linkTopologyMetadata struct {
	ClusterID               string
	ControllerID            int32
	BrokerCount, TopicCount int
	Nodes                   []linkTopologyNode
}
type linkTopologyCoordinator struct {
	Version   int16
	ErrorCode int16
	Node      *linkTopologyNode
}

func validateLinkTopologyMetadata(got linkTopologyMetadata, cluster, endpoint string) error {
	if _, err := ownedBrokerPort(endpoint); err != nil {
		return err
	}
	if cluster == "" || got.ClusterID != cluster {
		return errors.New("link topology cluster identity mismatch")
	}
	if got.BrokerCount != 1 || len(got.Nodes) != 1 || got.TopicCount != 0 {
		return errors.New("link topology expected one broker and no topic metadata")
	}
	if got.Nodes[0].ID != 1 || got.ControllerID != 1 || got.Nodes[0].Address != endpoint {
		return errors.New("link topology advertised route escapes the owned endpoint")
	}
	return nil
}

// A transient coordinator status is retryable only if any supplied endpoint is
// either the expected owned node or the explicit negative-node placeholder.
func validateLinkTopologyCoordinator(got linkTopologyCoordinator, endpoint string) (bool, error) {
	if _, err := ownedBrokerPort(endpoint); err != nil {
		return false, err
	}
	if got.Version != 3 {
		return false, errors.New("unexpected coordinator response version")
	}
	placeholder := got.Node == nil || (got.Node.ID < 0 && (got.Node.Address == "" || got.Node.Address == ":-1" || got.Node.Address == ":0"))
	if !placeholder && (got.Node.ID != 1 || got.Node.Address != endpoint) {
		return false, errors.New("coordinator route escapes the owned worker endpoint")
	}
	if got.ErrorCode == 0 {
		if placeholder {
			return false, errors.New("successful coordinator response has no owned endpoint")
		}
		return false, nil
	}
	switch sarama.KError(got.ErrorCode) {
	case sarama.ErrOffsetsLoadInProgress, sarama.ErrConsumerCoordinatorNotAvailable, sarama.ErrNotCoordinatorForConsumer:
		return true, errors.New("source coordinator is not ready")
	default:
		return false, errors.New("source coordinator returned a non-readiness error")
	}
}
func linkTopologyTransportRetryable(err error) bool {
	var decoding sarama.PacketDecodingError
	var decodingPointer *sarama.PacketDecodingError
	if errors.As(err, &decoding) || errors.As(err, &decodingPointer) || errors.Is(err, sarama.ErrInsufficientData) || errors.Is(err, sarama.ErrIncompleteResponse) {
		return false
	}
	var operation *net.OpError
	return errors.As(err, &operation) && scenarioTransientPreparation(err)
}

func TestLinkTopologyRejectsLiteralRouteAndIdentityFailures(t *testing.T) {
	// Given literal bootstrap responses, when checked before discovery, then a
	// direct-listener escape, wrong cluster or missing node cannot authorize a dial.
	valid := linkTopologyMetadata{ClusterID: "source-cluster", ControllerID: 1, BrokerCount: 1, Nodes: []linkTopologyNode{{ID: 1, Address: "127.0.0.1:20201"}}}
	if err := validateLinkTopologyMetadata(valid, "source-cluster", "127.0.0.1:20201"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		got  linkTopologyMetadata
	}{
		{"direct route instead of proxy", linkTopologyMetadata{ClusterID: "source-cluster", ControllerID: 1, BrokerCount: 1, Nodes: []linkTopologyNode{{ID: 1, Address: "127.0.0.1:20101"}}}},
		{"wrong cluster", linkTopologyMetadata{ClusterID: "destination-cluster", ControllerID: 1, BrokerCount: 1, Nodes: []linkTopologyNode{{ID: 1, Address: "127.0.0.1:20201"}}}},
		{"missing endpoint", linkTopologyMetadata{ClusterID: "source-cluster", ControllerID: 1}},
		{"extra advertised endpoint", linkTopologyMetadata{ClusterID: "source-cluster", ControllerID: 1, BrokerCount: 2, Nodes: []linkTopologyNode{{ID: 1, Address: "127.0.0.1:20201"}, {ID: 2, Address: "127.0.0.1:29999"}}}},
		{"unexpected topic listing", linkTopologyMetadata{ClusterID: "source-cluster", ControllerID: 1, BrokerCount: 1, TopicCount: 1, Nodes: []linkTopologyNode{{ID: 1, Address: "127.0.0.1:20201"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateLinkTopologyMetadata(tc.got, "source-cluster", "127.0.0.1:20201"); err == nil {
				t.Fatal("unsafe metadata accepted")
			}
		})
	}
}
func TestLinkCoordinatorReadinessNeverRetriesWrongEndpointsOrDecoderFailures(t *testing.T) {
	// Given a transient status, when its endpoint is foreign, then identity
	// failure is fatal; a missing successful endpoint is equally nonpassing.
	for _, got := range []linkTopologyCoordinator{
		{Version: 3, ErrorCode: 15, Node: &linkTopologyNode{ID: 1, Address: "127.0.0.1:20101"}},
		{Version: 3, Node: nil},
		{Version: 2, Node: &linkTopologyNode{ID: 1, Address: "127.0.0.1:20201"}},
	} {
		retry, err := validateLinkTopologyCoordinator(got, "127.0.0.1:20201")
		if err == nil || retry {
			t.Fatalf("fatal identity became readiness: %+v retry=%v err=%v", got, retry, err)
		}
	}
	retry, err := validateLinkTopologyCoordinator(linkTopologyCoordinator{Version: 3, ErrorCode: 15}, "127.0.0.1:20201")
	if err == nil || !retry {
		t.Fatal("bounded readiness status not classified")
	}
	if !linkTopologyTransportRetryable(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}) {
		t.Fatal("known connection-refused readiness was not eligible for bounded retry")
	}
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"decoder", sarama.PacketDecodingError{Info: "synthetic malformed response"}},
		{"insufficient data", sarama.ErrInsufficientData},
		{"incomplete response", sarama.ErrIncompleteResponse},
		{"unknown", errors.New("unknown failure")},
		{"wrapped decoder", &net.OpError{Op: "read", Net: "tcp", Err: &sarama.PacketDecodingError{Info: "malformed response"}}},
		{"access denied", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EACCES}},
		{"operation forbidden", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EPERM}},
		{"unknown network", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("unknown failure")}},
		{"network beside receipt", errors.Join(refused, errors.New("receipt persistence failed"))},
		{"network beside authorization", errors.Join(refused, sarama.ErrGroupAuthorizationFailed)},
		{"network beside unknown", errors.Join(refused, errors.New("unknown failure"))},
		{"network beside permission", errors.Join(refused, syscall.EPERM)},
		{"nested permission", &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(syscall.ECONNREFUSED, syscall.EACCES)}},
		{"network beside canceled", errors.Join(refused, context.Canceled)},
		{"network beside deadline", errors.Join(refused, context.DeadlineExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if linkTopologyTransportRetryable(tc.err) {
				t.Fatalf("fatal error became retryable: %T", tc.err)
			}
		})
	}
}

func TestLinkMetadataRequestUsesLiteralEmptyTopicArray(t *testing.T) {
	// Given an explicitly allocated empty topic slice, when the existing public
	// encoder writes Metadata8, then its literal request uses zero topics rather
	// than the null/all-topics sentinel. No local request encoder is implemented.
	var encoded bytes.Buffer
	err := protocol.WriteRequest(&encoded, 8, 7, "lab", &metadataAPI.Request{TopicNames: []string{}, AllowAutoTopicCreation: false})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := hex.DecodeString("00000014000300080000000700036c616200000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded.Bytes(), expected) {
		t.Fatalf("no-topic Metadata8 request changed: %x", encoded.Bytes())
	}
}

func TestLinkTopologyProxyInspectionPreservesSafeRetainedFailure(t *testing.T) {
	// Given the shared linked executor already retained an exact private failure,
	// when the topology control fails its proxy inspection, then it preserves the
	// safe receipt-bearing diagnostic rather than discarding the final reference.
	retained := errors.New("linked Docker action failed; private receipt synthetic-reference; Docker facility stopped")
	calls := 0
	state := fixture.State{Proxy: &fixture.ProxyState{ContainerID: "synthetic-owned-proxy-id"}}
	err := checkLiveLinkProxyOwnership(context.Background(), state, func(_ context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) != 5 || args[0] != "container" || args[1] != "inspect" || args[2] != state.Proxy.ContainerID {
			t.Fatal("unexpected topology inspection", args)
		}
		return nil, retained
	})
	if !errors.Is(err, retained) || calls != 1 {
		t.Fatal("private receipt diagnostic discarded or action retried", calls, err)
	}
}
