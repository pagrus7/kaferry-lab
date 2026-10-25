package campaign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"github.com/pagrus7/kaferry-lab/internal/observer"
)

// kafkaBrokerProbe sends only ApiVersions to the already verified loopback
// endpoint. It never discovers or follows advertised brokers. Sarama's socket
// operations have no context API; each is limited to at most 500ms and a quarter
// of the remaining two-second probe budget. No timeout goroutine is abandoned.
func kafkaBrokerProbe(ctx context.Context, endpoint string) (result brokerProbeResult, err error) {
	if _, err := ownedBrokerPort(endpoint); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return result, errors.New("broker probe requires a deadline")
	}
	socketTimeout := min(500*time.Millisecond, time.Until(deadline)/4)
	if socketTimeout <= 0 {
		return result, context.DeadlineExceeded
	}
	config := observer.Config("kaferry-lab-m2-broker-probe")
	config.ApiVersionsRequest = false
	config.Net.DialTimeout, config.Net.ReadTimeout, config.Net.WriteTimeout = socketTimeout, socketTimeout, socketTimeout
	broker := sarama.NewBroker(endpoint)
	if err := broker.Open(config); err != nil {
		return result, err
	}
	defer func() {
		closeErr := broker.Close()
		if closeErr != nil && !errors.Is(closeErr, sarama.ErrNotConnected) {
			err = errors.Join(err, closeErr)
		}
	}()
	connected, err := broker.Connected()
	if err != nil {
		return brokerTransportFailure(err)
	}
	if !connected {
		return result, errors.New("Sarama has no connected broker and no transport cause")
	}
	response, err := broker.ApiVersions(&sarama.ApiVersionsRequest{Version: 0})
	if err != nil {
		return brokerTransportFailure(err)
	}
	if response == nil {
		return result, errors.New("Kafka ApiVersions response missing")
	}
	result.APIKeys, result.ErrorCode = len(response.ApiKeys), response.ErrorCode
	if response.ErrorCode != 0 || len(response.ApiKeys) == 0 {
		return result, fmt.Errorf("Kafka API responded without readiness: error=%d APIs=%d", response.ErrorCode, len(response.ApiKeys))
	}
	result.Available = true
	return result, nil
}

// Only an observed transport failure supports unavailability. A decode/config
// error or a Kafka error response cannot masquerade as the reached pause fault.
func brokerTransportFailure(err error) (brokerProbeResult, error) {
	var networkError net.Error
	kind := ""
	switch {
	case errors.As(err, &networkError) && networkError.Timeout():
		kind = "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		kind = "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		kind = "connection_reset"
	case errors.Is(err, syscall.EPIPE):
		kind = "broken_pipe"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		kind = "connection_closed"
	}
	if kind == "" {
		return brokerProbeResult{}, fmt.Errorf("Kafka API probe failed without transport unavailability evidence: %w", err)
	}
	return brokerProbeResult{Unavailable: true, Failure: kind, TransportError: err.Error()}, nil
}
