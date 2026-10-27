package fixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/IBM/sarama"
)

type linkBrokerProbeResult struct {
	Opened, Closed     bool
	Version, ErrorCode int16
	APIKeys            int
	Connection         linkBrokerConnectionResult
}
type linkBrokerProbe func(context.Context, string) (linkBrokerProbeResult, error)

type linkBrokerConnectionResult struct {
	DialAttempts, Connections, CloseCalls int
	ReadBytes                             int64
	CloseReturned, CloseSucceeded         bool
}

// This observes the same direct socket, without capturing or parsing payloads.
// Sarama v1.61.0 config.go:getDialer constructs exactly this net.Dialer; its
// exported Proxy.Dialer hook selects our observer, not a proxy or another route.
// Resolver and every other unspecified net.Dialer option keep their zero values.
type linkBrokerDirectDialer struct {
	direct   net.Dialer
	endpoint string
	wrap     func(net.Conn) net.Conn // literal close-failure control; nil in production
	mu       sync.Mutex
	result   linkBrokerConnectionResult
	closeErr error
}

func (d *linkBrokerDirectDialer) Dial(network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.result.DialAttempts++
	allowed := d.result.DialAttempts == 1 && network == "tcp" && address == d.endpoint
	d.mu.Unlock()
	if !allowed {
		return nil, errors.New("linked broker unexpected dial; no alternate connection allowed")
	}
	conn, err := d.direct.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if d.wrap != nil {
		conn = d.wrap(conn)
	}
	d.mu.Lock()
	d.result.Connections++
	d.mu.Unlock()
	return &linkBrokerObservedConn{Conn: conn, owner: d}, nil
}

func (d *linkBrokerDirectDialer) snapshot() (linkBrokerConnectionResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.result, d.closeErr
}

type linkBrokerObservedConn struct {
	net.Conn
	owner *linkBrokerDirectDialer
	once  sync.Once
}

func (c *linkBrokerObservedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.owner.mu.Lock()
	c.owner.result.ReadBytes += int64(n)
	c.owner.mu.Unlock()
	return n, err
}

func (c *linkBrokerObservedConn) Close() error {
	c.owner.mu.Lock()
	c.owner.result.CloseCalls++
	c.owner.mu.Unlock()
	// Never retry an uncertain descriptor, including when Sarama asks twice.
	c.once.Do(func() {
		err := c.Conn.Close()
		c.owner.mu.Lock()
		c.owner.closeErr = err
		c.owner.result.CloseReturned = true
		c.owner.result.CloseSucceeded = err == nil
		c.owner.mu.Unlock()
	})
	_, err := c.owner.snapshot()
	return err
}

type linkBrokerEmptyEOF struct{ connection linkBrokerConnectionResult }

func (*linkBrokerEmptyEOF) Error() string { return io.EOF.Error() }
func (*linkBrokerEmptyEOF) Unwrap() error { return io.EOF }
func cleanLinkBrokerEOF(c linkBrokerConnectionResult) bool {
	return c.DialAttempts == 1 && c.Connections == 1 && c.ReadBytes == 0 && c.CloseCalls == 1 && c.CloseReturned && c.CloseSucceeded
}

// This marker belongs only to an actual raw-broker request, never Docker,
// ownership, configuration, response validation, close or receipt failures.
type linkBrokerSocketError struct{ cause error }

func (e *linkBrokerSocketError) Error() string { return e.cause.Error() }
func (e *linkBrokerSocketError) Unwrap() error { return e.cause }
func linkBrokerRequestFailure(err error) error {
	// Sarama v1.61.0 exposes the same io.EOF from an empty response header and
	// a complete header with an absent response body. Its ApiVersions error
	// path also discards an automatic close error before our deferred Close.
	// EOF receives its separate marker only after direct byte/close observation.
	var op *net.OpError
	if errors.As(err, &op) {
		return &linkBrokerSocketError{cause: err}
	}
	return err
}

// One raw Sarama Broker means one fixed direct loopback endpoint: no discovery,
// automatic ApiVersions, metadata lookup or internal request retry. Sarama's
// pinned process-global response bound remains unchanged (100MiB by default);
// the 64KiB evidence limit below is a notice bound, not a wire allocation cap.
func kafkaLinkBrokerProbe(ctx context.Context, endpoint string) (observed linkBrokerProbeResult, err error) {
	return kafkaLinkBrokerProbeWithConnection(ctx, endpoint, nil)
}

func kafkaLinkBrokerProbeWithConnection(ctx context.Context, endpoint string, wrap func(net.Conn) net.Conn) (observed linkBrokerProbeResult, err error) {
	if _, err = loopbackPort(endpoint); err != nil {
		return observed, err
	}
	if err = ctx.Err(); err != nil {
		return observed, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return observed, errors.New("linked broker probe requires a deadline")
	}
	limit := min(500*time.Millisecond, time.Until(deadline)/4)
	if limit <= 0 {
		return observed, context.DeadlineExceeded
	}
	config := sarama.NewConfig()
	config.Version = sarama.V3_9_0_0
	config.ClientID = "kaferry-lab-link-readiness"
	config.ApiVersionsRequest = false
	config.Metadata.Retry.Max = 0
	config.Net.MaxOpenRequests = 1
	config.Net.DialTimeout, config.Net.ReadTimeout, config.Net.WriteTimeout = limit, limit, limit
	dialer := &linkBrokerDirectDialer{endpoint: endpoint, wrap: wrap, direct: net.Dialer{
		Timeout: config.Net.DialTimeout, KeepAlive: config.Net.KeepAlive, LocalAddr: config.Net.LocalAddr,
	}}
	config.Net.Proxy.Enable, config.Net.Proxy.Dialer = true, dialer
	broker := sarama.NewBroker(endpoint)
	requestEOF := false
	defer func() {
		closeErr := broker.Close()
		var actualCloseErr error
		observed.Connection, actualCloseErr = dialer.snapshot()
		c := observed.Connection
		observed.Closed = c.Connections == 1 && c.CloseCalls == 1 && c.CloseReturned && c.CloseSucceeded
		if c.Connections == 0 && c.DialAttempts <= 1 && closeErr == sarama.ErrNotConnected {
			observed.Closed = true // no socket was created, rather than an inferred close
		}
		if closeErr != nil && closeErr != sarama.ErrNotConnected {
			err = errors.Join(err, fmt.Errorf("linked broker close failed: %w", closeErr))
		}
		if requestEOF && err == io.EOF && ctx.Err() == nil && cleanLinkBrokerEOF(c) && (closeErr == nil || closeErr == sarama.ErrNotConnected) {
			err = &linkBrokerEmptyEOF{connection: c}
		}
		err = errors.Join(err, actualCloseErr)
		if !observed.Closed {
			err = errors.Join(err, errors.New("linked broker actual connection closure unavailable"))
		}
		err = errors.Join(err, ctx.Err())
	}()
	if err = broker.Open(config); err != nil {
		return observed, err
	}
	connected, e := broker.Connected()
	if e != nil {
		return observed, linkBrokerRequestFailure(e)
	}
	if !connected {
		return observed, errors.New("linked broker not connected without transport cause")
	}
	observed.Opened = true
	response, e := broker.ApiVersions(&sarama.ApiVersionsRequest{Version: 0})
	if e != nil {
		requestEOF = e == io.EOF && response == nil
		return observed, linkBrokerRequestFailure(e)
	}
	if response == nil {
		return observed, errors.New("linked broker ApiVersions response missing")
	}
	observed.Version, observed.ErrorCode, observed.APIKeys = response.Version, response.ErrorCode, len(response.ApiKeys)
	return observed, nil
}
func validateLinkBrokerProbe(observed linkBrokerProbeResult) error {
	if !observed.Opened || !observed.Closed || observed.Version != 0 || observed.ErrorCode != 0 || observed.APIKeys < 1 || observed.APIKeys > 256 {
		return errors.New("linked broker readiness response/state invalid")
	}
	return nil
}
func linkBrokerAvailability(err error) bool {
	var decode sarama.PacketDecodingError
	var decodePointer *sarama.PacketDecodingError
	if errors.As(err, &decode) || errors.As(err, &decodePointer) || errors.Is(err, sarama.ErrInsufficientData) || errors.Is(err, sarama.ErrIncompleteResponse) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, branch := range joined.Unwrap() {
			if !linkBrokerAvailability(branch) {
				return false
			}
		}
		return len(joined.Unwrap()) > 0
	}
	switch err {
	case nil, io.EOF, io.ErrUnexpectedEOF, context.Canceled, context.DeadlineExceeded, syscall.EACCES, syscall.EPERM:
		return false
	case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ETIMEDOUT:
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return linkBrokerAvailability(wrapped.Unwrap())
	}
	timeout, ok := err.(net.Error)
	return ok && timeout.Timeout()
}
func linkBrokerRetryable(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, branch := range joined.Unwrap() {
			if !linkBrokerRetryable(branch) {
				return false
			}
		}
		return len(joined.Unwrap()) > 0
	}
	if eof, ok := err.(*linkBrokerEmptyEOF); ok {
		return cleanLinkBrokerEOF(eof.connection)
	}
	socket, ok := err.(*linkBrokerSocketError)
	if !ok {
		return false
	}
	var op *net.OpError
	return errors.As(socket.cause, &op) && linkBrokerAvailability(socket.cause)
}

// Fresh exact ownership is checked once before polling and once after success.
// A Docker failure stops immediately; it never turns into another probe route.
func readyLinkedBrokers(ctx context.Context, s State, run Executor, probe linkBrokerProbe) error {
	if err := validateLinkPlan(s); err != nil {
		return err
	}
	if run == nil || probe == nil {
		return errors.New("linked broker readiness executor missing")
	}
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for index := range s.Containers {
		if err := readyLinkedBroker(bounded, s, index, run, probe); err != nil {
			return err
		}
	}
	return nil
}
func readyLinkedBroker(ctx context.Context, s State, index int, run Executor, probe linkBrokerProbe) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if index < 0 || index >= 2 {
		return errors.New("unexpected linked broker index")
	}
	n, present, err := inspectLinkNetwork(ctx, s, run)
	if err != nil || !present {
		return errors.Join(err, errors.New("linked broker network unavailable before readiness"))
	}
	image, err := inspectLinkImage(ctx, run, Image)
	if err != nil {
		return err
	}
	if s.Proxy.BrokerImageID != "" && s.Proxy.BrokerImageID != image {
		return errors.New("retained linked broker image changed before readiness")
	}
	initial, present, err := inspectLinkContainer(ctx, s, run, index, n.ID, image, true)
	if err != nil || !present || !initial.Running || initial.Paused {
		return errors.Join(err, errors.New("linked broker ownership/state unavailable before readiness"))
	}
	endpoint := []string{s.Source, s.Destination}[index]
	for attempt := 1; attempt <= 64; attempt++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		started := time.Now()
		intent := struct {
			RunID, Endpoint, ContainerID, Operation        string
			Attempt                                        int
			StartedAt                                      time.Time
			MaxAttempts                                    int
			AttemptTimeoutNanoseconds, PollWaitNanoseconds int64
		}{s.RunID, endpoint, initial.ID, "direct Sarama ApiVersions-v0", attempt, started.UTC(), 64, int64(2 * time.Second), int64(500 * time.Millisecond)}
		intentRef, e := writeLinkPrivate(linkPrivateDirectory(s.RunID), "", intent)
		if e != nil {
			return e
		}
		if e = linkReceipt(s, "broker-readiness-request", intent); e != nil {
			return e
		}
		one, cancel := context.WithTimeout(ctx, 2*time.Second)
		observed, probeErr := probe(one, endpoint)
		probeErr = errors.Join(probeErr, one.Err())
		cancel()
		if probeErr == nil {
			probeErr = validateLinkBrokerProbe(observed)
		}
		if !observed.Closed {
			probeErr = errors.Join(probeErr, errors.New("linked broker probe not closed"))
		}
		notice := []byte(nil)
		if probeErr != nil {
			notice = []byte(probeErr.Error())
		}
		reported := len(notice)
		complete := reported <= linkOutputLimit
		if !complete {
			notice = notice[:linkOutputLimit]
		}
		safeCause := safeLinkDockerCause(ctx, probeErr)
		reference, e := writeLinkPrivate(linkPrivateDirectory(s.RunID), "", struct {
			RunID, Intent, Classification string
			Endpoint, ContainerID         string
			Attempt                       int
			StartedAt, EndedAt            time.Time
			ElapsedNanoseconds            int64
			Observation                   linkBrokerProbeResult
			CauseText                     []byte
			CauseSHA256                   string
			ReportedCauseBytes            int
			CauseComplete                 bool
			Cause                         linkDockerCause
		}{s.RunID, intentRef, "PRIVATE RAW EVIDENCE", endpoint, initial.ID, attempt, started.UTC(), time.Now().UTC(), time.Since(started).Nanoseconds(), observed, notice, linkDigest(notice), reported, complete, safeCause})
		if e != nil {
			return e
		}
		summary := struct {
			RunID, Endpoint, ContainerID, PrivateReference, CauseSHA256 string
			Attempt, ReportedCauseBytes                                 int
			CauseComplete, Retryable                                    bool
			Observation                                                 linkBrokerProbeResult
			Cause                                                       linkDockerCause
		}{s.RunID, endpoint, initial.ID, reference, linkDigest(notice), attempt, reported, complete, complete && ctx.Err() == nil && attempt < 64 && linkBrokerRetryable(probeErr), observed, safeCause}
		if e = linkReceipt(s, "broker-readiness", summary); e != nil {
			return e
		}
		if probeErr == nil && complete {
			// Reinspect via the same Docker boundary and compare the immutable ID;
			// a replacement at the same name/port cannot establish startup readiness.
			final, exists, e := inspectLinkContainer(ctx, s, run, index, n.ID, image, true)
			if e != nil || !exists || final.ID != initial.ID || !final.Running || final.Paused {
				return errors.Join(e, errors.New("linked broker identity/state changed during readiness"))
			}
			return ctx.Err()
		}
		safeFailure := fmt.Errorf("direct linked broker readiness failed; private receipt %s", reference)
		if !summary.Retryable || attempt == 64 {
			return errors.Join(safeFailure, ctx.Err())
		}
		select {
		case <-ctx.Done():
			return errors.Join(safeFailure, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("linked broker readiness attempt bound exhausted")
}
