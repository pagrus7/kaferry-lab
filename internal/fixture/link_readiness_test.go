package fixture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

func linkReadyResult() linkBrokerProbeResult {
	return linkBrokerProbeResult{Opened: true, Closed: true, APIKeys: 1}
}
func linkReadySocket(cause error) error {
	return &linkBrokerSocketError{cause: &net.OpError{Op: "dial", Net: "tcp", Err: cause}}
}
func linkReadyExecutor(t *testing.T, s State, change func(string, map[string]any)) Executor {
	t.Helper()
	run, err := LinkExecutor(s, linkTestDocker(t, s, change))
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestLinkedReadinessRetryRequiresOnlyLiteralRequestAvailability(t *testing.T) {
	// Given literal typed request failures, when a retry is considered, then every
	// joined leaf must be reviewed availability from the request origin. Docker,
	// receipt, close, permission, decoder, context and unknown leaves stop.
	refused := linkReadySocket(syscall.ECONNREFUSED)
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"request refused", refused, true},
		{"request reset", linkReadySocket(syscall.ECONNRESET), true},
		{"request syscall timeout", linkReadySocket(syscall.ETIMEDOUT), true},
		{"request socket deadline", linkReadySocket(os.ErrDeadlineExceeded), true},
		{"all availability", errors.Join(refused, linkReadySocket(syscall.ECONNRESET)), true},
		{"Docker refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
		{"bare refused", syscall.ECONNREFUSED, false},
		{"marker without request socket", &linkBrokerSocketError{cause: syscall.ECONNREFUSED}, false},
		{"permission", linkReadySocket(syscall.EACCES), false},
		{"policy permission", linkReadySocket(syscall.EPERM), false},
		{"unknown", linkReadySocket(errors.New("unknown socket error")), false},
		{"canceled", linkReadySocket(context.Canceled), false},
		{"context deadline", linkReadySocket(context.DeadlineExceeded), false},
		{"decoder", linkReadySocket(sarama.PacketDecodingError{Info: "synthetic malformed response"}), false},
		{"incomplete", linkReadySocket(sarama.ErrIncompleteResponse), false},
		{"insufficient", linkReadySocket(sarama.ErrInsufficientData), false},
		{"EOF not reviewed", linkReadySocket(io.EOF), false},
		{"bare EOF", io.EOF, false},
		{"EOF text", errors.New("EOF"), false},
		{"partial EOF", linkReadySocket(io.ErrUnexpectedEOF), false},
		{"pipe not reviewed", linkReadySocket(syscall.EPIPE), false},
		{"receipt beside socket", errors.Join(refused, errors.New("receipt persistence failed")), false},
		{"close beside socket", errors.Join(refused, errors.New("client close failed")), false},
		{"permission nested in request", linkReadySocket(errors.Join(syscall.ECONNREFUSED, syscall.EPERM)), false},
		{"decoder beside socket", errors.Join(refused, sarama.PacketDecodingError{Info: "decode"}), false},
		{"context beside socket", errors.Join(refused, context.DeadlineExceeded), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := linkBrokerRetryable(tc.err); got != tc.retry {
				t.Fatalf("retry=%v want=%v", got, tc.retry)
			}
		})
	}
}

type linkReadyPeerResult struct {
	RequestBytes, ResponseBytes int
	RequestComplete, Closed     bool
	err                         error
}

func retainLinkReadyControlError(t *testing.T, s State, operation string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if _, e := RetainLinkNetworkFailure(s, []string{"synthetic_readiness_control", operation}, nil, err); e != nil {
		t.Fatal("synthetic readiness control private evidence unavailable")
	}
}

// One owned loopback peer reads one bounded ApiVersions-v0 handshake, sends a
// fixed synthetic reply prefix, and closes. It never forwards or handles data.
func runLinkReadyPeer(t *testing.T, s State, parent context.Context, mode string, wrap func(net.Conn) net.Conn) (linkBrokerProbeResult, error, linkReadyPeerResult) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		retainLinkReadyControlError(t, s, "listen", err)
		t.Fatal("synthetic readiness listener unavailable; private cause retained")
	}
	defer func() {
		if e := listener.Close(); e != nil {
			retainLinkReadyControlError(t, s, "listener close", e)
			t.Error("synthetic readiness listener close failed; private cause retained")
		}
	}()
	if err = listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		retainLinkReadyControlError(t, s, "accept deadline", err)
		t.Fatal("synthetic readiness accept deadline failed; private cause retained")
	}
	done := make(chan linkReadyPeerResult, 1)
	go func() {
		var result linkReadyPeerResult
		conn, e := listener.AcceptTCP()
		if e != nil {
			result.err = e
			done <- result
			return
		}
		defer func() {
			e := conn.Close()
			result.Closed = e == nil
			result.err = errors.Join(result.err, e)
			done <- result
		}()
		if result.err = conn.SetDeadline(time.Now().Add(2 * time.Second)); result.err != nil {
			return
		}
		var size [4]byte
		n, e := io.ReadFull(conn, size[:])
		result.RequestBytes += n
		if e != nil {
			result.err = e
			return
		}
		length := binary.BigEndian.Uint32(size[:])
		if length < 10 || length > 256 {
			result.err = errors.New("synthetic handshake request length rejected")
			return
		}
		request := make([]byte, int(length))
		n, e = io.ReadFull(conn, request)
		result.RequestBytes += n
		if e != nil {
			result.err = e
			return
		}
		if binary.BigEndian.Uint16(request[:2]) != 18 || binary.BigEndian.Uint16(request[2:4]) != 0 || int(binary.BigEndian.Uint16(request[8:10])) != len(request)-10 || string(request[10:]) != "kaferry-lab-link-readiness" {
			result.err = errors.New("synthetic peer did not receive the single fixed ApiVersions-v0 request")
			return
		}
		result.RequestComplete = true
		header := make([]byte, 8)
		binary.BigEndian.PutUint32(header[:4], 10) // correlation plus six-byte body
		copy(header[4:], request[4:8])
		var reply []byte
		switch mode {
		case "empty":
		case "header only":
			reply = header
		case "partial header":
			reply = header[:4]
		case "partial body":
			reply = append(header, 0)
		case "malformed":
			reply = append(header, 0, 0, 0, 0, 0, 1) // one absent API entry
		case "healthy":
			binary.BigEndian.PutUint32(header[:4], 16)
			reply = append(header, 0, 0, 0, 0, 0, 1, 0, 18, 0, 0, 0, 0)
		default:
			result.err = errors.New("unknown synthetic readiness peer mode")
			return
		}
		if len(reply) > 0 {
			n, result.err = conn.Write(reply)
			result.ResponseBytes = n
			if n != len(reply) {
				result.err = errors.Join(result.err, io.ErrShortWrite)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	observed, probeErr := kafkaLinkBrokerProbeWithConnection(ctx, listener.Addr().String(), wrap)
	var peer linkReadyPeerResult
	select {
	case peer = <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("synthetic readiness peer failed its bounded join")
	}
	retainLinkReadyControlError(t, s, "peer exchange", peer.err)
	retainLinkReadyControlError(t, s, "actual Sarama probe", probeErr)
	if peer.err != nil || !peer.Closed || !peer.RequestComplete {
		t.Fatal("synthetic readiness handshake or close incomplete; exact private causes retained")
	}
	return observed, probeErr, peer
}

func TestLinkedRawReadinessEmptyEOFRequiresActualByteAndCloseWitness(t *testing.T) {
	for _, mode := range []string{"empty", "header only", "partial header", "partial body", "malformed", "healthy"} {
		t.Run(mode, func(t *testing.T) {
			// Given an actual sole direct Sarama request to an owned peer, When
			// it closes after this fixed prefix, Then only a zero-byte clean EOF
			// is availability; an independently counted nonempty prefix is fatal.
			s := linkRetentionState(t)
			observed, err, peer := runLinkReadyPeer(t, s, context.Background(), mode, nil)
			if !observed.Opened || !observed.Closed || observed.Connection.ReadBytes != int64(peer.ResponseBytes) || observed.Connection.DialAttempts != 1 || observed.Connection.Connections != 1 || observed.Connection.CloseCalls != 1 || !observed.Connection.CloseReturned || !observed.Connection.CloseSucceeded {
				t.Fatal("actual connection byte or terminal-close witness differs from independent peer")
			}
			switch mode {
			case "empty":
				if !errors.Is(err, io.EOF) || !linkBrokerRetryable(err) || peer.ResponseBytes != 0 {
					t.Fatal("actual clean empty response EOF was not narrowly retryable")
				}
			case "header only":
				if !errors.Is(err, io.EOF) || linkBrokerRetryable(err) || peer.ResponseBytes != 8 {
					t.Fatal("header-only typed EOF was confused with empty response")
				}
			case "healthy":
				if err != nil || validateLinkBrokerProbe(observed) != nil || observed.APIKeys != 1 {
					t.Fatal("fixed healthy handshake control did not establish readiness")
				}
			case "partial header", "partial body":
				if !errors.Is(err, io.ErrUnexpectedEOF) || linkBrokerRetryable(err) || peer.ResponseBytes == 0 {
					t.Fatal("actual partial-response EOF not reached or treated as availability")
				}
			case "malformed":
				if !errors.Is(err, sarama.ErrInsufficientData) || linkBrokerRetryable(err) || peer.ResponseBytes != 14 {
					t.Fatal("actual incomplete API-entry decoder path not reached or treated as availability")
				}
			}
			t.Logf("synthetic handshake request_bytes=%d response_bytes=%d peer_closed=true; actual client bytes/close matched", peer.RequestBytes, peer.ResponseBytes)
		})
	}
}

type linkReadyFailedClose struct{ net.Conn }

func (c *linkReadyFailedClose) Close() error {
	return errors.Join(c.Conn.Close(), errors.New("PRIVATE_READINESS=synthetic actual close return failure"))
}

func TestLinkedRawReadinessRetainsSaramaHiddenCloseFailureAndRejectsRetry(t *testing.T) {
	// Given a real peer EOF and a literal failure returned after actual socket
	// close, When Sarama discards that close return, Then the same-connection
	// observer still retains it privately and cannot authorize another request.
	s := linkRetentionState(t)
	observed, err, peer := runLinkReadyPeer(t, s, context.Background(), "empty", func(c net.Conn) net.Conn { return &linkReadyFailedClose{Conn: c} })
	if !errors.Is(err, io.EOF) || err == nil || !strings.Contains(err.Error(), "PRIVATE_READINESS=") || observed.Closed || observed.Connection.CloseCalls != 1 || !observed.Connection.CloseReturned || observed.Connection.CloseSucceeded || linkBrokerRetryable(err) || peer.ResponseBytes != 0 {
		t.Fatal("hidden close failure was discarded or permitted retry")
	}
	assertLinkPublicWithholds(t, s, []byte("PRIVATE_READINESS=synthetic actual close return failure"))
}

type linkReadyCancelEOF struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *linkReadyCancelEOF) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		c.cancel()
	}
	return n, err
}

func TestLinkedRawReadinessCancellationBesideActualEmptyEOFIsFatal(t *testing.T) {
	// Given the actual peer EOF, When cancellation is observed on that same
	// Read return, Then a complete close still cannot permit an EOF retry.
	s := linkRetentionState(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed, err, _ := runLinkReadyPeer(t, s, ctx, "empty", func(c net.Conn) net.Conn {
		return &linkReadyCancelEOF{Conn: c, cancel: cancel}
	})
	if !errors.Is(err, io.EOF) || !errors.Is(err, context.Canceled) || !observed.Closed || linkBrokerRetryable(err) {
		t.Fatal("actual EOF bypassed observed cancellation")
	}
}

func TestLinkedReadinessEmptyEOFWitnessAndFatalJoins(t *testing.T) {
	// Given literal witness sensitivity controls (not native proof), When any
	// required fact is absent or another fatal leaf joins EOF, Then retry stops.
	complete := linkBrokerConnectionResult{DialAttempts: 1, Connections: 1, CloseCalls: 1, CloseReturned: true, CloseSucceeded: true}
	if !linkBrokerRetryable(&linkBrokerEmptyEOF{connection: complete}) {
		t.Fatal("complete literal witness control rejected")
	}
	for _, mutate := range []func(*linkBrokerConnectionResult){
		func(c *linkBrokerConnectionResult) { c.DialAttempts = 2 },
		func(c *linkBrokerConnectionResult) { c.Connections = 0 },
		func(c *linkBrokerConnectionResult) { c.ReadBytes = 1 },
		func(c *linkBrokerConnectionResult) { c.CloseCalls = 0 },
		func(c *linkBrokerConnectionResult) { c.CloseCalls = 2 },
		func(c *linkBrokerConnectionResult) { c.CloseReturned = false },
		func(c *linkBrokerConnectionResult) { c.CloseSucceeded = false },
	} {
		partial := complete
		mutate(&partial)
		if linkBrokerRetryable(&linkBrokerEmptyEOF{connection: partial}) {
			t.Fatal("incomplete connection witness permitted EOF retry")
		}
	}
	for _, fatal := range []error{syscall.EACCES, syscall.EPERM, context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF, sarama.ErrInsufficientData, sarama.PacketDecodingError{Info: "synthetic malformed"}, errors.New("synthetic failed close"), errors.New("synthetic failed receipt")} {
		if linkBrokerRetryable(errors.Join(&linkBrokerEmptyEOF{connection: complete}, fatal)) {
			t.Fatal("fatal joined leaf permitted EOF retry")
		}
	}
}

func TestLinkedReadinessRetainsWitnessedEmptyEOFBeforeSameEndpointRetry(t *testing.T) {
	// Given a literal completed connection witness, When the controller retries,
	// Then the first exact private cause and counters precede the next request.
	// Actual Sarama origin/bytes/close are calibrated by the native peer above.
	s := linkRetentionState(t)
	c := linkBrokerConnectionResult{DialAttempts: 1, Connections: 1, CloseCalls: 1, CloseReturned: true, CloseSucceeded: true}
	calls := 0
	var endpoints []string
	err := readyLinkedBrokers(context.Background(), s, linkReadyExecutor(t, s, nil), func(_ context.Context, endpoint string) (linkBrokerProbeResult, error) {
		calls++
		endpoints = append(endpoints, endpoint)
		if calls == 1 {
			return linkBrokerProbeResult{Opened: true, Closed: true, Connection: c}, &linkBrokerEmptyEOF{connection: c}
		}
		files, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
		if e != nil {
			t.Fatal("literal EOF private inventory unavailable")
		}
		found := false
		for _, path := range files {
			body, e := os.ReadFile(path)
			if e != nil {
				t.Fatal("literal EOF private receipt unavailable")
			}
			var value struct {
				CauseText     []byte
				CauseComplete bool
				Observation   linkBrokerProbeResult
			}
			if json.Unmarshal(body, &value) == nil && string(value.CauseText) == "EOF" && value.CauseComplete && value.Observation.Connection == c {
				found = true
			}
		}
		if !found {
			t.Fatal("next request preceded complete private EOF witness retention")
		}
		return linkReadyResult(), nil
	})
	if err != nil || calls != 3 || endpoints[0] != endpoints[1] || endpoints[0] != s.Source || endpoints[2] != s.Destination {
		t.Fatal("literal EOF controller recovery changed endpoint or failed")
	}
}

func TestLinkedReadinessWitnessedEOFCancellationOrReceiptFailureStops(t *testing.T) {
	for _, stage := range []string{"cancel", "private outcome", "public outcome"} {
		t.Run(stage, func(t *testing.T) {
			s := linkRetentionState(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			err := readyLinkedBrokers(ctx, s, linkReadyExecutor(t, s, nil), func(context.Context, string) (linkBrokerProbeResult, error) {
				calls++
				if stage == "cancel" {
					cancel()
				} else {
					path := linkPrivateDirectory(s.RunID)
					if stage == "public outcome" {
						path = linkDirectory(s.RunID)
					}
					if e := os.Rename(path, path+".retained"); e != nil {
						retainLinkReadyControlError(t, s, "prepare receipt failure", e)
						t.Fatal("synthetic receipt-failure preparation unavailable")
					}
					if e := os.WriteFile(path, []byte("synthetic occupied receipt root"), 0600); e != nil {
						t.Fatal("synthetic occupied receipt root unavailable")
					}
				}
				c := linkBrokerConnectionResult{DialAttempts: 1, Connections: 1, CloseCalls: 1, CloseReturned: true, CloseSucceeded: true}
				return linkBrokerProbeResult{Opened: true, Closed: true, Connection: c}, &linkBrokerEmptyEOF{connection: c}
			})
			if err == nil || calls != 1 || stage == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("EOF bypassed cancellation or mandatory receipt failure")
			}
		})
	}
}

func TestLinkedReadinessRetainsUnavailableAttemptThenRecoversDirectly(t *testing.T) {
	// Given an owned cold broker, when its first direct read is refused and the
	// next succeeds, then each attempt is retained before retry, both direct
	// endpoints are reached and Docker exec is never part of readiness.
	s := linkRetentionState(t)
	run := linkReadyExecutor(t, s, nil)
	endpoints := []string{}
	notice := linkReadySocket(syscall.ECONNREFUSED)
	err := readyLinkedBrokers(context.Background(), s, run, func(ctx context.Context, endpoint string) (linkBrokerProbeResult, error) {
		endpoints = append(endpoints, endpoint)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("unbounded readiness attempt")
		}
		if len(endpoints) == 1 {
			return linkBrokerProbeResult{Closed: true}, notice
		}
		return linkReadyResult(), nil
	})
	if err != nil || len(endpoints) != 3 || endpoints[0] != s.Source || endpoints[1] != s.Source || endpoints[2] != s.Destination {
		t.Fatal("direct startup recovery incomplete", endpoints, err)
	}
	files, e := filepath.Glob(filepath.Join(linkDirectory(s.RunID), "broker-readiness-*.json"))
	if e != nil || len(files) != 6 {
		t.Fatal("missing intent/outcome attempts", files, e)
	}
	found := false
	private, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range private {
		body, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		var receipt struct {
			CauseText     []byte
			CauseComplete bool
		}
		if json.Unmarshal(body, &receipt) == nil && string(receipt.CauseText) == notice.Error() && receipt.CauseComplete {
			found = true
		}
	}
	if !found {
		t.Fatal("unavailable request's exact private notice was discarded")
	}
}

func TestLinkedReadinessStopsDeniedUnknownDecoderOrCloseFirstAttempt(t *testing.T) {
	// Given a direct probe's fatal failure, when readiness observes it, then only
	// one probe is sent, its exact private cause survives and public text is safe.
	for _, cause := range []error{linkReadySocket(syscall.EACCES), linkReadySocket(syscall.EPERM), linkReadySocket(errors.New("PRIVATE_READINESS=unknown cause")), linkReadySocket(sarama.PacketDecodingError{Info: "PRIVATE_READINESS=decoder detail"}), errors.Join(linkReadySocket(syscall.ECONNREFUSED), errors.New("PRIVATE_READINESS=client close failure"))} {
		t.Run(cause.Error(), func(t *testing.T) {
			s := linkRetentionState(t)
			calls := 0
			err := readyLinkedBrokers(context.Background(), s, linkReadyExecutor(t, s, nil), func(context.Context, string) (linkBrokerProbeResult, error) {
				calls++
				return linkBrokerProbeResult{Closed: true}, cause
			})
			if err == nil || calls != 1 || strings.Contains(err.Error(), "PRIVATE_READINESS") {
				t.Fatal("fatal readiness failure retried/leaked", calls, err)
			}
			assertLinkPublicWithholds(t, s, []byte(cause.Error()), []byte("PRIVATE_READINESS"))
		})
	}
}

func TestLinkedReadinessNeverProbesAfterDockerOwnershipFailure(t *testing.T) {
	// Given a first one-shot Docker ownership denial or unknown failure, when
	// readiness begins, then no Kafka dial/probe or alternate Docker call occurs.
	for _, cause := range []error{syscall.EACCES, syscall.EPERM, errors.New("unknown Docker ownership failure")} {
		t.Run(cause.Error(), func(t *testing.T) {
			s := linkRetentionState(t)
			dockerCalls := 0
			run, err := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) {
				dockerCalls++
				return []byte("exact readiness ownership failure"), cause
			})
			if err != nil {
				t.Fatal(err)
			}
			err = readyLinkedBrokers(context.Background(), s, run, func(context.Context, string) (linkBrokerProbeResult, error) {
				t.Fatal("Kafka probe after failed Docker facility")
				return linkReadyResult(), nil
			})
			if err == nil || dockerCalls != 1 {
				t.Fatal("ownership failure retried", dockerCalls, err)
			}
			readLinkPrivateFailure(t, err)
		})
	}
}

func TestLinkedReadinessReceiptFailurePreventsFirstOrNextProbe(t *testing.T) {
	// Given mandatory receipt storage becomes unavailable, when an intent or an
	// outcome cannot persist, then no first/next probe is permitted even beside
	// a literal connection-refused result that otherwise allows retry.
	for _, stage := range []string{"intent", "private outcome", "public outcome"} {
		t.Run(stage, func(t *testing.T) {
			s := linkRetentionState(t)
			run := linkReadyExecutor(t, s, nil)
			if stage == "intent" {
				path := linkDirectory(s.RunID)
				if e := os.Rename(path, path+".retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte("path occupied"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			err := readyLinkedBrokers(context.Background(), s, run, func(context.Context, string) (linkBrokerProbeResult, error) {
				calls++
				path := linkDirectory(s.RunID)
				if stage == "private outcome" {
					path = linkPrivateDirectory(s.RunID)
				}
				if e := os.Rename(path, path+".retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte("path occupied"), 0600); e != nil {
					t.Fatal(e)
				}
				return linkBrokerProbeResult{Closed: true}, linkReadySocket(syscall.ECONNREFUSED)
			})
			want := 1
			if stage == "intent" {
				want = 0
			}
			if err == nil || calls != want {
				t.Fatal("receipt failure did not stop probe sequence", calls, want, err)
			}
		})
	}
}

func TestLinkedReadinessRejectsInvalidSuccessfulObservation(t *testing.T) {
	// Given a syntactically successful callback, when response or client-state
	// facts are incomplete, then no next attempt or destination probe is allowed.
	for _, observed := range []linkBrokerProbeResult{
		{Opened: true, Closed: true, APIKeys: 0},
		{Opened: true, Closed: true, APIKeys: 257},
		{Opened: true, Closed: true, Version: 1, APIKeys: 1},
		{Opened: true, Closed: true, ErrorCode: 35, APIKeys: 1},
		{Opened: true, Closed: false, APIKeys: 1},
		{Opened: false, Closed: true, APIKeys: 1},
	} {
		t.Run(string(rune('a'+observed.APIKeys%26)), func(t *testing.T) {
			s := linkRetentionState(t)
			calls := 0
			err := readyLinkedBrokers(context.Background(), s, linkReadyExecutor(t, s, nil), func(context.Context, string) (linkBrokerProbeResult, error) { calls++; return observed, nil })
			if err == nil || calls != 1 {
				t.Fatal("invalid readiness accepted or retried", calls, observed, err)
			}
		})
	}
}

func TestLinkedReadinessFinalIdentityChangeIsFatal(t *testing.T) {
	// Given the initial exact broker, when the successful probe is followed by a
	// fresh inspect with a different immutable ID, then readiness cannot pass.
	s := linkRetentionState(t)
	s.Proxy.BrokerIDs = nil // interrupted setup still resolves planned exact names
	changed := false
	run := linkReadyExecutor(t, s, func(target string, object map[string]any) {
		if changed && target == s.Containers[0] {
			object["Id"] = strings.Repeat("f", 64)
		}
	})
	calls := 0
	err := readyLinkedBrokers(context.Background(), s, run, func(context.Context, string) (linkBrokerProbeResult, error) {
		calls++
		changed = true
		return linkReadyResult(), nil
	})
	if err == nil || calls != 1 {
		t.Fatal("replaced broker established readiness", calls, err)
	}
}

func TestLinkedReadinessExpiredContextAndIncompleteNoticeDoNotRetry(t *testing.T) {
	// Given an exhausted context or over-bound cause, when readiness examines it,
	// then no availability-looking result may authorize another probe.
	t.Run("expired", func(t *testing.T) {
		s := linkRetentionState(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		run := func(context.Context, ...string) ([]byte, error) {
			t.Fatal("Docker after expired readiness")
			return nil, nil
		}
		if err := readyLinkedBrokers(ctx, s, run, func(context.Context, string) (linkBrokerProbeResult, error) {
			t.Fatal("probe after expired readiness")
			return linkReadyResult(), nil
		}); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("oversized private notice", func(t *testing.T) {
		s := linkRetentionState(t)
		calls := 0
		cause := &linkBrokerSocketError{cause: &net.OpError{Op: strings.Repeat("x", linkOutputLimit), Net: "tcp", Err: syscall.ECONNREFUSED}}
		err := readyLinkedBrokers(context.Background(), s, linkReadyExecutor(t, s, nil), func(context.Context, string) (linkBrokerProbeResult, error) {
			calls++
			return linkBrokerProbeResult{Closed: true}, cause
		})
		if err == nil || calls != 1 {
			t.Fatal("incomplete notice retried", calls, err)
		}
	})
}

func TestLinkedReadinessContextCancellationStopsReviewedAvailability(t *testing.T) {
	// Given typed refusal, when cancellation arrives during the bounded poll wait,
	// then a second request is forbidden even though the first error is retryable.
	s := linkRetentionState(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := readyLinkedBrokers(ctx, s, linkReadyExecutor(t, s, nil), func(context.Context, string) (linkBrokerProbeResult, error) {
		calls++
		timer := time.AfterFunc(20*time.Millisecond, cancel)
		t.Cleanup(func() { timer.Stop() })
		return linkBrokerProbeResult{Closed: true}, linkReadySocket(syscall.ECONNREFUSED)
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("readiness ignored cancellation/retried", calls, err)
	}
}

func TestLinkedRawReadinessRejectsMissingDeadlineBeforeSocket(t *testing.T) {
	// Given no numerical budget, when the real raw probe is called, then it fails
	// before creating a Sarama Broker; it cannot dial an unbounded connection.
	observed, err := kafkaLinkBrokerProbe(context.Background(), "127.0.0.1:20201")
	if err == nil || observed.Opened || observed.Closed {
		t.Fatal("deadline-free raw readiness admitted", observed, err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	observed, err = kafkaLinkBrokerProbe(ctx, "127.0.0.1:20201")
	if !errors.Is(err, context.DeadlineExceeded) || observed.Opened {
		t.Fatal("expired raw readiness admitted", observed, err)
	}
}

func TestLinkedUpDirectReadinessFailureRetainsResourcesWithoutDockerRetry(t *testing.T) {
	// Given linked containers have been started, when their independent direct
	// readiness probe is denied/unknown, then Up neither cleans nor retries any
	// Docker command, and a later wrapper sees the persisted incomplete stop.
	for _, cause := range []error{linkReadySocket(syscall.EACCES), errors.New("PRIVATE_STARTUP=unknown direct probe failure")} {
		t.Run(cause.Error(), func(t *testing.T) {
			t.Chdir(t.TempDir())
			failed, probes := false, 0
			run := func(ctx context.Context, args ...string) ([]byte, error) {
				if failed {
					t.Fatal("Docker action after failed readiness", args)
				}
				if args[0] == "exec" {
					t.Fatal("Docker exec readiness retry route", args)
				}
				if args[0] == "info" {
					return []byte("linux/amd64"), nil
				}
				if args[0] == "pull" || args[0] == "run" || args[0] == "network" && args[1] == "create" {
					return nil, nil
				}
				path, _ := StatePath("test")
				body, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var state State
				if e = json.Unmarshal(body, &state); e != nil {
					t.Fatal(e)
				}
				return linkTestDocker(t, state, nil)(ctx, args...)
			}
			_, err := up(context.Background(), "test", run, true, func(context.Context, string, string, string, []byte) (int, []byte, error) {
				t.Fatal("proxy API after failed broker readiness")
				return 0, nil, nil
			}, func(context.Context, string) (linkBrokerProbeResult, error) {
				probes++
				failed = true
				return linkBrokerProbeResult{Closed: true}, cause
			})
			if err == nil || probes != 1 || strings.Contains(err.Error(), "PRIVATE_STARTUP") {
				t.Fatal("failed direct startup retried/leaked", probes, err)
			}
			state, e := Load("test")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = LinkExecutor(state, run); e == nil {
				t.Fatal("failed linked startup did not persist unresolved resources/stop")
			}
		})
	}
}
