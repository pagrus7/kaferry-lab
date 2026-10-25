package campaign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

func latencyNoticeState(t *testing.T) fixture.State {
	t.Helper()
	t.Chdir(t.TempDir())
	id, prefix := "latency-test", "kaferry-lab-latency-test"
	s := fixture.State{RunID: id, Image: fixture.Image, Network: prefix, Containers: []string{prefix + "-source", prefix + "-dest"}, ClusterIDs: []string{"source-cluster", "dest-cluster"}, Source: "127.0.0.1:19092", Destination: "127.0.0.1:19093", WorkerSource: "127.0.0.1:29092", WorkerDestination: "127.0.0.1:29093", Proxy: &fixture.ProxyState{Image: fixture.ProxyImage, Container: prefix + "-links", API: "127.0.0.1:18474", Source: fixture.ProxyMapping{Name: prefix + "-source-worker", Listen: "0.0.0.0:8666", Upstream: prefix + "-source:29092"}, Destination: fixture.ProxyMapping{Name: prefix + "-dest-worker", Listen: "0.0.0.0:8667", Upstream: prefix + "-dest:29092"}}}
	for _, path := range []string{filepath.Join(".cache", "fixtures", id+"-links"), filepath.Join(".cache", "fixtures-private", id+"-links")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(struct{ RunID string }{id})
	if err := os.WriteFile(filepath.Join(".cache", "fixtures-private", id+"-links", "PRIVATE.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	return s
}

func checkLatencyPrivate(t *testing.T, state fixture.State, failure error, action []string, notice []byte, cause string) {
	t.Helper()
	retained, ok := failure.(*linkLatencyRetainedFailure)
	if !ok || retained.Reference == "" || strings.Contains(failure.Error(), "PRIVATE_") {
		t.Fatalf("unsafe or missing retained failure: %T %v", failure, failure)
	}
	body, err := os.ReadFile(retained.Reference)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(retained.Reference)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private failure not owner-only", err)
	}
	var raw struct {
		Action                        []string
		Notice, CauseText             []byte
		NoticeComplete, CauseComplete bool
	}
	if json.Unmarshal(body, &raw) != nil || !reflect.DeepEqual(raw.Action, action) || !bytes.Equal(raw.Notice, notice) || string(raw.CauseText) != cause || !raw.NoticeComplete || !raw.CauseComplete {
		t.Fatal("original action/notice/cause changed or incomplete")
	}
	public, err := filepath.Glob(filepath.Join(".cache", "fixtures", state.RunID+"-links", "*.json"))
	if err != nil || len(public) == 0 {
		t.Fatal("safe public outcome absent", err)
	}
	for _, path := range public {
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, []byte("PRIVATE_")) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString([]byte(cause)))) {
			t.Fatal("private cause entered public receipt", path, err)
		}
	}
}

func TestLatencyActualHTTPRequestRetainsWholeFailureBeforeRetry(t *testing.T) {
	private := errors.New("PRIVATE_LATENCY=unreviewed request reason")
	for _, tc := range []struct {
		name          string
		cause         error
		requestOrigin bool
		wantCalls     int
	}{
		{"clean refusal", syscall.ECONNREFUSED, true, 2},
		{"permission mixed", errors.Join(syscall.ECONNREFUSED, syscall.EPERM), true, 1},
		{"access mixed", errors.Join(syscall.ECONNREFUSED, syscall.EACCES), true, 1},
		{"context mixed", errors.Join(syscall.ECONNREFUSED, context.Canceled), true, 1},
		{"deadline mixed", errors.Join(syscall.ECONNREFUSED, context.DeadlineExceeded), true, 1},
		{"unknown mixed", errors.Join(syscall.ECONNREFUSED, private), true, 1},
		{"close mixed", errors.Join(syscall.ECONNREFUSED, errors.New("PRIVATE_CLOSE=fatal")), true, 1},
		{"receipt mixed", errors.Join(syscall.ECONNREFUSED, errors.New("PRIVATE_RECEIPT=fatal")), true, 1},
		{"unmarked refusal", syscall.ECONNREFUSED, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given literal actual-request failures, including joined fatal leaves.
				state := latencyNoticeState(t)
				cause := tc.cause
				if tc.requestOrigin {
					cause = &url.Error{Op: "Get", URL: "http://127.0.0.1:18474/version", Err: &net.OpError{Op: "dial", Net: "tcp", Err: cause}}
				}
				calls, requests := 0, 0
				var first error
				// When the actual request/retention path decides startup readiness,
				err := readyLinkLatencyAPI(context.Background(), func() (string, error) {
					calls++
					_, data, requestErr := requestLinkLatencyHTTP(context.Background(), state, "127.0.0.1:18474", "GET", "/version", nil, func(*http.Request) (*http.Response, error) {
						requests++
						if requests == 1 {
							return nil, cause
						}
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"version":"2.12.0"}`))}, nil
					})
					if requestErr != nil {
						first = requestErr
						return "", requestErr
					}
					var version struct{ Version string }
					if err := json.Unmarshal(data, &version); err != nil {
						t.Fatal(err)
					}
					return version.Version, nil
				})
				// Then only the complete retained clean request refusal reaches a
				// second actual request; exact private bytes survive every fatal tree.
				if calls != tc.wantCalls || requests != tc.wantCalls || (err == nil) != (tc.wantCalls == 2) {
					t.Fatalf("reads=%d requests=%d error=%v", calls, requests, err)
				}
				checkLatencyPrivate(t, state, first, []string{"latency_http", "GET", "127.0.0.1:18474", "/version"}, nil, cause.Error())
			})
		})
	}
}

type latencyControlBody struct {
	io.Reader
	readFailure, closeFailure error
	closed                    int
}

func (b *latencyControlBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.readFailure != nil {
		return n, b.readFailure
	}
	return n, err
}
func (b *latencyControlBody) Close() error { b.closed++; return b.closeFailure }

func TestLatencyActualHTTPBodyReadStatusCloseAndBoundsArePrivateFatal(t *testing.T) {
	for _, condition := range []string{"read", "status", "close", "refused close", "overflow"} {
		t.Run(condition, func(t *testing.T) {
			// Given a real response-body path with literal read/status/close faults.
			state := latencyNoticeState(t)
			notice := []byte("PRIVATE_HTTP_BODY=original bounded notice")
			body := &latencyControlBody{Reader: bytes.NewReader(notice)}
			status := 200
			var requestFailure error
			switch condition {
			case "read":
				body.readFailure = &net.OpError{Op: "read", Net: "tcp", Err: errors.New("PRIVATE_READ=original")}
			case "status":
				status = 503
			case "close":
				body.closeFailure = errors.New("PRIVATE_CLOSE=original")
			case "refused close":
				requestFailure = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				body.closeFailure = syscall.ECONNREFUSED
			case "overflow":
				notice = []byte(strings.Repeat("x", (8<<10)+1))
				body.Reader = bytes.NewReader(notice)
			}
			calls, requests := 0, 0
			var first error
			// When those outcomes traverse the actual bounded HTTP/close path,
			err := readyLinkLatencyAPI(context.Background(), func() (string, error) {
				calls++
				_, _, first = requestLinkLatencyHTTP(context.Background(), state, "127.0.0.1:18474", "GET", "/version", nil, func(*http.Request) (*http.Response, error) {
					requests++
					return &http.Response{StatusCode: status, Body: body}, requestFailure
				})
				return "", first
			})
			// Then the first failure stops and body close is checked even when a
			// request refusal is present; raw body/cause never become public text.
			if calls != 1 || requests != 1 || err == nil || body.closed != 1 {
				t.Fatalf("reads=%d requests=%d close=%d error=%v", calls, requests, body.closed, err)
			}
			retained, ok := first.(*linkLatencyRetainedFailure)
			if !ok || retained.Retryable {
				t.Fatal("body/close/status promoted to retry", first)
			}
			data, e := os.ReadFile(retained.Reference)
			if e != nil {
				t.Fatal(e)
			}
			var raw struct{ Notice, CauseText []byte }
			if json.Unmarshal(data, &raw) != nil || !bytes.Equal(raw.Notice, notice) || len(raw.CauseText) == 0 {
				t.Fatal("body/cause lost")
			}
			wantAction := []string{"latency_http", "GET", "127.0.0.1:18474", "/version"}
			if condition == "read" || condition == "overflow" {
				wantAction = append(wantAction, "response_prefix_incomplete", "capture_limit_bytes=8192", fmt.Sprintf("observed_prefix_bytes=%d", len(notice)))
			}
			checkLatencyPrivate(t, state, first, wantAction, notice, string(raw.CauseText))
		})
	}
}

func TestLatencyRefusalCannotRetryAfterRetentionFailureOrOverflow(t *testing.T) {
	for _, condition := range []string{"private persistence", "public persistence", "cause overflow"} {
		t.Run(condition, func(t *testing.T) {
			// Given a request refusal and a mandatory evidence failure.
			state := latencyNoticeState(t)
			if condition != "cause overflow" {
				kind := "fixtures-private"
				if condition == "public persistence" {
					kind = "fixtures"
				}
				path := filepath.Join(".cache", kind, state.RunID+"-links")
				if err := os.RemoveAll(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cause := error(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
			if condition == "cause overflow" {
				cause = &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(syscall.ECONNREFUSED, errors.New("PRIVATE_"+strings.Repeat("x", 64<<10)))}
			}
			calls, requests := 0, 0
			// When startup handles that actual request and retention result,
			err := readyLinkLatencyAPI(context.Background(), func() (string, error) {
				calls++
				_, _, err := requestLinkLatencyHTTP(context.Background(), state, "127.0.0.1:18474", "GET", "/version", nil, func(*http.Request) (*http.Response, error) {
					requests++
					return nil, cause
				})
				return "", err
			})
			// Then no second request or unsafe raw public error is possible.
			if err == nil || calls != 1 || requests != 1 || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatalf("reads=%d requests=%d error=%v", calls, requests, err)
			}
			if retained, ok := err.(*linkLatencyRetainedFailure); ok && retained.Retryable {
				t.Fatal("incomplete retention permitted retry")
			}
		})
	}
}

// This literal connection only exercises the calibration's concrete failure
// boundaries. It never dials or implements an alternate network/proxy route.
type latencyFaultConn struct {
	stage      string
	cause      error
	mu         sync.Mutex
	read       int
	closed     bool
	closeCalls int
}

func (c *latencyFaultConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stage == "ReadFirstByte" || c.stage == "ReadRemainingBytes" && c.read > 0 {
		return 0, c.cause
	}
	if c.read >= 32 {
		return 0, io.EOF
	}
	n := min(len(p), 32-c.read)
	for i := range n {
		p[i] = byte(c.read + i)
	}
	c.read += n
	return n, nil
}
func (c *latencyFaultConn) Write(p []byte) (int, error) {
	if c.stage == "Write" {
		return 0, c.cause
	}
	return len(p), nil
}
func (c *latencyFaultConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCalls++
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	if c.stage == "Close" {
		return c.cause
	}
	return nil
}
func (*latencyFaultConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20001}
}
func (*latencyFaultConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20002}
}
func (c *latencyFaultConn) SetDeadline(time.Time) error {
	if c.stage == "SetDeadline" {
		return c.cause
	}
	return nil
}
func (c *latencyFaultConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *latencyFaultConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func TestLatencyActualSocketFailuresRetainExactActionAndCause(t *testing.T) {
	for _, operation := range []string{"Listen", "Dial", "SetDeadline", "Write", "ReadFirstByte", "ReadRemainingBytes", "Close"} {
		t.Run(operation, func(t *testing.T) {
			// Given literal syscall/unknown failures at the actual narrow I/O seam.
			state := latencyNoticeState(t)
			cause := &net.OpError{Op: operation, Net: "tcp", Err: errors.Join(syscall.EPERM, errors.New("PRIVATE_SOCKET=original "+operation))}
			if operation == "Close" {
				cause.Err = errors.Join(net.ErrClosed, cause.Err)
			}
			var err error
			var action []string
			switch operation {
			case "Listen":
				_, err = listenLinkLatency(state, func(network, address string) (net.Listener, error) {
					if network != "tcp4" || address != "127.0.0.1:0" {
						t.Fatal("wrong listen action")
					}
					return nil, cause
				})
				action = []string{"latency_listener", "Listen", "tcp4", "127.0.0.1:0"}
			case "Dial":
				_, err = dialLinkLatency(context.Background(), state, "127.0.0.1:20002", func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp4" || address != "127.0.0.1:20002" {
						t.Fatal("wrong dial action")
					}
					return nil, cause
				})
				action = []string{"latency_client", "Dial", "tcp4", "127.0.0.1:20002"}
			case "Close":
				err = closeLinkLatencyClient(state, &latencyFaultConn{stage: operation, cause: cause})
				action = []string{"latency_client", "Close", "127.0.0.1:20001", "127.0.0.1:20002"}
			default:
				got, e := exchangeLinkLatency(context.Background(), state, time.Now(), &latencyFaultConn{stage: operation, cause: cause}, make(chan linkLatencyServerReceipt))
				err = e
				if got.Error == "" || strings.Contains(got.Error, "PRIVATE_") {
					t.Fatal("unsafe or missing public exchange failure")
				}
				action = []string{"latency_exchange", operation, "127.0.0.1:20001", "127.0.0.1:20002", got.Nonce}
			}
			// When the operation fails, Then its original cause is privately exact
			// and the caller receives only the reference, never the raw notice.
			want := cause.Error()
			checkLatencyPrivate(t, state, err, action, nil, want)
		})
	}
}

type latencyAcceptFailure struct{ cause error }

func (l latencyAcceptFailure) Accept() (net.Conn, error) { return nil, l.cause }
func (latencyAcceptFailure) Close() error                { return nil }
func (latencyAcceptFailure) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20003}
}

func TestLatencyActualAsyncAcceptFailureSurvivesPrivateHandoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given a literal asynchronous listener denial, never a real socket.
		state := latencyNoticeState(t)
		cause := &net.OpError{Op: "accept", Net: "tcp", Err: errors.Join(syscall.EACCES, errors.New("PRIVATE_ACCEPT=original"))}
		failures := make(chan linkLatencyNetworkFailure, 32)
		stop := startLinkLatencyEcho(context.Background(), time.Now(), latencyAcceptFailure{cause}, make(chan linkLatencyServerReceipt, 16), failures)
		synctest.Wait()
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if len(failures) != 1 {
			t.Fatalf("lost asynchronous original cause: %d", len(failures))
		}
		got := <-failures
		if got.Cause != cause {
			t.Fatal("asynchronous cause replaced")
		}
		failures <- got
		// When the owner drains actual server failures, Then private retention
		// precedes any public failure and the handoff does not drop the notice.
		err := retainLinkLatencyServerFailures(state, failures)
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 1 {
			t.Fatal("async failure not surfaced", err)
		}
		checkLatencyPrivate(t, state, joined.Unwrap()[0], []string{"latency_echo", "Accept", "127.0.0.1:20003"}, nil, cause.Error())
	})
}

type latencyOneConnListener struct {
	closeFailure error
	conn         net.Conn
	mu           sync.Mutex
	given        bool
	closed       chan struct{}
	once         sync.Once
}

func (l *latencyOneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.given {
		l.given = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}
func (l *latencyOneConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.closeFailure
}
func (*latencyOneConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20003}
}

func TestLatencyActualAsyncSocketFailuresAndCompletedEOF(t *testing.T) {
	for _, operation := range []string{"SetDeadline", "ReadFirstByte", "ReadRemainingBytes", "Write", "Close", "completed EOF"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// Given literal server I/O outcomes and a single owned synthetic
				// connection, including expected EOF after one complete response.
				state := latencyNoticeState(t)
				cause := &net.OpError{Op: operation, Net: "tcp", Err: errors.Join(syscall.EPERM, errors.New("PRIVATE_SERVER=original "+operation))}
				if operation == "Close" {
					cause.Err = errors.Join(net.ErrClosed, cause.Err)
				}
				conn := &latencyFaultConn{stage: operation, cause: cause}
				listener := &latencyOneConnListener{conn: conn, closed: make(chan struct{})}
				failures := make(chan linkLatencyNetworkFailure, 32)
				receipts := make(chan linkLatencyServerReceipt, 16)
				stop := startLinkLatencyEcho(context.Background(), time.Now(), listener, receipts, failures)
				synctest.Wait()
				if err := stop(); err != nil {
					t.Fatal(err)
				}
				conn.mu.Lock()
				closeCalls := conn.closeCalls
				conn.mu.Unlock()
				if closeCalls != 1 {
					t.Fatalf("close was retried: %d", closeCalls)
				}
				// When the real asynchronous server path completes, Then only the
				// proved zero-byte post-response EOF is benign; every actual fault
				// hands its original typed cause to mandatory private retention.
				if operation == "completed EOF" {
					if len(receipts) != 1 || len(failures) != 0 {
						t.Fatalf("completed EOF not benign: receipts=%d failures=%d", len(receipts), len(failures))
					}
					return
				}
				if len(failures) != 1 {
					t.Fatalf("async failure count=%d", len(failures))
				}
				failure := <-failures
				want := cause.Error()
				if failure.Cause.Error() != want {
					t.Fatal("server original cause changed")
				}
				failures <- failure
				err := retainLinkLatencyServerFailures(state, failures)
				joined, ok := err.(interface{ Unwrap() []error })
				if !ok || len(joined.Unwrap()) != 1 {
					t.Fatal("server failure not surfaced", err)
				}
				checkLatencyPrivate(t, state, joined.Unwrap()[0], []string{"latency_echo", operation, "127.0.0.1:20002"}, nil, want)
			})
		})
	}
}

func TestLatencyActualAsyncListenerCloseRetainsMixedFatalCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given an owned listener whose close reports a mixed expected/fatal tree.
		state := latencyNoticeState(t)
		cause := &net.OpError{Op: "close", Net: "tcp", Err: errors.Join(net.ErrClosed, syscall.EPERM, errors.New("PRIVATE_LISTENER_CLOSE=original"))}
		listener := &latencyOneConnListener{given: true, closed: make(chan struct{}), closeFailure: cause}
		failures := make(chan linkLatencyNetworkFailure, 32)
		stop := startLinkLatencyEcho(context.Background(), time.Now(), listener, make(chan linkLatencyServerReceipt, 16), failures)
		synctest.Wait()
		// When cleanup closes and reaps the actual asynchronous listener path,
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		// Then net.ErrClosed cannot hide its fatal leaf or original private notice.
		if len(failures) != 1 {
			t.Fatalf("listener close failure lost: %d", len(failures))
		}
		err := retainLinkLatencyServerFailures(state, failures)
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 1 {
			t.Fatal("listener close not surfaced", err)
		}
		checkLatencyPrivate(t, state, joined.Unwrap()[0], []string{"latency_echo", "ListenerClose", "127.0.0.1:20003"}, nil, cause.Error())
	})
}
