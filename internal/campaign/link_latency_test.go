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
	s := fixture.State{RunID: id, DockerPlatform: "linux/amd64", Image: fixture.Image, Network: prefix, Containers: []string{prefix + "-source", prefix + "-dest"}, ClusterIDs: []string{"source-cluster", "dest-cluster"}, Source: "127.0.0.1:19092", Destination: "127.0.0.1:19093", WorkerSource: "127.0.0.1:29092", WorkerDestination: "127.0.0.1:29093", Proxy: &fixture.ProxyState{Image: fixture.ProxyImage, Container: prefix + "-links", API: "127.0.0.1:18474", Source: fixture.ProxyMapping{Name: prefix + "-source-worker", Listen: "0.0.0.0:8666", Upstream: prefix + "-source:29092"}, Destination: fixture.ProxyMapping{Name: prefix + "-dest-worker", Listen: "0.0.0.0:8667", Upstream: prefix + "-dest:29092"}}}
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

const literalLatencyEmptyMapping = `{"echo-fixed":{"name":"echo-fixed","listen":"127.0.0.1:18001","upstream":"127.0.0.1:18002","enabled":true,"toxics":[]}}`

func latencyExpectedMapping() linkLatencyProxy {
	return linkLatencyProxy{Name: "echo-fixed", Listen: "127.0.0.1:18001", Upstream: "127.0.0.1:18002", Enabled: true}
}

func readLatencyMappingObservation(t *testing.T, state fixture.State) (linkLatencyMappingReadback, []byte) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(".cache", "fixtures-private", state.RunID+"-links", "docker-*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("single private mapping readback missing")
	}
	body, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal("private mapping readback unavailable")
	}
	info, err := os.Stat(paths[0])
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || len(body) > 256<<10 {
		t.Fatal("mapping readback file not private or bounded")
	}
	var envelope struct {
		Notice, CauseText             []byte
		NoticeComplete, CauseComplete bool
	}
	var observation linkLatencyMappingReadback
	if json.Unmarshal(body, &envelope) != nil || !envelope.NoticeComplete || !envelope.CauseComplete || len(envelope.Notice) > 64<<10 || json.Unmarshal(envelope.Notice, &observation) != nil {
		t.Fatal("private mapping readback incomplete or malformed")
	}
	return observation, envelope.CauseText
}

func TestLatencyMappingExplicitEmptyCollectionsAndMissingFacts(t *testing.T) {
	for _, tc := range []struct {
		name, raw, mismatch string
		accepted            bool
	}{
		{"empty array", literalLatencyEmptyMapping, "", true},
		{"explicit null", strings.Replace(literalLatencyEmptyMapping, `"toxics":[]`, `"toxics":null`, 1), "", true},
		{"missing toxics", strings.Replace(literalLatencyEmptyMapping, `,"toxics":[]`, ``, 1), "toxics_present", false},
		{"false enabled", strings.Replace(literalLatencyEmptyMapping, `"enabled":true`, `"enabled":false`, 1), "enabled", false},
		{"wrong upstream", strings.Replace(literalLatencyEmptyMapping, `127.0.0.1:18002`, `PRIVATE_UPSTREAM=wrong`, 1), "upstream", false},
		{"wrong name", strings.Replace(literalLatencyEmptyMapping, `"name":"echo-fixed"`, `"name":"other"`, 1), "name", false},
		{"different mapping", strings.Replace(literalLatencyEmptyMapping, `{"echo-fixed":`, `{"other":`, 1), "unique_mapping", false},
		{"extra mapping", strings.TrimSuffix(literalLatencyEmptyMapping, `}`) + `,"other":{}}`, "unique_mapping", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given independent literal JSON, When checking an expected empty
			// active list, Then explicit null/[] pass and absent/different facts
			// fail only after exact private readback and component retention.
			state := latencyNoticeState(t)
			_, err := checkLinkLatencyMapping(state, []byte(tc.raw), latencyExpectedMapping(), []linkLatencyToxic{})
			if (err == nil) != tc.accepted {
				t.Fatal("mapping result disagrees with independent literal expectation")
			}
			readback, cause := readLatencyMappingObservation(t, state)
			if readback.PrivateRecordKind != "latency-mapping-readback" || readback.Matched != tc.accepted || !readback.ObservationComplete || !bytes.Equal(readback.ResponseBytes, []byte(tc.raw)) || readback.Expected.Name != "echo-fixed" || readback.Expected.Upstream != "127.0.0.1:18002" || (len(cause) == 0) != tc.accepted {
				t.Fatal("raw mapping, expected values or explicit observation classification changed")
			}
			if !tc.accepted && readback.Components[tc.mismatch] {
				t.Fatal("required component mismatch was hidden")
			}
			if tc.accepted && !readback.ToxicsFieldPresent {
				t.Fatal("accepted empty list lacked explicit toxics presence")
			}
			public, _ := filepath.Glob(filepath.Join(".cache", "fixtures", state.RunID+"-links", "*.json"))
			for _, path := range public {
				body, e := os.ReadFile(path)
				if e != nil || bytes.Contains(body, []byte("PRIVATE_UPSTREAM=")) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString([]byte(tc.raw)))) {
					t.Fatal("raw mapping readback entered public facts")
				}
			}
		})
	}
}

func TestLatencyMappingNonemptyToxicsKeepFullFieldsAndValuesStrict(t *testing.T) {
	const toxic = `[{"name":"latency","type":"latency","stream":"downstream","toxicity":1,"attributes":{"latency":400,"jitter":0}}]`
	want := linkLatencyToxic{Name: "latency", Type: "latency", Stream: "downstream", Toxicity: 1}
	want.Attributes.Latency = 400
	for _, tc := range []struct {
		name, raw string
		accepted  bool
	}{
		{"exact", toxic, true},
		{"unknown type", strings.Replace(toxic, `"type":"latency"`, `"type":"other"`, 1), false},
		{"wrong direction", strings.Replace(toxic, `downstream`, `upstream`, 1), false},
		{"changed latency", strings.Replace(toxic, `400`, `401`, 1), false},
		{"changed toxicity", strings.Replace(toxic, `"toxicity":1`, `"toxicity":0.5`, 1), false},
		{"unknown toxic field", strings.Replace(toxic, `"name":"latency"`, `"unexpected":"PRIVATE_TOXIC=extra","name":"latency"`, 1), false},
		{"missing zero jitter", strings.Replace(toxic, `,"jitter":0`, ``, 1), false},
		{"null zero jitter", strings.Replace(toxic, `"jitter":0`, `"jitter":null`, 1), false},
		{"unknown attribute", strings.Replace(toxic, `"jitter":0`, `"jitter":0,"unexpected":0`, 1), false},
		{"null loses required toxic", `null`, false},
		{"array loses required toxic", `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given a nonempty exact toxic expectation, When any field/value or
			// membership differs, Then null/empty normalization cannot admit it.
			state := latencyNoticeState(t)
			raw := []byte(strings.Replace(literalLatencyEmptyMapping, `"toxics":[]`, `"toxics":`+tc.raw, 1))
			_, err := checkLinkLatencyMapping(state, raw, latencyExpectedMapping(), []linkLatencyToxic{want})
			if (err == nil) != tc.accepted {
				t.Fatal("nonempty toxic comparison weakened field or value requirements")
			}
			readback, _ := readLatencyMappingObservation(t, state)
			if !bytes.Equal(readback.ResponseBytes, raw) || readback.Matched != tc.accepted || !readback.ToxicsFieldPresent {
				t.Fatal("nonempty raw readback or mismatch evidence lost")
			}
		})
	}
}

func TestLatencyMappingPrivatePersistenceFailureCannotAdmitMatchingResponse(t *testing.T) {
	// Given a semantically matching response and an occupied private root,
	// When exact readback cannot persist, Then the matching mapping is not
	// admitted; no fallback sink or second checker invocation is attempted.
	state := latencyNoticeState(t)
	root := filepath.Join(".cache", "fixtures-private", state.RunID+"-links")
	if err := os.Rename(root, root+".retained"); err != nil {
		t.Fatal("synthetic persistence-failure setup unavailable")
	}
	if err := os.WriteFile(root, []byte("synthetic occupied private root"), 0600); err != nil {
		t.Fatal("synthetic occupied private root unavailable")
	}
	_, err := checkLinkLatencyMapping(state, []byte(literalLatencyEmptyMapping), latencyExpectedMapping(), nil)
	if err == nil || strings.Contains(err.Error(), "echo-fixed") {
		t.Fatal("missing private readback admitted matching response or leaked it publicly")
	}
}

func TestLatencyMappingSerializedReadbackBounds(t *testing.T) {
	t.Run("full bounded response preserved", func(t *testing.T) {
		// Given a complete response at the existing HTTP body bound, When its
		// raw bytes and decoded/expected values are serialized, Then the entire
		// private notice fits the courier cap and preserves trailing whitespace.
		state := latencyNoticeState(t)
		raw := append([]byte(literalLatencyEmptyMapping), bytes.Repeat([]byte{' '}, (8<<10)-len(literalLatencyEmptyMapping))...)
		if _, err := checkLinkLatencyMapping(state, raw, latencyExpectedMapping(), nil); err != nil {
			t.Fatal("bounded complete response could not be retained")
		}
		readback, _ := readLatencyMappingObservation(t, state)
		if !readback.Matched || !bytes.Equal(readback.ResponseBytes, raw) {
			t.Fatal("bounded raw response prefix or trailing bytes changed")
		}
	})
	t.Run("serialized expected overflow stops", func(t *testing.T) {
		// Given future expected-value drift beyond the courier budget, When the
		// serialized notice overflows despite a small raw body, Then a bounded
		// incomplete prefix remains private and cannot admit a mapping.
		state := latencyNoticeState(t)
		mapping := latencyExpectedMapping()
		mapping.Name = strings.Repeat("synthetic expected identity ", 4096)
		if _, err := checkLinkLatencyMapping(state, []byte(literalLatencyEmptyMapping), mapping, nil); err == nil {
			t.Fatal("serialized notice overflow was admitted")
		}
		paths, _ := filepath.Glob(filepath.Join(".cache", "fixtures-private", state.RunID+"-links", "docker-*.json"))
		if len(paths) != 1 {
			t.Fatal("single overflow prefix receipt missing")
		}
		body, e := os.ReadFile(paths[0])
		var envelope struct {
			Notice         []byte
			NoticeComplete bool
		}
		if e != nil || json.Unmarshal(body, &envelope) != nil || envelope.NoticeComplete || len(envelope.Notice) != 64<<10 {
			t.Fatal("serialized overflow lost its bounded incomplete private prefix")
		}
	})
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

func TestLatencyActualHTTPStatusReasonIsPrivateWithEmptyBody(t *testing.T) {
	// Given an independently supplied status reason and an empty response body,
	// distinct from the body marker used by the neighboring body controls.
	state := latencyNoticeState(t)
	const reportedStatus = "403 PRIVATE_STATUS_REASON=exact independent denial"
	const absentBodyMarker = "PRIVATE_HTTP_BODY=not present in this response"
	body := &latencyControlBody{Reader: bytes.NewReader(nil)}
	reads, requests := 0, 0
	var first error
	// When the actual request/retention/readiness path receives that response,
	err := readyLinkLatencyAPI(context.Background(), func() (string, error) {
		reads++
		status, _, requestErr := requestLinkLatencyHTTP(context.Background(), state, "127.0.0.1:18474", "GET", "/version", nil, func(*http.Request) (*http.Response, error) {
			requests++
			return &http.Response{StatusCode: 403, Status: reportedStatus, Body: body}, nil
		})
		if status != 403 {
			t.Fatal("status integer changed")
		}
		first = requestErr
		return "", requestErr
	})
	// Then the original reason is exact in private evidence independently of
	// body capture; it closes once, never retries and remains absent publicly.
	if err == nil || reads != 1 || requests != 1 || body.closed != 1 || strings.Contains(err.Error(), "PRIVATE_") {
		t.Fatalf("reads=%d requests=%d close=%d error=%v", reads, requests, body.closed, err)
	}
	retained, ok := first.(*linkLatencyRetainedFailure)
	if !ok || retained.Retryable {
		t.Fatal("status reason was not a retained fatal failure")
	}
	data, readErr := os.ReadFile(retained.Reference)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var raw struct{ Notice, CauseText []byte }
	if json.Unmarshal(data, &raw) != nil || len(raw.Notice) != 0 || string(raw.CauseText) != reportedStatus || bytes.Contains(raw.CauseText, []byte(absentBodyMarker)) {
		t.Fatal("status reason lost, changed, or confused with body capture")
	}
	checkLatencyPrivate(t, state, first, []string{"latency_http", "GET", "127.0.0.1:18474", "/version"}, nil, reportedStatus)
}

func TestLatencyTwentySecondsUsesIndependentServerWriteEnd(t *testing.T) {
	// Given literal monotonic observations of a20s response delay after a prompt
	// known-nonce request and independent server write, not merely20s total time.
	observed := linkLatencyExchange{
		RequestStartNS: 1_000_000_000, ClientWriteStartNS: 1_001_000_000, ClientWriteEndNS: 1_002_000_000,
		ServerFirstByteNS: 1_003_000_000, ServerReceiveNS: 1_004_000_000,
		ServerWriteStartNS: 1_005_000_000, ServerWriteEndNS: 1_006_000_000,
		ClientFirstByteNS: 21_006_000_000, ClientReadEndNS: 21_007_000_000, ExactBytes: true,
	}
	if !linkLatencyLongDownstreamObserved(observed) {
		t.Fatal("literal20s server-write interval rejected")
	}
	for _, condition := range []string{"only400ms", "delay before server write", "blocked server write", "slow upstream", "unknown bytes", "outside request budget", "read precedes write"} {
		t.Run(condition, func(t *testing.T) {
			v := observed
			switch condition {
			case "only400ms":
				v.ClientFirstByteNS, v.ClientReadEndNS = 1_406_000_000, 1_407_000_000
			case "delay before server write":
				v.ServerFirstByteNS, v.ServerReceiveNS, v.ServerWriteStartNS, v.ServerWriteEndNS = 20_000_000_000, 20_001_000_000, 20_002_000_000, 20_003_000_000
			case "blocked server write":
				v.ServerWriteEndNS = 21_005_000_000
			case "slow upstream":
				v.ServerFirstByteNS, v.ServerReceiveNS, v.ServerWriteStartNS, v.ServerWriteEndNS = 1_901_000_000, 1_902_000_000, 1_903_000_000, 1_904_000_000
				v.ClientFirstByteNS, v.ClientReadEndNS = 21_904_000_000, 21_905_000_000
			case "unknown bytes":
				v.ExactBytes = false
			case "outside request budget":
				v.ClientFirstByteNS, v.ClientReadEndNS = 26_006_000_000, 26_007_000_000
			case "read precedes write":
				v.ClientFirstByteNS, v.ClientReadEndNS = 1_001_000_000, 1_002_000_000
			}
			// When the actual interval oracle decides, Then request elapsed time,
			// upstream/server stalls or missing bytes cannot replace this response interval.
			if linkLatencyLongDownstreamObserved(v) {
				t.Fatal("unproved20s response delay accepted")
			}
		})
	}
}

func TestLatencyPendingRemovalReportsObservedPlacementWithoutAssumingFlush(t *testing.T) {
	// Given a literal matching server-written response, an outstanding client
	// read, a bounded removal interval and an actually reaped exact-byte reader.
	observed := linkLatencyPendingRemoval{
		Exchange: linkLatencyExchange{
			RequestStartNS: 1_000_000_000, ClientWriteStartNS: 1_001_000_000, ClientWriteEndNS: 1_002_000_000,
			ServerFirstByteNS: 1_003_000_000, ServerReceiveNS: 1_004_000_000, ServerWriteStartNS: 1_005_000_000, ServerWriteEndNS: 1_006_000_000,
			ClientFirstByteNS: 1_050_000_000, ClientReadEndNS: 1_051_000_000, ExactBytes: true,
		},
		ClientReadStartedNS: 1_003_000_000, ClientReadOutstandingCheckNS: 1_010_000_000,
		RemovalStartNS: 1_020_000_000, RemovalEndNS: 1_060_000_000, ReaderReaped: true,
	}
	for _, tc := range []struct {
		name       string
		first, end int64
		want       string
	}{
		{"during removal", 1_050_000_000, 1_051_000_000, "first_byte_during_removal_before_20s_reference"},
		{"after removal", 2_000_000_000, 2_001_000_000, "first_byte_after_removal_before_20s_reference"},
		{"no early arrival observed", 21_006_000_000, 21_007_000_000, "first_byte_at_or_after_20s_reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := observed
			v.Exchange.ClientFirstByteNS, v.Exchange.ClientReadEndNS = tc.first, tc.end
			// When removal's effect is classified, Then the independent raw
			// intervals decide; lack of early arrival is not relabeled a flush.
			got, err := linkLatencyPendingEffect(v)
			if err != nil || got != tc.want {
				t.Fatalf("effect=%s error=%v", got, err)
			}
		})
	}
	for _, condition := range []string{"already read before removal", "stale server write", "missing write start", "unreaped reader", "changed bytes", "request budget exceeded"} {
		t.Run(condition, func(t *testing.T) {
			v := observed
			switch condition {
			case "already read before removal":
				v.Exchange.ClientFirstByteNS, v.Exchange.ClientReadEndNS = 1_015_000_000, 1_016_000_000
			case "stale server write":
				v.ClientReadOutstandingCheckNS, v.RemovalStartNS, v.RemovalEndNS = 2_100_000_000, 2_110_000_000, 2_120_000_000
				v.Exchange.ClientFirstByteNS, v.Exchange.ClientReadEndNS = 2_130_000_000, 2_140_000_000
			case "missing write start":
				v.Exchange.ServerWriteStartNS = 0
			case "unreaped reader":
				v.ReaderReaped = false
			case "changed bytes":
				v.Exchange.ExactBytes = false
			case "request budget exceeded":
				v.Exchange.ClientFirstByteNS, v.Exchange.ClientReadEndNS = 26_050_000_000, 26_051_000_000
			}
			if _, err := linkLatencyPendingEffect(v); err == nil {
				t.Fatal("unreached or incomplete pending-removal evidence accepted")
			}
		})
	}
}
