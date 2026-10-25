package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestLinkNetworkNoticeRetainsLiteralActionsAndNeverPublishesRaw(t *testing.T) {
	// Given exact in-process listen/dial/read/write/deadline/close failure facts,
	// when the shared production sink retains them, then only the private receipt
	// contains their exact action/notice/cause. Timing is never invented.
	for _, operation := range []string{"listen", "dial", "HTTP read", "TCP read", "TCP write", "set-deadline", "close"} {
		t.Run(operation, func(t *testing.T) {
			s := linkRetentionState(t)
			action := []string{operation, "tcp4", "127.0.0.1:20300", "PRIVATE_ACTION=unreviewed"}
			notice := []byte("PRIVATE_NOTICE=exact bounded reported bytes\n")
			cause := &net.OpError{Op: operation, Net: "tcp", Err: errors.Join(syscall.EACCES, errors.New("PRIVATE_CAUSE=literal unknown detail"))}
			ref, err := RetainLinkNetworkFailure(s, action, notice, cause)
			if err != nil || ref == "" {
				t.Fatal("private retention failed", err)
			}
			body, err := os.ReadFile(ref)
			var receipt struct {
				RunID                         string
				Action                        []string
				Notice, CauseText             []byte
				NoticeComplete, CauseComplete bool
				StartedAt, EndedAt            any
			}
			if err != nil || json.Unmarshal(body, &receipt) != nil || receipt.RunID != s.RunID || !reflect.DeepEqual(receipt.Action, action) || !bytes.Equal(receipt.Notice, notice) || string(receipt.CauseText) != cause.Error() || !receipt.NoticeComplete || !receipt.CauseComplete || receipt.StartedAt != nil || receipt.EndedAt != nil {
				t.Fatal("exact action/notice/cause or timing contract lost")
			}
			assertLinkPublicWithholds(t, s, notice, []byte(cause.Error()), []byte("PRIVATE_ACTION"), []byte("PRIVATE_CAUSE"))
		})
	}
}

func TestLinkNetworkNoticeOverflowAndPersistenceAreFatal(t *testing.T) {
	// Given an over-bound notice/cause or unavailable private/public sink, when
	// retention is attempted, then it cannot report complete evidence or permit
	// another linked facility operation via a new wrapper.
	for _, kind := range []string{"notice overflow", "cause overflow", "private failure", "public failure"} {
		t.Run(kind, func(t *testing.T) {
			s := linkRetentionState(t)
			notice := []byte("exact notice")
			cause := error(syscall.EPERM)
			if kind == "notice overflow" {
				notice = bytes.Repeat([]byte{'x'}, linkOutputLimit+1)
			}
			if kind == "cause overflow" {
				cause = errors.New(strings.Repeat("x", linkOutputLimit+1))
			}
			if kind == "private failure" || kind == "public failure" {
				path := linkDirectory(s.RunID)
				if kind == "private failure" {
					path = linkPrivateDirectory(s.RunID)
				}
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("path occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ref, err := RetainLinkNetworkFailure(s, []string{"HTTP", "GET", "http://127.0.0.1:20300/version"}, notice, cause)
			if err == nil {
				t.Fatal("incomplete/private evidence accepted")
			}
			if ref != "" {
				body, e := os.ReadFile(ref)
				if e != nil {
					t.Fatal(e)
				}
				var receipt struct{ NoticeComplete, CauseComplete bool }
				if json.Unmarshal(body, &receipt) != nil {
					t.Fatal("invalid private receipt")
				}
				if kind == "notice overflow" && receipt.NoticeComplete || kind == "cause overflow" && receipt.CauseComplete {
					t.Fatal("truncated notice claimed complete")
				}
			}
			if _, e := LinkExecutor(s, func(context.Context, ...string) ([]byte, error) {
				t.Fatal("new facility action after fatal evidence failure")
				return nil, nil
			}); e == nil {
				t.Fatal("fatal network evidence failure did not stop facility")
			}
		})
	}
}

// This is a literal response body, not a network mock: the real exchange owns
// and checks its Read/Close results on the same code path used by client.Do.
type linkLiteralHTTPBody struct {
	data              []byte
	readErr, closeErr error
	read, closed      bool
}

func (b *linkLiteralHTTPBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(p, b.data), b.readErr
}
func (b *linkLiteralHTTPBody) Close() error { b.closed = true; return b.closeErr }

func TestLinkedHTTPProductionExchangeRetainsMarkedAndBodyFailuresPrivately(t *testing.T) {
	// Given literal client.Do/read/close/status outcomes, when the production API
	// boundary handles the real exchange helper, then every original failure is
	// private and only clean request-origin availability can remain retryable.
	for _, kind := range []string{"refused", "marked PRIVATE", "joined fatal", "read", "close", "status", "status text"} {
		t.Run(kind, func(t *testing.T) {
			s := linkRetentionState(t)
			raw := error(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
			body := &linkLiteralHTTPBody{data: []byte("PRIVATE_BODY=reported response prefix")}
			status := 500
			switch kind {
			case "marked PRIVATE":
				raw = &net.OpError{Op: "read", Net: "tcp", Err: errors.New("PRIVATE_CAUSE=marked unknown")}
			case "joined fatal":
				raw = &net.OpError{Op: "dial", Net: "tcp", Err: errors.Join(syscall.ECONNREFUSED, errors.New("PRIVATE_CAUSE=joined fatal"))}
			case "read":
				raw = errors.New("PRIVATE_CAUSE=read failure")
				body.readErr = raw
			case "close":
				raw = errors.New("PRIVATE_CAUSE=close failure")
				body.closeErr = raw
				status = 200
			case "status":
				raw = nil
			case "status text":
				raw = errors.New("proxy HTTP reported status 500 PRIVATE_STATUS=reported reason")
			}
			calls := 0
			request := func(ctx context.Context, endpoint, method, path string, _ []byte) (int, []byte, error) {
				req, e := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, nil)
				if e != nil {
					t.Fatal(e)
				}
				return linkHTTPExchange(req, func(*http.Request) (*http.Response, error) {
					calls++
					if kind == "refused" || kind == "marked PRIVATE" || kind == "joined fatal" {
						return nil, raw
					}
					response := &http.Response{StatusCode: status, Body: body}
					if kind == "status text" {
						response.Status = "500 PRIVATE_STATUS=reported reason"
					}
					return response, nil
				})
			}
			err := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "GET", "/version", nil, 0)
			if err == nil || calls != 1 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("failure omitted/leaked or request repeated")
			}
			if got := linkStartupRetryable(err); got != (kind == "refused") {
				t.Fatal("origin/fatal classification changed", got, kind)
			}
			assertLinkPublicWithholds(t, s, []byte("PRIVATE_CAUSE"), []byte("PRIVATE_BODY"), []byte("PRIVATE_STATUS"))
			files, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
			if e != nil || len(files) != 1 {
				t.Fatal("missing exact private outcome", e)
			}
			bytes, e := os.ReadFile(files[0])
			var receipt struct {
				Action                        []string
				Notice, CauseText             []byte
				NoticeComplete, CauseComplete bool
			}
			if e != nil || json.Unmarshal(bytes, &receipt) != nil || !receipt.NoticeComplete || !receipt.CauseComplete || !reflect.DeepEqual(receipt.Action, []string{"HTTP", "GET", "http://" + s.Proxy.API + "/version"}) {
				t.Fatal("private action/notice completeness lost")
			}
			if raw != nil && string(receipt.CauseText) != raw.Error() {
				t.Fatal("original raw cause changed before private retention")
			}
			if kind == "read" || kind == "close" || kind == "status" || kind == "status text" {
				if !body.closed || string(receipt.Notice) != string(body.data) {
					t.Fatal("read prefix or close result discarded")
				}
			}
		})
	}
}

func TestLinkedHTTPProductionExchangePrivateReceiptFailureSuppressesRetry(t *testing.T) {
	// Given genuine request-origin refusal, when its mandatory private or public
	// retention path fails after Do, then no second API request is authorized.
	for _, target := range []string{"private", "public"} {
		t.Run(target, func(t *testing.T) {
			s := linkRetentionState(t)
			calls := 0
			request := func(ctx context.Context, endpoint, method, path string, _ []byte) (int, []byte, error) {
				req, e := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, nil)
				if e != nil {
					t.Fatal(e)
				}
				return linkHTTPExchange(req, func(*http.Request) (*http.Response, error) {
					calls++
					dir := linkDirectory(s.RunID)
					if target == "private" {
						dir = linkPrivateDirectory(s.RunID)
					}
					if e := os.Rename(dir, dir+".retained"); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(dir, []byte("path occupied"), 0600); e != nil {
						t.Fatal(e)
					}
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
				})
			}
			err := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "GET", "/version", nil, 0)
			if err == nil || calls != 1 || linkStartupRetryable(err) {
				t.Fatal("receipt failure authorized next request", calls, err)
			}
		})
	}
}

func TestLinkedHTTPProductionResponseOverflowRetainsPrefixAndStops(t *testing.T) {
	// Given a response just beyond the actual64KiB HTTP capture bound, when the
	// production exchange reads it, then the private prefix is explicitly
	// incomplete and no transient-looking error can authorize a next request.
	s := linkRetentionState(t)
	calls := 0
	request := func(ctx context.Context, endpoint, method, path string, _ []byte) (int, []byte, error) {
		req, e := http.NewRequestWithContext(ctx, method, "http://"+endpoint+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		return linkHTTPExchange(req, func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, 65537)))}, nil
		})
	}
	err := linkAPICall(context.Background(), s, linkTestDocker(t, s, nil), request, "GET", "/version", nil, 0)
	if err == nil || calls != 1 || linkStartupRetryable(err) {
		t.Fatal("oversized response accepted/retried", calls, err)
	}
	files, e := filepath.Glob(filepath.Join(linkPrivateDirectory(s.RunID), "docker-*.json"))
	if e != nil || len(files) != 1 {
		t.Fatal("missing incomplete private response", e)
	}
	body, e := os.ReadFile(files[0])
	var receipt struct {
		Notice              []byte
		NoticeComplete      bool
		ReportedNoticeBytes int
	}
	if e != nil || json.Unmarshal(body, &receipt) != nil || receipt.NoticeComplete || len(receipt.Notice) != 65536 || receipt.ReportedNoticeBytes != 65537 {
		t.Fatal("response-prefix completeness lost")
	}
}
