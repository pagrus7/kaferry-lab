package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func specimenID() Identity {
	return Identity{RunID: "metadata-1234-1", SourceHead: strings.Repeat("a", 40), GitHubRunID: "1234", Job: "metadata", Attempt: "1"}
}

type closeBody struct {
	io.Reader
	closeErr error
	closes   int
}

func (b *closeBody) Close() error { b.closes++; return b.closeErr }

func response(code int, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: code, Status: "403 Forbidden", Proto: "HTTP/2.0", Header: http.Header{}, Body: body}
}

func decodeFrames(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var fields [][]byte
	for len(raw) > 0 {
		if len(raw) < 8 {
			t.Fatal("incomplete frame length")
		}
		n := binary.BigEndian.Uint64(raw[:8])
		raw = raw[8:]
		if n > uint64(len(raw)) {
			t.Fatal("incomplete frame payload")
		}
		fields = append(fields, append([]byte{}, raw[:int(n)]...))
		raw = raw[int(n):]
	}
	return fields
}

func TestComplete403RetainsExactBytesWithoutQualification(t *testing.T) {
	// Given arbitrary client-visible bytes, when the fixed request returns403,
	// then one complete observation preserves every byte without qualification.
	raw := []byte{0, 255, 128, '\n', '"', '\\'}
	body := &closeBody{Reader: bytes.NewReader(raw)}
	calls := 0
	client := captureClient(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != "GET" || req.URL.String() != metadataURL || req.Header.Get("Accept") != "application/vnd.github+json" || req.Header.Get("User-Agent") != "kaferry-lab-artifact" {
			t.Fatal("request drift")
		}
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.URL.User != nil {
			t.Fatal("credential attached")
		}
		r := response(403, body)
		r.Header["X-Bytes"] = []string{string([]byte{255, 0, 128}), "second", ""}
		r.Trailer = http.Header{"X-End": []string{"done"}}
		return r, nil
	}))
	r := observe(context.Background(), specimenID(), client, nil)
	if calls != 1 || body.closes != 1 || !r.CaptureComplete || r.StatusCode != 403 || r.ReleaseQualified || r.Namespace != "calibration/metadata-diagnostic" {
		t.Fatalf("bad observation: calls=%d close=%d complete=%v", calls, body.closes, r.CaptureComplete)
	}
	if !bytes.Equal(r.Body.Prefix, raw) {
		t.Fatal("body changed")
	}
	fields := decodeFrames(t, r.Headers.Prefix)
	want := [][]byte{[]byte("403 Forbidden"), []byte("HTTP/2.0"), []byte("headers"), []byte("X-Bytes"), []byte("3"), {255, 0, 128}, []byte("second"), {}, []byte("trailers"), []byte("X-End"), []byte("1"), []byte("done")}
	if len(fields) != len(want) {
		t.Fatalf("field count %d", len(fields))
	}
	for n := range want {
		if !bytes.Equal(fields[n], want[n]) {
			t.Fatalf("field %d changed", n)
		}
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var recovered Receipt
	if err := json.Unmarshal(encoded, &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Body.Prefix, raw) || !bytes.Equal(recovered.Headers.Prefix, r.Headers.Prefix) {
		t.Fatal("JSON changed binary bytes")
	}
}

func Test200AlsoOnlyObservation(t *testing.T) {
	r := observe(context.Background(), specimenID(), captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := response(200, io.NopCloser(strings.NewReader("{}")))
		r.Status = "200 OK"
		return r, nil
	})), nil)
	if !r.CaptureComplete || r.ReleaseQualified || r.AttemptCount != 1 {
		t.Fatal("200 converted into qualification or incomplete")
	}
}

func TestClientVisibleStatusAndProtocolBytesAreLossless(t *testing.T) {
	status := string([]byte{'4', '0', '3', ' ', 255, 0})
	proto := string([]byte{'H', 'T', 'T', 'P', '/', 128})
	r := observe(context.Background(), specimenID(), captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := response(403, io.NopCloser(strings.NewReader("")))
		r.Status = status
		r.Proto = proto
		return r, nil
	})), nil)
	fields := decodeFrames(t, r.Headers.Prefix)
	if !r.CaptureComplete || len(fields) != 2 || string(fields[0]) != status || string(fields[1]) != proto {
		t.Fatal("client-visible status/protocol bytes normalized")
	}
}

func TestRedirectNeverMakesSecondRequest(t *testing.T) {
	calls := 0
	c := captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		r := response(302, io.NopCloser(strings.NewReader("redirect body")))
		r.Status = "302 Found"
		r.Header.Set("Location", "https://example.invalid/alternative")
		return r, nil
	}))
	r := observe(context.Background(), specimenID(), c, nil)
	if calls != 1 || r.StatusCode != 302 || !r.CaptureComplete || c.Jar != nil || c.Timeout != 30*time.Second {
		t.Fatal("redirect/client policy drift")
	}
}

func TestReadBoundsDetectOverflowAndShortReadFailure(t *testing.T) {
	for _, n := range []int{0, bodyLimit - 1, bodyLimit, bodyLimit + 1, bodyLimit + 100} {
		b, err := readBounded(bytes.NewReader(bytes.Repeat([]byte{255}, n)), bodyLimit)
		if err != nil || b.Complete != (n <= bodyLimit) || b.Overflow != (n > bodyLimit) || len(b.Prefix) > bodyLimit || b.ObservedBytes != int64(min(n, bodyLimit+1)) {
			t.Fatalf("bound %d", n)
		}
	}
	prefix := []byte{255, 128, 0}
	b, err := readBounded(&partialReader{raw: prefix, err: errors.New("read failure")}, bodyLimit)
	if err == nil || b.Complete || b.Overflow || !bytes.Equal(b.Prefix, prefix) {
		t.Fatal("partial read lost")
	}
}

type partialReader struct {
	raw  []byte
	err  error
	sent bool
}

func (r *partialReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, r.raw), r.err
}

func TestReadAndCloseFailuresRetainBothExactCauses(t *testing.T) {
	readCause := string([]byte{'r', 255, 0})
	closeCause := string([]byte{'c', 128, 0})
	b := &closeBody{Reader: &partialReader{raw: []byte{1, 2, 3}, err: errors.New(readCause)}, closeErr: errors.New(closeCause)}
	r := observe(context.Background(), specimenID(), captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) { return response(403, b), nil })), nil)
	if r.CaptureComplete || b.closes != 1 || r.Body.Complete || r.BodyCloseSucceeded || !r.Errors.Complete {
		t.Fatal("failure admitted or close omitted")
	}
	fields := decodeFrames(t, r.Errors.Prefix)
	if len(fields) != 6 || string(fields[0]) != "1" || string(fields[2]) != readCause || string(fields[3]) != "2" || string(fields[5]) != closeCause {
		t.Fatal("exact private causes lost")
	}
}

func TestTransportAbsenceAndSetupFailuresNeverClaimResponse(t *testing.T) {
	for _, setup := range []bool{false, true} {
		calls := 0
		cause := errors.New(string([]byte{'x', 255, 0}))
		c := captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, cause }))
		var setupErr error
		if setup {
			setupErr = cause
		}
		r := observe(context.Background(), specimenID(), c, setupErr)
		if r.ResponseAvailable || r.CaptureComplete || !r.Errors.Complete || (setup && calls != 0) || (!setup && calls != 1) {
			t.Fatal("missing response admitted")
		}
		if !bytes.Contains(r.Errors.Prefix, []byte(cause.Error())) {
			t.Fatal("transport/setup bytes lost")
		}
	}
}

func TestCancellationIsIncompleteAndClosesBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	body := &closeBody{Reader: strings.NewReader("prefix")}
	r := observe(ctx, specimenID(), captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) { cancel(); return response(403, body), nil })), nil)
	if r.CaptureComplete || body.closes != 1 || !bytes.Contains(r.Errors.Prefix, []byte(context.Canceled.Error())) {
		t.Fatal("cancellation lost")
	}
}

type cycleError struct{}

func (*cycleError) Error() string   { return "cycle" }
func (e *cycleError) Unwrap() error { return e }

func TestHeaderBodyErrorOverflowAndErrorGraphGuard(t *testing.T) {
	r := observe(context.Background(), specimenID(), captureClient(roundTripFunc(func(*http.Request) (*http.Response, error) {
		r := response(403, io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'b'}, bodyLimit+1))))
		r.Header["X-Big"] = []string{strings.Repeat("h", headerLimit+1)}
		return r, nil
	})), nil)
	if r.CaptureComplete || !r.Headers.Overflow || !r.Body.Overflow || len(r.Headers.Prefix) != headerLimit || len(r.Body.Prefix) != bodyLimit {
		t.Fatal("overflow admitted")
	}
	for _, cause := range []error{errors.New(strings.Repeat("e", errorLimit+1)), &cycleError{}} {
		e := errorFrames([]error{cause})
		if e.Complete || len(e.Prefix) > errorLimit {
			t.Fatal("error bound/cycle admitted")
		}
	}
}

type fakeSink struct {
	raw                         []byte
	short                       bool
	writeErr, syncErr, closeErr error
	writes, syncs, closes       int
}

func (s *fakeSink) Write(p []byte) (int, error) {
	s.writes++
	n := len(p)
	if s.short {
		n--
	}
	s.raw = append(s.raw, p[:n]...)
	return n, s.writeErr
}
func (s *fakeSink) Sync() error  { s.syncs++; return s.syncErr }
func (s *fakeSink) Close() error { s.closes++; return s.closeErr }

func TestPersistFailureControlsAlwaysCloseAndNeverReportSuccess(t *testing.T) {
	for _, name := range []string{"write", "short", "sync", "close"} {
		t.Run(name, func(t *testing.T) {
			s := &fakeSink{}
			cause := errors.New("synthetic sink failure")
			switch name {
			case "write":
				s.writeErr = cause
			case "short":
				s.short = true
			case "sync":
				s.syncErr = cause
			case "close":
				s.closeErr = cause
			}
			if persist(s, newReceipt(specimenID())) == nil || s.writes != 1 || s.closes != 1 {
				t.Fatal("sink failure admitted")
			}
			if (name == "short" || name == "write") && s.syncs != 0 {
				t.Fatal("sync after failed write")
			}
		})
	}
}

func TestSerializedBudgetAndOversizeFailureClose(t *testing.T) {
	r := newReceipt(specimenID())
	r.Headers = Bytes{Prefix: bytes.Repeat([]byte{255}, headerLimit)}
	r.Body = Bytes{Prefix: bytes.Repeat([]byte{255}, bodyLimit)}
	r.Errors = Bytes{Prefix: bytes.Repeat([]byte{255}, errorLimit)}
	s := &fakeSink{}
	if persist(s, r) != nil || len(s.raw) > receiptLimit || s.syncs != 1 || s.closes != 1 {
		t.Fatal("actual bounded serialization failed")
	}
	r.Body.Prefix = bytes.Repeat([]byte{255}, receiptLimit)
	s = &fakeSink{}
	if persist(s, r) == nil || s.writes != 0 || s.syncs != 0 || s.closes != 1 {
		t.Fatal("oversized serialization written")
	}
}

func TestPrivateFailurePreservesBinaryCauseAndWritesOnlyOnce(t *testing.T) {
	cause := errors.New(string([]byte{'x', 255, 0, '\n'}))
	s := &fakeSink{}
	privateFailure(s, specimenID(), "output-reservation", cause)
	var envelope struct {
		RunID  string
		Errors Bytes `json:"errors"`
	}
	if err := json.Unmarshal(s.raw, &envelope); err != nil {
		t.Fatal(err)
	}
	fields := decodeFrames(t, envelope.Errors.Prefix)
	if envelope.RunID != specimenID().RunID || len(fields) != 3 || string(fields[2]) != cause.Error() || !envelope.Errors.Complete || s.writes != 1 || s.syncs != 0 || s.closes != 0 {
		t.Fatal("private cause changed or borrowed channel closed")
	}
	for _, sink := range []*fakeSink{{short: true}, {writeErr: errors.New("private channel failed")}} {
		privateFailure(sink, specimenID(), "receipt-write-sync-close", cause)
		if sink.writes != 1 || sink.syncs != 0 || sink.closes != 0 {
			t.Fatal("private failure retried or took caller sink ownership")
		}
	}
	s = &fakeSink{}
	privateFailure(s, specimenID(), "receipt-write-sync-close", errors.New(strings.Repeat("x", errorLimit+100)))
	if len(s.raw) > 48<<10 || s.writes != 1 {
		t.Fatal("private error serialization overflow")
	}
	if err := json.Unmarshal(s.raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Errors.Complete || !envelope.Errors.Overflow || len(envelope.Errors.Prefix) != errorLimit {
		t.Fatal("private error truncation concealed")
	}
}

func TestPersistRetainsWriteAndFinalCloseCauses(t *testing.T) {
	writeCause := errors.New("synthetic write cause")
	closeCause := errors.New("synthetic final close cause")
	s := &fakeSink{writeErr: writeCause, closeErr: closeCause}
	err := persist(s, newReceipt(specimenID()))
	if !errors.Is(err, writeCause) || !errors.Is(err, closeCause) || s.closes != 1 || s.syncs != 0 {
		t.Fatal("secondary/final cause discarded")
	}
}

func TestWrongIdentityRejected(t *testing.T) {
	if !validIdentity(specimenID()) {
		t.Fatal("fixture identity invalid")
	}
	for _, change := range []func(*Identity){
		func(i *Identity) { i.RunID = "../metadata-1234-1" }, func(i *Identity) { i.RunID = "metadata-999-1" }, func(i *Identity) { i.SourceHead = strings.Repeat("A", 40) },
		func(i *Identity) { i.Job = "links" }, func(i *Identity) { i.Attempt = "01" }, func(i *Identity) { i.GitHubRunID = "0" },
	} {
		id := specimenID()
		change(&id)
		if validIdentity(id) {
			t.Fatal("identity mismatch admitted")
		}
	}
}

func TestCanonicalContextMismatchRejectedWithoutRequest(t *testing.T) {
	id := specimenID()
	canonical := map[string]string{"GITHUB_REPOSITORY": "pagrus7/kaferry-lab", "GITHUB_REPOSITORY_ID": "1432555755", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/codex/resilience-release-lab", "GITHUB_SHA": id.SourceHead, "GITHUB_RUN_ID": id.GitHubRunID, "GITHUB_RUN_ATTEMPT": id.Attempt, "GITHUB_JOB": id.Job}
	get := func(k string) string { return canonical[k] }
	if !validContext(id, get) {
		t.Fatal("canonical context rejected")
	}
	for key, original := range canonical {
		canonical[key] = "untrusted"
		if validContext(id, get) {
			t.Fatalf("context mismatch admitted: %s", key)
		}
		canonical[key] = original
	}
}

func TestReservationExclusiveOwnerOnlyAndNoSymlinkAdoption(t *testing.T) {
	t.Chdir(t.TempDir())
	id := specimenID()
	root := filepath.Join(".cache", "fixtures-private", id.RunID+"-links")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := reserve(id)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private file mode")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if f, err := reserve(id); err == nil {
		f.Close()
		t.Fatal("existing output adopted")
	}
	if err := os.Remove(filepath.Join(root, "metadata.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../unrelated", filepath.Join(root, "metadata.json")); err != nil {
		t.Fatal(err)
	}
	if f, err := reserve(id); err == nil {
		f.Close()
		t.Fatal("symlink adopted")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if f, err := reserve(id); err == nil {
		f.Close()
		t.Fatal("nonprivate root admitted")
	}
}

func TestExecuteRelativeOutputRetainsUnreachedTrustFailure(t *testing.T) {
	// Given the real CLI contract and an unavailable synthetic trust file,
	// When execute reserves its output, Then it retains the setup failure and
	// returns a closed incomplete observation without invoking HTTP.
	t.Chdir(t.TempDir())
	id := specimenID()
	for key, value := range map[string]string{
		"GITHUB_REPOSITORY": "pagrus7/kaferry-lab", "GITHUB_REPOSITORY_ID": "1432555755",
		"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/codex/resilience-release-lab",
		"GITHUB_SHA": id.SourceHead, "GITHUB_RUN_ID": id.GitHubRunID,
		"GITHUB_RUN_ATTEMPT": id.Attempt, "GITHUB_JOB": id.Job,
		"SSL_CERT_FILE": "synthetic-trust-file-does-not-exist",
	} {
		t.Setenv(key, value)
	}
	root := filepath.Join(".cache", "fixtures-private", id.RunID+"-links")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "metadata.json")
	args := []string{"--run-id", id.RunID, "--source-head", id.SourceHead, "--job", id.Job,
		"--attempt", id.Attempt, "--output", output}
	if code := execute(args); code != 2 {
		t.Fatalf("closed unreached observation returned %d", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.AttemptCount != 0 || r.CaptureComplete || r.ResponseAvailable || r.ReleaseQualified || len(r.Errors.Prefix) == 0 || !r.Errors.Complete {
		t.Fatal("unreached setup failure misclassified or lost")
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = absolute
	if code := execute(args); code != 1 {
		t.Fatal("noncanonical absolute output admitted")
	}
}
