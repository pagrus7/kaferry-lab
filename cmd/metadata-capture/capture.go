package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"time"
)

const (
	metadataURL  = "https://api.github.com/repos/pagrus7/kaferry/git/ref/tags/v0.6.0"
	headerLimit  = 16 << 10
	bodyLimit    = 64 << 10
	errorLimit   = 32 << 10
	receiptLimit = 256 << 10
)

// Bytes is an observed prefix. ObservedBytes is exact only if Complete is true;
// otherwise it is a lower bound, including any overflow detection byte.
// encoding/json encodes Prefix as base64 without changing arbitrary bytes.
type Bytes struct {
	Prefix                []byte `json:"prefix_base64"`
	ObservedBytes         int64  `json:"observed_bytes_lower_bound"`
	Complete              bool   `json:"complete"`
	Overflow              bool   `json:"overflow"`
	TraversalGuardReached bool   `json:"traversal_guard_reached"`
}

type Identity struct {
	RunID       string
	SourceHead  string `json:"source_head"`
	GitHubRunID string `json:"github_run_id"`
	Job         string `json:"job"`
	Attempt     string `json:"attempt"`
}

var headPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var runPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var attemptPattern = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)

func validIdentity(id Identity) bool {
	return headPattern.MatchString(id.SourceHead) && runPattern.MatchString(id.GitHubRunID) && attemptPattern.MatchString(id.Attempt) && id.Job == "metadata" && id.RunID == "metadata-"+id.GitHubRunID+"-"+id.Attempt
}

type Receipt struct {
	Identity
	Namespace             string `json:"namespace"`
	ReleaseQualified      bool   `json:"release_qualified"`
	Platform              string `json:"platform"`
	Method                string `json:"method"`
	URL                   string `json:"url"`
	Accept                string `json:"accept"`
	UserAgent             string `json:"user_agent"`
	AttemptCount          int    `json:"attempt_count"`
	StartedUTC            string `json:"started_utc"`
	ElapsedNS             int64  `json:"elapsed_ns_monotonic"`
	ResponseAvailable     bool   `json:"response_available"`
	StatusCode            int    `json:"status_code"`
	HeadersRepresentation string `json:"headers_representation"`
	Headers               Bytes  `json:"headers"`
	BodyRepresentation    string `json:"body_representation"`
	Body                  Bytes  `json:"body"`
	BodyCloseAttempted    bool   `json:"body_close_attempted"`
	BodyCloseSucceeded    bool   `json:"body_close_succeeded"`
	Uncompressed          bool   `json:"net_http_uncompressed"`
	ErrorsRepresentation  string `json:"errors_representation"`
	Errors                Bytes  `json:"errors"`
	CaptureComplete       bool   `json:"capture_complete"`
}

// Each frame is uint64 big-endian byte length followed by those exact bytes.
// A capped frame stream can end inside a length or payload. No wire precision
// is claimed: these are net/http's decoded fields, including exposed trailers.
type frames struct {
	bytes Bytes
	limit int
}

func (f *frames) append(raw []byte) {
	f.bytes.ObservedBytes += int64(len(raw))
	remaining := f.limit - len(f.bytes.Prefix)
	if len(raw) > remaining {
		f.bytes.Overflow = true
		raw = raw[:remaining]
	}
	f.bytes.Prefix = append(f.bytes.Prefix, raw...)
}

func (f *frames) field(raw []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(raw)))
	f.append(n[:])
	f.append(raw)
}

func headerFields(f *frames, label string, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// Count preserves empty value slices as well as repeated values.
		f.field([]byte(label))
		f.field([]byte(k))
		f.field([]byte(strconv.Itoa(len(h[k]))))
		for _, v := range h[k] {
			f.field([]byte(v))
		}
	}
}

func readBounded(r io.Reader, limit int) (Bytes, error) {
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	b := Bytes{Prefix: raw, ObservedBytes: int64(len(raw)), Complete: err == nil}
	if len(raw) > limit {
		b.Prefix = raw[:limit]
		b.Overflow = true
		b.Complete = false
	}
	return b, err
}

// Error nodes contain path/type/Error() byte frames. Graph traversal is capped
// to avoid cycles. Exhausting byte/node/depth bounds makes this stream incomplete.
func errorFrames(causes []error) Bytes {
	f := frames{limit: errorLimit, bytes: Bytes{Prefix: []byte{}}}
	nodes := 0
	guard := false
	var visit func(error, string, int)
	visit = func(err error, path string, depth int) {
		if err == nil {
			return
		}
		if f.bytes.Overflow || nodes >= 256 || depth >= 64 {
			guard = true
			return
		}
		nodes++
		f.field([]byte(path))
		f.field([]byte(reflect.TypeOf(err).String()))
		f.field([]byte(err.Error()))
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			for n, child := range e.Unwrap() {
				visit(child, path+"/"+strconv.Itoa(n), depth+1)
				if guard {
					break
				}
			}
		case interface{ Unwrap() error }:
			visit(e.Unwrap(), path+"/0", depth+1)
		}
	}
	for n, err := range causes {
		visit(err, strconv.Itoa(n), 0)
	}
	f.bytes.Complete = !f.bytes.Overflow && !guard
	f.bytes.TraversalGuardReached = guard
	return f.bytes
}

func newReceipt(id Identity) Receipt {
	return Receipt{Identity: id, Namespace: "calibration/metadata-diagnostic", Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Headers: Bytes{Prefix: []byte{}}, Body: Bytes{Prefix: []byte{}}, Errors: Bytes{Prefix: []byte{}},
		Method: "GET", URL: metadataURL, Accept: "application/vnd.github+json", UserAgent: "kaferry-lab-artifact",
		HeadersRepresentation: "CLIENT-DECODED net/http fields; uint64be-length frames: status,protocol, then section,name,value-count,values; sections=headers,trailers; sorted names; not wire octets",
		BodyRepresentation:    "net/http exposed response-body bytes; may be transparently decompressed; not wire octets",
		ErrorsRepresentation:  "uint64be-length frames: node-path,Go-type,Error()-bytes; root 0=setup/transport,1=body-read,2=body-close,3=context; bounded unwrap graph"}
}

func observe(ctx context.Context, id Identity, client *http.Client, setupErr error) Receipt {
	r := newReceipt(id)
	start := time.Now()
	r.StartedUTC = start.UTC().Format(time.RFC3339Nano)
	var transportErr, readErr, closeErr error
	if setupErr == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
		if err != nil {
			transportErr = err
		} else {
			req.Header.Set("Accept", r.Accept)
			req.Header.Set("User-Agent", r.UserAgent)
			r.AttemptCount = 1
			resp, err := client.Do(req)
			transportErr = err
			if resp != nil {
				r.ResponseAvailable = true
				r.StatusCode = resp.StatusCode
				r.Uncompressed = resp.Uncompressed
				f := frames{limit: headerLimit}
				f.field([]byte(resp.Status))
				f.field([]byte(resp.Proto))
				headerFields(&f, "headers", resp.Header)
				if resp.Body != nil {
					r.Body, readErr = readBounded(resp.Body, bodyLimit)
					r.BodyCloseAttempted = true
					closeErr = resp.Body.Close()
					r.BodyCloseSucceeded = closeErr == nil
				} else {
					readErr = errors.New("response body unavailable")
				}
				headerFields(&f, "trailers", resp.Trailer)
				f.bytes.Complete = !f.bytes.Overflow && r.Body.Complete
				r.Headers = f.bytes
			}
		}
	} else {
		transportErr = setupErr
	}
	r.ElapsedNS = time.Since(start).Nanoseconds()
	r.Errors = errorFrames([]error{transportErr, readErr, closeErr, ctx.Err()})
	r.CaptureComplete = r.ResponseAvailable && transportErr == nil && readErr == nil && closeErr == nil && ctx.Err() == nil && r.Headers.Complete && r.Body.Complete && r.BodyCloseSucceeded && r.Errors.Complete
	return r
}

func productionClient() (*http.Client, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	// Matches the existing verifier's SSL_CERT_FILE behavior. No trust bypass,
	// proxy replacement, credentials, cookies, cache, or retry wrapper.
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("SSL_CERT_FILE has no trusted certificates")
		}
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	t.MaxResponseHeaderBytes = headerLimit
	return captureClient(t), nil
}

func captureClient(t http.RoundTripper) *http.Client {
	return &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type privateSink interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// A receipt describes HTTP observation, never its own successful persistence.
// Only the outer caller can witness return after this write/sync/close sequence.
func persist(s privateSink, r Receipt) error {
	raw, err := json.Marshal(r)
	if err != nil || len(raw)+1 > receiptLimit {
		if err == nil {
			err = errors.New("metadata receipt exceeds serialized byte limit")
		}
		return errors.Join(err, s.Close())
	}
	raw = append(raw, '\n')
	n, writeErr := s.Write(raw)
	var syncErr error
	if writeErr == nil && n == len(raw) {
		syncErr = s.Sync()
	}
	closeErr := s.Close()
	var shortErr error
	if n != len(raw) {
		shortErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, shortErr, syncErr, closeErr)
}

// This channel is PRIVATE RAW EVIDENCE, never a public log. The sole reviewed
// caller must pre-reserve/bound stderr before launch and never tee it. Base64
// preserves bytes; it does not redact or encrypt them. One write, no retry or
// alternate destination if it fails. The whole encoded record stays <48KiB.
func privateFailure(w io.Writer, id Identity, phase string, cause error) {
	envelope := struct {
		RunID          string
		Namespace      string `json:"namespace"`
		Phase          string `json:"phase"`
		Representation string `json:"representation"`
		Errors         Bytes  `json:"errors"`
	}{id.RunID, "calibration/metadata-diagnostic-private-error", phase,
		"PRIVATE RAW EVIDENCE; base64 is not redaction/encryption; uint64be-length frames node-path,Go-type,Error()-bytes; root0=operation error", errorFrames([]error{cause})}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw)+1 > 48<<10 {
		return
	}
	raw = append(raw, '\n')
	_, _ = w.Write(raw)
}
