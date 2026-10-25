package fixture

import (
	"context"
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
