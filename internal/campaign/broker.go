package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/fixture"
)

const brokerOwnerLabel = "io.kaferry-lab.run"

type brokerInterval struct {
	StartedAt, EndedAt                             time.Time
	StartElapsedNanoseconds, EndElapsedNanoseconds int64
}

type brokerFacts struct {
	SelectedManifest                                                  *fixture.ImageManifestIdentity `json:",omitempty"`
	RunningPresent, PausedPresent                                     bool
	ConfiguredExternalBindings, PublishedExternalBindings             []brokerPortBinding
	RunID, Role, ContainerID, Name, ImageID, ImageReference, Endpoint string
	Running, Paused                                                   bool
	StartedAt                                                         time.Time
}

type brokerSnapshot struct {
	Interval brokerInterval
	Facts    *brokerFacts
	Error    string `json:",omitempty"`
}

type brokerRequest struct {
	Operation, ContainerID string
	Interval               brokerInterval
	Output, Error          string
}

type brokerProbeResult struct {
	TransportError         string
	Available, Unavailable bool
	APIKeys                int
	ErrorCode              int16
	Failure                string
}

type brokerProbeObservation struct {
	Interval brokerInterval
	Endpoint string
	Result   brokerProbeResult
	Error    string `json:",omitempty"`
}

type brokerCheck struct {
	Snapshot brokerSnapshot
	Probe    *brokerProbeObservation
}

type brokerObservation struct {
	RunID, Role, ContainerID, Operation string
	Calibration                         bool
	Interval                            brokerInterval
	Before                              brokerSnapshot
	Request                             *brokerRequest
	Checks                              []brokerCheck
	Reached, RecoveryNeeded             bool
	Error                               string `json:",omitempty"`
}

type brokerProbe func(context.Context, string) (brokerProbeResult, error)

type ownedBroker struct {
	runID, role, name, id, endpoint string
	origin                          time.Time // retains the monotonic reading for all returned intervals
	run                             fixture.Executor
	probe                           brokerProbe
	calibration                     bool
	linkedImage                     *fixture.State
}

// openOwnedBroker accepts only source/destination resources described by a valid
// fixture manifest. Initial discovery is read-only by the exact derived name;
// every subsequent inspect and mutation targets the retained immutable ID.
// Returned observations contain selected Docker facts, never Config.Env.
func openOwnedBroker(ctx context.Context, state fixture.State, role string, run fixture.Executor) (*ownedBroker, brokerSnapshot, error) {
	return openBrokerWithProbe(ctx, state, role, run, kafkaBrokerProbe, false)
}

// Only synthetic controller calibration supplies a probe implementation. Actual
// campaign entry always uses the independent Sarama Kafka API probe above.
func openBrokerWithProbe(ctx context.Context, state fixture.State, role string, run fixture.Executor, probe brokerProbe, calibration bool) (*ownedBroker, brokerSnapshot, error) {
	var empty brokerSnapshot
	if _, err := fixture.StatePath(state.RunID); err != nil {
		return nil, empty, err
	}
	prefix := "kaferry-lab-" + state.RunID
	if state.Image != fixture.Image || state.Network != prefix || len(state.Containers) != 2 || state.Containers[0] != prefix+"-source" || state.Containers[1] != prefix+"-dest" {
		return nil, empty, errors.New("broker requires exact owned fixture identity")
	}
	if run == nil || probe == nil {
		return nil, empty, errors.New("missing broker executor/probe")
	}
	if _, err := ownedBrokerPort(state.Source); err != nil {
		return nil, empty, err
	}
	if _, err := ownedBrokerPort(state.Destination); err != nil {
		return nil, empty, err
	}
	if state.Source == state.Destination {
		return nil, empty, errors.New("fixture broker endpoints overlap")
	}
	name, endpoint := prefix+"-source", state.Source
	switch role {
	case "source":
	case "destination":
		name, endpoint = prefix+"-dest", state.Destination
	default:
		return nil, empty, errors.New("broker role must be source or destination")
	}
	b := &ownedBroker{runID: state.RunID, role: role, name: name, endpoint: endpoint, origin: time.Now(), run: run, probe: probe, calibration: calibration}
	if state.Proxy != nil {
		if _, err := fixture.ValidatedLinkImage(state, false); err != nil {
			return nil, empty, err
		}
		owned := state
		b.linkedImage = &owned
	}
	snapshot, err := b.inspect(ctx, name)
	if err != nil {
		return nil, snapshot, err
	}
	b.id = snapshot.Facts.ContainerID
	return b, snapshot, nil
}

// Pause requires both Docker's explicit paused state and a fresh independent
// Kafka API transport failure. RecoveryNeeded remains true after any pause
// request, including ambiguous command failure. The caller must Restore before
// freezing receipts or releasing this lab fixture. Serialize operations on each
// handle; cleanup can call Restore with a fresh context after campaign cancellation.
func (b *ownedBroker) Pause(ctx context.Context) (brokerObservation, error) {
	return b.change(ctx, "pause", 10*time.Second)
}

// Restore targets this handle's ID only. It unpauses a suspended broker, or
// restarts the same stopped container, then observes running/unpaused state and
// an independently successful Kafka API request. It never removes resources.
func (b *ownedBroker) Restore(ctx context.Context) (brokerObservation, error) {
	return b.change(ctx, "restore", 45*time.Second)
}

// Restart is an audit drain boundary on the same container and storage. Reached
// requires a different Docker StartedAt and successful independent readiness.
// The campaign separately records its broker-storage/stabilization assumptions.
func (b *ownedBroker) Restart(ctx context.Context) (brokerObservation, error) {
	return b.change(ctx, "restart", 60*time.Second)
}

func (b *ownedBroker) change(ctx context.Context, operation string, budget time.Duration) (observation brokerObservation, err error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	started := time.Now()
	observation = brokerObservation{RunID: b.runID, Role: b.role, ContainerID: b.id, Operation: operation, Calibration: b.calibration, RecoveryNeeded: operation != "pause"}
	defer func() {
		observation.Interval = b.interval(started, time.Now())
		if err != nil {
			observation.Error = err.Error()
		}
	}()
	observation.Before, err = b.inspect(ctx, b.id)
	if err != nil {
		return observation, err
	}
	before := observation.Before.Facts
	observation.RecoveryNeeded = observation.RecoveryNeeded || before.Paused || !before.Running
	command := operation
	switch operation {
	case "pause":
		if !before.Running || before.Paused {
			return observation, errors.New("pause requires a running, unpaused owned broker")
		}
	case "restore":
		switch {
		case before.Paused:
			command = "unpause"
		case !before.Running:
			command = "restart"
		default:
			command = ""
		}
	case "restart":
		if before.Paused {
			return observation, errors.New("restore paused broker before audit restart")
		}
	default:
		return observation, errors.New("unsupported broker operation")
	}
	if command != "" {
		observation.RecoveryNeeded = true
		request := b.request(ctx, command)
		observation.Request = &request
		if request.Error != "" {
			return observation, errors.New(request.Error)
		}
	}
	for {
		snapshot, inspectErr := b.inspect(ctx, b.id)
		check := brokerCheck{Snapshot: snapshot}
		if inspectErr != nil {
			observation.Checks = append(observation.Checks, check)
			return observation, inspectErr
		}
		facts := snapshot.Facts
		if operation == "pause" && (!facts.Running || !facts.Paused) {
			observation.Checks = append(observation.Checks, check)
			return observation, errors.New("Docker did not confirm running, paused owned broker")
		}
		if operation != "pause" && (!facts.Running || facts.Paused) {
			observation.Checks = append(observation.Checks, check)
			return observation, errors.New("Docker did not confirm running, unpaused owned broker")
		}
		if command == "restart" && facts.StartedAt.Equal(before.StartedAt) {
			observation.Checks = append(observation.Checks, check)
			return observation, errors.New("broker restart has no changed StartedAt observation")
		}
		probe := b.observeProbe(ctx)
		check.Probe = &probe
		observation.Checks = append(observation.Checks, check)
		if probe.Error != "" {
			return observation, errors.New(probe.Error)
		}
		if operation == "pause" {
			if !probe.Result.Unavailable {
				return observation, errors.New("paused broker Kafka API unavailability was not observed")
			}
			observation.Reached = true
			return observation, nil
		}
		if probe.Result.Available {
			observation.Reached = true
			observation.RecoveryNeeded = false
			return observation, nil
		}
		select {
		case <-ctx.Done():
			return observation, fmt.Errorf("owned broker recovery not reached: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (b *ownedBroker) interval(start, end time.Time) brokerInterval {
	return brokerInterval{StartedAt: start.UTC(), EndedAt: end.UTC(), StartElapsedNanoseconds: start.Sub(b.origin).Nanoseconds(), EndElapsedNanoseconds: end.Sub(b.origin).Nanoseconds()}
}

func (b *ownedBroker) request(ctx context.Context, operation string) brokerRequest {
	start := time.Now()
	request := brokerRequest{Operation: operation, ContainerID: b.id}
	args := []string{operation, b.id}
	timeout := 5 * time.Second
	if operation == "restart" {
		args = []string{"restart", "--time", "5", b.id}
		timeout = 15 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	if err := commandCtx.Err(); err != nil {
		cancel()
		request.Interval = b.interval(start, time.Now())
		request.Error = err.Error()
		return request
	}
	out, err := b.run(commandCtx, args...)
	if commandCtx.Err() != nil {
		err = errors.Join(err, commandCtx.Err())
	}
	cancel()
	request.Interval = b.interval(start, time.Now())
	// Mutation output is a container identity/diagnostic, never an inspect document.
	// Refuse oversized output rather than silently discarding required evidence.
	if len(out) > 4096 {
		err = errors.Join(err, errors.New("Docker mutation output exceeds evidence limit"))
		out = out[:4096]
	}
	request.Output = string(out)
	if err != nil {
		request.Error = err.Error()
	}
	return request
}

func (b *ownedBroker) inspect(ctx context.Context, target string) (snapshot brokerSnapshot, err error) {
	start := time.Now()
	defer func() {
		snapshot.Interval = b.interval(start, time.Now())
		if err != nil {
			snapshot.Error = err.Error()
		}
	}()
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := commandCtx.Err(); err != nil {
		return snapshot, brokerInspectFailure(target, err)
	}
	out, err := b.run(commandCtx, "container", "inspect", target, "--format", "{{json .}}")
	if commandCtx.Err() != nil {
		err = errors.Join(err, commandCtx.Err())
	}
	if err != nil {
		// fixture.Docker includes CombinedOutput in its error. A full inspect can
		// contain Config.Env, so retain only safe command/context/exit information.
		return snapshot, brokerInspectFailure(target, err)
	}
	if len(out) > 1<<20 {
		return snapshot, errors.New("owned broker inspect exceeds evidence limit")
	}
	var info struct {
		ID, Name, Image         string
		ImageManifestDescriptor *fixture.ImageManifestIdentity
		Config                  struct {
			Image  string
			Labels map[string]string
		}
		State struct {
			Running, Paused *bool
			StartedAt       string
		}
		HostConfig struct {
			PortBindings map[string][]brokerPortBinding
		}
		NetworkSettings struct {
			Ports map[string][]brokerPortBinding
		}
	}
	if err = json.Unmarshal(out, &info); err != nil {
		return snapshot, errors.New("invalid owned broker inspect JSON")
	}
	facts := &brokerFacts{RunID: info.Config.Labels[brokerOwnerLabel], Role: b.role, ContainerID: info.ID, Name: info.Name, ImageID: info.Image, ImageReference: info.Config.Image, Endpoint: b.endpoint, SelectedManifest: info.ImageManifestDescriptor}
	snapshot.Facts = facts
	facts.RunningPresent, facts.PausedPresent = info.State.Running != nil, info.State.Paused != nil
	facts.ConfiguredExternalBindings = append([]brokerPortBinding(nil), info.HostConfig.PortBindings["19092/tcp"]...)
	facts.PublishedExternalBindings = append([]brokerPortBinding(nil), info.NetworkSettings.Ports["19092/tcp"]...)
	if b.linkedImage != nil {
		if err := fixture.ValidateLinkContainerImage(*b.linkedImage, false, info.Image, info.ImageManifestDescriptor); err != nil {
			return snapshot, err
		}
	}
	if !brokerContainerID(info.ID) || (b.id != "" && info.ID != b.id) || info.Name != "/"+b.name || facts.RunID != b.runID || info.Config.Image != fixture.Image || !strings.HasPrefix(info.Image, "sha256:") || !brokerContainerID(strings.TrimPrefix(info.Image, "sha256:")) {
		return snapshot, errors.New("owned broker container ID, name, label or image mismatch")
	}
	if info.State.Running == nil || info.State.Paused == nil {
		return snapshot, errors.New("owned broker inspect lacks explicit Running/Paused state")
	}
	facts.Running, facts.Paused = *info.State.Running, *info.State.Paused
	if facts.Paused && !facts.Running {
		return snapshot, errors.New("owned broker inspect has paused but nonrunning state")
	}
	facts.StartedAt, err = time.Parse(time.RFC3339Nano, info.State.StartedAt)
	if err != nil || facts.StartedAt.IsZero() {
		return snapshot, errors.New("owned broker inspect lacks valid StartedAt")
	}
	port, _ := ownedBrokerPort(b.endpoint)
	for _, bindings := range []map[string][]brokerPortBinding{info.HostConfig.PortBindings, info.NetworkSettings.Ports} {
		binding := bindings["19092/tcp"]
		if len(binding) != 1 || binding[0].HostIP != "127.0.0.1" || binding[0].HostPort != port {
			return snapshot, errors.New("owned broker EXTERNAL port binding mismatch")
		}
	}
	return snapshot, nil
}

// Inspect failure diagnostics must never wrap the executor error or its output.
// target comes only from the validated fixture name or retained container ID.
func brokerInspectFailure(target string, cause error) error {
	operation := "owned broker docker container inspect " + target + " failed"
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", operation, context.DeadlineExceeded)
	case errors.Is(cause, context.Canceled):
		return fmt.Errorf("%s: %w", operation, context.Canceled)
	}
	var exit interface{ ExitCode() int }
	if errors.As(cause, &exit) {
		return fmt.Errorf("%s: exit code %d", operation, exit.ExitCode())
	}
	return errors.New(operation + ": executor failure")
}

type brokerPortBinding struct{ HostIP, HostPort string }

func ownedBrokerPort(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || host != "127.0.0.1" || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", errors.New("broker endpoint must be an exact loopback IPv4 port")
	}
	return port, nil
}

func brokerContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (b *ownedBroker) observeProbe(ctx context.Context) brokerProbeObservation {
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := b.probe(probeCtx, b.endpoint)
	if probeCtx.Err() != nil {
		err = errors.Join(err, probeCtx.Err())
	}
	observation := brokerProbeObservation{Interval: b.interval(start, time.Now()), Endpoint: b.endpoint, Result: result}
	if result.Available == result.Unavailable {
		err = errors.Join(err, errors.New("probe did not distinguish Kafka API availability"))
	}
	if result.Available && (result.APIKeys < 1 || result.ErrorCode != 0) {
		err = errors.Join(err, errors.New("probe has no successful Kafka API response"))
	}
	if result.Unavailable && (result.TransportError == "" || !brokerTransportCategory(result.Failure)) {
		err = errors.Join(err, errors.New("probe has no recognized transport-failure evidence"))
	}
	if err != nil {
		observation.Error = err.Error()
	}
	return observation
}

func brokerTransportCategory(kind string) bool {
	switch kind {
	case "timeout", "connection_refused", "connection_reset", "broken_pipe", "connection_closed":
		return true
	default:
		return false
	}
}
