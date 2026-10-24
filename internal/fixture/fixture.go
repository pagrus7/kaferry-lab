// Package fixture controls only uniquely named, disposable lab Docker resources.
package fixture

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Image = "apache/kafka@sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02"
const ownerLabel = "io.kaferry-lab.run"

var validID = regexp.MustCompile(`^[a-z][a-z0-9-]{3,48}$`)

type State struct {
	ClusterIDs     []string `json:"cluster_ids"`
	RunID          string   `json:"run_id"`
	Image          string   `json:"image"`
	Network        string   `json:"network"`
	Containers     []string `json:"containers"`
	Source         string   `json:"source"`
	Destination    string   `json:"destination"`
	DockerPlatform string   `json:"docker_platform"`
	Created        string   `json:"created"`
}

type Executor func(context.Context, ...string) ([]byte, error)

func Docker(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

func StatePath(id string) (string, error) {
	if !validID.MatchString(id) {
		return "", errors.New("run ID must match [a-z][a-z0-9-]{3,48}")
	}
	return filepath.Join(".cache", "fixtures", id+".json"), nil
}

func unusedPort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	return port, l.Close()
}

func save(s State) error {
	path, err := StatePath(s.RunID)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Exclusive creation prevents replacing another run's recovery information.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(b, '\n'))
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

// Up records intended resources before creating any, so interrupted setup can be reaped.
func Up(ctx context.Context, id string, run Executor) (s State, err error) {
	if _, err = StatePath(id); err != nil {
		return s, err
	}
	p, err := unusedPort()
	if err != nil {
		return s, err
	}
	q, err := unusedPort()
	if err != nil {
		return s, err
	}
	if p == q {
		return s, errors.New("ephemeral port collision; choose a new run")
	}
	platform, err := run(ctx, "info", "--format", "{{.OSType}}/{{.Architecture}}")
	if err != nil {
		return s, err
	}
	ids := make([]string, 2)
	for i := range ids {
		raw := make([]byte, 16)
		if _, err = rand.Read(raw); err != nil {
			return s, err
		}
		ids[i] = base64.RawURLEncoding.EncodeToString(raw)
	}
	if ids[0] == ids[1] {
		return s, errors.New("random cluster identity collision")
	}
	s = State{ClusterIDs: ids, RunID: id, Image: Image, Network: "kaferry-lab-" + id, Containers: []string{"kaferry-lab-" + id + "-source", "kaferry-lab-" + id + "-dest"}, Source: fmt.Sprintf("127.0.0.1:%d", p), Destination: fmt.Sprintf("127.0.0.1:%d", q), DockerPlatform: strings.TrimSpace(string(platform)), Created: time.Now().UTC().Format(time.RFC3339Nano)}
	if err = save(s); err != nil {
		return s, err
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = errors.Join(err, Down(cleanup, s, run))
		}
	}()
	if _, err = run(ctx, "pull", Image); err != nil {
		return s, err
	}
	if _, err = run(ctx, "network", "create", "--label", ownerLabel+"="+id, s.Network); err != nil {
		return s, err
	}
	for i, name := range s.Containers {
		port := p
		if i == 1 {
			port = q
		}
		args := []string{"run", "-d", "--name", name, "--label", ownerLabel + "=" + id, "--network", s.Network, "--memory", "768m", "--cpus", "1.5", "-p", fmt.Sprintf("127.0.0.1:%d:19092", port)}
		env := []string{"CLUSTER_ID=" + ids[i], "KAFKA_HEAP_OPTS=-Xms128m -Xmx256m", "KAFKA_NODE_ID=1", "KAFKA_PROCESS_ROLES=broker,controller", "KAFKA_CONTROLLER_QUORUM_VOTERS=1@" + name + ":9093", "KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092", "KAFKA_ADVERTISED_LISTENERS=INTERNAL://" + name + ":9092,EXTERNAL://127.0.0.1:" + fmt.Sprint(port), "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT", "KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL", "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER", "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1", "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1", "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1", "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0", "KAFKA_AUTO_CREATE_TOPICS_ENABLE=false", "KAFKA_LOG_RETENTION_MS=-1", "KAFKA_LOG_RETENTION_BYTES=-1"}
		for _, v := range env {
			args = append(args, "-e", v)
		}
		args = append(args, Image)
		if _, err = run(ctx, args...); err != nil {
			return s, err
		}
	}
	for _, name := range s.Containers {
		if err = ready(ctx, name, run); err != nil {
			return s, err
		}
	}
	return s, nil
}

func ready(ctx context.Context, name string, run Executor) error {
	var last error
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	for {
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, last = run(probe, "exec", name, "/opt/kafka/bin/kafka-broker-api-versions.sh", "--bootstrap-server", name+":9092")
		cancel()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), last)
		case <-deadline.C:
			return fmt.Errorf("broker readiness timed out: %w", last)
		case <-time.After(time.Second):
		}
	}
}

func Load(id string) (State, error) {
	path, err := StatePath(id)
	if err != nil {
		return State{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var s State
	if err = json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	if s.RunID != id || s.Network != "kaferry-lab-"+id || len(s.Containers) != 2 || s.Containers[0] != "kaferry-lab-"+id+"-source" || s.Containers[1] != "kaferry-lab-"+id+"-dest" {
		return s, errors.New("invalid fixture resource identity")
	}
	return s, nil
}

// Down refuses resources without the exact run label, even if their names match.
// Evidence and state are retained; repeated cleanup tolerates absent resources.
func Down(ctx context.Context, s State, run Executor) error {
	if _, err := StatePath(s.RunID); err != nil {
		return err
	}
	var errs []error
	for _, name := range s.Containers {
		if name != "kaferry-lab-"+s.RunID+"-source" && name != "kaferry-lab-"+s.RunID+"-dest" {
			errs = append(errs, errors.New("unexpected container name"))
			continue
		}
		if err := remove(ctx, "container", name, s.RunID, run); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Network != "kaferry-lab-"+s.RunID {
		errs = append(errs, errors.New("unexpected network name"))
	} else if err := remove(ctx, "network", s.Network, s.RunID, run); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func remove(ctx context.Context, kind, name, id string, run Executor) error {
	out, err := run(ctx, kind, "inspect", name, "--format", "{{json .}}")
	if err != nil {
		// Only Docker's explicit absence is idempotent success, never a daemon failure.
		if strings.Contains(string(out), "No such container") || strings.Contains(string(out), "No such network") || strings.Contains(string(out), "No such object") {
			return nil
		}
		return err
	}
	var info struct {
		Config struct{ Labels map[string]string }
		Labels map[string]string
	}
	if err = json.Unmarshal(out, &info); err != nil {
		return err
	}
	labels := info.Labels
	if kind == "container" {
		labels = info.Config.Labels
	}
	if labels[ownerLabel] != id {
		return fmt.Errorf("refuse removal of unowned %s %s", kind, name)
	}
	var evidenceErr error
	if kind == "container" {
		logs, logErr := run(ctx, "logs", name)
		path, pathErr := StatePath(id)
		if pathErr == nil {
			pathErr = os.MkdirAll(filepath.Dir(path), 0700)
		}
		if pathErr == nil {
			pathErr = os.WriteFile(filepath.Join(filepath.Dir(path), name+".log"), logs, 0600)
		}
		evidenceErr = errors.Join(logErr, pathErr)
	}
	args := []string{kind, "rm"}
	if kind == "container" {
		args = append(args, "-f")
	}
	args = append(args, name)
	_, err = run(ctx, args...)
	return errors.Join(evidenceErr, err)
}
