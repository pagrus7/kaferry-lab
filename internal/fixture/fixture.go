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
	ClusterIDs        []string        `json:"cluster_ids"`
	RunID             string          `json:"run_id"`
	Image             string          `json:"image"`
	Network           string          `json:"network"`
	Containers        []string        `json:"containers"`
	Source            string          `json:"source"`
	Destination       string          `json:"destination"`
	DockerPlatform    string          `json:"docker_platform"`
	Created           string          `json:"created"`
	WorkerSource      string          `json:"worker_source,omitempty"`
	WorkerDestination string          `json:"worker_destination,omitempty"`
	Proxy             *ProxyState     `json:"proxy,omitempty"`
	Direct            *DirectIdentity `json:"direct,omitempty"`
}

type Executor func(context.Context, ...string) ([]byte, error)

func Docker(ctx context.Context, args ...string) ([]byte, error) {
	if linked, _ := ctx.Value(linkCaptureKey{}).(bool); linked {
		return boundedLinkDocker(ctx, args...)
	}
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

// Up records the immutable plan before resource creation. Incomplete direct
// setup retains its STOP and resources, without authorizing guessed-ID cleanup.
func Up(ctx context.Context, id string, run Executor) (State, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	return up(ctx, id, run, false, nil, kafkaLinkBrokerProbe)
}

// UpLinks adds only the owned worker proxy path. Independent clients continue
// using the direct Source and Destination endpoints returned by Up.
func UpLinks(ctx context.Context, id string, run Executor) (State, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	return up(ctx, id, run, true, linkHTTP, kafkaLinkBrokerProbe)
}

func up(ctx context.Context, id string, run Executor, links bool, request linkRequest, probe linkBrokerProbe) (s State, err error) {
	if run == nil || probe == nil || links && request == nil {
		return s, errors.New("fixture requires Docker and fixed API executors")
	}
	if _, err = StatePath(id); err != nil {
		return s, err
	}
	if links {
		if err = reserveLinkEvidence(id); err != nil {
			return s, err
		}
		if err = os.MkdirAll(filepath.Dir(linkDirectory(id)), 0700); err != nil {
			return s, errors.New("public link evidence parent unavailable")
		}
		if err = os.Mkdir(linkDirectory(id), 0700); err != nil {
			return s, errors.New("public link evidence reservation failed")
		}
		if run, err = linkExecutor(id, run); err != nil {
			return s, err
		}
		defer func() {
			if err != nil {
				err = errors.Join(err, stopLinkOperation(id, "linked startup incomplete"))
			}
		}()
	} else {
		root := directPrivateDirectory(id)
		if err = reservePrivateFixtureEvidence(id, root); err != nil {
			return s, err
		}
		if err = validateDirectReservation(id); err != nil {
			return s, err
		}
		primary, e := os.OpenFile(filepath.Join(root, "startup-control.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return s, e
		}
		defer directStartupFailure(id, primary, &err)
		if run, err = privateFixtureExecutor(id, root, run); err != nil {
			return s, err
		}
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
	profile, err := fixedImageProfile(s.DockerPlatform)
	if err != nil {
		return s, err
	}
	if links {
		if err = planLinks(&s); err != nil {
			return s, err
		}
	}
	if err = save(s); err != nil {
		return s, err
	}
	if links {
		if err = linkReceipt(s, "plan", s); err != nil {
			return s, err
		}
		if _, err = run(ctx, "pull", "--quiet", "--platform", profile.platform, s.Proxy.Image); err != nil {
			return s, err
		}
	}
	pullArgs := []string{"pull", "--platform", profile.platform, Image}
	if links {
		pullArgs = []string{"pull", "--quiet", "--platform", profile.platform, Image}
	}
	if _, err = run(ctx, pullArgs...); err != nil {
		return s, err
	}
	// Resolve exact config and native platform before creating any resource.
	var directImage LinkImageIdentity
	if links {
		if _, err = inspectLinkImage(ctx, run, s, Image); err != nil {
			return s, err
		}
		if _, err = inspectLinkImage(ctx, run, s, s.Proxy.Image); err != nil {
			return s, err
		}
	} else {
		if directImage, err = inspectFixtureImage(ctx, run, s, Image); err != nil {
			return s, err
		}
		if _, err = directPlanBytes(s); err != nil {
			return s, err
		}
		if _, err = imagePrivateAuthority(s); err != nil {
			return s, err
		}
	}
	// Failed/ambiguous Docker actions preserve STOP and unresolved resources;
	// no new cleanup executor may retry the same stopped facility.
	if _, err = run(ctx, "network", "create", "--label", ownerLabel+"="+id, s.Network); err != nil {
		return s, err
	}
	for i, name := range s.Containers {
		port := p
		if i == 1 {
			port = q
		}
		args := []string{"run", "-d", "--platform", profile.platform, "--name", name, "--label", ownerLabel + "=" + id, "--network", s.Network, "--memory", "768m", "--cpus", "1.5", "-p", fmt.Sprintf("127.0.0.1:%d:19092", port)}
		env := []string{"CLUSTER_ID=" + ids[i], "KAFKA_HEAP_OPTS=-Xms128m -Xmx256m", "KAFKA_NODE_ID=1", "KAFKA_PROCESS_ROLES=broker,controller", "KAFKA_CONTROLLER_QUORUM_VOTERS=1@" + name + ":9093", "KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092", "KAFKA_ADVERTISED_LISTENERS=INTERNAL://" + name + ":9092,EXTERNAL://127.0.0.1:" + fmt.Sprint(port), "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT", "KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL", "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER", "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1", "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1", "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1", "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0", "KAFKA_AUTO_CREATE_TOPICS_ENABLE=false", "KAFKA_LOG_RETENTION_MS=-1", "KAFKA_LOG_RETENTION_BYTES=-1"}
		args = append(args, "--label", linkRoleLabel+"="+[]string{"source", "destination"}[i], "--pids-limit", "256", "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1")
		if links {
			env = linkBrokerEnvironment(env, s, i)
		}
		for _, v := range env {
			args = append(args, "-e", v)
		}
		args = append(args, Image)
		if _, err = run(ctx, args...); err != nil {
			return s, err
		}
	}
	if links {
		if err = readyLinkedBrokers(ctx, s, run, probe); err != nil {
			return s, err
		}
	} else {
		if err = admitDirectResources(ctx, &s, run, directImage); err != nil {
			return s, err
		}
		if err = readyDirectBrokers(ctx, s, run, probe); err != nil {
			return s, err
		}
	}
	if links {
		if err = setupLinks(ctx, &s, run, request); err != nil {
			return s, err
		}
	}
	return s, nil
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
	if s.Proxy != nil {
		if err = validateLinkPlan(s); err != nil {
			return s, err
		}
		if err = loadLinkIdentity(&s, b); err != nil {
			return s, err
		}
	} else if s.WorkerSource != "" || s.WorkerDestination != "" {
		return s, errors.New("worker endpoints require owned proxy state")
	} else if err = loadDirectIdentity(&s); err != nil {
		return s, err
	}
	return s, nil
}

// Down refuses resources without the exact run label, even if their names match.
// Evidence and state are retained; repeated cleanup tolerates absent resources.
func Down(ctx context.Context, s State, run Executor) error {
	if s.Proxy != nil {
		return downLinks(ctx, s, run)
	}
	return downDirect(ctx, s, run)
}
