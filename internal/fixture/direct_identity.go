package fixture

// Fixed direct topology: two brokers, no proxy, no worker-link endpoints.
// These receipts authorize only this run's exact resources and private route.
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

type DirectIdentity struct {
	RunID, ManifestSHA256, NetworkID string
	BrokerIDs                        []string
	Image                            LinkImageIdentity
}

func directPrivateDirectory(id string) string {
	return filepath.Join(".cache", "fixtures-private", id+"-brokers")
}

func validateDirectReservation(id string) error {
	if _, err := StatePath(id); err != nil {
		return err
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	// Getwd may return a logical PWD alias for the actual current directory
	// (including Darwin's /var -> /private/var). Canonicalize that base once,
	// bind it to '.', then require every run-owned descendant to be canonical.
	base, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil {
		return err
	}
	current, currentErr := os.Stat(".")
	resolved, resolvedErr := os.Stat(base)
	if currentErr != nil || resolvedErr != nil || !os.SameFile(current, resolved) {
		return errors.Join(currentErr, resolvedErr, errors.New("canonical direct working directory identity rejected"))
	}
	root := filepath.Join(base, directPrivateDirectory(id))
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root {
		return errors.New("canonical direct reservation required")
	}
	for _, path := range []string{filepath.Dir(root), root} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || owner.Uid != uint32(os.Geteuid()) {
			return errors.New("direct reservation directory identity rejected")
		}
	}
	body, err := readImagePrivateFile(filepath.Join(root, "PRIVATE.json"), 4096)
	if err != nil {
		return err
	}
	var marker struct{ RunID, Classification, Publication string }
	if err = decodeImageArchiveJSON(body, &marker); err != nil {
		return err
	}
	if marker.RunID != id || marker.Classification != "PRIVATE RAW EVIDENCE" {
		return errors.New("direct reservation marker rejected")
	}
	return nil
}

func validateDirectPlan(s State) error {
	if _, err := StatePath(s.RunID); err != nil {
		return err
	}
	prefix := "kaferry-lab-" + s.RunID
	if s.Proxy != nil || s.WorkerSource != "" || s.WorkerDestination != "" || s.Image != Image || s.Network != prefix || len(s.Containers) != 2 || s.Containers[0] != prefix+"-source" || s.Containers[1] != prefix+"-dest" {
		return errors.New("unexpected direct fixture topology/image/resource names")
	}
	if _, err := fixedImageProfile(s.DockerPlatform); err != nil {
		return err
	}
	for _, endpoint := range []string{s.Source, s.Destination} {
		if _, err := loopbackPort(endpoint); err != nil {
			return err
		}
	}
	if s.Source == s.Destination || len(s.ClusterIDs) != 2 || s.ClusterIDs[0] == s.ClusterIDs[1] {
		return errors.New("direct fixture endpoint/cluster ambiguity")
	}
	for _, id := range s.ClusterIDs {
		b, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(b) != 16 || base64.RawURLEncoding.EncodeToString(b) != id {
			return errors.New("direct fixture cluster identity rejected")
		}
	}
	if created, err := time.Parse(time.RFC3339Nano, s.Created); err != nil || created.IsZero() {
		return errors.New("direct fixture creation identity missing")
	}
	return nil
}

func directPlanBytes(s State) ([]byte, error) {
	if err := validateDirectPlan(s); err != nil {
		return nil, err
	}
	path, _ := StatePath(s.RunID)
	body, err := readImagePrivateFile(path, 256<<10)
	if err != nil {
		return nil, err
	}
	var planned State
	if err = decodeImageArchiveJSON(body, &planned); err != nil {
		return nil, err
	}
	copy := s
	copy.Direct = nil
	if planned.Direct != nil || !reflect.DeepEqual(planned, copy) {
		return nil, errors.New("direct identity differs from exclusive initial plan")
	}
	return body, nil
}

func validatedDirectIdentity(s State) (DirectIdentity, error) {
	var id DirectIdentity
	if s.Direct == nil {
		return id, errors.New("direct fixture complete identity receipt missing; no resource action permitted")
	}
	root, err := imagePrivateAuthority(s)
	if err != nil {
		return id, err
	}
	plan, err := directPlanBytes(s)
	if err != nil {
		return id, err
	}
	body, err := readImagePrivateFile(filepath.Join(root, "identity.json"), 256<<10)
	if err != nil {
		return id, err
	}
	if err = decodeImageArchiveJSON(body, &id); err != nil {
		return id, err
	}
	if !reflect.DeepEqual(id, *s.Direct) || id.RunID != s.RunID || id.ManifestSHA256 != linkDigest(plan) || !linkID(id.NetworkID) || len(id.BrokerIDs) != 2 || !linkID(id.BrokerIDs[0]) || !linkID(id.BrokerIDs[1]) || id.BrokerIDs[0] == id.BrokerIDs[1] {
		return id, errors.New("direct fixture retained identity/plan binding rejected")
	}
	profile, _ := fixedImageProfile(s.DockerPlatform)
	checked, err := validatedFixtureImage(s, id.Image.RuntimeImageID, profile.brokerConfig, Image, &id.Image)
	if err != nil || !reflect.DeepEqual(checked, id.Image) {
		return id, errors.Join(errors.New("direct fixture typed image authority rejected"), err)
	}
	return id, nil
}

func saveDirectIdentity(s *State, network string, brokers []string, image LinkImageIdentity) error {
	root, err := imagePrivateAuthority(*s)
	if err != nil {
		return err
	}
	body, err := directPlanBytes(*s)
	if err != nil {
		return err
	}
	id := DirectIdentity{s.RunID, linkDigest(body), network, append([]string(nil), brokers...), image}
	if _, err = writeLinkPrivate(root, "identity.json", id); err != nil {
		return err
	}
	s.Direct = &id
	_, err = validatedDirectIdentity(*s)
	return err
}

func loadDirectIdentity(s *State) error {
	if s.Direct != nil {
		return errors.New("initial plan cannot self-assert direct resource identity")
	}
	body, err := readImagePrivateFile(filepath.Join(directPrivateDirectory(s.RunID), "identity.json"), 256<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil // historical or interrupted plan, never authority to mutate
	}
	if err != nil {
		return err
	}
	var id DirectIdentity
	if err = decodeImageArchiveJSON(body, &id); err != nil {
		return err
	}
	s.Direct = &id
	_, err = validatedDirectIdentity(*s)
	return err
}

// FixtureExecutor is the single real-campaign wiring boundary. Only complete
// typed identities select either compiled topology; no bare-Docker fallback.
func FixtureExecutor(s State, run Executor) (Executor, error) {
	if s.Proxy != nil {
		if s.Direct != nil {
			return nil, errors.New("conflicting direct/linked fixture identities")
		}
		return LinkExecutor(s, run)
	}
	if _, err := validatedDirectIdentity(s); err != nil {
		return nil, err
	}
	return privateFixtureExecutor(s.RunID, directPrivateDirectory(s.RunID), run)
}

func StopFixtureEvidence(s State, operation string) error {
	if s.Proxy != nil {
		return StopLinkEvidence(s, operation)
	}
	if err := validateDirectPlan(s); err != nil {
		return err
	}
	if len(operation) == 0 || len(operation) > 1024 {
		return errors.New("direct stop operation bound rejected")
	}
	return stopPrivateFixtureOperation(s.RunID, directPrivateDirectory(s.RunID), operation)
}

func ValidatedBrokerImage(s State) (LinkImageIdentity, error) {
	if s.Proxy != nil {
		return ValidatedLinkImage(s, false)
	}
	id, err := validatedDirectIdentity(s)
	return id.Image, err
}

type directNetwork struct {
	ID, Name   string
	Labels     map[string]string
	Containers map[string]struct{ Name string }
}

func inspectDirectNetwork(ctx context.Context, s State, run Executor, retained string) (directNetwork, bool, error) {
	target := retained
	if target == "" {
		target = s.Network
	}
	var n directNetwork
	present, err := linkInspect(ctx, run, "network", target, &n)
	if err != nil || !present {
		return n, present, err
	}
	if !linkID(n.ID) || n.Name != s.Network || n.Labels[ownerLabel] != s.RunID || retained != "" && n.ID != retained || len(n.Containers) > 2 {
		return n, true, errors.New("direct network identity/ownership ambiguity")
	}
	seen := map[string]bool{}
	for id, c := range n.Containers {
		if !linkID(id) || c.Name != s.Containers[0] && c.Name != s.Containers[1] || seen[c.Name] {
			return n, true, errors.New("direct network has foreign/ambiguous attachment")
		}
		seen[c.Name] = true
		if s.Direct != nil {
			i := 0
			if c.Name == s.Containers[1] {
				i = 1
			}
			if id != s.Direct.BrokerIDs[i] {
				return n, true, errors.New("direct network retained broker ID changed")
			}
		}
	}
	return n, true, nil
}

type directContainer struct {
	ID, Name, Image         string
	ImageManifestDescriptor *ImageManifestIdentity
	Config                  struct {
		Image  string
		Labels map[string]string
		Env    []string
	}
	State      struct{ Running, Paused *bool }
	HostConfig struct {
		NetworkMode      string
		Memory, NanoCPUs int64
		PidsLimit        int64
		PortBindings     map[string][]linkBinding
		LogConfig        struct {
			Type   string
			Config map[string]string
		}
	}
	NetworkSettings struct {
		Ports    map[string][]linkBinding
		Networks map[string]struct{ NetworkID string }
	}
}

func validateDirectContainer(raw []byte, s State, index int, network string, image LinkImageIdentity, retained string, setup bool) (linkFacts, error) {
	var c directContainer
	if len(raw) > linkOutputLimit || decodeImageArchiveJSON(raw, &c) != nil {
		return linkFacts{}, errors.New("direct container inspect malformed/oversized")
	}
	name, role := s.Containers[index], []string{"source", "destination"}[index]
	if !linkID(c.ID) || c.Name != "/"+name || retained != "" && c.ID != retained || c.Config.Labels[ownerLabel] != s.RunID || c.Config.Labels[linkRoleLabel] != role || c.Config.Image != Image || c.HostConfig.NetworkMode != s.Network || !linkID(network) || c.State.Running == nil || c.State.Paused == nil {
		return linkFacts{}, errors.New("direct container ID/name/owner/image/network mismatch")
	}
	if err := validateContainerImageIdentity(image, c.Image, c.ImageManifestDescriptor); err != nil {
		return linkFacts{}, err
	}
	if c.HostConfig.Memory != 768<<20 || c.HostConfig.NanoCPUs != 1500000000 || c.HostConfig.PidsLimit != 256 || c.HostConfig.LogConfig.Type != "json-file" || c.HostConfig.LogConfig.Config["max-size"] != "1m" || c.HostConfig.LogConfig.Config["max-file"] != "1" {
		return linkFacts{}, errors.New("direct broker finite resource/log configuration mismatch")
	}
	active := *c.State.Running || setup
	networks := c.NetworkSettings.Networks
	if *c.State.Paused && !*c.State.Running || len(networks) > 1 || len(networks) == 1 && networks[s.Network].NetworkID != network || active && len(networks) != 1 || setup && (!*c.State.Running || *c.State.Paused) {
		return linkFacts{}, errors.New("direct container running/network attachment mismatch")
	}
	endpoint := []string{s.Source, s.Destination}[index]
	port, _ := loopbackPort(endpoint)
	for position, bindings := range []map[string][]linkBinding{c.HostConfig.PortBindings, c.NetworkSettings.Ports} {
		for key, list := range bindings {
			if len(list) != 0 && (key != "19092/tcp" || len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != port) {
				return linkFacts{}, errors.New("direct broker foreign port binding")
			}
		}
		if position == 1 && !active {
			continue
		}
		list := bindings["19092/tcp"]
		if len(list) != 1 || list[0].HostIP != "127.0.0.1" || list[0].HostPort != port {
			return linkFacts{}, errors.New("direct broker loopback binding missing")
		}
	}
	wanted := map[string]string{"CLUSTER_ID": s.ClusterIDs[index], "KAFKA_LISTENERS": "INTERNAL://:9092,CONTROLLER://:9093,EXTERNAL://:19092", "KAFKA_ADVERTISED_LISTENERS": "INTERNAL://" + name + ":9092,EXTERNAL://" + endpoint, "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP": "INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT"}
	found := map[string]bool{}
	for _, entry := range c.Config.Env {
		key, value, ok := strings.Cut(entry, "=")
		if expected, needed := wanted[key]; needed {
			if !ok || found[key] || value != expected {
				return linkFacts{}, errors.New("direct broker configured listener/cluster mismatch")
			}
			found[key] = true
		}
	}
	if len(found) != len(wanted) {
		return linkFacts{}, errors.New("direct broker configured identity missing")
	}
	return linkFacts{c.ID, name, c.Image, c.Config.Image, network, role, *c.State.Running, *c.State.Paused}, nil
}

// Called at each real campaign inspect before probe/mutation. It reloads the
// same-run typed proof and validates the complete current container candidate.
func ValidateDirectBrokerContainer(s State, role string, raw []byte) error {
	id, err := validatedDirectIdentity(s)
	if err != nil {
		return err
	}
	i := 0
	if role == "destination" {
		i = 1
	} else if role != "source" {
		return errors.New("direct broker role rejected")
	}
	_, err = validateDirectContainer(raw, s, i, id.NetworkID, id.Image, id.BrokerIDs[i], false)
	return err
}

func admitDirectResources(ctx context.Context, s *State, run Executor, image LinkImageIdentity) error {
	n, exists, err := inspectDirectNetwork(ctx, *s, run, "")
	if err != nil || !exists || len(n.Containers) != 2 {
		return errors.Join(err, errors.New("complete direct owned network unavailable"))
	}
	ids := make([]string, 2)
	for i, name := range s.Containers {
		raw, err := run(ctx, "container", "inspect", name, "--format", "{{json .}}")
		if err != nil {
			return err
		}
		fact, err := validateDirectContainer(raw, *s, i, n.ID, image, "", true)
		if err != nil {
			return err
		}
		if attached, ok := n.Containers[fact.ID]; !ok || attached.Name != name {
			return errors.New("direct broker ID differs from network attachment")
		}
		ids[i] = fact.ID
	}
	return saveDirectIdentity(s, n.ID, ids, image)
}

func readyDirectBrokers(ctx context.Context, s State, run Executor, probe linkBrokerProbe) error {
	bounded, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if probe == nil {
		return errors.New("direct readiness probe missing")
	}
	for index, endpoint := range []string{s.Source, s.Destination} {
		for attempt := 1; attempt <= 64; attempt++ {
			if err := bounded.Err(); err != nil {
				return err
			}
			id, err := validatedDirectIdentity(s)
			if err != nil {
				return err
			}
			if err = inspectReadyDirectBroker(bounded, s, run, index); err != nil {
				return err
			}
			root := directPrivateDirectory(s.RunID)
			intent, err := writeLinkPrivate(root, "", struct {
				RunID, Endpoint, ContainerID, Operation string
				Attempt                                 int
			}{s.RunID, endpoint, id.BrokerIDs[index], "direct Sarama ApiVersions-v0", attempt})
			if err != nil {
				return err
			}
			one, done := context.WithTimeout(bounded, 2*time.Second)
			observed, cause := probe(one, endpoint)
			cause = errors.Join(cause, one.Err())
			done()
			if cause == nil {
				cause = validateLinkBrokerProbe(observed)
			}
			if !observed.Closed {
				cause = errors.Join(cause, errors.New("direct readiness probe close unproven"))
			}
			var notice []byte
			if cause != nil {
				notice = []byte(cause.Error())
			}
			complete := len(notice) <= linkOutputLimit
			if !complete {
				notice = notice[:linkOutputLimit]
			}
			if _, err = writeLinkPrivate(root, "", struct {
				RunID, Intent string
				Observed      linkBrokerProbeResult
				Cause         []byte
				CauseComplete bool
			}{s.RunID, intent, observed, notice, complete}); err != nil {
				return err
			}
			if cause == nil {
				// A successful API reply cannot authorize a replacement container or
				// a changed image/network while that direct socket was in use.
				if err = inspectReadyDirectBroker(bounded, s, run, index); err != nil {
					return err
				}
				break
			}
			if !complete || !observed.Closed || !linkBrokerRetryable(cause) || attempt == 64 {
				return errors.New("direct readiness failed; exact original retained privately")
			}
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-bounded.Done():
				timer.Stop()
				return bounded.Err()
			case <-timer.C:
			}
		}
	}
	for index := range s.Containers {
		if err := inspectReadyDirectBroker(bounded, s, run, index); err != nil {
			return err
		}
	}
	return bounded.Err()
}

func inspectReadyDirectBroker(ctx context.Context, s State, run Executor, index int) error {
	id, err := validatedDirectIdentity(s)
	if err != nil {
		return err
	}
	n, present, err := inspectDirectNetwork(ctx, s, run, id.NetworkID)
	if err != nil || !present || len(n.Containers) != 2 {
		return errors.Join(err, errors.New("complete direct readiness network unavailable"))
	}
	raw, present, err := inspectDirectContainerRaw(ctx, run, id.BrokerIDs[index])
	if err != nil || !present {
		return errors.Join(err, errors.New("direct readiness broker unavailable"))
	}
	_, err = validateDirectContainer(raw, s, index, id.NetworkID, id.Image, id.BrokerIDs[index], true)
	return err
}

func downDirect(ctx context.Context, s State, raw Executor) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = validateDirectPlan(s); err != nil {
		return err
	}
	id, err := validatedDirectIdentity(s)
	if err != nil {
		return err // no inspection/removal without a complete retained receipt
	}
	run, err := FixtureExecutor(s, raw)
	if err != nil {
		return err
	}
	root := directPrivateDirectory(s.RunID)
	control, err := os.CreateTemp(root, "cleanup-control-*.json")
	if err != nil {
		return errors.Join(err, stopImageOperation(s, "direct cleanup diagnostic reservation failed"))
	}
	defer finishImageControl(control, s, "direct cleanup incomplete", &err)
	n, networkPresent, err := inspectDirectNetwork(ctx, s, run, id.NetworkID)
	if err != nil {
		return err
	}
	facts, present := [2]linkFacts{}, [2]bool{}
	for i, target := range id.BrokerIDs {
		var body []byte
		body, present[i], err = inspectDirectContainerRaw(ctx, run, target)
		if err != nil {
			return err
		}
		if !present[i] {
			continue
		}
		if !networkPresent {
			return errors.New("direct container exists without its retained network")
		}
		// Capture already occurred in the executor; semantic validation uses
		// this same original, not a second inspect of a changing candidate.
		facts[i], err = validateDirectContainer(body, s, i, n.ID, id.Image, target, false)
		if err != nil {
			return err
		}
	}
	for i, fact := range facts {
		if !present[i] {
			continue
		}
		logs, err := run(ctx, "logs", "--tail", "200", fact.ID)
		if err != nil || len(logs) > linkOutputLimit {
			return errors.Join(err, errors.New("direct bounded logs unavailable"))
		}
		ref, err := writeLinkPrivate(root, "", struct {
			RunID, ContainerID, Classification string
			Bytes                              []byte
		}{s.RunID, fact.ID, "PRIVATE RAW EVIDENCE", logs})
		if err != nil {
			return err
		}
		if _, err = writeLinkPrivate(root, "", struct {
			Facts                          linkFacts
			PrivateLogReference, LogSHA256 string
			LogBytes                       int
		}{fact, ref, linkDigest(logs), len(logs)}); err != nil {
			return err
		}
		// Logs and their receipt must be durable before destructive work. Admit
		// a fresh candidate through the same predicate immediately before rm.
		if _, err = validatedDirectIdentity(s); err != nil {
			return err
		}
		if _, exists, e := inspectDirectNetwork(ctx, s, run, id.NetworkID); e != nil || !exists {
			return errors.Join(e, errors.New("direct cleanup network changed before removal"))
		}
		current, exists, e := inspectDirectContainerRaw(ctx, run, fact.ID)
		if e != nil || !exists {
			return errors.Join(e, errors.New("direct cleanup broker changed before removal"))
		}
		if _, err = validateDirectContainer(current, s, i, id.NetworkID, id.Image, fact.ID, false); err != nil {
			return err
		}
		if _, err = run(ctx, "container", "rm", "-f", fact.ID); err != nil {
			return err
		}
	}
	if networkPresent {
		if _, err = validatedDirectIdentity(s); err != nil {
			return err
		}
		current, exists, e := inspectDirectNetwork(ctx, s, run, id.NetworkID)
		if e != nil || !exists || len(current.Containers) != 0 {
			return errors.Join(e, errors.New("direct cleanup network absence/empty attachment proof changed"))
		}
		if _, err = writeLinkPrivate(root, "", struct{ ID, Name string }{n.ID, n.Name}); err != nil {
			return err
		}
		_, err = run(ctx, "network", "rm", n.ID)
	}
	return err
}

func inspectDirectContainerRaw(ctx context.Context, run Executor, target string) ([]byte, bool, error) {
	body, err := run(ctx, "container", "inspect", target, "--format", "{{json .}}")
	if err != nil {
		var failure *linkDockerFailure
		if errors.As(err, &failure) && failure.ExactAbsence && !failure.PersistenceFailed {
			return nil, false, nil
		}
		return nil, false, err
	}
	return body, true, nil
}

func directStartupFailure(id string, file *os.File, outcome *error) {
	if *outcome != nil {
		*outcome = errors.Join(*outcome, stopPrivateFixtureOperation(id, directPrivateDirectory(id), "direct startup incomplete"))
	}
	var cause []byte
	if *outcome != nil {
		cause = []byte((*outcome).Error())
	}
	complete := len(cause) <= linkOutputLimit
	if !complete {
		cause = cause[:linkOutputLimit]
	}
	body, e := json.Marshal(struct {
		RunID         string
		Cause         []byte
		CauseComplete bool
	}{id, cause, complete})
	*outcome = errors.Join(*outcome, e, persistLinkPrivateReceipt(file, append(body, '\n')))
	if *outcome != nil {
		*outcome = errors.Join(*outcome, stopPrivateFixtureOperation(id, directPrivateDirectory(id), "direct startup custody incomplete"))
	}
}
