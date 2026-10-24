package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pagrus7/kaferry-lab/internal/artifact"
)

const runtimeImage = "apache/kafka@sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02"

type verifiedMetadata struct {
	Tag                       string              `json:"tag"`
	Commit                    string              `json:"commit"`
	Platform                  string              `json:"platform"`
	ReleaseID                 int64               `json:"release_id"`
	ReleaseImmutable          bool                `json:"github_release_immutable"`
	ArchiveSHA256             string              `json:"archive_sha256"`
	BinarySHA256              string              `json:"binary_sha256"`
	ContractSHA256            string              `json:"contract_sha256"`
	Contracts                 []artifact.Contract `json:"contracts"`
	VersionOutput             string              `json:"version_output"`
	VersionRuntime            string              `json:"version_runtime"`
	ProvenanceVerifier        string              `json:"provenance_verifier"`
	ProvenanceVerifierVersion string              `json:"provenance_verifier_version"`
	ReceiptSHA256             string              `json:"receipt_sha256"`
	Directory                 string              `json:"directory"`
}

func sha(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func newFile(path string, raw []byte, mode os.FileMode) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}

func verifiedClient() (*http.Client, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		pem, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SSL_CERT_FILE has no trusted certificates")
		}
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: t, Timeout: 30 * time.Second}, nil
}

func verify(ctx context.Context, directory string) (result verifiedMetadata, err error) {
	client, err := verifiedClient()
	if err != nil {
		return result, err
	}
	if err = os.MkdirAll(filepath.Dir(directory), 0755); err != nil {
		return result, err
	}
	if err = os.Mkdir(directory, 0755); err != nil {
		return result, err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			b, _ := json.Marshal(map[string]string{"status": "UNVERIFIED", "error": err.Error()})
			_ = newFile(filepath.Join(directory, "FAILED.json"), append(b, '\n'), 0644)
		}
	}()
	verifier := artifact.Verifier{Client: client, Attest: func(ctx context.Context, archive, bundle []byte, id artifact.Identity) (artifact.Receipt, error) {
		receipt := artifact.Receipt{Verifier: "gh attestation verify"}
		if e := newFile(filepath.Join(directory, id.Subject), archive, 0644); e != nil {
			return receipt, e
		}
		bundlePath := filepath.Join(directory, "provenance-linux-amd64.json")
		if e := newFile(bundlePath, bundle, 0644); e != nil {
			return receipt, e
		}
		version, e := exec.CommandContext(ctx, "gh", "--version").Output()
		if e != nil {
			return receipt, e
		}
		receipt.Version = strings.TrimSpace(strings.SplitN(string(version), "\n", 2)[0])
		args := []string{"attestation", "verify", filepath.Join(directory, id.Subject), "--bundle", bundlePath, "--repo", "pagrus7/kaferry", "--signer-workflow", "pagrus7/kaferry/" + id.Workflow, "--source-digest", id.Commit, "--source-ref", id.Ref, "--deny-self-hosted-runners", "--format", "json"}
		command := exec.CommandContext(ctx, "gh", args...)
		stderr, e := os.OpenFile(filepath.Join(directory, "gh-attestation.stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return receipt, e
		}
		command.Stderr = stderr
		raw, e := command.Output()
		closeErr := stderr.Close()
		_ = newFile(filepath.Join(directory, "gh-attestation.json"), raw, 0644)
		if e != nil {
			return receipt, fmt.Errorf("trusted attestation verification failed: %w (retained stderr)", e)
		}
		if closeErr != nil {
			return receipt, closeErr
		}
		var verified []json.RawMessage
		if e = json.Unmarshal(raw, &verified); e != nil || len(verified) == 0 {
			return receipt, fmt.Errorf("trusted verifier returned no valid verification results")
		}
		receipt.Output = raw
		return receipt, nil
	}}
	v, err := verifier.Verify(ctx, artifact.Request{Tag: artifact.Tag, Platform: "linux-amd64"})
	if err != nil {
		return result, err
	}
	for i, doc := range v.Evidence {
		raw, e := json.Marshal(map[string]any{"url": doc.URL, "sha256": doc.SHA256, "bytes": len(doc.Bytes)})
		if e != nil {
			return result, e
		}
		if e = newFile(filepath.Join(directory, fmt.Sprintf("document-%02d.metadata.json", i)), append(raw, '\n'), 0644); e != nil {
			return result, e
		}
		if e = newFile(filepath.Join(directory, fmt.Sprintf("document-%02d.raw", i)), doc.Bytes, 0644); e != nil {
			return result, e
		}
	}
	for _, f := range []struct {
		name string
		raw  []byte
		mode os.FileMode
	}{{"kaferry", v.Binary, 0555}, {"LICENSE", v.License, 0444}, {"THIRD_PARTY_NOTICES.txt", v.Notices, 0444}} {
		if err = newFile(filepath.Join(directory, f.name), f.raw, f.mode); err != nil {
			return result, err
		}
	}
	path := filepath.Join(directory, "kaferry")
	out, runtimeBoundary, e := observeVersion(ctx, path, directory)
	if e != nil {
		return result, e
	}
	if err = newFile(filepath.Join(directory, "version.txt"), out, 0644); err != nil {
		return result, err
	}
	if !strings.Contains(string(out), artifact.Tag) {
		return result, fmt.Errorf("version output does not identify reviewed tag")
	}
	after, e := os.ReadFile(path)
	if e != nil || sha(after) != v.BinarySHA256 {
		return result, fmt.Errorf("verified executable changed during version observation")
	}
	result = verifiedMetadata{Tag: v.Tag, Commit: v.Commit, Platform: "linux/amd64", ReleaseID: v.ReleaseID, ReleaseImmutable: v.ReleaseImmutable, ArchiveSHA256: v.ArchiveSHA256, BinarySHA256: v.BinarySHA256, ContractSHA256: v.ContractSHA256, Contracts: v.Contracts, VersionOutput: strings.TrimSpace(string(out)), VersionRuntime: runtimeBoundary, ProvenanceVerifier: v.Provenance.Verifier, ProvenanceVerifierVersion: v.Provenance.Version, ReceiptSHA256: sha(v.Provenance.Output), Directory: directory}
	raw, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return result, e
	}
	err = newFile(filepath.Join(directory, "verified.json"), append(raw, '\n'), 0644)
	return result, err
}

// Version output is bounded and container identity is recorded before start.
// --rm is supplemented by exact-label cleanup even when the Docker CLI times out.
type boundedOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := (64 << 10) - b.buffer.Len()
	if len(raw) > remaining {
		n, _ := b.buffer.Write(raw[:remaining])
		return n, fmt.Errorf("version output exceeded 64KiB budget")
	}
	return b.buffer.Write(raw)
}
func observeVersion(ctx context.Context, path, directory string) (out []byte, boundary string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--version")
	boundary = "native linux/amd64 host"
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		platform, e := exec.CommandContext(ctx, "docker", "info", "--format", "{{.OSType}}/{{.Architecture}}").Output()
		if e != nil {
			return nil, "", e
		}
		raw := make([]byte, 8)
		if _, e = rand.Read(raw); e != nil {
			return nil, "", e
		}
		id := "verify-" + hex.EncodeToString(raw)
		name := "kaferry-lab-" + id
		record, _ := json.Marshal(map[string]any{"name": name, "owner_label": id, "image": runtimeImage, "docker_platform": strings.TrimSpace(string(platform)), "target_platform": "linux/amd64", "network": "none", "memory": "128m", "cpus": 1})
		if e = newFile(filepath.Join(directory, "version-runtime.json"), append(record, '\n'), 0644); e != nil {
			return nil, "", e
		}
		defer func() {
			cleanup, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelCleanup()
			inspect, e := exec.CommandContext(cleanup, "docker", "container", "inspect", name, "--format", `{{index .Config.Labels "io.kaferry-lab.run"}}`).CombinedOutput()
			if e != nil {
				if strings.Contains(string(inspect), "No such object") || strings.Contains(string(inspect), "No such container") {
					e = nil
				}
			} else if strings.TrimSpace(string(inspect)) != id {
				e = fmt.Errorf("refuse cleanup of unowned version container %s", name)
			} else {
				_, e = exec.CommandContext(cleanup, "docker", "container", "rm", "-f", name).CombinedOutput()
			}
			cleanupRecord, _ := json.Marshal(map[string]any{"name": name, "cleanup_complete": e == nil, "detail": fmt.Sprint(e)})
			err = errors.Join(err, e, newFile(filepath.Join(directory, "version-cleanup.json"), append(cleanupRecord, '\n'), 0644))
		}()
		boundary = "linux/amd64 container on Docker " + strings.TrimSpace(string(platform)) + "; emulated when host architecture differs"
		command = exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "--label", "io.kaferry-lab.run="+id, "--platform", "linux/amd64", "--network", "none", "--read-only", "--memory", "128m", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", "type=bind,src="+directory+",dst=/artifact,readonly", "--entrypoint", "/artifact/kaferry", runtimeImage, "--version")
	}
	var buffer boundedOutput
	command.Stdout = &buffer
	command.Stderr = &buffer
	err = command.Run()
	out = buffer.buffer.Bytes()
	if err != nil {
		err = fmt.Errorf("verified version observation failed: %w: %s", err, out)
	}
	return out, boundary, err
}
