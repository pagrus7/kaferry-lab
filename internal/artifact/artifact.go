// Package artifact verifies the one reviewed release without building or running it.
// It never writes extracted files. Callers persist the returned bytes/evidence.
package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	Tag                  = "v0.6.0"
	ReleaseID      int64 = 422917545
	ArchiveSHA256        = "d1ce67ce82f610b479b0458cc7f76b4a6cdb6094f60382d58edcc484ef12670f"
	BinarySHA256         = "becd8ee9762488af391097c5086a8105721725e753d07e8a9c0c0e70ae377770"
	BinarySize           = 23814268
	Commit               = "d7d485b96a52b711cb10d76dca09aa9b155dec5e"
	tagObject            = "689234eefe461435a89338322a001c2ea5240ad5"
	repository           = "https://github.com/pagrus7/kaferry"
	api                  = "https://api.github.com/repos/pagrus7/kaferry"
	archiveName          = "kaferry-v0.6.0-linux-amd64.tar.gz"
	provenanceName       = "provenance-linux-amd64.json"
	maxArchive           = 32 << 20
	maxDocument          = 2 << 20
)

// ContractRoot hashes the three reviewed source-document hashes in path order,
// using lowercase digest + two spaces + path + LF for each manifest line.
const ContractRoot = "df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46"

var (
	ErrUnsupported = errors.New("unsupported release identity or platform")
	ErrIdentity    = errors.New("release identity drift")
	ErrIntegrity   = errors.New("artifact integrity failure")
	ErrEvidence    = errors.New("required evidence unavailable or invalid")
	ErrProvenance  = errors.New("provenance not cryptographically verified")
)

// Document retains exact downloaded evidence, not a claim of signature validity.
type Document struct {
	URL, SHA256 string
	Bytes       []byte
}
type Contract struct{ Path, SHA256 string }
type Request struct{ Tag, Platform string }

// AttestationVerifier is a mandatory trust boundary, normally implemented by a
// trusted Sigstore/GitHub verifier. It must verify certificate trust, workflow
// identity, DSSE signature and transparency evidence against trusted roots, not
// merely decode JSON or trust its embedded certificate. This package binds the
// parsed statement to Identity separately. The callback must not execute Archive.
type AttestationVerifier func(context.Context, []byte, []byte, Identity) (Receipt, error)
type Identity struct{ Repository, Workflow, Ref, Commit, Subject, SHA256 string }
type Receipt struct {
	Verifier, Version string
	Output            []byte
}

type Verifier struct {
	Client *http.Client
	Attest AttestationVerifier
}

// Verified is returned only after every check, including Attest, succeeds.
// Version execution remains a separate platform-specific step: no binary is run.
// Checksums/API metadata are unsigned HTTPS observations, not signed attestations.
type Verified struct {
	Tag, Commit, Platform             string
	ReleaseID                         int64
	ReleaseImmutable                  bool
	ArchiveSHA256, BinarySHA256       string
	Archive, Binary, License, Notices []byte
	ContractSHA256                    string
	Contracts                         []Contract
	Evidence                          []Document
	Provenance                        Receipt
}

type releaseAsset struct {
	Name, Digest string
	Size         int64
	Download     string `json:"browser_download_url"`
}
type release struct {
	ID                           int64
	Tag                          string `json:"tag_name"`
	Draft, Prerelease, Immutable bool
	Assets                       []releaseAsset
}
type object struct{ SHA, Type string }
type ref struct {
	Ref    string
	Object object
}
type annotated struct {
	SHA, Tag string
	Object   object
}

var contractPins = []Contract{
	{"design/archive.md", "c78bb4ea8a48c53835e6c537e0fc4d1b63e6fbec4fb50f9f71771a1a098283d6"},
	{"design/client-compatibility.md", "7e0a52b112411b6023746a7421845601a004ca54d7de08176c56a972abf70b12"},
	{"design/decisions.md", "93ce1a40c36b1884c59e9619bb9d85d29ea4348562afa5444aab322bcd801d01"},
}

// Verify supports the two explicitly pinned Linux platforms for the reviewed release. A failed check
// returns nil: unavailable evidence, unsigned metadata or a parsed payload cannot
// become Verified. Mutable release metadata cannot replace the reviewed archive
// or executable bytes, even if new checksums and attestations agree. Cancellation and a two-minute upper bound cover all requests.
func (v Verifier) Verify(ctx context.Context, request Request) (*Verified, error) {
	platform, ok := reviewedRequestPlatform(request.Platform)
	if request.Tag != Tag || !ok {
		return nil, ErrUnsupported
	}
	return v.verify(ctx, request, releasePins{ReleaseID, platform.ArchiveSHA256, platform.BinarySHA256, platform.BinarySize})
}

// releasePins is package-private so network-free tests can use visibly synthetic
// bytes. Public Verify always uses the fixed platform identity pins.
type releasePins struct {
	releaseID                   int64
	archiveSHA256, binarySHA256 string
	binarySize                  int
}

func (v Verifier) verify(ctx context.Context, request Request, pins releasePins) (*Verified, error) {
	platform, ok := reviewedRequestPlatform(request.Platform)
	if request.Tag != Tag || !ok {
		return nil, ErrUnsupported
	}
	archiveName, provenanceName := platform.ArchiveName, platform.ProvenanceName
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out := &Verified{Tag: Tag, Commit: Commit, Platform: request.Platform}
	get := func(address string, limit int64) ([]byte, error) {
		data, err := v.download(ctx, address, limit)
		if err != nil {
			return nil, err
		}
		out.Evidence = append(out.Evidence, Document{address, digest(data), data})
		return data, nil
	}
	decode := func(address string, dst any) error {
		data, err := get(address, maxDocument)
		if err != nil {
			return err
		}
		if err = decodeJSON(data, dst); err != nil {
			return fmt.Errorf("%w: JSON at %s: %v", ErrEvidence, address, err)
		}
		return nil
	}
	var reference ref
	if err := decode(api+"/git/ref/tags/"+Tag, &reference); err != nil {
		return nil, err
	}
	if reference.Ref != "refs/tags/"+Tag || reference.Object.Type != "tag" || reference.Object.SHA != tagObject {
		return nil, fmt.Errorf("%w: annotated tag ref", ErrIdentity)
	}
	var tag annotated
	if err := decode(api+"/git/tags/"+reference.Object.SHA, &tag); err != nil {
		return nil, err
	}
	if tag.SHA != tagObject || tag.Tag != Tag || tag.Object.Type != "commit" || tag.Object.SHA != Commit {
		return nil, fmt.Errorf("%w: tag target", ErrIdentity)
	}
	var rel release
	if err := decode(api+"/releases/tags/"+Tag, &rel); err != nil {
		return nil, err
	}
	if rel.ID != pins.releaseID || rel.Tag != Tag || rel.Draft || rel.Prerelease {
		return nil, fmt.Errorf("%w: published release", ErrIdentity)
	}
	out.ReleaseID = rel.ID
	out.ReleaseImmutable = rel.Immutable
	assets := map[string]releaseAsset{}
	for _, a := range rel.Assets {
		if _, ok := assets[a.Name]; ok {
			return nil, fmt.Errorf("%w: duplicate asset", ErrEvidence)
		}
		assets[a.Name] = a
	}
	fetchAsset := func(name string, limit int64) ([]byte, error) {
		a, ok := assets[name]
		if !ok || a.Size <= 0 || a.Size > limit || a.Download != repository+"/releases/download/"+Tag+"/"+name || !validDigest(strings.TrimPrefix(a.Digest, "sha256:")) || !strings.HasPrefix(a.Digest, "sha256:") {
			return nil, fmt.Errorf("%w: asset metadata for %s", ErrEvidence, name)
		}
		data, err := get(a.Download, limit)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != a.Size || "sha256:"+digest(data) != a.Digest {
			return nil, fmt.Errorf("%w: API digest/size for %s", ErrIntegrity, name)
		}
		return data, nil
	}
	sums, err := fetchAsset("SHA256SUMS", maxDocument)
	if err != nil {
		return nil, err
	}
	checksums, err := parseChecksums(sums)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{archiveName, provenanceName} {
		a, ok := assets[name]
		expected, found := checksums[name]
		if !ok || !found || "sha256:"+expected != a.Digest {
			return nil, fmt.Errorf("%w: checksum/API agreement for %s", ErrIntegrity, name)
		}
	}
	archive, err := fetchAsset(archiveName, maxArchive)
	if err != nil {
		return nil, err
	}
	if digest(archive) != pins.archiveSHA256 {
		return nil, fmt.Errorf("%w: reviewed archive digest", ErrIdentity)
	}
	bundle, err := fetchAsset(provenanceName, maxDocument)
	if err != nil {
		return nil, err
	}
	files, err := extract(archive)
	if err != nil {
		return nil, err
	}
	out.Archive = archive
	out.Binary = files["kaferry"]
	out.License = files["LICENSE"]
	out.Notices = files["THIRD_PARTY_NOTICES.txt"]
	out.ArchiveSHA256 = digest(archive)
	out.BinarySHA256 = digest(out.Binary)
	if out.BinarySHA256 != pins.binarySHA256 || len(out.Binary) != pins.binarySize {
		return nil, fmt.Errorf("%w: reviewed executable identity", ErrIdentity)
	}
	var manifest strings.Builder
	for _, pin := range contractPins {
		data, err := get("https://raw.githubusercontent.com/pagrus7/kaferry/"+Commit+"/"+pin.Path, maxDocument)
		if err != nil {
			return nil, err
		}
		if digest(data) != pin.SHA256 {
			return nil, fmt.Errorf("%w: source contract %s", ErrIntegrity, pin.Path)
		}
		out.Contracts = append(out.Contracts, pin)
		fmt.Fprintf(&manifest, "%s  %s\n", pin.SHA256, pin.Path)
	}
	out.ContractSHA256 = digest([]byte(manifest.String()))
	if out.ContractSHA256 != ContractRoot {
		return nil, fmt.Errorf("%w: reviewed contract root", ErrIntegrity)
	}
	identity := Identity{repository, ".github/workflows/release.yml", "refs/tags/" + Tag, Commit, archiveName, out.ArchiveSHA256}
	if err := bindProvenance(bundle, identity); err != nil {
		return nil, err
	}
	if v.Attest == nil {
		return nil, fmt.Errorf("%w: trusted verifier required", ErrProvenance)
	}
	receipt, err := v.Attest(ctx, bytes.Clone(archive), bytes.Clone(bundle), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProvenance, err)
	}
	if receipt.Verifier == "" || receipt.Version == "" || len(receipt.Output) == 0 || len(receipt.Output) > maxDocument {
		return nil, fmt.Errorf("%w: verifier receipt missing", ErrProvenance)
	}
	out.Provenance = receipt
	return out, nil
}

func (v Verifier) download(ctx context.Context, address string, limit int64) ([]byte, error) {
	client := http.Client{Timeout: 30 * time.Second}
	if v.Client != nil {
		client = *v.Client
		if client.Timeout == 0 || client.Timeout > 30*time.Second {
			client.Timeout = 30 * time.Second
		}
	}
	oldRedirect := client.CheckRedirect
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || !trustedURL(r.URL) {
			return fmt.Errorf("%w: redirect", ErrEvidence)
		}
		if oldRedirect != nil {
			return oldRedirect(r, via)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	if !trustedURL(req.URL) {
		return nil, fmt.Errorf("%w: URL", ErrEvidence)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kaferry-lab-artifact")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrEvidence, address, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s: HTTP %d", ErrEvidence, address, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: bounded body at %s", ErrEvidence, address)
	}
	return data, nil
}
func trustedURL(u *url.URL) bool {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "api.github.com", "github.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	}
	return false
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func parseChecksums(data []byte) (map[string]string, error) {
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if len(line) < 67 || line[64:66] != "  " || !validDigest(line[:64]) {
			return nil, fmt.Errorf("%w: malformed SHA256SUMS", ErrEvidence)
		}
		name := line[66:]
		if name == "" || strings.ContainsAny(name, "/\\\r\n\t ") || name == "." || name == ".." {
			return nil, fmt.Errorf("%w: checksum path", ErrEvidence)
		}
		if _, ok := result[name]; ok {
			return nil, fmt.Errorf("%w: duplicate checksum", ErrEvidence)
		}
		result[name] = line[:64]
	}
	return result, nil
}
