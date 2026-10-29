package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ImageManifestIdentity is the selected native execution manifest, distinct
// from both the image-store target and the immutable configuration blob.
type ImageManifestIdentity struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform"`
}

type LinkImageIdentity struct {
	Mode, RuntimeImageID, ConfigDigest, ProofSHA256 string
	Manifest                                        *ImageManifestIdentity `json:",omitempty"`
}

const classicImageMode = "exact-config-v1"
const manifestImageMode = "native-arm64-manifest-v1"
const identityOCIManifest = "application/vnd.oci.image.manifest.v1+json"
const identityOCIIndex = "application/vnd.oci.image.index.v1+json"
const identityDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

type fixedModernImage struct {
	reference, runtime       string
	target, manifest, config imageArchiveDescriptor
	role                     string
}

func modernImage(s State, reference string) (fixedModernImage, error) {
	p, err := fixedImageProfile(s.DockerPlatform)
	if err != nil || p.architecture != "arm64" {
		return fixedModernImage{}, errors.New("unreviewed modern image platform")
	}
	if reference == Image {
		return fixedModernImage{Image, "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02", imageArchiveDescriptor{identityOCIIndex, "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02", 1609}, imageArchiveDescriptor{identityOCIManifest, "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", 2201}, imageArchiveDescriptor{"application/vnd.oci.image.config.v1+json", arm64BrokerConfigID, 8254}, "broker"}, nil
	}
	if reference == arm64ProxyImage {
		d := imageArchiveDescriptor{identityDockerManifest, strings.TrimPrefix(arm64ProxyImage, "ghcr.io/shopify/toxiproxy@"), 739}
		return fixedModernImage{arm64ProxyImage, d.Digest, d, d, imageArchiveDescriptor{"application/vnd.docker.container.image.v1+json", arm64ProxyConfigID, 1822}, "proxy"}, nil
	}
	return fixedModernImage{}, errors.New("unreviewed modern image reference")
}

func nativeManifest(d imageArchiveDescriptor) *ImageManifestIdentity {
	m := &ImageManifestIdentity{MediaType: d.MediaType, Digest: d.Digest, Size: d.Size}
	m.Platform.OS, m.Platform.Architecture = "linux", "arm64"
	return m
}

func sameManifest(a, b *ImageManifestIdentity) bool { return a != nil && b != nil && *a == *b }

// ValidatedLinkImage accepts historical journals only for their exact config
// IDs. Modern journals require a distinct mode and same-run retained proof.
func ValidatedLinkImage(s State, proxy bool) (LinkImageIdentity, error) {
	p, err := fixedImageProfile(s.DockerPlatform)
	if err != nil || s.Proxy == nil {
		return LinkImageIdentity{}, errors.New("linked image state unavailable")
	}
	id, want, reference, saved := s.Proxy.BrokerImageID, p.brokerConfig, Image, s.Proxy.BrokerImageIdentity
	if proxy {
		id, want, reference, saved = s.Proxy.ImageID, p.proxyConfig, p.proxyImage, s.Proxy.ImageIdentity
	}
	if id == want {
		classic := LinkImageIdentity{Mode: classicImageMode, RuntimeImageID: id, ConfigDigest: want}
		if saved != nil && *saved != classic {
			return LinkImageIdentity{}, errors.New("classic image identity carries conflicting manifest authority")
		}
		return classic, nil
	}
	modern, err := modernImage(s, reference)
	if err != nil || saved == nil || saved.Mode != manifestImageMode || saved.RuntimeImageID != id || id != modern.runtime || saved.ConfigDigest != modern.config.Digest || !sameManifest(saved.Manifest, nativeManifest(modern.manifest)) || !linkID(saved.ProofSHA256) {
		return LinkImageIdentity{}, errors.New("modern runtime image requires exact typed manifest/config proof")
	}
	proof, err := loadImageProof(s, modern)
	if err != nil || proof.ProofSHA256 != saved.ProofSHA256 {
		return LinkImageIdentity{}, errors.Join(errors.New("retained image proof missing or changed"), err)
	}
	return *saved, nil
}

func ValidateLinkContainerImage(s State, proxy bool, runtimeID string, descriptor *ImageManifestIdentity) error {
	id, err := ValidatedLinkImage(s, proxy)
	if err != nil {
		return err
	}
	if runtimeID != id.RuntimeImageID || id.Mode == manifestImageMode && !sameManifest(descriptor, id.Manifest) || id.Mode == classicImageMode && descriptor != nil {
		return errors.New("container runtime target or native manifest mismatch")
	}
	return nil
}

type imageInspectIdentity struct {
	ID           string `json:"Id"`
	OS           string `json:"Os"`
	Architecture string
	RepoDigests  []string
	Descriptor   *struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		Platform  *struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant,omitempty"`
		} `json:"platform"`
	}
}

func inspectModernImage(raw []byte, fixed fixedModernImage, selected bool) error {
	var got imageInspectIdentity
	if len(raw) > linkOutputLimit || decodeImageArchiveJSON(raw, &got) != nil || got.OS != "linux" || got.Architecture != "arm64" || len(got.RepoDigests) != 1 || got.RepoDigests[0] != fixed.reference || got.Descriptor == nil {
		return errors.New("modern native image inspection missing exact reference/descriptor/platform")
	}
	want := fixed.target
	if selected {
		want = fixed.manifest
	}
	d := got.Descriptor
	if got.ID != want.Digest || d.MediaType != want.MediaType || d.Digest != want.Digest || d.Size != want.Size {
		return errors.New("modern image target or selected manifest differs from fixed pin")
	}
	if d.Platform != nil && (d.Platform.OS != "linux" || d.Platform.Architecture != "arm64" || d.Platform.Variant != "") {
		return errors.New("modern image descriptor platform conflicts")
	}
	if fixed.role == "broker" && selected && d.Platform == nil {
		return errors.New("selected broker manifest lacks native platform")
	}
	return nil
}

func imagePrivateAuthority(s State) (string, error) {
	if s.Proxy == nil || validateLinkPlan(s) != nil {
		return "", errors.New("modern image proof requires existing linked private authority; nonlinked M0 integration unavailable")
	}
	root := linkPrivateDirectory(s.RunID)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("private image authority directory unavailable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return "", errors.New("private image authority owner mismatch")
	}
	if _, err = os.Lstat(filepath.Join(root, "STOPPED.json")); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("image proof stopped or stop state unavailable")
	}
	body, err := readImagePrivateFile(filepath.Join(root, "PRIVATE.json"), 256<<10)
	var reservation struct{ RunID, Classification, Publication string }
	if err != nil || json.Unmarshal(body, &reservation) != nil || reservation.RunID != s.RunID || reservation.Classification != "PRIVATE RAW EVIDENCE" {
		return "", errors.New("existing private image reservation missing")
	}
	return root, nil
}

func readImagePrivateFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 || st.Size() < 0 || st.Size() > limit {
		return nil, errors.Join(errors.New("private image file identity/bound rejected"), f.Close())
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	if err = errors.Join(readErr, statErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(b)) > limit || !os.SameFile(st, after) || st.Size() != after.Size() || st.ModTime() != after.ModTime() {
		return nil, errors.New("private image file changed during read")
	}
	return b, nil
}

type imageProof struct {
	RunID, Reference, RuntimeImageID, ArchivePath, ArchiveSHA256 string
	ArchiveBytes                                                 int64
	Manifest, Config                                             []byte
	ManifestDescriptor, ConfigDescriptor                         imageArchiveDescriptor
	Complete                                                     bool
}

func imageProofPath(s State, fixed fixedModernImage) string {
	return filepath.Join(linkPrivateDirectory(s.RunID), "image-"+fixed.role+"-proof.json")
}

func validateImageProof(s State, fixed fixedModernImage, proof imageProof) error {
	if proof.RunID != s.RunID || proof.Reference != fixed.reference || proof.RuntimeImageID != fixed.runtime || proof.ArchivePath != savedImageArchivePath(s) || !proof.Complete || proof.ManifestDescriptor != fixed.manifest || proof.ConfigDescriptor != fixed.config || int64(len(proof.Manifest)) != fixed.manifest.Size || "sha256:"+linkDigest(proof.Manifest) != fixed.manifest.Digest || int64(len(proof.Config)) != fixed.config.Size || "sha256:"+linkDigest(proof.Config) != fixed.config.Digest {
		return errors.New("private image proof binding rejected")
	}
	result, err := parseSavedImage(s, fixed)
	if err != nil || !result.Complete || result.ArchiveBytes != proof.ArchiveBytes || result.ArchiveSHA256 != proof.ArchiveSHA256 {
		return errors.Join(errors.New("saved image archive missing, changed or incomplete"), err)
	}
	return nil
}

func loadImageProof(s State, fixed fixedModernImage) (LinkImageIdentity, error) {
	if _, err := imagePrivateAuthority(s); err != nil {
		return LinkImageIdentity{}, err
	}
	body, err := readImagePrivateFile(imageProofPath(s, fixed), 256<<10)
	var proof imageProof
	if err == nil {
		err = decodeImageArchiveJSON(body, &proof)
	}
	if err != nil {
		return LinkImageIdentity{}, errors.Join(errors.New("private image proof unavailable"), err)
	}
	if err = validateImageProof(s, fixed, proof); err != nil {
		return LinkImageIdentity{}, err
	}
	return LinkImageIdentity{Mode: manifestImageMode, RuntimeImageID: fixed.runtime, ConfigDigest: fixed.config.Digest, ProofSHA256: linkDigest(body), Manifest: nativeManifest(fixed.manifest)}, nil
}

func admitModernImage(ctx context.Context, run Executor, s State, reference string, raw []byte) (id LinkImageIdentity, err error) {
	fixed, err := modernImage(s, reference)
	if err != nil {
		return id, err
	}
	root, err := imagePrivateAuthority(s)
	if err != nil {
		return id, err
	}
	notice, err := os.CreateTemp(root, "image-admission-*.json")
	if err != nil {
		return id, errors.Join(err, stopLinkOperation(s.RunID, "image admission diagnostic reservation failed"))
	}
	defer finishImageControl(notice, s, "modern image admission incomplete", &err)
	if err = inspectModernImage(raw, fixed, false); err != nil {
		return id, err
	}
	selected, err := run(ctx, "image", "inspect", "--platform", "linux/arm64", reference, "--format", "{{json .}}")
	if err != nil {
		return id, err
	}
	if err = inspectModernImage(selected, fixed, true); err != nil {
		return id, err
	}
	if _, statErr := os.Lstat(imageProofPath(s, fixed)); statErr == nil {
		return loadImageProof(s, fixed)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return id, statErr
	}
	if err = ensureSavedImages(ctx, s); err != nil {
		return id, err
	}
	result, err := parseSavedImage(s, fixed)
	if err != nil {
		return id, err
	}
	proof := imageProof{s.RunID, reference, fixed.runtime, savedImageArchivePath(s), result.ArchiveSHA256, result.ArchiveBytes, result.Manifest, result.Config, result.ManifestDescriptor, result.ConfigDescriptor, result.Complete}
	if _, err = writeLinkPrivate(root, filepath.Base(imageProofPath(s, fixed)), proof); err != nil {
		return id, err
	}
	return loadImageProof(s, fixed)
}

func imageIdentityForInspection(s State, proxy bool, imageID string) (LinkImageIdentity, error) {
	p, err := fixedImageProfile(s.DockerPlatform)
	if err != nil {
		return LinkImageIdentity{}, err
	}
	want, ref := p.brokerConfig, Image
	if proxy {
		want, ref = p.proxyConfig, p.proxyImage
	}
	if imageID == want {
		return LinkImageIdentity{Mode: classicImageMode, RuntimeImageID: imageID, ConfigDigest: want}, nil
	}
	fixed, err := modernImage(s, ref)
	if err != nil || imageID != fixed.runtime {
		return LinkImageIdentity{}, fmt.Errorf("unreviewed runtime image target")
	}
	return loadImageProof(s, fixed)
}
