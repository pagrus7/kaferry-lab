package fixture

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

const imageArchiveMaximum = 512 << 20
const imageArchiveJSONMaximum = 64 << 10
const imageArchiveEntryMaximum = 256

// These private inputs are supplied by a reviewed fixed image profile, never an
// arbitrary production registry selector. Synthetic controls use their own pins.
type imageArchiveDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
type imageArchiveExpected struct {
	Manifest, Config imageArchiveDescriptor
	OS, Architecture string
}
type imageArchiveResult struct {
	Complete                             bool
	ArchiveBytes                         int64
	ArchiveSHA256                        string
	Entries, Blobs                       int
	Manifest, Config                     []byte
	ManifestDescriptor, ConfigDescriptor imageArchiveDescriptor
	Layers                               []imageArchiveDescriptor
}
type imageArchiveLimits struct {
	bytes              int64
	entries, jsonBytes int
}

type imageArchiveStream struct {
	source         io.Reader
	digest         hash.Hash
	count, maximum int64
}

func (r *imageArchiveStream) Read(p []byte) (int, error) {
	if int64(len(p)) > r.maximum-r.count+1 {
		p = p[:r.maximum-r.count+1]
	}
	n, err := r.source.Read(p)
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	if n > 0 {
		r.count += int64(n)
		_, _ = r.digest.Write(p[:n])
	}
	if r.count > r.maximum {
		return n, errors.New("image archive exceeds whole-stream byte bound")
	}
	return n, err
}
func imageArchiveDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func imageArchivePath(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}
func imageArchiveDescriptorValid(d imageArchiveDescriptor) bool {
	return imageArchiveDigest(d.Digest) && d.Size > 0 && d.Size <= imageArchiveJSONMaximum
}

// readImageArchive consumes a complete stock OCI-save tar. It neither closes the
// caller's stream nor establishes process/wait/sink closure. An exported index is
// local export metadata, never proof of the original registry index/reference.
func readImageArchive(source io.Reader, expected imageArchiveExpected) (imageArchiveResult, error) {
	return readImageArchiveBounded(source, expected, imageArchiveLimits{imageArchiveMaximum, imageArchiveEntryMaximum, imageArchiveJSONMaximum})
}
func readImageArchiveBounded(source io.Reader, expected imageArchiveExpected, limits imageArchiveLimits) (imageArchiveResult, error) {
	var zero imageArchiveResult
	fail := func(err error) (imageArchiveResult, error) {
		return zero, fmt.Errorf("verify image save archive: %w", err)
	}
	if source == nil || limits.bytes <= 0 || limits.bytes > imageArchiveMaximum || limits.entries <= 0 || limits.entries > imageArchiveEntryMaximum || limits.jsonBytes <= 0 || limits.jsonBytes > imageArchiveJSONMaximum || !imageArchiveDescriptorValid(expected.Manifest) || !imageArchiveDescriptorValid(expected.Config) || expected.OS != "linux" || expected.Architecture != "arm64" {
		return fail(errors.New("invalid fixed image archive admission"))
	}
	configMedia := "application/vnd.oci.image.config.v1+json"
	layerMedia := "application/vnd.oci.image.layer.v1.tar+gzip"
	switch expected.Manifest.MediaType {
	case "application/vnd.oci.image.manifest.v1+json":
	case "application/vnd.docker.distribution.manifest.v2+json":
		configMedia = "application/vnd.docker.container.image.v1+json"
		layerMedia = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	default:
		return fail(errors.New("unreviewed selected manifest media type"))
	}
	if expected.Config.MediaType != configMedia {
		return fail(errors.New("selected config media type mismatch"))
	}
	stream := &imageArchiveStream{source: source, digest: sha256.New(), maximum: limits.bytes}
	reader := tar.NewReader(stream)
	seen := make(map[string]bool)
	blobs := make(map[string]int64)
	metadata := make(map[string][]byte)
	var result imageArchiveResult
	for {
		before := stream.count
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			// Each successful archive must contain the two explicit terminating
			// zero blocks, not merely an underlying EOF at a header boundary.
			if stream.count-before < 1024 {
				return fail(errors.New("image archive missing complete two-block terminator"))
			}
			break
		}
		if err != nil {
			return fail(fmt.Errorf("read tar header: %w", err))
		}
		result.Entries++
		if result.Entries > limits.entries {
			return fail(errors.New("image archive entry bound exceeded"))
		}
		if seen[header.Name] {
			return fail(errors.New("duplicate image archive member"))
		}
		seen[header.Name] = true
		// USTAR is the narrow admitted format; actual native export format
		// remains an integration evidence requirement.
		// Reject PAX/GNU extensions rather than allowing tar.Reader's merged
		// names/metadata to hide additional physical entries or aliases.
		if header.Format != tar.FormatUSTAR || len(header.PAXRecords) != 0 || header.Linkname != "" || header.Size < 0 || header.Size > limits.bytes {
			return fail(errors.New("image archive header format or size rejected"))
		}
		if header.Name == "blobs" || header.Name == "blobs/sha256" {
			if header.Typeflag != tar.TypeDir || header.Size != 0 {
				return fail(errors.New("image archive directory type rejected"))
			}
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fail(errors.New("image archive nonregular member rejected"))
		}
		blob := strings.HasPrefix(header.Name, "blobs/sha256/") && imageArchiveDigest("sha256:"+strings.TrimPrefix(header.Name, "blobs/sha256/"))
		selected := header.Name == imageArchivePath(expected.Manifest.Digest) || header.Name == imageArchivePath(expected.Config.Digest)
		plain := header.Name == "index.json" || header.Name == "manifest.json" || header.Name == "oci-layout"
		if !blob && !plain {
			return fail(errors.New("image archive noncanonical member path"))
		}
		if (selected || plain) && header.Size > int64(limits.jsonBytes) {
			return fail(errors.New("image archive selected JSON bound exceeded"))
		}
		digest := sha256.New()
		var saved bytes.Buffer
		var sink io.Writer = digest
		if selected || plain {
			sink = io.MultiWriter(digest, &saved)
		}
		count, err := io.Copy(sink, reader)
		if err != nil {
			return fail(fmt.Errorf("read tar member %s: %w", header.Name, err))
		}
		if count != header.Size {
			return fail(errors.New("image archive incomplete member"))
		}
		if blob {
			if hex.EncodeToString(digest.Sum(nil)) != strings.TrimPrefix(header.Name, "blobs/sha256/") {
				return fail(errors.New("image archive blob digest mismatch"))
			}
			blobs["sha256:"+strings.TrimPrefix(header.Name, "blobs/sha256/")] = count
			result.Blobs++
		}
		if selected || plain {
			metadata[header.Name] = saved.Bytes()
		}
	}
	// tar.Reader stops at its terminator; independently consume the source to
	// actual EOF. Nonzero trailers, a later read failure and over-limit zero
	// padding all reject. Include every accepted trailing zero in the hash.
	buffer := make([]byte, 32<<10)
	for {
		n, err := stream.Read(buffer)
		for _, value := range buffer[:n] {
			if value != 0 {
				return fail(errors.New("image archive nonzero trailing bytes"))
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("read archive trailer: %w", err))
		}
		if n == 0 {
			return fail(io.ErrNoProgress)
		}
	}
	if stream.count%512 != 0 {
		return fail(errors.New("image archive incomplete trailing block"))
	}
	manifestRaw, configRaw := metadata[imageArchivePath(expected.Manifest.Digest)], metadata[imageArchivePath(expected.Config.Digest)]
	if int64(len(manifestRaw)) != expected.Manifest.Size || int64(len(configRaw)) != expected.Config.Size {
		return fail(errors.New("selected manifest or config missing or size mismatch"))
	}
	var manifest struct {
		SchemaVersion int                      `json:"schemaVersion"`
		MediaType     string                   `json:"mediaType"`
		Config        imageArchiveDescriptor   `json:"config"`
		Layers        []imageArchiveDescriptor `json:"layers"`
	}
	if err := decodeImageArchiveJSON(manifestRaw, &manifest); err != nil {
		return fail(fmt.Errorf("decode selected manifest: %w", err))
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != expected.Manifest.MediaType || manifest.Config != expected.Config || len(manifest.Layers) == 0 || len(manifest.Layers) > limits.entries {
		return fail(errors.New("selected image manifest commitment mismatch"))
	}
	for _, layer := range manifest.Layers {
		size, exists := blobs[layer.Digest]
		if !imageArchiveDigest(layer.Digest) || layer.MediaType != layerMedia || layer.Size < 0 || !exists || size != layer.Size {
			return fail(errors.New("selected image layer commitment missing or mismatched"))
		}
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := decodeImageArchiveJSON(configRaw, &config); err != nil {
		return fail(fmt.Errorf("decode selected config: %w", err))
	}
	if config.OS != expected.OS || config.Architecture != expected.Architecture || config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return fail(errors.New("selected config platform or rootfs mismatch"))
	}
	for _, diff := range config.RootFS.DiffIDs {
		if !imageArchiveDigest(diff) {
			return fail(errors.New("selected config invalid diff ID"))
		}
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := decodeImageArchiveJSON(metadata["oci-layout"], &layout); err != nil {
		return fail(fmt.Errorf("decode OCI layout: %w", err))
	}
	if layout.Version != "1.0.0" {
		return fail(errors.New("unsupported OCI layout version"))
	}
	var index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			imageArchiveDescriptor
			Platform *struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := decodeImageArchiveJSON(metadata["index.json"], &index); err != nil {
		return fail(fmt.Errorf("decode exported index: %w", err))
	}
	if index.SchemaVersion != 2 || index.MediaType != "application/vnd.oci.image.index.v1+json" {
		return fail(errors.New("unsupported exported index"))
	}
	matches := 0
	for _, entry := range index.Manifests {
		if entry.Digest == expected.Manifest.Digest {
			matches++
			if entry.imageArchiveDescriptor != expected.Manifest || entry.Platform != nil && (entry.Platform.OS != expected.OS || entry.Platform.Architecture != expected.Architecture) {
				return fail(errors.New("exported selected descriptor mismatch"))
			}
		}
	}
	if matches != 1 {
		return fail(errors.New("exported selected descriptor missing or ambiguous"))
	}
	// Legacy Docker manifest metadata is not the OCI config identity oracle.
	// If present, still refuse malformed, duplicate-key or non-array JSON.
	if body, exists := metadata["manifest.json"]; exists {
		var legacy []json.RawMessage
		if err := decodeImageArchiveJSON(body, &legacy); err != nil {
			return fail(fmt.Errorf("decode legacy export metadata: %w", err))
		}
	}
	result.Manifest, result.Config = manifestRaw, configRaw
	result.ManifestDescriptor, result.ConfigDescriptor = expected.Manifest, expected.Config
	result.Layers = manifest.Layers
	result.ArchiveBytes, result.ArchiveSHA256 = stream.count, hex.EncodeToString(stream.digest.Sum(nil))
	result.Complete = true
	return result, nil
}

// Reject duplicate keys and excessive nesting before decoding the narrow view.
// Preserve concrete JSON decoder/read errors through wrapping at the caller.
func decodeImageArchiveJSON(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("image archive JSON nesting bound exceeded")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return errors.New("duplicate image archive JSON key")
				}
				keys[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected image archive JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("trailing image archive JSON value")
	}
	return json.Unmarshal(body, value)
}
