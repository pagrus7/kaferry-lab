package artifact

// PlatformIdentity binds the exact canonical platform and legacy request spelling
// to one published subject and executable. It is a source pin, not evidence that
// any current request has passed Verify or that the executable has been run.
type PlatformIdentity struct {
	Platform, RequestPlatform, ArchiveName, ProvenanceName string
	ArchiveSHA256, BinarySHA256                            string
	BinarySize                                             int
}

// ReviewedPlatform returns a copy of one of two fixed platform identities. Only
// exact canonical spellings are accepted; aliases and mixed separators refuse.
// ARM64 pins derive from retained static archive inspection, not fresh metadata
// or cryptographic verification. Verify must still obtain all required evidence.
func ReviewedPlatform(canonical string) (PlatformIdentity, bool) {
	switch canonical {
	case "linux/amd64":
		return PlatformIdentity{
			Platform: "linux/amd64", RequestPlatform: "linux-amd64",
			ArchiveName: archiveName, ProvenanceName: provenanceName,
			ArchiveSHA256: ArchiveSHA256, BinarySHA256: BinarySHA256, BinarySize: BinarySize,
		}, true
	case "linux/arm64":
		return PlatformIdentity{
			Platform: "linux/arm64", RequestPlatform: "linux-arm64",
			ArchiveName: "kaferry-v0.6.0-linux-arm64.tar.gz", ProvenanceName: "provenance-linux-arm64.json",
			ArchiveSHA256: "e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2",
			BinarySHA256:  "389aa874f084389b35f22a00002ee1ba8e66e3b563ee46e963f18e88dca97a92", BinarySize: 22085756,
		}, true
	default:
		return PlatformIdentity{}, false
	}
}

// Keep request admission exact without changing the existing dashed Request API.
func reviewedRequestPlatform(request string) (PlatformIdentity, bool) {
	switch request {
	case "linux-amd64":
		return ReviewedPlatform("linux/amd64")
	case "linux-arm64":
		return ReviewedPlatform("linux/arm64")
	default:
		return PlatformIdentity{}, false
	}
}
