# Local Linux ARM64 qualification target

On 2026-10-26, the user selected native Linux ARM64 execution under OrbStack on
an Apple M4 Pro Mac, replacing native Linux AMD64 as the required final target.
Execution and private evidence retention stay on the Mac. Tailscale and hosted
Linux workers are not selected. All M0–M6 fault, oracle, recovery and review
requirements remain in force. A future ARM64 result will make no AMD64 claim.

This is a target decision, not an implemented port or a qualification result.
The current CLI admits the pinned AMD64 executable, and existing evidence and
process gates deliberately reject ARM64. Do not remove those gates to obtain a
green run. Preserve earlier accepted M0/M1 and bounded M2 evidence as historical
AMD64 measurements. Revalidate architecture-sensitive capabilities on ARM64;
portable checker results alone cannot establish those runtime capabilities.

## Published subject and current evidence

The target remains published Kaferry v0.6.0, commit
`d7d485b96a52b711cb10d76dca09aa9b155dec5e`, with reviewed contract root
`df2f5b7965ed15e7f434f2b06e16b2982c86b63a34dd48cd52ae918a7384eb46`.
Retained release metadata and SHA256SUMS from run40274928298's completed healthy
PRESERVE job list these ARM64 assets:

| Asset | Bytes | SHA-256 in retained metadata and checksum file |
| --- | ---: | --- |
| `kaferry-v0.6.0-linux-arm64.tar.gz` | 7,858,654 | `e79718f78eb5619e51a4505e3a87ddc37c38dd7049292bfe4b6037cbe5102bf2` |
| `provenance-linux-arm64.json` | 10,513 | `b26408c35c49def617360668f2688894e329685c3462071d3373b04a1741fea0` |

This is historical asset discovery only. The ARM64 archive, executable digest,
ELF identity, signed provenance and native version have not been verified by
this lab. Do not use the historical metadata as a fallback for failed fresh
verification. The separate source-startup job's tag-metadata GET returned403;
its provider reason was not retained. That failure remains UNVERIFIED, with no
unchanged retry, alternate credential, endpoint, cache or source fallback.

Fresh admission must bind one exact platform/archive/executable/provenance
identity to the unchanged contract. Keep historical AMD64 bundle checking
available; an ARM64 subject may not borrow AMD64 hashes, names, process points
or attestation receipts. Do not add a source-build fallback.

## Local execution and custody boundary

Read-only inspection found OrbStack2.2.3, a Linux/aarch64 Docker engine, and an
Apple M4 Pro/arm64 host. OrbStack uses Rosetta for AMD64 programs on Apple
silicon; `--platform linux/amd64` therefore cannot establish native AMD64
execution. See [OrbStack architecture](https://docs.orbstack.dev/architecture)
and [Intel emulation](https://docs.orbstack.dev/docker/).

A dedicated preparation machine was created as `kaferry-lab-arm64-20261026`, with
Ubuntu24.04/ARM64, two CPUs, 4GiB memory and a16GiB disk limit. Its intended
boundary uses `--isolated --isolate-network`, no host mounts and no forwarded
SSH agent. Identify ownership before creation and retain command outputs and
any notices privately. Do not start a GitHub listener during preparation.
The first root filesystem transfer failed with an HTTP/2 protocol error; the
original was retained. One bounded retry used the same command and source and
succeeded. Native `Linux aarch64` was observed. A123-byte synthetic file was
written with fsync, read back, read again after one clean stop/start, copied
to private host storage and checked after final stop. All second-attempt
commands exited0 with empty stderr. The machine is stopped. This calibrates
local storage only: no Go build, provenance verification, Kaferry, GitHub job,
network fault or capture ran. It proves neither CI custody nor backup, power
failure durability or isolation from privileged guest code.

OrbStack machines and containers share a Linux kernel. Isolation flags do not
create an independent kernel or prove protection against hostile public PR
code. A different guest username does not establish a non-admin account;
default passwordless sudo must be accounted for before runner admission.
The recorded guest mount table includes shared block-device nodes; their
permissions and capabilities were not measured, and no device contents were
read. Do not infer protection of other OrbStack storage or permit privileged
storage faults from isolation flags alone.
See [isolated machines](https://docs.orbstack.dev/machines/isolated).

The public-repository Mac runner21 remains offline. Custom labels, first-time
contributor approval and a job-level condition cannot restrict other workflows
that select a repository runner. Before activation, establish supported trusted
admission, a narrow storage boundary and least-privilege job credentials. A
private control repository or verified restricted organization runner group is
a possible separate arrangement, not something provisioned by this decision.
Do not reassign the four other-project runners or expose their files or Docker
socket to the lab job.

Private originals and unknown-notice capsules stay off GitHub logs, artifacts,
caches, repositories and releases, even if encrypted. A local producer can
retain them without a network courier. Existing private-store helper admission,
exact-attempt closure/receipt/hash checks, bounded retention and independent
recovery still apply. A directory path or a single file hash is not durable CI
custody. Keep decryption keys outside the worker; same-host copies are one
failure domain. Only separately reviewed redacted facts may be published.

## Required adaptation and admission checks

1. Establish permitted build and provenance verification operations without
   bypassing the recorded local stops. Local Go/build/test/vet/typecheck,
   Sigstore-cache and packet-capture operations remain stopped. A new runner,
   VM, UID, cache directory or verifier is not a remedy for a denied action.
   Retain exact notices and obtain resolution through the responsible control.
   Data-only inspection and bounded environment/storage preparation remain
   separate permitted work.
2. Verify the immutable ARM64 subject and review its exact pins. Adapt
   `internal/artifact`, `cmd/lab/verify.go`, `internal/evidence` and scenario
   admission consistently. Negative controls must reject cross-platform
   substitutions; historical AMD64 offline checks must keep their meaning.
3. Validate the ARM64 Go process/native-kernel identity and Linux process
   ownership, stop/continue, subreaper, terminal wait and resource accounting.
   Existing AMD64-only test build tags and skip gates are not ARM64 evidence.
4. Verify pinned native ARM64 Kafka/proxy manifests and actual container image
   identities. Adapt advertised endpoints and the independent observer path for
   the isolated guest. Do not use another project's shared Docker socket or
   silently run AMD64 images through Rosetta.
5. Rework and calibrate architecture-specific public ELF/Go metadata, entry
   anchors and any selected hardware/caller observer. Existing x86 register,
   instruction/frame and hardware-point research does not transfer to AArch64.
   Missing capability stays UNSUPPORTED; generic logs, timers and errors cannot
   prove accepted work, drain, save timing or worker ACK receipt.
6. Establish trusted runner admission and actual private storage/recovery.
   Then port the workflow steps and Linux assertions deliberately. The old
   `ubuntu-24.04` workflow is disabled at the repository while this transition
   is incomplete. Its source is retained; disabled CI is not passing CI.
7. Obtain independent docs, test/oracle and simplicity reviews of frozen
   increments, then run permitted final-head ARM64 CI and all required M2–M6
   cases with fault-reached, restoration, reaped-process and offline-checkable
   evidence. Missing observations never pass. Open no PR before completion.

For each runtime fault, continue using Given/When/Then and the existing evidence
rules. A local platform change supplies no new product scenario, does not
qualify Kaferry, and does not remove any required timeout, threshold or
source-save case.
