# Encrypted diagnostics on hosted runners

On 2026-10-26, the user changed direction to GitHub-hosted Ubuntu24.04/native
Linux AMD64 runners and the existing encryption proposal. This explicitly
supersedes the earlier prohibition on uploading encrypted capsules and the
local-only ARM64/Tailscale plans. Required M0–M6 observations, synthetic-only
workloads, fault ownership/bounds and local execution stops remain unchanged.

Only bounded encrypted diagnostic capsules receive this publication exception.
Plaintext originals, raw consultation transcripts and private keys must never
enter GitHub artifacts, logs, caches, repositories or releases. Public plaintext
remains limited to reviewed redacted facts. Treat uploaded ciphertext as public;
encryption does not make it redacted, and artifact expiry does not prove that
all copies disappear.

The hosted runner receives the pinned public recipient certificate only. The
private decryption key stays owner-only on the Mac. The existing stock OpenSSL
CMS envelope uses AES-256-CBC and RSA-OAEP/SHA-256 with MGF1/SHA-256. **CBC is not
AEAD.** Local recovery therefore requires authenticated GitHub API metadata for
the expected repository, workflow, head, run, attempt, job and artifact, plus the
SHA-256 of the complete ZIP, before parsing or decrypting any ciphertext. A
self-hash or adjacent JSON does not establish authenticity. Losing the private
key can make the capsule unrecoverable; copies on one Mac share one failure
domain.

## Hosted upload and local recovery

The workflow retains the actual foreground return and typed writer/tree closure
proof. Only that proof can authorize sealing the fixed private driver/fixture
roots. A declaration, marker or log alone is insufficient. After sealer terminal
completion, admission checks the exact run/head/job/attempt/certificate, bounded
regular0600 ciphertext, hash/size and matching caller facts. The upload contains
exactly one `notice.cms` member, with a canonical artifact name, no overwrite and
seven-day retention. It contains no plaintext metadata or private directory.
A failed calibration may retain complete encrypted evidence; upload or sealing
success never converts a failed, incomplete or unreached case into PASS.

The sealer's completion record still says that publication requires an explicit
exception. It does not grant permission itself; the narrowly gated workflow
uses the user's exception. The fixed public certificate is SHA-256
`ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57`.

`scripts/retrieve-link-notices.py` checks authenticated API identity and the
whole-ZIP digest; `scripts/unseal-link-notices.py` validates the sole ciphertext,
inner manifest and member hashes before exclusive private recovery. The existing
retriever permits exactly one encrypted notice artifact across a workflow run.
The reviewed unit transport sample runs only while linked runtime is disabled,
so it must not collide with a future linked capsule. Recover and independently
check each new actual run; historical sample success is not new custody proof.

The restored hosted path passed source/native review at `e521c099`. Its
calibration used the real Go diagnostic's known setup failure through the same
foreground/admission/sealing/upload path, then authenticated Mac recovery. The
single real diagnostic returned200 with the pinned annotated tag reference;
headers/body remain private. The historical403 reason remains unknown.

The next source activation enables stock-link runtime and ordinary release
verification on trusted feature pushes; those new runtime outcomes remain
unmeasured. Metadata dispatch remains separate and cannot trigger release jobs.
Do not retry with alternate credentials, endpoints, source or cache. Neither
metadata availability nor capsule recovery establishes Kaferry qualification.

## Metadata-only modes

The source implements `workflow_dispatch` modes `normal`,
`metadata-calibration` and `metadata-diagnostic` in the existing workflow, restricted
to `codex/resilience-release-lab`. The default is `normal`, preserving the partial
harness path. Dispatch and the actual Go/caller/capsule path were measured at `e521c099`; see
[setup evidence](setup.md#metadata-only-calibration-and-diagnostic). Fresh
exact-head source review, native evidence and private Mac recovery must precede
any newly selected diagnostic. `m1` and `m2-release` require trusted pushes and
cannot run in a metadata-only dispatch.

`metadata-calibration` exercises the metadata producer/caller and existing
encrypted transport using fixed synthetic observations and controlled child,
stream and sink failures. It must not contact the original metadata endpoint. The final
calibration also runs the freshly built Go executable through the same foreground,
admission, sealing and upload steps as the diagnostic. Only that synthetic invocation
selects a fixed, confirmed-absent trust file; ordinary trust setup must fail before any
HTTP client invocation. Admission requires the exact ENOENT cause, attempt_count0, no
response and closed incomplete return2. This is a negative fixture, never a TLS bypass
or an alternate trust route for the real request. Its recovered capsule contains
PRIVATE.json, metadata.json and capture-closure.json; verify those originals and actual
closure on the Mac before selecting the diagnostic.
Before selecting `metadata-diagnostic`, independently review the exact native calibration
result and authenticate, retrieve, decrypt and compare its known synthetic bytes
on the Mac. An earlier transport sample or successful upload alone cannot meet
that prerequisite for the newly selected path.

`metadata-diagnostic` must be explicitly selected after those prerequisites. It is one
unauthenticated GET of
`https://api.github.com/repos/pagrus7/kaferry/git/ref/tags/v0.6.0`, with Accept
`application/vnd.github+json` and User-Agent `kaferry-lab-artifact`. It has no
alternate URL, credentials, cache, redirect following or automatic chained
retry. A client invocation count does not prove remote receipt. The original403
body/headers were discarded and its reason remains unknown. A new response is
a separate observation; even an explicit explanation describes that new attempt,
and200 does not authorize release verification or qualify Kaferry.

Both metadata modes must suppress the ordinary unit sample and linked runtime
ciphertext uploads, leaving exactly one encrypted notice artifact across the
entire run. They reuse the existing fixture-v1 sealing, artifact convention,
authenticated ZIP retrieval and private unsealing without a new transport or
payload protocol. Their receipts use the calibration namespace and
`release_qualified:false`. Source-only proposals do not establish that these
paths have executed or that any new capsule has survived recovery.

The caller source reserves its private error/stream sinks before launch and
actually waits/reaps its sole producer, observes pipe EOF, closes its readers and
syncs/closes its private writers. The final closure JSON includes the bounded original caller-error graph and
base64 stream prefixes after those writers close; its own write, sync and close
must finish before the foreground caller returns. The workflow must observe that
return and validate the matching typed closure before sealing. A file, stable
inventory or closure declaration alone cannot establish that any writer stopped.
Missing or uncertain closure suppresses sealing/upload. A closed, explicitly
incomplete observation can retain useful failure evidence without passing the
request or capture check; an unreached request must remain explicitly unreached.

The private-filesystem handoff is no longer a workflow dependency. Its helper
and storage controls remain retained; the retired26caller integration controls
are preserved at `codex/m2-private-filesystem-retained-6ee`. The ARM64 source
proposal is preserved uncompiled/unrun at `codex/m2-arm64-source-proposal-20261026`.
The dedicated Mac runner remains offline and both local preparation machines
remain stopped. Tailscale is inactive. No other-project runner was reassigned.

## Bounds and incomplete evidence

The sealer accepts fixed run-owned regular0600 JSON receipts only: up to1,024
files,256KiB per file,8MiB payload and four path levels. The inner manifest binds
run/head/job/attempt/certificate/member bytes. Tar/CMS/ZIP caps remain10/12/16MiB.
Two inventories check consistency, not quiescence; actual caller closure proof
remains mandatory. Missing fixture roots use only the existing narrowly
admitted v2 absence receipt; other missing, malformed or denied inputs fail.

For the metadata path, the outer caller bounds each stdout/stderr pipe
prefix to64KiB. The producer's private stderr error envelope, including JSON,
base64 and newline, must be strictly smaller than48KiB; its underlying framed
error graph is capped at32KiB. Base64 preserves bytes and supplies no redaction
or encryption. These limits describe different encoding layers, not competing
caps on the same bytes.

The client-decoded response header frame prefix is capped at16KiB, exposed body
prefix at64KiB plus one overflow-detection byte, and framed observed
setup/transport/read/close/cancellation errors at32KiB. Decoded headers and a
possibly transparently decompressed body are not wire octets. Every affected
stream records completeness/overflow and observed-length limits; a truncated
prefix cannot claim the unseen bytes. Each final serialized JSON receipt,
including encoding expansion and newline, must fit the existing256KiB file cap.
These are source admission bounds. Native controls measure selected boundaries,
not proof that every possible cause fits. Overflow may leave incomplete evidence; missing or failed final
persistence cannot pass.

Complete input, terminal child wait/reap, joined stream copies and sink
sync/close must be observed. First-sink failure, lost runners, incomplete input,
final close or public-output failure can leave evidence unavailable. Admission
failures after sealing retain available originals privately on the transient
worker and suppress upload; those later errors are not retroactively inside the
completed capsule. Do not claim every failure is durably recoverable. Restore
owned faults and retain actual cleanup outcomes; cleanup0 does not prove writer
closure, calibration, accepted work, drain, save timing or worker ACK receipt.

## Retained helpers and validation scope

The private-filesystem helper remains available as retained source; its17storage
controls have historical native evidence. It is not required by hosted uploads.
The removed workflow caller test is preserved in the explicit private-filesystem
branch. The current exact-workflow encrypted-upload controls replace that
integration check, including incomplete closure, stale tuples, changed or unsafe
ciphertext, size bounds, cancellation, output failures and plaintext allowlists.
New control counts and native results must be read from PROGRESS; source or
synthetic success does not establish actual unknown-notice recovery.

Existing sealer/unsealer/retriever controls include stock-CMS roundtrips, wrong
keys, trusted-ZIP admission, unsafe paths/bounds, original-error retention and
API tuple rejection. Native run40227817066 at source525bb5ea produced a reviewed
fixed sample, followed by seven authenticated requests and exact private local
recovery of two literal files. That historical calibration is not evidence for
the new linked runtime. No Kaferry release is qualified.
