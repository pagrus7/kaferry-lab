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

The initial restored hosted increment keeps `LAB_LINK_RUNTIME: disabled`.
The `m1` and `m2-release` jobs remain explicitly skipped while the original tag
GET403 lacks privately retained provider response evidence. Harness controls and
build-only links may run; this is partial CI, not final qualification CI. A
future original-endpoint diagnostic attempt needs reviewed bounded encrypted
retention first. Do not retry with alternate credentials, endpoints, source or
cache. Existing source verification and capsule runtime are not proved by this
policy change.

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
