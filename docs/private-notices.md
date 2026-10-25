# Private linked-fixture notices

The optional stock-link source stores raw Docker and in-process HTTP/TCP failure
notices separately from public selected facts. Those owner-only files under
`.cache/fixtures-private/RUN_ID-links/` cannot survive an ephemeral runner by
hashes alone. Proxy runtime remains disabled in the current CI matrix until a
reviewed durable retention route is available.

[AGENTS.md](../AGENTS.md#operations-and-publication) requires: “Publish only
reviewed, redacted evidence containing synthetic inputs.” Encryption provides
confidentiality, not content review or redaction. No exception to that rule has
been authorized, and no unknown-notice public encrypted upload is enabled. The unknown-notice
upload proposal remains ignored under `.cache/m2/notice-sealing-implementation/`.
These helpers prepare a concrete retention option; they are not qualification.

## Implemented helpers and bounds

`scripts/seal-link-notices.py` accepts a validated run ID, reviewed source head,
job/attempt and pinned recipient certificate. It snapshots only the fixed private
run directory: regular owner-only JSON receipts, no links/special files, at most
1,024 receipts, 256 KiB per complete receipt, 8 MiB total and four path levels.
A second inventory checks observed consistency. The caller must first stop all
notice writers; inventories cannot establish quiescence by themselves.

The helper puts the run/head/job/attempt/certificate and file hashes in a fixed
inner tar manifest, then uses stock OpenSSL CMS with AES-256-CBC,
RSA-OAEP/SHA-256 and MGF1/SHA-256. **CBC is not authenticated encryption.**
The fixed quarantine contains bounded ciphertext and completion metadata, never
raw tar, notices or keys. Any future upload must select only `notice.cms`.
Completion metadata is not publication permission or a product verdict.

`scripts/unseal-link-notices.py` requires an externally trusted SHA-256 for the
entire artifact ZIP before it parses the ZIP or decrypts. It accepts exactly one
bounded regular `notice.cms` member, validates the decrypted manifest and all
bytes, and writes only an exclusive owner-only recovery directory. A ciphertext
self-hash or adjacent manifest supplies no external authenticity.

`scripts/retrieve-link-notices.py` implements read-only authenticated recovery
for `pagrus7/kaferry-lab`. It checks the expected repository, branch, workflow,
reviewed head, run, current attempt, job and canonical artifact identity using
HTTPS API metadata. Tokens arrive only through bounded stdin, never arguments
or credential-store fallback. Download redirects never receive cross-origin
Authorization. The API digest authenticates the complete ZIP, not a nested CMS
file directly. No malformed tuple, missing digest or extra encrypted artifact
can authorize decryption. This acquisition path has synthetic transport tests;
real API recovery of an encrypted artifact has not been exercised.

Completion metadata is staged, synced and closed while the private error sink
is live. The sink is detached and closed exactly once before a final rename
publishes COMPLETE. Failure of that terminal close or rename is explicitly
incomplete with exact notice unavailable; it never opens a replacement sink.
Interrupted command drains mark streams incomplete and retain actual cleanup
outcomes, including unavailable reap results. An early stdin closure is retained
as the original failed write and cannot pass even if the child exits zero.
Receipts distinguish intended input bytes from bytes accepted by successful pipe
writes; complete input also requires successful stdin closure. These counts do
not prove that the child processed the input.

Both command/OS notice paths reserve private error storage before sensitive
operations. Exact original failures stay private when that sink works; public
diagnostics are fixed. Credential-bearing API error text is withheld and
explicitly marked incomplete. Missing/truncated/failed retention is incomplete
and fatal. No alternate sink, retry, tool or trust setting repairs a
denied action. Helpers do not upload, grant a publication exception, qualify a
release or prove a source-save/threshold/worker-ACK mechanism.

## Current validation and remaining gate

Local synthetic controls cover real stock-CMS roundtrip and algorithm IDs,
wrong keys, ZIP-digest admission, unsafe input/archive paths, bounds, injected
OS failures, original private notices/public suppression and authenticated API
tuple rejection using fake HTTPS. The isolated repaired source passed 112 local controls, including terminal-close,
interruption/cleanup, late sample-mutation and early-stdin-closure failures. Native checks are required
for the final source. The CI unit job runs those controls without real HTTPS, Docker or
released Kaferry. Test keys/private bytes stay outside its public artifact tree.

A trusted feature-branch push also creates one transport calibration using
`scripts/create-notice-transport-sample.py --reviewed-synthetic-transport-only`.
It creates a fresh private tree containing only `PRIVATE.json` and
`transport-sample.json`; their exact literal payloads are checked again at the
production sealer snapshot. Only validated run/head/unit-job/attempt fields vary.
The notice is exactly “Reviewed fixed synthetic notice transport sample.”
The namespace is `calibration/private-notice-transport`, with `synthetic:true`
and `release_qualified:false`. Existing, extra or changed inputs are refused
before encryption. CI uploads only this sample ciphertext under the canonical
unit artifact name, using the pinned public certificate; it never reads the
recipient private key. This reviewed synthetic sample fits the existing
publication rule. It grants no exception for unknown notices. Actual native
creation and authenticated API recovery remain pending.

The task-generated recipient certificate is public and pinned in source; its
private key remains only in ignored owner-only coordinator storage. Local
custody and certificate agreement were checked, with a same-host copy retained;
this is not independent-media backup or a user identity certificate. Never
commit/upload the private key or recovered notices. Recover, inspect and redact
synthetic evidence before any ordinary release-evidence publication.

A future enabled producer needs an exact reviewed source/CI binding, explicit
writer-stop/reap evidence, native tool checks, the approved recipient and either
an actual private durable transfer or explicit authorization for the proposed
public ciphertext exception. Until then, linked runtime and unknown-notice encrypted public
retention remain off. Real product fault coverage and M2–M6 acceptance remain
separate requirements.
