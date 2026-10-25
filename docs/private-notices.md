# Private linked-fixture notices

The optional stock-link source stores raw Docker and in-process HTTP/TCP failure
notices separately from public selected facts. Those owner-only files under
`.cache/fixtures-private/RUN_ID-links/` cannot survive an ephemeral runner by
hashes alone. Proxy runtime remains disabled in the current CI matrix until a
reviewed durable retention route is available.

[AGENTS.md](../AGENTS.md#operations-and-publication) requires: “Publish only
reviewed, redacted evidence containing synthetic inputs.” Encryption provides
confidentiality, not content review or redaction. No exception to that rule has
been authorized, and no public encrypted-notice upload is enabled. The inert
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
tuple rejection using fake HTTPS. Native checks are required for the final
source. The CI unit job runs those controls without real HTTPS, Docker or
released Kaferry. Test keys/private bytes stay outside its public artifact tree.

The task-generated recipient certificate is public and pinned in source; its
private key remains only in ignored owner-only coordinator storage. Local
custody and certificate agreement were checked, with a same-host copy retained;
this is not independent-media backup or a user identity certificate. Never
commit/upload the private key or recovered notices. Recover, inspect and redact
synthetic evidence before any ordinary release-evidence publication.

A future enabled producer needs an exact reviewed source/CI binding, explicit
writer-stop/reap evidence, native tool checks, the approved recipient and either
an actual private durable transfer or explicit authorization for the proposed
public ciphertext exception. Until then, linked runtime and encrypted public
retention remain off. Real product fault coverage and M2–M6 acceptance remain
separate requirements.
