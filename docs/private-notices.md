# Private linked-fixture notices

The optional stock-link source stores raw Docker and in-process HTTP/TCP failure
notices separately from public selected facts. Those owner-only files under
`.cache/fixtures-private/RUN_ID-links/` cannot survive an ephemeral runner by
hashes alone. The last independently accepted native run, `b61b6145`, kept
proxy runtime disabled. The local activation candidate requests live execution;
it must not be pushed until the publication decision below is explicit.

[AGENTS.md](../AGENTS.md#operations-and-publication) requires: “Publish only
reviewed, redacted evidence containing synthetic inputs.” Encryption provides
confidentiality, not content review or redaction. The activation candidate
sets `LAB_LINK_RUNTIME` to `enabled`; that source selection supplies no
publication authority. An explicit user exception for the bounded public
ciphertext or a reviewed private durable route is required before its push.
These helpers prepare a concrete retention option; they are not qualification.

## Implemented helpers and bounds

`scripts/seal-link-notices.py` accepts a validated run ID, reviewed source head,
job/attempt and pinned recipient certificate. Its default v1 layout snapshots
the fixed fixture private directory. Explicit `--layout linked-calibration-v2`
(job `links` only) also selects the fixed driver private root, with `driver/`
and `fixture/` archive prefixes. Both layouts admit regular owner-only JSON
receipts, no links/special files, at most
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
can authorize decryption. Native [run 40227817066](https://github.com/pagrus7/kaferry-lab/actions/runs/40227817066)
at source `525bb5ea` produced the
fixed reviewed sample. Actual seven-request authenticated recovery, private
stock-CMS decryption and exact two-file literal checking completed and passed
independent review. This proves only that known synthetic transport path.

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

Local synthetic controls cover stock-CMS roundtrip and algorithm IDs,
wrong keys, ZIP-digest admission, unsafe paths/bounds, injected OS failures,
private original notices/public suppression and API tuple rejection with fake
HTTPS. The repaired source passed 114 local controls. Native run 40227817066
passed 115, including actual pipe-capacity readback 8192 with exact 10240-byte
stdout drain and joined writer. Interrupted/open-stdin controls returned with
truthful unavailable fake-child reap and closed/joined fixture resources;
these are synthetic control measurements, not Kaferry or actual target waits.

The earlier `971183b7` native attempt failed report copying because `.cache/m2`
was absent; `dfcbbdb2` then passed notice controls but failed a separate Go
metadata calibration. Both failed runs remain retained failures. The `525bb5ea`
run passed all seven jobs, including repaired metadata/unit/race controls. CI
creates the expected report parent explicitly and publishes six fixed reviewed
numeric/boolean control rows, checked source hashes and fixed Linux/Python
fields. Unknown fields, notices, keys and command diagnostics are excluded.
The unit controls use no real HTTPS, Docker or released Kaferry; the separate
fixed-sample recovery exercised actual authenticated HTTPS. Test keys and full
private reports remain outside the public unit artifact tree.

A trusted feature-branch push with linked runtime disabled creates one
transport calibration using
`scripts/create-notice-transport-sample.py --reviewed-synthetic-transport-only`.
It creates a fresh private tree containing only `PRIVATE.json` and
`transport-sample.json`; their exact literal payloads are checked again at the
production sealer snapshot. Only validated run/head/unit-job/attempt fields vary.
The notice is exactly “Reviewed fixed synthetic notice transport sample.”
The namespace is `calibration/private-notice-transport`, with `synthetic:true`
and `release_qualified:false`. Existing, extra or changed inputs are refused
before encryption. That disabled path uploads only this sample ciphertext under
the canonical
unit artifact name, using the pinned public certificate; it never reads the
recipient private key. This reviewed synthetic sample fits the existing
publication rule. It grants no exception for unknown notices. Native creation
and actual authenticated recovery of the two exact reviewed JSON files passed
at `525bb5ea`; no other raw input was authorized by that operation.

The task-generated recipient certificate is public and pinned in source; its
private key remains only in ignored owner-only coordinator storage. Local
custody and certificate agreement were checked, with a same-host copy retained;
this is not independent-media backup or a user identity certificate. Never
commit/upload the private key or recovered notices. Recover, inspect and redact
synthetic evidence before any ordinary release-evidence publication.

A future enabled producer needs an exact reviewed source/CI binding, explicit
writer-stop/reap evidence, native tool checks, the approved recipient and either
an actual private durable transfer or explicit authorization for the proposed
public ciphertext exception. Until that decision, the enabled candidate stays local and published linked
runtime and unknown-notice encrypted public retention stay off. Real product fault coverage and M2–M6 acceptance remain
separate requirements.

## Linked v2 and caller activation

V2 requires the caller declaration `--notice-writers-stopped-and-reaped`.
The helper records `observed_proof:false`: it does not observe processes.
Only genuine ENOENT of the fixed fixture root or its parent permits a partial
bundle, always `bundle_complete:false` and `release_qualified:false`. The
original absence exception is serialized once and retained both privately and
inside the encrypted manifest with exact byte length, SHA-256, base64 body,
run identity and scope. Recovery checks that bounded record before writing the
same bytes privately. Missing descendants, malformed existing roots,
permissions, unknown failures and failed retention cannot use this exception.
The driver root is mandatory. The serialized absence observation body is capped at 16KiB. Its larger
base64/identity envelope stays within the complete 256KiB manifest limit;
archive limits remain 10MiB tar, 12MiB CMS and 16MiB ZIP.

The driver final marker follows selected-result staging, actual child/adopted
waits and ECHILD, then primary private sink sync/close. CI additionally requires
actual foreground return and noncancelled admission, exact typed run/head/hash
and private references, terminal waits and joined stream copies. A failed
calibration may establish writer closure; that does not establish cleaned
resources or successful calibration. The final job remains failed even if its
notice bytes could be retained. `SealingReady` and `PublicationAuthorized` in
the driver stay false; neither a marker nor the sealer declaration grants
permission. Native positive/negative lifecycle and caller controls are required
before enabling runtime. Native `b61b6145` passed the authored isolated
lifecycle and data-only caller controls; actual combined driver/courier
execution remains unmeasured.

The new v2 source passed 168 local synthetic controls in its preserved proposal.
Integrated native `b61b6145` passed the 169-control helper gate, including the
native small-pipe case. The public artifact retains six selected numeric rows
and exact source hashes; the private full 169-row report was not uploaded.
Independent literal archive membership/bytes and tampered/missing absence
controls are in that reviewed source. All 46 data-only caller rows are retained
and passed natively. This validates the bounded helper gates, not actual proxy
execution, combined writer closure or authenticated linked-v2 retrieval.

An enabled head would skip the unit fixed-sample producer/upload so the current
retriever still admits exactly one canonical encrypted artifact in a run.
The last accepted `links` job built only specimens. The activation candidate's
guarded upload selects only the sole CMS member for 14 days, with read-only contents permission
and no publishing credential or recipient key. Before such a head is pushed,
the concrete source, native controls and exact publication exception or private
transfer require review. Encryption remains separate from redaction.

No guarantee covers a first required sink failure, failed final close, missing
accepted archive, failed encryption, cancelled unconfirmed writer or lost
runner. Such failures are incomplete, not durably retained by assumption.
There is no alternate sink, cleanup tool or capture route after denial.
