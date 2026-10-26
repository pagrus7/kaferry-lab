# Private linked-fixture notices

The publication decision is settled: reviewed structured facts may be public;
original raw diagnostics stay private. This includes their encrypted capsules.
The earlier `b4eca248` public-CMS activation proposal is superseded, not awaiting
another publication exception. Live linked calibration remains disabled while
the private storage route is prepared and verified.

The selected route is to keep completed sealed originals on the user's worker
storage, described by the user as a Mac mini. The actual runner-visible private
mount and its backing/lifecycle mapping are **unverified**. Current workflow
jobs select `ubuntu-24.04`; no registered self-hosted runner was found in the
read-only preflight. The local session is separately Darwin/arm64. Host inspection found four Mac runner services under
`/Users/pg/services/github-runners/`, all registered to
`pagrus7/knowledge-assistant`. They do not supply a configured storage path for
this lab’s current Ubuntu jobs. Native Linux AMD64 execution
remains a separate requirement.

[AGENTS.md](../AGENTS.md#operations-and-publication) requires: “Publish only
reviewed, redacted evidence containing synthetic inputs.” Encryption is not
review or redaction. The existing reviewed fixed synthetic transport sample
remains an allowed public calibration; it grants no exception for unknown
notices. Public unknown-notice CMS upload stays off, with no fallback to it
when private retention fails.

## Private filesystem handoff — source and synthetic controls

The configuration prerequisite is one existing absolute private directory,
visible to the actual executing worker, outside the checkout, temporary storage
and public artifact/cache trees. Identify its owner/account, narrow mount path,
actual retained backing and the runner/VM/container lifecycle it survives.
Confirm that lifecycle with bounded write/sync/close/readback and later private
recovery before claiming durable custody. A path string, runner label or
same-directory hash is insufficient. One host is one failure domain.

Expose only this dedicated mount to the trusted job/account. Untrusted PR/fork
jobs must not receive it; mode 0700 alone cannot isolate jobs sharing the same
UID. Do not mount a whole home directory. The recipient private key stays in
private coordinator custody and is never mounted, fetched or copied onto the
worker. The pinned public certificate is enough to seal. If that worker has a
verified persistent mount, the filesystem handoff needs no publishing credential
or object-storage service. The current native-worker-to-Mac connection is still
unconfigured.

`scripts/store-link-notices-private.py` implements `preflight` and `store`.
Both require `--private-root`, `--storage-id`, `--run-id`, `--source-head`,
`--job links` and `--attempt`, with the exact canonical trusted-push CI context.
The workflow obtains the two storage settings from repository variables
`LAB_PRIVATE_EVIDENCE_ROOT` and `LAB_PRIVATE_STORAGE_ID`. Live runtime remains
disabled; an enabled job must pass private-root admission before fixture setup.

The root must already be an owner-only0700 directory outside the checkout. Its
owner-only0600 `PRIVATE-STORE.json` has exactly `version` (integer1), `storage_id`,
`root_device`, `root_inode`, `operator_confirmed_persistent`, `private`,
`exclusive_trusted_writer`, `repository` and `repository_id`. Device/inode are
those observed by the executing worker; the three operator flags must be true.
These are explicit operator attestations, not empirical proof of persistence,
Mac backing or trusted-job isolation. The helper does not provision the root.

After completed writer closure and sealing, `store` exclusively copies three
fixed payloads: `notice.cms`, original sealer metadata as `SEAL-COMPLETE.json`,
and `caller-proof.json`. An owned private `OS-ERROR.json` and final storage
`COMPLETE.json` account for copy failures/finalization. The dedicated root admits
at most64 attempt directories with a13MiB helper-owned budget each, no overwrite,
retry, alternative slot or automatic deletion. Public output contains only exact
identity, hashes, byte counts and status. The workflow checks those fields against
its preflight, sealer and caller receipts before publishing selected facts.

Fourteen local synthetic Python controls passed, including literal short-write,
write-plus-close causes, final-sync/close failures, collision, quota and metadata
rejection. Twenty-two data-only controls of the exact workflow projection passed.
These use synthetic files and injected errors; no real root, host mount, crypto,
Go or native custody was exercised. Fresh frozen source reviews and final-head
native CI remain required. A marker can remain after uncertain final close;
recovery must also require the successful exact-attempt store receipt and hashes.
Successful private storage does not change failed calibration into success.

The existing raw writers and sealer keep their fixed checkout paths. Only an
already sealed, closure-admitted capsule is selected for the private copy;
this does not relocate every writer or preserve every early failure. Private
local recovery must verify the selected repository/head/run/attempt/job,
successful retention result and exact capsule bytes. The existing authenticated
GitHub retriever remains strict for GitHub artifacts; local custody must not be
relabeled API-authenticated. A local recovery entry point and custody validation
are still pending.

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
raw tar, notices or keys. Unknown-notice `notice.cms` stays private; only the
separately reviewed fixed sample may be uploaded publicly. Completion metadata
is not publication permission or a product verdict.

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

## Existing helper validation and remaining work

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
writer-stop/reap evidence, native tool checks, the pinned recipient and a
verified private mount/retention route. The selected policy needs no further
publication exception. Current private-copy integration is source preparation;
no actual private custody, lifecycle recovery or linked runtime has been
measured. Real product fault coverage and M2–M6 acceptance remain separate.

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

The reviewed fixed-sample unit producer/upload remains a separate public
calibration under its existing guards. The last accepted `links` job built only
specimens; unknown linked-notice ciphertext must have no public upload path.
Private-copy integration requires frozen source reviews and final-head native
checks before any activation. Earlier native helper/sample results do not
validate the new storage path. Encryption remains separate from redaction.

No guarantee covers a first required sink failure, overflow, failed final close,
missing accepted archive/closure, failed encryption, failed private copy, or
cancelled/lost runner before the copy completes. Raw checkout files can be lost
in those cases. The capsule does not automatically include every sealer/copy
diagnostic or the separate hardware proposal root. Partial v2 evidence remains
partial. Sync/close and hashes do not establish power-loss durability or
independent backup. Such failures are incomplete, not retained by assumption.
There is no alternate sink, cleanup tool or capture route after denial.
