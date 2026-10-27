# Local evidence on the Mac mini

The user selected Mac mini runners and local plaintext evidence on2026-10-27.
The active workflow has no encryption, artifact upload or cache upload. The
previous hosted encryption route is retired. Historical ciphertext, keys,
recovered originals, failures and source proposals are preserved; this change
neither deletes them nor retroactively completes failed transfers.

Evidence is private host data, outside the reusable checkout. The dedicated root
is `/Users/pg/services/kaferry-lab-local-evidence-20261027`, with owner-only0700
directories and0600 regular single-link files. Each attempt binds the repository,
source head, GitHub run, attempt and fixed job. A new attempt is exclusive: no
reuse, overwrite or automatic deletion. The approved-head descriptor binds the
actual root device/inode and uid. These checks do not make same-uid data immutable
or protect it from malicious code running as that user.

## Current executable scope

The sole workflow job is **local retention calibration**, not harness CI or a
released Kaferry campaign. It runs on the existing repository-scoped Mac runner's
unique `kaferry-lab-mac-custody-20261025` label. It does not select hosted runners,
Go, a product executable, Docker faults, packet capture or metadata diagnostics.
Ordinary Go builds/tests with unchanged caches are now user-authorized and the
original host retry succeeded. Separate attestation-cache/capture stops remain.
The selected qualification target is native Linux ARM64 in OrbStack; this Darwin
host and the fixed custody workflow cannot provide that runtime evidence. No
emulated run may silently replace native qualification. M2–M6 remain unfinished.

The calibration writes fixed synthetic binary/JSON bytes directly into the
private attempt and checks their lengths, hashes and exact bytes. Raw errors
stay in reserved private sinks when available. Its public output is limited to
fixed status classifications and `release_qualified:false`. A missing error
sink, rejected admission, short write, sync/close failure or interrupted attempt
remains incomplete. There is no alternate sink or retry after a denied action.

## Runner hooks and interrupted jobs

The reviewed helper and shell hooks must be installed outside the runner
application and checkout, under `/Users/pg/services/kaferry-lab-mac-control-20261027`.
GitHub's synchronous pre-job hook validates the exact repository/id/ref, trusted
push or manual-dispatch event, fixed job and operator-approved source head
**before checkout**. It reserves a private attempt and an INFLIGHT latch first.
A pull request, fork or unapproved head cannot run on this data-bearing runner.
The workflow also checks that installed helper bytes match its checkout.

A missing post-job callback leaves the latch and all available partial bytes.
The next pre-job hook rejects reuse; there is no automatic unlock, cleanup or
recovery declaration. An operator must inspect the exact prior attempt before
any later change. The post-job hook releases the latch only after checking the
known no-child calibration files and finishing its private writes. Its record
means callback and fixed-byte observation only: it does not prove application
writer closure, child reaping, fault restoration, filesystem immutability or
Kaferry qualification. A completed file cannot attest its own final close.

Bounds are16 attempts,256MiB per attempt and4GiB aggregate, with a free-space
guard of2GiB plus the per-attempt reservation. These are admission checks, not a
hard filesystem quota. Current payloads are tiny fixed fixtures. No disk-fill
fault targets this host directory. Jobs have a five-minute budget; hooks do only
bounded data operations, although a kernel/filesystem stall can exceed a
user-space deadline. A final sink/close/unlink or public-output failure can leave an original
unavailable; it remains nonpassing, with no alternate sink or retry. No universal
durability or hard-cancel retention claim is made. The unmodified original partial bytes remain useful evidence.

## Qualification and historical evidence

Whole released-campaign execution and process/writer/cleanup proof still need
integration and measurements on the selected native Linux platform. This
calibration cannot authorize those steps or replace their independent oracles.
Actual hook execution, runner lifecycle retention and rechecks must be observed
before calling the local retention path operational; source controls alone are
insufficient. See [local runner setup](local-runners.md) and PROGRESS.md.

The former hosted workflow and its encryption/recovery helpers are retained at
`codex/retained-hosted-encryption-4f625ad` and in git history. Those helper files
remain available for old evidence only; the active workflow invokes none of
them. Historical encrypted recovery requires its original authenticated ZIP
identity/digest and private key. CBC ciphertext was not AEAD. Do not weaken those
historical checks or infer that local retention repairs missing old artifacts.
