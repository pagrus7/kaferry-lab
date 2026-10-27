# Lab setup and implemented checks

M0 and M1 are accepted. M2 targeted release scenarios are in development; required M2–M6 fault evidence and campaigns are incomplete. Harness checks and calibration test the lab. They cannot qualify Kaferry, and `lab qualify` explicitly returns `UNSUPPORTED` with `release_qualified:false`.

Selected execution is GitHub-hosted native Linux AMD64. Diagnostic capsules may
use the explicit [encrypted-artifact exception](private-notices.md); the private
key stays on the Mac. Local Go/verification/capture stops remain binding.
Trusted feature pushes select fresh release verification, the existing narrow
release cases and stock-link calibration. Native results for this activation
remain pending; harness CI does not establish M2 or final qualification.

## Prepare and check the harness

Use Go matching `go.mod`. Published-artifact verification also needs network access and GitHub CLI with `gh attestation verify` and its source/workflow policy flags. Live observer checks need Docker. Use an authenticated GitHub CLI for publishing reviewed increments. Keep the sibling Kaferry checkout read-only; it is a tagged reference, not a build dependency. If your host needs a custom trusted CA bundle, set `SSL_CERT_FILE` to its path; do not disable certificate verification.

```sh
./scripts/check.sh
mkdir -p .cache/bin
go build -o .cache/bin/lab ./cmd/lab
```

The check script runs formatting, vet and race-enabled unit controls without Docker. Live observer tests are opt-in; skipping them is not measured capability evidence.

## Verify the published artifact

```sh
.cache/bin/lab verify .cache/releases/verify-001
```

Choose a new output directory for each attempt. Verification accepts only the reviewed v0.6.0 Linux AMD64 release at commit `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. It checks the annotated tag, release and asset identities, published checksums, pinned archive/executable bytes, tagged contract document hashes, and cryptographic provenance through `gh attestation verify`. It then runs the verified executable with `--version` and checks its digest again. There is no main/latest selection or source-build fallback. Unknown identities or missing required verification evidence fail closed.

The command has a three-minute overall budget. `verified.json` records the release, hashes, provenance verifier and version runtime; downloaded documents, the archive, executable, verification receipt and version output stay alongside it. A failed attempt retains available files and `FAILED.json`; preserve that directory and use a new one after resolving the failure. These files establish artifact verification, not a fault campaign or qualification.

Version observation requires native Linux AMD64. The command checks the Go and kernel architectures before launching its 20-second version subprocess. Other hosts cannot complete verification; use the native CI workflow when orchestrating from macOS. Docker remains a prerequisite for live Kafka fixtures.

## Check a bundle offline

```sh
.cache/bin/lab check internal/evidence/testdata/valid
```

`check` needs only the lab executable and a stable bundle directory containing `manifest.json`, `artifact.json`, `events.jsonl` and `complete.json`. It makes no network calls and needs no Kafka, Docker or target executable. Keep all four files together. Hashes and run identity bind the recorded observations; they do not authenticate an untrusted author's claims. The checker checks consistency of recorded artifact verification rather than repeating cryptographic provenance verification.

| Exit | Meaning |
| --- | --- |
| 0 | `PASS`: this supported history meets its recorded obligations. |
| 1 | `VIOLATION`: the history demonstrates a checked property failure. |
| 2 | `HARNESS_ERROR`, invalid invocation, or command failure: evidence or execution cannot support a result. |
| 3 | `UNSUPPORTED`: schema, contract, scope or command is outside implemented support. |
| 4 | `INCONCLUSIVE`: required observations, such as a reached trigger or complete scan, are missing. |

The verdict is JSON on stdout when a checker result is available; command errors also use stderr. `PASS` covers one partial history and always reports `release_qualified:false`. Unknown schema versions, truncated streams, changed run identity and missing required evidence cannot pass. Archive/checkpoint checking remains unsupported. The version1 process-kill histories retain their narrow contract; targeted M2 histories use version2 typed observations. Byte-identical records have an explicit limitation: replay can conceal loss of a particular indistinguishable occurrence. See the [offline evidence contract](../internal/evidence/README.md) for exact bounds and supported observations, and [targeted M2 runs](m2.md) for real release execution.

## Calibrate detection with real child processes

```sh
.cache/bin/lab calibrate .cache/calibration/cal-001
.cache/bin/lab check .cache/calibration/cal-001/healthy-pause/bundle
# Expected VIOLATION, exit 1:
.cache/bin/lab check .cache/calibration/cal-001/faulty/bundle
```

Choose a new calibration directory. This command uses three synthetic records and at most one child at a time, with a 20-second total budget. It pauses each stand-in at an observed saved position, records outstanding output, kills it, confirms the signal exit, and restarts from saved state. The faulty stand-in saves progress before producing a required record. The command succeeds only when the healthy history passes and the faulty history produces a violation. Controller failures are command failures, not successful detection.

Reports and bundles use the `calibration` namespace and identify the stand-in executable. They are not Kaferry runs. Each mode retains its four-file bundle plus input, output, saved-state and child logs under `work/`; preserve partial output after a failure. Rechecking an unchanged complete bundle produces the same result. Calibration reaps its children on success, error and cancellation; a later attempt uses a new directory rather than resuming one.

## Measure the live observer

```sh
run_id="m0-$(date +%s)"
go run ./cmd/fixture up "$run_id"
eval "$(go run ./cmd/fixture env "$run_id")"
go test -v -count=1 -timeout=4m ./internal/observer -run Live
go run ./cmd/fixture down "$run_id"
```

Always run cleanup after a failed test. Fixture state remains in `.cache/fixtures/<run_id>.json` so cleanup is restartable. Distinct random Kafka cluster IDs are recorded and checked by live metadata observations. Startup has a four-minute total budget, bounded probes, two memory/CPU-limited single-broker clusters, loopback host ports, and unique resource names. Failure triggers cleanup; cleanup refuses names/labels that do not belong to this run. It never prunes global Docker resources. Retain failed startup/broker logs before removing resources when diagnosing an environment failure.

Kafka is pinned to `apache/kafka@sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02` (3.9.2 multi-platform index). The AMD64 manifest is `sha256:f5f8605794dce59d1d566f63667682771c2fec9e96088b0d6a5ef0f8476dd4b2`; ARM64 is `sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0`. Fixture state records the actual Docker platform. Retention/compaction are disabled for initial record-ledger controls. Brokers are plaintext and contain synthetic data only; keep their ports on loopback.

## CI and retained evidence

Harness CI selects GitHub-hosted native Linux AMD64 `ubuntu-24.04` runners.
Trusted feature pushes select unit/offline/controller controls, live observer
calibration, fresh release verification, the existing four-case release matrix
and stock-link calibration. Actions are commit-pinned, jobs have explicit time
budgets and contents-read permission, and untrusted PR code receives no
publishing credential. Release and link runtime jobs admit only the exact lab
repository and trusted feature-branch push. Metadata-only dispatch runs none of
those jobs. Calibration checks the lab, not Kaferry.

The source reactivates `m1` and `m2-release` after reviewed diagnostic retention
and authenticated recovery at `e521c099`. The new activation still needs its own
native CI/evidence review. The release matrix covers healthy PRESERVE/KEY,
source-startup and repeated-kill development cases with fresh artifact
verification, restoration/cleanup and network-isolated offline rechecks after
target removal. It supplies no missing timeout, threshold-drain or source-save
witness, and is not a complete M2 campaign. Packet capture remains stopped.

The historical source-startup tag GET403 discarded its body/headers; its cause
remains unknown. The separate one-shot diagnostic returned200 with the expected
annotated tag reference; it made no tag-target, release-asset or provenance
request. New ordinary verification must complete all those checks itself. No
alternate credentials, endpoint, source or cache replaces a failed request.

The user now authorizes bounded encrypted diagnostic artifacts from hosted
synthetic runs. Plaintext originals and the private recipient key remain
private; the runner needs only the pinned public certificate. No Mac mount,
private network or `LAB_PRIVATE_*` variables are required by this route.
Ciphertext is treated as public and recovery authenticates the whole ZIP via the
expected GitHub API tuple/digest before parsing or decryption. See
[encrypted diagnostics](private-notices.md) for exact bounds and early/late
failure limits. The old private-filesystem route is retained in its explicit
branch, not as an active setup prerequisite.

The feature-push `links` job builds `cmd/link-calibration` and the campaign test
binary with clean exact-head metadata. `LAB_LINK_RUNTIME` is enabled in source;
its first actual stock-proxy outcome remains pending. The unit transport sample
is suppressed, leaving one linked ciphertext artifact for the run. Actual
foreground return, waits/tree/stream/sink closure and matching sealed metadata
admit only `notice.cms`, with seven-day retention and no overwrite. Failed
calibration may retain complete evidence but remains failed. Public selected
build/caller/admission facts have separate14-day retention. Recover each actual
linked capsule; metadata recovery does not prove stock-proxy behavior. Local Go
and capture stops remain in force; hosted CI is separately authorized.

Feature pushes remain the premerge release trigger. Narrow metadata-only manual
dispatch is now measured on the feature branch. It does not establish manual or
scheduled M6 campaigns or change the default branch.

## Metadata-only calibration and diagnostic

The source implements `workflow_dispatch` on
`codex/resilience-release-lab`, with modes `normal` (default),
`metadata-calibration` and `metadata-diagnostic`. The exact-head source and native path at `e521c099` passed independent review.
Select a reviewed head, verify the resulting run identity and obtain fresh
calibration/recovery evidence before any newly selected diagnostic. Local Go/build/verification/capture
stops remain in force; separately authorized hosted CI supplies future native
Linux AMD64 evidence.

The `normal` mode keeps the current partial harness behavior. The two
metadata-only modes suppress ordinary unit-sample and linked-runtime ciphertext
uploads so the existing retriever sees exactly one encrypted notice artifact
across the whole run. `m1` and `m2-release` require trusted pushes and cannot run in either
metadata mode; a successful diagnostic does not trigger them.

Select `metadata-calibration` first, after frozen-source review. It must use fixed
synthetic responses and controlled native child/stream/sink failures without
querying the original endpoint. The final calibration also runs the freshly built Go
executable through the same foreground, admission, sealing and upload steps as the
diagnostic. Only that synthetic invocation selects a fixed, confirmed-absent trust file;
ordinary trust setup must fail before any HTTP client invocation. Admission requires the
exact ENOENT cause, attempt_count0, no response and closed incomplete return2. This is a
negative fixture, never a TLS bypass or an alternate trust route for the real request.
Its recovered capsule contains PRIVATE.json, metadata.json and capture-closure.json;
verify those originals and actual closure on the Mac before selecting the diagnostic.
Review the native result, then authenticate the
expected GitHub run/job/artifact and whole-ZIP digest before private Mac
decryption. Compare the recovered known synthetic bytes and independently review
that recovery. Upload completion, mocked controls and historical sample recovery
cannot establish this new path's custody.

Only after those prerequisites may `metadata-diagnostic` be explicitly selected for one
unauthenticated original tag-metadata GET. There is no automatic transition from
calibration, no alternate credentials/endpoint/cache/redirect route and no
chained retry or release verification. The discarded original403 response cannot
be recovered retroactively; its reason remains unknown. A new403 or200 is a
separate diagnostic observation and always has `release_qualified:false`.

The producer and caller source use the existing fixture-v1 encryption and
authenticated retrieval unchanged. The final closure JSON includes bounded original caller errors and base64 stream
prefixes after actual producer/pipe/error-writer closure. Its own write, sync and
close must finish before foreground return and sealing.
Admission needs that actual return and matching typed closure, never existence
of a receipt alone. Closed incomplete prefixes can be useful evidence, while
unreached requests, uncertain closure and failed sinks cannot pass.

Source limits are64KiB for each caller stdout/stderr pipe prefix, a producer
private error envelope strictly below48KiB after JSON/base64/newline encoding,
and32KiB for its raw framed error graph. Response header frames are capped
at16KiB, exposed body prefix at64KiB plus one detection byte, and framed observed
errors at32KiB. Final serialized JSON receipts must fit256KiB each. Client-decoded
headers and potentially decompressed body bytes are not wire octets; completeness,
overflow and observed-length facts must stay explicit. See
[encrypted diagnostics](private-notices.md) for closure, recovery and sink-loss
limits. Measured diagnostic and recovery evidence is listed below; none is Kaferry
qualification.

The reviewed native calibration at
[run40509295871](https://github.com/pagrus7/kaferry-lab/actions/runs/40509295871)
passed17Go,27mocked caller,9admission and10native child cases, followed by
Mac recovery of the actual three-file setup-failure capsule. Two native cleanup
cases inject deadline/cancellation triggers and measure actual TERM/KILL/reap.
The reviewed single diagnostic at
[run40510578859](https://github.com/pagrus7/kaferry-lab/actions/runs/40510578859)
returned200 and the pinned annotated tag reference; all three receipts were
privately recovered after API whole-ZIP authentication. That observation does
not explain the historical403 or verify the complete release.
