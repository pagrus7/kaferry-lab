# Lab setup and implemented checks

The selected final target is now local native Linux ARM64 under OrbStack; see the [transition and current blockers](local-linux-arm64.md). The interfaces below describe the existing AMD64 implementation. ARM64 support is not implemented, the hosted workflow is disabled, and recorded local build/capture stops remain binding. Do not execute these examples as a workaround.

M0 and M1 are accepted. M2 targeted release scenarios are in development; required M2–M6 fault evidence and campaigns are incomplete. Harness checks and calibration test the lab. They cannot qualify Kaferry, and `lab qualify` explicitly returns `UNSUPPORTED` with `release_qualified:false`.

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

Harness CI uses native Linux AMD64 `ubuntu-24.04` runners. It checks the harness, golden offline histories, actual stand-in calibration, the full published-artifact verification/version path, and live observer capabilities. A four-minute M2 controller calibration uses the same owned fixtures to check actual pause/recovery/restart and known input readback; it does not execute Kaferry or establish M2 scenario coverage. The combined observer job has a 16-minute budget to include this calibration and cleanup. Offline CLI checks run in a network namespace with no network interfaces available beyond loopback. CI retains logs, verification output, calibration bundles and fixture evidence with `always()`, including failed attempts, for 14 days under unique run/attempt names.

Jobs have explicit time budgets, read-only contents permission, commit-pinned actions and no publishing credentials. The partial M2 jobs have a 25-minute budget. They attempt no packet capture and retain its separate `UNSUPPORTED` status with the denied run reference. They execute healthy PRESERVE/KEY controls, an inaccessible-source startup case and repeated crashes with fresh artifact verification, retained operation evidence, restoration and cleanup. When a finalized bundle exists, they remove the disposable target executable before repeated network-isolated offline rechecks, including nonpassing histories. An incomplete scenario still fails its execution step; successful rechecking confirms the recorded verdict. These jobs are development checks; all mandatory M2 variants still need measured acceptance. Retained Go profiles cover unit checks, actual M1 commands, live M2 helpers and these release cases for changed-line review. A green workflow is harness evidence, not release qualification. Native AMD64 required release campaigns and reviewed bundle publication remain later milestones.

The optional stock-link fixture and its opt-in topology/nonce controls are
source integrations awaiting accepted native proxy execution. The last accepted
native workflow kept them disabled. The earlier public-CMS activation proposal
is superseded: reviewed structured facts may be public, while original raw
diagnostics and their encrypted capsules remain private. The reviewed fixed
synthetic unit transport sample remains separately allowed. Unknown-notice CMS
has no public retention fallback.

The selected private route keeps completed sealed originals on the user's
worker storage, described as a Mac mini. Supply one existing runner-visible
absolute private directory outside the checkout, temporary storage and public
artifact/cache paths, with its owner, narrow mount and actual persistent backing
identified. The actual mapping and survival across checkout/worker lifecycle
are unverified. Current workflow jobs select `ubuntu-24.04`; read-only preflight
found no registered self-hosted runner. Local Darwin/arm64 does not establish
what backs those jobs. Host inspection found four Mac runner services registered
to `pagrus7/knowledge-assistant`; this lab’s native-worker-to-Mac storage connection
is not configured. Native Linux AMD64 readiness remains separate.

Expose only the dedicated private mount to the trusted job/account; no whole
home directory or untrusted PR/fork access. The recipient private key stays off
the worker in coordinator custody. The private filesystem helper preflights that
root before driver launch and stores an exclusive, identity-bound copy only after
actual closure and sealing. Repository variables `LAB_PRIVATE_EVIDENCE_ROOT` and
`LAB_PRIVATE_STORAGE_ID` select the preprovisioned root/descriptor. They are not
configured here; `LAB_LINK_RUNTIME` remains disabled. Local synthetic storage and
caller controls passed, but actual persistence has not been observed. See
[private-notices](private-notices.md) for the implemented helper interface, exact
custody prerequisites, existing helper evidence and early-failure limits, and
[M2](m2.md) for the missing mechanism observations.

The feature-push `links` job builds `cmd/link-calibration` and a fresh
`internal/campaign` test binary on native Linux AMD64 with clean exact-head VCS
metadata. Accepted run `40236814641` used `LAB_LINK_RUNTIME: 'disabled'` and
uploaded selected build metadata only. Integration keeps runtime disabled;
actual private retention, later private recovery and combined driver/fixture
execution remain unmeasured. The foreground driver and its fixed paths remain
encoded in CI. Local Go execution remains stopped under the recorded denial.
The job has a 20-minute outer budget with separate build, driver, proof and
retention limits. Frozen source reviews and final-head native CI are required
for the new integration; earlier native results do not validate it.

Feature pushes are the working premerge trigger. Read-only API preflight found
no CI workflow file on default branch `main`; manual dispatch has not been
established for this branch. Manual and scheduled required campaigns remain M6
work, with no default-branch or repository-setting change made here.
