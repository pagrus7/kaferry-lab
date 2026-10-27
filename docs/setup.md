# Lab setup and implemented checks

M0 and M1 are accepted. M2 targeted release scenarios are in development; required M2–M6 fault evidence and campaigns are incomplete. Harness checks and calibration test the lab. They cannot qualify Kaferry, and `lab qualify` explicitly returns `UNSUPPORTED` with `release_qualified:false`.

Selected execution is the owned Mac mini runner with [private local evidence](private-notices.md).
The active workflow performs fixed local retention calibration only; hosted jobs,
encryption and artifact/cache uploads are removed. No Go, verification, product or capture step is active in that workflow.
The user approved ordinary default-cache Go builds/tests and native Linux ARM64
qualification in OrbStack. The host build retry succeeded; native execution is
still under preparation. See
[local runner setup](local-runners.md). The commands below are implemented reference interfaces; record and stop on a
renewed denial without cache, verifier or safeguard workarounds.

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

Choose a new output directory for each attempt. The source port admits only the two exact reviewed v0.6.0 Linux AMD64/ARM64 tuples at commit `d7d485b96a52b711cb10d76dca09aa9b155dec5e`. It checks the annotated tag, release and asset identities, published checksums, pinned archive/executable bytes, tagged contract document hashes, and cryptographic provenance through `gh attestation verify`. It then runs the verified executable with `--version` and checks its digest again. There is no main/latest selection or source-build fallback. Unknown identities or missing required verification evidence fail closed.

The command has a three-minute overall budget. `verified.json` records the release, hashes, provenance verifier and version runtime; downloaded documents, the archive, executable, verification receipt and version output stay alongside it. A failed attempt retains available files and `FAILED.json`; preserve that directory and use a new one after resolving the failure. These files establish artifact verification, not a fault campaign or qualification.

Version observation requires a matching reviewed native Linux Go/kernel pair
(AMD64/x86_64 or ARM64/aarch64). The command checks the Go and kernel architectures before launching its 20-second version subprocess. Other hosts cannot complete verification; the new custody-only workflow does not launch it from macOS. Docker remains a prerequisite for live Kafka fixtures.

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

The sole source-selected job is `local-retention` on the owned Mac runner.
Once the reviewed hooks and root are installed, the pre-job hook reserves a
private unique attempt before checkout. The fixed calibration writes synthetic
bytes directly there, and the post-job hook checks them. All data remains on
the Mac; there is no sealer, artifact/cache upload, metadata request or native
product command. Installation and actual hook observations are separate gates;
PROGRESS.md records their measured state. A missing callback or failure before
latch release preserves partial bytes and blocks the next job. A final public
output failure after release can return failure with the latch already absent;
no process/closure or universal retention guarantee follows. Completion of this
no-child calibration is not process/writer or qualification evidence.

[Local runner setup](local-runners.md) describes roots, approved-head admission,
installation, observations and limits. Actual source/review/runtime status is
in PROGRESS.md. Preserve the retired hosted matrix and historical failures via
`codex/retained-hosted-encryption-4f625ad`; do not equate their job API statuses or
partial artifacts with new native acceptance. The metadata diagnostic and old
ciphertext recovery are historical, not active workflow modes. Earlier
source-startup403 remains unexplained; later200 does not resolve its cause.

Before product work, measure the approved native Linux ARM64 platform and
resolve its ordinary verification/runtime prerequisites. The four narrow
historical release cases do not fulfill the M2 timeout/threshold/source-save
requirements; M3–M6 remain required. No PR or release qualification follows from
this local-retention switch.
