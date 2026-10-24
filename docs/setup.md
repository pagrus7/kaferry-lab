# Lab setup and implemented checks

M0 development is in progress. These commands test the lab observer, not Kaferry qualification. No `lab qualify` command exists yet.

Use Go matching `go.mod`, Docker, and an authenticated GitHub CLI for publishing reviewed increments. On the repaired local host, GitHub CLI uses `SSL_CERT_FILE=/etc/ssl/cert.pem`; do not disable certificate verification. The sibling Kaferry checkout is a read-only tagged reference.

Run formatting/vet/unit controls with `./scripts/check.sh`. Unit checks do not need Docker. Live observer tests are opt-in and require both clusters; skipping them in a unit run is not measured capability evidence.

```sh
run_id="m0-$(date +%s)"
go run ./cmd/fixture up "$run_id"
eval "$(go run ./cmd/fixture env "$run_id")"
go test -v -count=1 -timeout=4m ./internal/observer -run Live
go run ./cmd/fixture down "$run_id"
```

Always run cleanup after a failed test. Fixture state remains in `.cache/fixtures/<run_id>.json` so cleanup is restartable. Distinct random Kafka cluster IDs are recorded and checked by live metadata observations. Startup has a four-minute total budget, bounded probes, two memory/CPU-limited single-broker clusters, loopback host ports, and unique resource names. Failure triggers cleanup; cleanup refuses names/labels that do not belong to this run. It never prunes global Docker resources. Retain failed startup/broker logs before removing resources when diagnosing an environment failure.

Kafka is pinned to `apache/kafka@sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02` (3.9.2 multi-platform index). The AMD64 manifest is `sha256:f5f8605794dce59d1d566f63667682771c2fec9e96088b0d6a5ef0f8476dd4b2`; ARM64 is `sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0`. Fixture state records the actual Docker platform. Retention/compaction are disabled for initial record-ledger controls. Brokers are plaintext and contain synthetic data only; keep their ports on loopback.

Local macOS ARM64 orchestration and native ARM64 Docker broker checks do not establish native Linux AMD64 release behavior. AMD64 emulation is available for development but must be labeled emulated. Harness CI runs on native `ubuntu-24.04`; final required qualification also needs a native AMD64 runner. A green observer/harness workflow is not a release qualification.

The CI workflow has read-only contents permission, commit-pinned actions, bounded jobs, no publishing secrets in PR jobs, and uniquely named retained evidence artifacts. Qualification/publishing campaigns will be added by later milestones.
