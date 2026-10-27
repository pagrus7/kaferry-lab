# Kaferry Lab

Tool resilience and data integrity testing for **published Kaferry releases**, starting with v0.6.0. Kaferry is the tool under test. The roadmap requires running the real executable in disposable Kafka and filesystem setups, injecting faults, observing records and saved progress independently, and retaining evidence that can be checked offline.

**Status: M0 and M1 accepted. M2 targeted release scenarios and independent observations are in development; required M2–M6 fault evidence and campaigns are incomplete. No Kaferry release is qualified.**

The selected final target is now **native Linux ARM64 under local OrbStack**, with private evidence retained on the Mac and no Tailscale. The current executable paths remain AMD64-only; the [ARM64 transition](docs/local-linux-arm64.md) is incomplete. Historical AMD64 results do not qualify ARM64. Local build and capture stops remain in effect. The command examples below describe implemented interfaces, not authorization to retry stopped local operations.

The purpose is to test how Kaferry handles failures during data copies, preserves records and saved progress, and recovers after faults are removed. Independent observers and combined failure scenarios provide evidence beyond its core suite. Successful copies are controls. Parser tests, rejection of old syntax, broad migration tests, and replicas of existing component tests are outside scope.

Build the implemented CLI, then check an authored synthetic history. Checking needs no Docker, Kafka, network access or Kaferry executable:

```sh
mkdir -p .cache/bin
go build -o .cache/bin/lab ./cmd/lab
.cache/bin/lab check internal/evidence/testdata/valid
```

`lab verify NEW_OUT_DIR` verifies the pinned published v0.6.0 Linux AMD64 artifact and observes its version on native Linux AMD64. `lab calibrate NEW_OUT_DIR` kills and restarts healthy and deliberately faulty stand-ins to test the lab's detection. `lab check BUNDLE` checks one recorded history; even `PASS` always has `release_qualified:false`. `lab scenario RUN_ID CASE ROUTING NEW_OUT_DIR` executes a bounded partial release case against a lab-owned fixture; see [targeted M2 runs](docs/m2.md). `lab qualify` returns `UNSUPPORTED` until the required scenarios and campaigns exist. See [setup and checks](docs/setup.md) for prerequisites, commands, verdicts and evidence retention; [capabilities](docs/observer.md) records observer limits.

## Implement with Codex

Use Codex with your subscription login, GitHub access, and a disposable Linux Docker environment for integration work. The project config selects **GPT-6.1 Sol, high effort**, including delegated agents. Project configuration requires a trusted checkout; the launcher below explicitly selects both parent and sub-agent settings even before trust is configured. Permissions remain your host settings.

```sh
cd /path/to/kaferry-lab
./scripts/start-codex.sh
```

Start with [AGENTS.md](AGENTS.md), [ROADMAP.md](ROADMAP.md), and [PROGRESS.md](PROGRESS.md). The [execution guide](docs/execution.md) explains delegation, reviews, evidence, and continuation across context limits. [Evidence rules](docs/evidence.md) define what a result can establish; [v0.6 contract notes](docs/contract-v0.6.md) constrain the checker.

Raw histories, downloads, logs, credentials, and exploratory transcripts stay in ignored `.cache/` or `artifacts/`. Small synthetic checker fixtures belong in version control. Publishing reviewed qualification bundles is planned for M6; no publishing campaign exists yet. Go orchestrates real processes; qualification must not import Kaferry code or build a substitute executable.

Configuration references: [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference) and [subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
