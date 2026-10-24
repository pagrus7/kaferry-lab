# Kaferry Lab

Independent adversarial evidence for **published Kaferry releases**, starting with v0.6.0. The roadmap requires running the real executable in disposable Kafka and filesystem setups, injecting faults, observing records and saved progress independently, and retaining evidence that can be checked offline.

**Status: M0 accepted; M1 artifact verification, offline checking and calibration underway. M2–M6 scenarios and campaigns are not implemented. No Kaferry release is qualified.**

The purpose is additional evidence beyond Kaferry's core suite: adverse timing, combined failures, independent observers, and integrated release behavior. Successful copies are controls. Parser tests, rejection of old syntax, broad migration tests, and replicas of existing component tests are outside scope.

Build the implemented CLI, then check an authored synthetic history. Checking needs no Docker, Kafka, network access or Kaferry executable:

```sh
mkdir -p .cache/bin
go build -o .cache/bin/lab ./cmd/lab
.cache/bin/lab check internal/evidence/testdata/valid
```

`lab verify NEW_OUT_DIR` verifies the pinned published v0.6.0 Linux AMD64 artifact and observes its version. `lab calibrate NEW_OUT_DIR` kills and restarts healthy and deliberately faulty stand-ins to test the lab's detection. `lab check BUNDLE` checks one recorded history; even `PASS` always has `release_qualified:false`. `lab qualify` returns `UNSUPPORTED` until the required scenarios and campaigns exist. See [setup and checks](docs/setup.md) for prerequisites, commands, verdicts and evidence retention; [capabilities](docs/observer.md) records observer limits.

## Implement with Codex

Use Codex with your subscription login, GitHub access, and a disposable Linux Docker environment for integration work. The project config selects **GPT-6.1 Sol, high effort**, including delegated agents. Project configuration requires a trusted checkout; the launcher below explicitly selects both parent and sub-agent settings even before trust is configured. Permissions remain your host settings.

```sh
cd /path/to/kaferry-lab
./scripts/start-codex.sh
```

Start with [AGENTS.md](AGENTS.md), [ROADMAP.md](ROADMAP.md), and [PROGRESS.md](PROGRESS.md). The [execution guide](docs/execution.md) explains delegation, reviews, evidence, and continuation across context limits. [Evidence rules](docs/evidence.md) define what a result can establish; [v0.6 contract notes](docs/contract-v0.6.md) constrain the checker.

Raw histories, downloads, logs, credentials, and exploratory transcripts stay in ignored `.cache/` or `artifacts/`. Small synthetic checker fixtures belong in version control. Publishing reviewed qualification bundles is planned for M6; no publishing campaign exists yet. Go orchestrates real processes; qualification must not import Kaferry code or build a substitute executable.

Configuration references: [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference) and [subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
