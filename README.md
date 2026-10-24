# Kaferry Lab

Independent adversarial qualification of **published Kaferry releases**, starting with v0.6.0. Run the real executable in disposable Kafka and filesystem setups; inject faults, observe records and saved progress independently, and retain evidence that can be checked offline.

**Status: repository setup and implementation roadmap only. No harness or qualification results yet.**

The purpose is additional evidence beyond Kaferry's core suite: adverse timing, combined failures, independent observers, and integrated release behavior. Successful copies are controls. Parser tests, rejection of old syntax, broad migration tests, and replicas of existing component tests are outside scope.

## Implement with Codex

Use Codex with your subscription login, GitHub access, and a disposable Linux Docker environment for integration work. The project config selects **GPT-6.1 Sol, high effort**, including delegated agents. Project configuration requires a trusted checkout; the command below explicitly selects the parent model and effort. Permissions remain your host settings.

```sh
cd /path/to/kaferry-lab
codex --model gpt-6.1-sol -c 'model_reasoning_effort="high"' "$(cat CODEX_PROMPT.md)"
```

Start with [AGENTS.md](AGENTS.md), [ROADMAP.md](ROADMAP.md), and [PROGRESS.md](PROGRESS.md). The [execution guide](docs/execution.md) explains delegation, reviews, evidence, and continuation across context limits. [Evidence rules](docs/evidence.md) define what a result can establish; [v0.6 contract notes](docs/contract-v0.6.md) constrain the checker.

Raw histories, downloads, logs, credentials, and exploratory transcripts stay in ignored `.cache/` or `artifacts/`. Small synthetic checker fixtures belong in version control. Durable qualification bundles are published separately by the implemented campaign workflow; they are never source commits.

The intended runtime interface and commands in the roadmap are **to be implemented**, not currently available. Go orchestrates real processes; it must not import Kaferry code or build a substitute executable for qualification.

Configuration references: [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference) and [subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
