# Mac mini runner and local evidence

The selected runner is `kaferry-lab-mac-mini-20261025`, repository runner21 for
`pagrus7/kaferry-lab`, installed at
`/Users/pg/services/github-runners/kaferry-lab-mac-20261025`. It has only the
custom label `kaferry-lab-mac-custody-20261025`. Four unrelated runners must not
be changed. The host is Darwin/arm64. The owned OrbStack ARM64 machine was
previously unresponsive. After the user restored OrbStack on2026-10-28, it was
observed stopped and then started normally for coordinator native development.
It is not used by the custody calibration. See PROGRESS.md for measured native
checks, release identity, failed link calibration and current resources.

The active workflow is `Mac local retention calibration`. Its fixed Python
calibration is distinct from Go harness CI, release execution and M0–M6
acceptance. No uploaded artifact, cache, ciphertext or private network transfer
is part of the new path. Only source and fixed status text reach GitHub. The user approved ordinary Go builds/tests with unchanged caches and native
Linux ARM64 qualification in OrbStack. The original host build succeeded without
a workaround. The current workflow remains custody-only until native execution
and retention are integrated. Separate capture/verification-cache stops remain;
the ARM64 source port still needs native evidence.

## Provisioning contract

Provision a new owner-only root at
`/Users/pg/services/kaferry-lab-local-evidence-20261027`; do not reuse the earlier
capsule-only storage root. Its0600 `PRIVATE-STORE.json` has exactly these fields:
`version`, `repository`, `repository_id`, `ref`, `job`, `root_device`, `root_inode`,
`owner_uid`, and `approved_source_heads`. Version is1; repository is
`pagrus7/kaferry-lab`, id `1432555755`, ref
`refs/heads/codex/resilience-release-lab`, job `local-retention`. Device, inode
and uid come from the actual provisioned root; approved heads are1..16 distinct
reviewed lowercase40-hex commits. A descriptor is an operator assertion, not
observed persistence. It grants no permission for another workflow or source.

Install the exact reviewed `scripts/mac-local-runner.py` and both
`mac-local-job-{started,completed}.sh` wrappers into
`/Users/pg/services/kaferry-lab-mac-control-20261027`, outside the checkout and
runner application. Record their hashes. Configure only this runner's `.env`
with `ACTIONS_RUNNER_HOOK_JOB_STARTED` and
`ACTIONS_RUNNER_HOOK_JOB_COMPLETED`, each pointing to its absolute installed
shell wrapper. Preserve existing environment entries and credentials; never
print or copy the credentials. Restarting this runner is needed to load changed
hook settings. Hook configuration and service installation remain separate from
observing their actual execution.

GitHub documents the synchronous hooks and fail-on-nonzero pre-job behavior in
[Running scripts before or after a job](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/run-scripts).
GitHub supplies no hook timeout setting. This implementation limits file counts
and sizes, but cannot bound a stalled filesystem syscall.

## Runtime evidence required

A source review is not runner activation. Retain the exact scoped service
installation/start result, job identity, actual hook invocations/foreground
returns, original private attempt bytes, all failures and final local hash
recheck. Confirm data remains after runner restart or workspace replacement.
A missing callback must preserve INFLIGHT and reject the next job before
checkout. Never delete a failed attempt or clear a latch merely to get green.
The post-job record's scope is the fixed no-child calibration only.

The workflow has a five-minute job budget and contents-read permission. It
admits only exact trusted feature-branch push/manual events and the approved
head; pull requests are absent. Keep the runner offline until reviewed hooks
are installed. Surface any actual launchctl, network, filesystem or runner
refusal unchanged and stop that selected operation; no sudo, alternate user,
service domain, runner or cache route may conceal it.

The user-approved original Go retry succeeded; a renewed denial must still stop
its operation, and other recorded refusals cannot be bypassed. Full qualification still requires the complete roadmap, a
matching pinned published release, independently reached faults/recovery,
complete membership/bytes/routing/saved-prefix audits and offline rechecks.

## Standalone guest caller admission (not yet CI wiring)

`scripts/admit-linked-caller.py` checks an already returned native ARM64 linked
driver using explicit repository/run/head/attempt inputs. It executes no driver,
Go, Docker or transport. The guest foreground parent must first write the actual
return status after its direct Wait; the admission reader cannot manufacture or
independently discover that event. Its final process return must also be observed
by its caller. An Orb client return is a separate host observation.

The implementation binds fixed native build paths, actual binary bytes/AArch64
ELF and retained Go build metadata, the existing driver marker, terminal child
wait/tree/EOF facts and the foreground result. Exit0 means admitted calibration
pass, exit2 means admitted quiescent FAILED calibration, and exit1 means
incomplete/rejected. No result means Kaferry qualification. Exact errors use the
one inherited caller-reserved private FD; no alternate sink is attempted.

The63 literal refusal/closure controls in `scripts/test-linked-caller.py` exercise
that exact implementation. Native development exercised its quiescent-failure
path after image admission failed; no delay fault passed. Source review, trusted
native job/hooks, complete bounded local guest-to-Mac retention, actual runtime
controls and final-head CI remain separate requirements. The active installed
no-child hook contract is unchanged and cannot accept a native evidence tree.
