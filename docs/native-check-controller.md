# Fixed native harness controller (not CI integration)

`cmd/native-check` is a prebuilt, one-shot Linux ARM64 controller for exactly
`/bin/sh scripts/check.sh`. It creates no Docker resources and enables no live
test opt-ins. Its harness verdict never qualifies Kaferry or proves its own final
process return, final close, guest-to-Mac transfer, or retention. The workflow,
installed hooks, guest foreground parent and Mac readback are separate unfinished
requirements. This source has not itself established a reached native check.

The external caller supplies only `--repository`, `--run-id`, `--reviewed-head`
and `--input-sha256`. Run IDs are lowercase letters/digits/hyphens, start with a
letter/digit and have at most64characters. The source root must be exactly
`/home/labrunner/kaferry-native-ci-RUN/source`, canonical, owned by uid501 and0700.
It contains a source-only catalogued tree, without `.git`. The prebuilt controller
comes from a separate clean VCS build at the reviewed head with Go1.26.0 for
linux/arm64. The parent must authenticate that controller's whole hash/build
receipt and map the source-only archive/catalog to the approved source head.
No fabricated guest VCS metadata or runtime build fallback is used.

Before execution the only `.cache` entries are `native-check-input.json` and
`native-check-private`; the latter contains only the new exclusive RUN directory
reserved by this controller. The0600 input is hashed as exact bytes against
`--input-sha256`. Its JSON fields are:

| Field | Required value |
|---|---|
| `Version` |string `1` |
| `RunID`, `SourceHead`, `Repository` |exact supplied run/head/canonical root |
| `GuestName` |`kaferry-lab-arm64-20261026` |
| `GuestMachineID` |`01M5XVQQ4GRX6H79K1SE76R0X1`, authenticated externally |
| `SDKArchiveSHA256` |`bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd` |
| `GoBinarySHA256` |externally authenticated whole hash of `/usr/local/go/bin/go` |
| `Files` |complete sorted catalog of source regular files |

Each file row has `Path`, `SHA256`, integer `Bytes` and integer `Mode` (384 for0600
or448 for0700). Include `go.mod`, `go.sum` and `scripts/check.sh`. Directories are
0700; regular files are owned single-link files without symlinks. The catalog is
at most1024files/16MiB; traversal is at most2048entries/depth12 and excludes the
entire `.cache` subtree. The input is at most1MiB. Unknown fields/trailing JSON,
unordered/duplicate file rows, missing/extra source files, Git metadata and
changed source hashes/modes fail. Repeat the complete source and SDK input check
after actual command-tree closure; source admission does not assert adversarial
filesystem immutability between the two observations.

Runtime admission requires uid/euid501, Linux/aarch64, the selected hostname,
kernel `7.0.14-orbstack-00380-ga7e0a2dc9535`, and Go1.26.0. The hostname/input cannot
discover or prove the OrbStack machine ID. The external Mac guard must bind that
ID to the current selected owned machine. The normal root-owned nonsymlink Go
executable is hash/build-metadata checked before and after the check. The parent
must still retain the SDK provenance and ordinary cache/environment observations.

The command receives only `PATH=/usr/local/go/bin:/usr/bin:/bin`,
`HOME=/home/labrunner`, and `LC_ALL=C`. It inherits no credentials, `LAB_*`,
`KAFERRY_LAB_*`, process-control specimens, loader hooks or coverage overrides.
The existing normal home must be canonical/owned/non-world-writable. Ambient
GOCACHE/GOMODCACHE/GOPATH/GOENV/GOROOT/XDG_CACHE_HOME overrides are rejected. The
controller does not create another home/cache or alter the normal Go environment
file, SDK or defaults. It does not impose the hardware caller's2MiB FSIZE limit
on compiler/cache files. Cache/storage limits outside selected evidence remain
external admission guards, not a claimed hard quota.

The command has a300s deadline and16MiB exact-prefix stdout/stderr bounds. The
existing link controller retains its64KiB profile and fixed two-test oracle.
Both use the same dedicated subreaper/held-group anchor/sole Wait/copy-join/tree
mechanics. The native anchor self-expires at390s. Existing2s grace,8s direct-wait
allowance and20s tree-close bound stay unchanged. No alternative signal follows
a refusal. If a refusal prevents terminal waits within that bound, retain the
actual PID/start/signal facts and leave the attempt incomplete; the390s expiry
does not itself establish an observed Wait. External later reconciliation cannot
relabel the original incomplete attempt.

Selected originals are under `.cache/native-check-private/RUN`,0700 with0600
single-link regular files: `errors.json` (256KiB including final footer),
`inputs.json` (1MiB), `stdout.bin`/`stderr.bin` (16MiB each), `command.json`,
`tree.json`, and `result.pending.json` or `result.json` (256KiB each). Files can be
absent on earlier failures. The first exact-error sink is reserved before source,
SDK or native admission; earlier reservation failures may lack an exact original.
Every payload write attempts Sync and Close on its original FD. Errors are
retained privately through the existing64KiB-per-cause/256KiB-total sink. No raw
error is printed by the CLI and no replacement sink follows final-close failure.

`result.pending.json` is staged while the error sink is alive. Only successful
error-sink finalization permits rename to `result.json`. The final result may
still be INCOMPLETE. A passing harness result requires the exact command's
successful return, actual terminal wait, complete bounded output, natural EOF/copy
closure, actual anchor/adopted waits and ECHILD, unchanged source, and closed prior
payload files. `OwnFinalCloseProven` and `ReleaseQualified` remain false;
`RequiresExternalWaitAndMacReadback` remains true. The external parent must wait
this exact producer and independently check all selected original files after
writer closure. Neither Orb client exit nor the result filename supplies that
guest actual-Wait fact. False EOF fields mean unproven; nonzero waits are
conservative because os/exec can prioritize ExitError over pipe-wait errors.

Linux failure controls retain their originals in
`.cache/native-check-controller-controls/{healthy,nonzero,orphan,cancel-exit0,post-start-membership,injected-wait-gate}-*`
(0700). Fixed0600 files are `errors.json`, `stdout.bin`, `stderr.bin`,
`result.json`/`result.pending.json`, `controller-wait.json`, `control-facts.json` and, when reached,
`specimen-ready` (PID/ready bytes). Streams retain at most16MiB each; receipts and
the primary error sink at most256KiB each. The first four finite controls prove capture
beyond the old64KiB profile, fake-PASS/nonzero rejection, an actually adopted
descendant holding a log pipe, and reached cancellation followed by actual
exit0. Their helper processes self-expire within12s, controller within32s and
outer test has38s. A test timeout/failure remains failed and originals remain.
Temporary coverage directories use Go test's normal temporary storage and are
not private diagnostic originals. Existing link failure controls remain intact.

The native unit helper uses its own12s anchor. Its one failure path retains the
original exact cause, attempts only the existing stop/sole-anchor-Wait/close
route if closure has not already started, and stages all actually obtained
Wait/Tree/PID/start/signal facts and output prefixes before `t.Fatal`.
`control-facts.json` is an original INCOMPLETE snapshot, never a completion receipt.
`post-start-membership` intentionally supplies the owned controller's nonmember
PID to the existing membership check after actual anchor start. The resulting
closed signal phase must issue zero signals; its same owner observes natural
unit-anchor expiry and terminal Wait within20s. Actual ECHILD/closed-tree facts
do not turn this failed identity experiment into success.

`injected-wait-gate` supplies a clearly synthetic false direct-wait admission
gate to the existing close function. It observes the actual terminal anchor Wait
but preserves the rejected original Tree with Closed/NoChildren false. No command
is launched, no command Wait is invented, and no second close/drain/signal route
relabels that snapshot. This exercises a real evidence-admission rejection and
retention; it does not claim a real timed-out or unreaped condition. The outer
test expects these two helper processes to fail and independently reads their
exact original causes and snapshots. Their failed experiments stay incomplete.
