# One-case native hardware calibration custody

`scripts/run-hardware-calibration.py` implements a small direct-child caller for
the four existing synthetic GDB wrappers at hardware source
`af5e4b2b62099ea53a45be935ebdee9be4f90378`. It uses private regular output files
and `Popen.wait`. It does not build, install, run Git, invoke GDB directly, copy
evidence, select a released Kaferry image or run multiple cases. The hardware
controller continues to own inner process identities, exact original/adopted
waits, hardware hits, guard checks, internal channel EOFs and writer closure.

After the launch-attempt repair,16 portable controls ran on the Mac:15 passed
and the Linux-only FSIZE control skipped. The native e703432 full check passed
all16 controls, including actual FSIZE, and the Go checks in55.169s. Independent
source reviews passed. An inert normal-shaped capture and an actual finite
FSIZE failure were retained and independently read back on the Mac before the
first debugger attempt. These controls do not execute the real specimen.

The first actual normal attempt, `hardware-native-20261029-normal`, failed
before an inferior launch. GDB emitted a startup index-cache path warning
because its explicit environment omitted HOME and XDG_CACHE_HOME. The reader
also rejected `cmd-param-changed` notifications from the supplied startup
settings. Exact stderr/MI, waits and the incomplete snapshot remain private
locally. The original controller cleanup verdict remains failed. Actual waits,
no exec-run command in the retained trace and scoped absence checks for the
three recorded PIDs support no remaining live process reconciliation for this
prelaunch failure; they do not establish hardware capability.

No permission denial was observed in that attempt. Hardware82f176f repairs
the startup environment and notification handling, requires initial prompt
evidence before inferior setup, and accounts for thread-only claims during
prelaunch cleanup. Native full checks passed in14.809s and all three affected
source reviews passed, after retained negative controls and a failed fixture
repair. Fatal stderr handling and the actual existing default home remain;
there is no cache redirect. These passing source/control checks require a new
actual debugger attempt to establish runtime capability.

The subsequent `hardware-native-20261029-normal-c` attempt passed startup,
all20 guard readbacks and both signal policies, then failed on the
`breakpoint-created` notification emitted by its fixed CLI `catch fork` command.
It never issued exec-run or launched an inferior; no hardware hit or permission
denial was observed. GDB stderr was empty. Actual GDB wait, closed channels,
scoped absence checks and independent failed-evidence readback support bounded
prelaunch reconciliation. Overall failure and the incomplete snapshot remain
unchanged. The selected notification handling was repaired at60c6ff9, with
finite synthetic presentation and both-order cleanup/context controls. That
source has all three independent reviews, a passing targeted native check
(.813s) and a passing full hardware-branch check (16.372s); actual GDB cases
were skipped, and this older branch has separate AMD64-only skips. A new
native build produced freshly bound synthetic binaries, copied and verified
privately on the Mac. Caller sourcec0f53c3 pinned that60 build and both
presentation source files. These are source/manual development observations,
not passing runtime controls or integrated native CI.
Three cancellation cases remain unrun; no next case starts automatically. No calibration or passing harness control qualifies
Kaferry or completes M2.

The subsequent normal-d attempt reached all24 guard readbacks, both signal
policies, all three catchpoint creations and the verified parent launch. GDB
reported parent exit02 before READY; no marker or hardware hit was reached.
The controller rejected that nonzero stop and retained ECHILD during cleanup.
Its actual GDB SIGKILL9 wait and the four later scoped PID absences cannot
replace the missing parent wait, EOF or cleanup success. All31 available
originals were privately hash-verified on the Mac; the snapshot stays incomplete.

Exact stock GDB source explains the launch defect: `exec-arguments` forwards raw
CLI text, and its no-shell path preserves individually added quotes. The specimen
therefore receives a literal quoted mode instead of `parent`. This is a
source-derived argument explanation, not a live argv observation or an inferred
wait. Sourceeb0fd52 emits six admitted raw ASCII tokens while keeping the shell
disabled and other MI-argument quoting unchanged. It has three independent
source reviews, targeted native checks passing in.913s and a full hardware-branch
check passing in15.737s; live GDB tests remain skipped. Fresh normal-e binaries reached READY, the parent-spawned target and its exec
catchpoint in a separately retained attempt. The numeric marker mapping check
then failed before any hardware insertion/hit. Actual original target SIGTERM15,
GDB SIGKILL9 and adopted parent exit1 waits and all four channel EOFs are retained;
normal-mode cleanup remains failed, and no hardware capability is established.
All33 originals were privately hash-verified on the Mac; scoped absence checks
cover the five recorded PIDs without creating a passing lifecycle verdict.

That bundle did not retain the rejected maps row or bound stat tuple. Exact ELF
arithmetic agrees, so the failed subcondition remains unknown. Hardwareaf5e4b2
changes only the private mismatch diagnostic: one already-read row capped1024
bytes, expected/actual tuples, field reasons and explicit incomplete truncation.
It preserves all comparisons, guards, query budgets and cleanup acceptance.
Targeted native checks passed in.795s and full hardware-branch checks in16.387s,
with all three affected source reviews passing; the actual GDB tests skipped.
Fresh normal-f binaries are bound below. No actual normal-f attempt is ready
until caller validation/reviews, filled inputs and custody admission complete.

The first normal-f data-admission check refused before any wrapper or debugger
launch: the caller still required the old `eb0fd52` directory prefix despite
its AF5 source/artifact pins. That failed packet and exact refusal are retained.
The canonical directory now derives its seven-character prefix from the same
fixed reviewed HEAD, keeping the existing exact guest/run/source constraint.
A control with literal AF5, stale EB and wrong-run directories fails against the
old source and distinguishes the corrected source-pin boundary. This corrects
caller preparation; no prior lifecycle failure or mapping gate is relaxed.

The subsequent normal-f attempt reached READY and target exec but failed the
unchanged mapping gate. Its complete diagnostic identifies only the device
minor: opened-file stat00:2a versus maps00:26, with the same inode, permissions,
range and calculated offset. All actual waits and copied originals remain
retained; normal-mode cleanup still fails and no hardware hit is established.
Current filesystem metadata identifies Btrfs, whose subvolume stat identity can
differ from the inode superblock reported in maps. Equal inode/path text alone
cannot repair that identity relation, so the gate is not relaxed.

The fixed next-case workspace uses the already existing, user-owned tmpfs at
`/run/user/501`, with unchanged UID, namespace, kernel, GDB, image bytes, HOME,
caches, guards and oracles. No mount, privilege or propagation change is made.
A small read-only data mapping matched file stat and distinguished an identical-byte
clone's inode; it did not execute an artifact or establish hardware capability.
The literal caller-root control also rejects the old home workspace before
source-pin reads. See [workspace ownership and retention](hardware-workspace.md)
for the separate capacity, volatile-lifetime and persistent-copy requirements.

## Exact inputs before launch

The coordinator prepares a fresh reviewedaf5e4b2 checkout per case at
`/run/user/501/kaferry-hardware-af5e4b2-RUN/source`. The caller checks canonical
paths, actual uid501 and Linux/aarch64 uname for the selected owned guest
`kaferry-lab-arm64-20261026`, kernel
`7.0.14-orbstack-00380-ga7e0a2dc9535`. OrbStack machine ID
`01M5XVQQ4GRX6H79K1SE76R0X1` is bound in the input; the coordinator must compare
the actual external ownership descriptor. Uname does not prove that control-plane
ID, physical hardware or kernel-source provenance.

Already-built inputs live under `.cache/hardware-build/`. The coordinator's
new native Go1.26 build occurred once in the normal-f source root; its exact
artifact bytes may be hash-verified private copies in the other three fresh
checkouts. Do not call those copies fresh builds: rebuilding at a different
absolute path may change DWARF/build bytes. The fixed artifacts are:

| File | Bytes | SHA256 |
|---|---:|---|
|`hardwarecalibration.test`|6567549|`00bd5b076d6b7cca613c0befe75223e22fb58634467b0b5b039fa27dbf1bf2c7`|
|`hardware-wait-specimen`|3993074|`a74db3f833905f1a550ae1346e844cc5f6369a7f2ad04a1ac1544b743035923c`|

The caller pins these whole bytes and twelveaf5e4b2 source/build-input files. It also
pins the whole `build-binding.json` receipt, caller script, existing GDB plan
and independently issued source-audit receipt. The build receipt's checked
fields are SourceHead, GoVersion=go1.26.0, GOOS=linux, GOARCH=arm64,
SDKArchiveSHA256=`bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd`,
TestSHA256 and SpecimenSHA256. Its actual build commands/waits, clean source
mapping and copied artifact identities need independent review; a manifest
does not authenticate its own claims. No build or source fallback exists.

Stage the reviewed caller bytes as `.cache/run-hardware-calibration.py` and
provide `.cache/hardware-gdb-caller-input.json`0600 with exactly these fields:
RunID, Case, RepoRoot, SourceHead, GuestName, GuestMachineID, CallerSHA256,
TestSHA256, TestBytes, SpecimenSHA256, SpecimenBytes, BuildSHA256, PlanSHA256 and
AuditSHA256. RunID is a nonsecret lowercase/digit/hyphen token of at most64bytes.
SourceHead/guest/artifact fields must match the constants above. RepoRoot must
be this exact current case checkout. SHA256 values pin actual complete bytes;
there are no placeholder/default pins or additional operator approval object.

The existing `.cache/hardware-gdb-calibration-plan.json` must be owner0600 and
contain the exact `GDBCalibrationConfig` eight fields. The same RunID, nonsecret
64-lower-hex nonce, exact current specimen path/hash and selected cancellation
tuple are required. Its GDB pin is stock Ubuntu
`15.1-1ubuntu1~24.04.1 arm64`, executable SHA256
`0a7a6c0c020f1bb52054f89444aba5f2ba813b0ef4a1ff01f72ef97f7185d93c`,
plus the separately reviewed receipt at
`.cache/hardware-gdb-audit/AuditSHA256.json`. The caller hashes that receipt;
the existing controller owns its exact schema/package/runtime checks. The
caller never manufactures an audit receipt, plan or guard-capability result.

## One fresh direct child

The preexisting `.cache/hardware-outer-private` and
`.cache/hardware-wait-private` bases must be canonical, owner0700. Both RUN
directories must be unused. The caller exclusively creates its outer attempt
and preopens errors.jsonl first, then regular stdout.bin, stderr.bin,
inputs.json, wait.json, result.json and inventory.json, all0600/single-link.
It reserves every slot before validating inputs or starting a child. There is
no existing-run adoption, truncation, automatic deletion or alternate sink.

After frozen review and prerequisite admission, the one command would be:

```text
/usr/bin/python3 .cache/run-hardware-calibration.py RUN INPUT_SHA256
```

This implemented interface was used by the failed first normal attempt above. Cwd is the
fresh hardware checkout. Input hash selection is concrete per case; the
coordinator supplies the already authorized fixed inputs without another
approval workflow. The only child argv is the fixed native test image with
`-test.run=^EXACT_NAME$ -test.count=1 -test.parallel=1 -test.timeout=75s -test.v`.
The only environment is LC_ALL=C, LAB_HARDWARE_GDB=1 and the selected case.
Stdin is `/dev/null`; stdout/stderr are the preopened regular files;
`close_fds=True`. No outer capture pipes, selectors, pidfds, raw wait4 or
subreaper are introduced.

| Case | Exact wrapper |
|---|---|
|normal|TestNativeFixedStockGDBCalibration|
|cancel|TestNativeGDBCancellationAtValidatedHardwareHit|
|early-cancel|TestNativeGDBCancellationBeforeReadyCleansEarlyInferior|
|pre-admission-cancel|TestNativeGDBPreAdmissionCancellationKeepsEarlyTargetHandle|

Immediately before spawn, this one-shot caller lowers its own soft **and hard**
RLIMIT_FSIZE to2MiB and checks the installed value. Its child/descendants inherit
it; no pre-exec helper, restoration, increase or fallback follows. A preexisting
lower limit refuses before changing it. This is a per-file resource cap, not
aggregate disk quota or a disk-fill fault. Existing inner stream caps remain
1MiB and journals/receipts keep their smaller bounds. Reached cap, at-cap
stdout, unexpected stderr or output failure cannot pass.

The actual guest parent records its PID, started child PID, elapsed interval
and public `Popen.wait` return code. Normal budget is90s. A timeout is retained
and remains incomplete even if planned owned-child cleanup later waits: TERM,
wait5s, then KILL/wait5s only if the previous TERM succeeded and its grace wait
timed out. A non-timeout spawn/wait refusal has no explicit retry/alternate
route. A signal refusal stops escalation. No process group, unknown PID or
inner GDB/parent/marker is signalled by this caller. Killing/waiting the direct
test child does not prove its descendants cleaned up. Missing inner closure
blocks further cases until separately proven owned resources are reconciled.

## Narrow closure and return meaning

Live admission uses the reviewed wrapper, without a second guard/hit/wait
oracle. Require actual unexpired child exit0; exactly the selected RUN, its
unique case/run-specific final assertion, exactly its PASS and final PASS;
no SKIP/FAIL/extra test or unexpected stderr. Inputs are rehashed after return.
The wrapper checks the **returned** controller report after final writer
closure. `controller-report.json` is serialized earlier: its WritersClosed
field remains false and cannot attest its own close. A loose PASS string, the
report alone or an outer result marker is insufficient.

Exit0 means that selected wrapper CONTROL was observed and local finalization
succeeded. Only normal sets NormalCalibrationComplete=true. Each cancellation
sets CancellationControlDetected=true and **ExperimentPassing=false**. All
results set ReleaseQualified=false. Any refusal, timeout, missing witness,
write/sync/close failure or inventory error returns2/INCOMPLETE; the script
never starts the next case. Before launch is attempted there are no new inner resources to reconcile.
`LaunchAttempted` is set before Popen, while `Started` records its successful
return with a child handle. A constructor exception cannot prove no launch
occurred: that failure remains incomplete with inner cleanup unresolved, no
known PID invented and no second spawn/signal/wait route. A preflight refusal
before the attempt is distinct. Failed wrappers also leave inner cleanup
unresolved.

Available exceptions and ordered read/close tracebacks remain in the existing
primary error file, up to64KiB per record/256KiB total. Overflow preserves an
incomplete prefix. Sink failure stops further error writes; first/final sink
failure may leave an original unavailable. No public raw diagnostic or alternate
copy of the cause is written. An earlier result may be optimistic if a later
final close fails: actual caller return/status is always mandatory.

After actual child return and output/input/wait writer closure, the exact
post-close wrapper witness gates inventory of the known hardware RUN. Only
twelve fixed regular names and two exact FIFOs are allowed; two parent journals
are optional only for early-cancel. Regular files retain their existing
per-file bounds and a6MiB aggregate bound, stable descriptor/path identity,
owner0600/single-link and whole-file hashes. FIFOs contribute metadata only;
they are never opened/copied. Unexpected/missing/link/symlink members refuse.
The primary sink closes after the ordinary stream, input, wait and result
writers. The terminal inventory then hashes those closed files and writes its
own file, with no remaining diagnostic route for a failure at that boundary.
Final inventory has OwnFinalCloseProven=false; it does not hash or attest its
own last close. Actual external return/status and Mac readback remain mandatory.

The existing bounded snapshot/Mac readback route must explicitly include these
fixed roots and pinned inputs/binaries, using artifact bounds separate from
the2MiB live-output cap. It must preserve guest originals, bind actual external
foreground operation/status and independently verify every selected private
Mac file's bytes/hash/mode after return. A host Orb wait is not the recorded
guest parent's wrapper wait. Caller final files do not prove their own close;
source-bound finalization plus external return/readback is the finite custody
boundary, without inventing another anchor chain. An inert sample using the
same regular-file/FIFO shapes must demonstrate local persistence before actual
hardware selection. Snapshot/readback is not implemented by this script.

## Caller controls and limits

`scripts/test-hardware-calibration-caller.py` uses visibly inert Python helpers
through ordinary private function seams; it never runs Go/GDB/the real specimen
or issues audit/plan inputs. The repaired targeted command passed on the Mac with15
controls passing and the Linux-only FSIZE control skipped:

```text
python3 scripts/test-hardware-calibration-caller.py
```

The standard `scripts/check.sh` now invokes these controls with verbose output
before its Go checks. That combined host check passed; native Linux execution
and independent review remain required.

Controls cover all four exact wrapper witnesses and cancellation meanings;
plain PASS, skip/wrong-case/extra-test/missing assertion; missing/substituted
input before spawn; whole-byte corruption, bounds/mode/symlink/hardlink refusal;
both available read and close causes on Python3.9; actual direct child
PID/wait/nonzero/binary outputs; actual timeout/owned wait; wait/signal refusal
without another route; first/last primary and output-close failure; exclusive
old-attempt refusal; fixed member/FIFO handling; and no FSIZE increase/restore.
Linux-only controls use a finite4096-byte positive payload and a finite
2MiB+4096-byte negative payload. The latter must retain exactly the2MiB prefix
and actual EFBIG/nonzero status. Only the inert child lowers its limit; no host
filling or real denial is induced. Portable controls do not change the test
parent's limits or caches.

Fresh private actual process/FSIZE originals, helper bytes, wait/error files and
hash summaries are retained beneath `.cache/hardware-caller-controls/` for
offline review. Each test invocation uses exclusive names and finite synthetic
data (the FSIZE payload retains at most2MiB); no old stopped run is reused or
deleted. These are caller-controller calibration evidence, never native GDB
enforcement or product qualification. The actual caller/source pipeline must
still be frozen, checked, independently reviewed and measured on the selected
native platform, followed by bounded Mac persistence/readback.

Synchronous filesystem/exec/kernel stalls can outlast userspace deadlines.
Same-uid immutability, power-loss durability, arbitrary session-loss recovery,
complete library/kernel-error observability and exact vendor-kernel source are
not proven. Preserve incomplete prefixes and unresolved resources on failure;
no alternate tool, privilege, guard, artifact or capture route replaces them.
