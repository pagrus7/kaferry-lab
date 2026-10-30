# Fixed synthetic hardware workspace

The caller admits one exact case source directory:
`/run/user/501/kaferry-hardware-HEAD7-RUN/source`. HEAD7 comes from the fixed
reviewed hardware source head; RUN remains a validated finite token. It is not
an operator-supplied alternate root. The code still requires the same native
UID501, hostname/kernel, twelve source hashes, immutable synthetic artifact
hashes, input/plan/audit and one selected wrapper. No GDB mapping predicate,
query, guard, signal, wait, cleanup or passing-result condition changes.

Normal-f failed before any hardware insertion because stat device00:2a and
maps device00:26 differed. Inode, permissions and calculated offset agreed.
Current selected filesystem metadata is Btrfs/subvolume258; Linux source
explains the different stat/subvolume and maps/superblock device fields.
The actual vendor implementation has not been reproduced or authenticated.
No general Btrfs/OverlayFS identity exception, pathname inference, inode-only
shortcut or privileged map-files reader is introduced. Normal-f stays failed.

The existing `/run/user/501` tmpfs is canonical, owned by501 and0700. The measured
mount is386/device168, rw/nosuid/nodev, without noexec, with419428KiB and104857
inodes configured. These are observed environment values, not future authority.
A fresh-case admission must recheck type/options/device/ownership/free capacity.
Its shared propagation is not changed: ordinary owned file allocation performs
no mount-table operation. The current UID has no CAP_SYS_ADMIN; no mount,
new UID/capability, namespace, helper service or safeguard change is selected.

The small `storage-file-calibration-20261029b` observation mapped4096 synthetic
bytes read-only. Its actual r--p row00:a8/inode24 matched file stat dev168/inode24;
an identical-byte second file had inode25. The mapping and FD closed before
cleanup. Original bytes and records were copied privately to the Mac before
removing only the two owned volatile files and their child directory. This
measures data mapping identity, not executable placement, hardware points,
current frames, released-worker behavior, kernel persistence or qualification.

## Admission and bounded storage

Before allocating a case, reserve an ownership descriptor on persistent guest
storage at `/home/labrunner/kaferry-hardware-custody-RUN`,0700 with0600 originals.
Bind the current external machine ID, same guest UID/namespace, exact unused
volatile path, parent mode/device/mount/type/options and copy-source hashes.
The descriptor does not authenticate its own claims; compare actual owned
machine metadata and filesystem observations. Refuse existing/foreign/linked
paths, unsupported metadata or missing free-space evidence. No fallback follows
a permission refusal, and no arbitrary source or observer directory is accepted.

Allow only one exclusive volatile case child at a time. Keep a64MiB tracked-case
allocation guard, including source/VCS/bundle copies, immutable binaries,
bounded controller/caller/parent originals, staging and a persistent snapshot.
The existing tmpfs limit is shared;64MiB is not a reservation, hard per-case
quota, process/RSS limit or power-loss guarantee. Require a sampled free reserve
before copying and check the planned component bounds, then record actual byte
and entry counts. Do not fill or resize the runtime filesystem.

The source/VCS/bundle profile has a4MiB allowance, immutable binaries/build data
12MiB, controller originals7MiB, caller originals6MiB, external-parent originals
5MiB, snapshot28MiB and staging/metadata2MiB. These sum to64MiB; each component
must be measured/admitted before it can support completion. Existing controller
1MiB stream/256KiB receipt limits and caller2MiB FSIZE bounds remain. Stop on a
component overflow rather than silently truncating a successful claim. Shared
normal caches, OS metadata and page cache are not this logical-file bound.

Copy the exact664fbbf test/specimen and build provenance from its dedicated
build, as pinned in [the custody contract](hardware-custody.md); do not rebuild
or pretend they were compiled in the new directory. Keep
the original build receipt/buildinfo and record copy source/target identities,
whole hashes, modes and closed-readback facts. DWARF may name the original build
path. The original hardware gate must still independently observe exact live
r-xp file-backed identity, offsets and hits at execution time. Small data-map
readiness cannot substitute for that gate.

## Persistent evidence and cleanup

Orb's disk transfer view does not expose the live tmpfs. The measured direct
pull returned ENOENT under `/root/ro/...`; this was not a permission denial.
The same UID subsequently read the same original inode/hash in the guest and
persisted it on Btrfs for transfer. Do not point Orb push/pull at live workspace
files or recreate a missing volatile workspace. Stage ordinary transfers at the
persistent custody directory, then copy exact admitted bytes inside the guest.

After actual wrapper/parent return, take the fixed selected-file snapshot from
the volatile workspace to its persistent custody directory. Hash and retain
available failures even when closure, evidence or the original run is incomplete.
The Mac pulls that persistent archive, verifies exact bytes/catalog and privately
reads back the selected originals. An absent volatile file, unobserved return,
wrong hash, missing notice or incomplete capture cannot pass. Runtime-directory
lifetime and space checks are sampled; reboot/logout/storage loss may remove
it. No kernel-page-cache or power-failure durability is asserted.

Only after evidence retention and actual original/adopted waits plus scoped
known-PID reconciliation may cleanup remove the exact owned child. Verify its
recorded identity and membership first; retain failures instead of global scans,
prune or guessed kills. Never unmount, resize, make private, clear or remove the
existing `/run/user/501` mount or unrelated files. Keep persistent originals and
all failed attempts. No case starts automatically after a failed attempt.
