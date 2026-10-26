#!/usr/bin/env python3
"""Copy one admitted linked-v2 capsule to an operator-provisioned private root.

No network, crypto, keys, runner configuration or persistence proof. A completed
copy still needs its successful stdout receipt; an on-disk marker alone is not
proof of final close or of surviving any worker/filesystem lifecycle boundary.
"""
import argparse
import base64
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import signal
import stat
import sys

# Generated diagnostics belong under .cache, never beside tracked scripts.
sys.dont_write_bytecode = True

try:
    _spec = importlib.util.spec_from_file_location("private_store_sealer", Path(__file__).with_name("seal-link-notices.py"))
    s = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(s)
except Exception:
    # Before any private sink exists, loading failure has no guaranteed original.
    print('{"namespace":"calibration/private-notice-store","status":"rejected-incomplete","complete":false,"release_qualified":false}')
    raise SystemExit(1) from None

REPOSITORY = "pagrus7/kaferry-lab"
REPOSITORY_ID = "1432555755"
NAMESPACE = "calibration/private-notice-store"
MAX_ATTEMPTS = 64
MAX_ATTEMPT_BYTES = 13 << 20
MAX_METADATA = 256 << 10
MAX_ERROR = 64 << 10
DESCRIPTOR = "PRIVATE-STORE.json"
LEAF = re.compile(r"links-[1-9][0-9]*-[1-9][0-9]{0,8}--[0-9a-f]{40}--links--[1-9][0-9]{0,8}\Z")
SCOPE = "Reviewed driver final marker after actual wait/tree closure and primary sink sync/close; no ACK or Kaferry qualification."


class IOFailures(Exception):
    def __init__(self, failures):
        self.failures = failures
        super().__init__("private storage operation incomplete")


def require(ok):
    if not ok:
        raise s.Rejected("private storage admission rejected")


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)
    return value


def identity(run, head, job, attempt, environment):
    value = s.identities(run, head, s.CERT_PIN, job, attempt, s.LINKED_LAYOUT)
    require(job == "links")
    expected = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
                "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/codex/resilience-release-lab",
                "GITHUB_JOB": job, "GITHUB_SHA": head, "GITHUB_RUN_ATTEMPT": str(attempt)}
    require(all(environment.get(k) == v for k, v in expected.items()))
    number = environment.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", number) is not None)
    require(run == "links-" + number + "-" + str(attempt))
    return value


def public_identity(value, binding):
    return dict(value, namespace=NAMESPACE, repository=REPOSITORY,
                repository_id=REPOSITORY_ID, storage_binding_sha256=binding,
                release_qualified=False)


def attempt_name(value):
    return "--".join(value[k] for k in ("run_id", "source_head", "job", "attempt"))


def root_entries(root):
    # Bounded dedicated namespace; no discovery, reuse, deletion or quota cleanup.
    names = []
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.name == DESCRIPTOR:
                continue
            require(len(names) < MAX_ATTEMPTS and LEAF.fullmatch(entry.name) is not None)
            s.check_private(entry.stat(follow_symlinks=False), directory=True)
            names.append(entry.name)
    return names


def open_root(base, root, storage_id):
    root = Path(root)
    require(root.is_absolute() and str(root) == os.path.abspath(root))
    base = Path(os.path.abspath(base))
    common = Path(os.path.commonpath((str(root), str(base))))
    require(common != root and common != base)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", storage_id) is not None)
    s.check_chain(root)
    before = root.lstat()
    s.check_private(before, directory=True)
    raw = s.read_regular(root / DESCRIPTOR, 2048, private=True)
    descriptor = s.parse_json(raw)
    require(type(descriptor) is dict and set(descriptor) == {
        "version", "storage_id", "root_device", "root_inode", "operator_confirmed_persistent",
        "private", "exclusive_trusted_writer", "repository", "repository_id"})
    require(type(descriptor["version"]) is int and descriptor["version"] == 1)
    require(descriptor["storage_id"] == storage_id and descriptor["repository"] == REPOSITORY
            and descriptor["repository_id"] == REPOSITORY_ID)
    require(all(descriptor[k] is True for k in ("operator_confirmed_persistent", "private", "exclusive_trusted_writer")))
    require(integer(descriptor["root_device"], 0, 1 << 64) == before.st_dev
            and integer(descriptor["root_inode"], 1, 1 << 64) == before.st_ino)
    root_entries(root)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        s.check_private(opened, directory=True)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
    except BaseException:
        os.close(fd)
        raise
    # Descriptor is the operator's assertion, never observation of mount durability.
    return root, fd, s.digest(raw)


def preflight(base, root, storage_id, value):
    checked_root, fd, binding = open_root(base, root, storage_id)
    try:
        names = root_entries(checked_root)
        require(len(names) < MAX_ATTEMPTS and attempt_name(value) not in names)
    finally:
        os.close(fd)
    return dict(public_identity(value, binding), status="preflight-ready", complete=False,
                retention_limit_attempts=MAX_ATTEMPTS,
                retention_limit_bytes_per_attempt=MAX_ATTEMPT_BYTES)


def closure(raw, value):
    proof = s.parse_json(raw)
    keys = {"namespace", "run_id", "source_head", "job", "attempt", "foreground_return_observed",
            "foreground_exit_code", "caller_cancelled_at_admission", "writers_quiescent",
            "private_capture_complete", "setup_returned", "cleanup_attempted", "cleanup_returned",
            "resources_cleaned", "fixture_cleanup_succeeded", "child_started", "child_wait_returned",
            "child_reaped", "stream_copies_joined", "anchor_started", "anchor_wait_returned",
            "anchor_reaped", "subreaper_enabled", "terminal_adopted_waits",
            "actual_ECHILD_observed_by_driver", "calibration_passed", "release_qualified", "scope"}
    require(type(proof) is dict and set(proof) == keys)
    require(all(proof[k] == value[k] for k in ("run_id", "source_head", "job", "attempt")))
    require(proof["namespace"] == "calibration/linked-caller" and proof["scope"] == SCOPE)
    boolean_keys = keys - {"namespace", "run_id", "source_head", "job", "attempt",
                           "foreground_exit_code", "terminal_adopted_waits", "scope"}
    require(all(type(proof[k]) is bool for k in boolean_keys))
    require(all(proof[k] for k in ("foreground_return_observed", "writers_quiescent", "private_capture_complete",
                                   "setup_returned", "subreaper_enabled", "actual_ECHILD_observed_by_driver")))
    require(not proof["caller_cancelled_at_admission"] and not proof["release_qualified"])
    require(proof["cleanup_attempted"] == proof["cleanup_returned"])
    code = integer(proof["foreground_exit_code"], 0, 255)
    integer(proof["terminal_adopted_waits"], 0, 16)
    for stem, suffixes in (("child", ("wait_returned", "reaped")), ("anchor", ("wait_returned", "reaped"))):
        require(all(proof[stem + "_" + suffix] == proof[stem + "_started"] for suffix in suffixes))
    require(proof["stream_copies_joined"] == proof["child_started"])
    require((code == 0) == proof["calibration_passed"])
    if proof["calibration_passed"]:
        require(all(proof[k] for k in ("cleanup_attempted", "cleanup_returned", "resources_cleaned", "fixture_cleanup_succeeded")))
    return proof


def payloads(base, value):
    quarantine = base / ".cache/link-quarantine" / value["run_id"]
    for directory in (base / ".cache", quarantine.parent, quarantine):
        s.check_private(directory.lstat(), directory=True)
    names = set()
    for member in quarantine.iterdir():
        require(len(names) < 2)
        names.add(member.name)
    require(names == {"notice.cms", "COMPLETE.json"})
    sealed = s.read_regular(quarantine / "COMPLETE.json", MAX_METADATA, private=True)
    metadata = s.parse_json(sealed)
    keys = set(value) | {"complete", "cms_bytes", "cms_sha256", "files", "total_bytes", "publication", "cipher",
                         "manifest_version", "components", "bundle_complete", "release_qualified", "caller_declaration",
                         "fixture_absence_sha256", "completion_scope"}
    require(type(metadata) is dict and set(metadata) == keys)
    require(all(metadata[k] == v for k, v in value.items()))
    require(metadata["complete"] is True and metadata["release_qualified"] is False
            and type(metadata["manifest_version"]) is int and metadata["manifest_version"] == 2)
    declaration = metadata["caller_declaration"]
    require(type(declaration) is dict and set(declaration) == {"notice_writers_stopped_and_reaped", "observed_proof"}
            and declaration["notice_writers_stopped_and_reaped"] is True and declaration["observed_proof"] is False)
    require(metadata["publication"] == "DISABLED; explicit encrypted-public-quarantine exception required")
    require(metadata["cipher"] == "AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD")
    require(metadata["completion_scope"] == "captured bytes only; no writer-quiescence, cleanup or calibration qualification")
    components = metadata["components"]
    require(type(components) is dict and set(components) == {"driver", "fixture"})
    for name, component in components.items():
        require(type(component) is dict and set(component) == {"availability", "files", "total_bytes"})
        count = integer(component["files"], 0, s.MAX_FILES)
        size = integer(component["total_bytes"], 0, s.MAX_PAYLOAD)
        if component["availability"] == "captured":
            require(count > 0 and size > 0)
        else:
            require(name == "fixture" and component["availability"] == "absent-ENOENT" and count == size == 0)
    require(integer(metadata["files"], 1, s.MAX_FILES) == sum(c["files"] for c in components.values()))
    require(integer(metadata["total_bytes"], 1, s.MAX_PAYLOAD) == sum(c["total_bytes"] for c in components.values()))
    require(type(metadata["bundle_complete"]) is bool)
    absent = components["fixture"]["availability"] == "absent-ENOENT"
    require(metadata["bundle_complete"] == (not absent))
    require((absent and type(metadata["fixture_absence_sha256"]) is str and s.SHA.fullmatch(metadata["fixture_absence_sha256"]) is not None)
            or (not absent and metadata["fixture_absence_sha256"] is None))
    cms = s.read_regular(quarantine / "notice.cms", s.MAX_CMS, private=True)
    require(integer(metadata["cms_bytes"], 1, s.MAX_CMS) == len(cms) and metadata["cms_sha256"] == s.digest(cms))
    proof_path = base / ".cache/links/caller-proof.json"
    proof = s.read_regular(proof_path, MAX_METADATA)
    info = proof_path.lstat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) in (0o600, 0o644))
    closure(proof, value)
    require(len(sealed) + len(proof) <= MAX_METADATA)
    return {"notice.cms": cms, "SEAL-COMPLETE.json": sealed, "caller-proof.json": proof}


def write_file(fd, name, body):
    # Single write; a short/failed write is fatal, never retried through any route.
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    failures = []
    try:
        try:
            if os.write(out, body) != len(body):
                raise OSError(5, "private storage short write")
            os.fsync(out)
        except OSError as error:
            failures.append(("write/sync " + name, error))
    finally:
        try:
            os.close(out)
        except OSError as error:
            failures.append(("close " + name, error))
    if failures:
        raise IOFailures(failures)


def retain_failure(fd, error):
    failures = error.failures if isinstance(error, IOFailures) else [("store", error)]
    records, seen = [], set()
    pending = list(failures)
    while pending and len(records) < 8:
        action, current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        records.append({"action": action, "type": type(current).__name__, "errno": getattr(current, "errno", None),
                        "exact_text": str(current), "filename": getattr(current, "filename", None),
                        "filename2": getattr(current, "filename2", None)})
        for relation, other in (("cause", current.__cause__), ("context", current.__context__)):
            if other is not None and id(other) not in seen:
                pending.append((relation, other))
    body = s.encode({"complete": not pending, "failures": records})
    if len(body) > MAX_ERROR:
        body = s.encode({"complete": False, "bytes": len(body), "sha256": s.digest(body),
                         "prefix_base64": base64.b64encode(body[:32768]).decode()})
    # One capture in the already reserved sink. A failure is unavailable, no retry.
    if os.write(fd, body) != len(body):
        raise s.EvidenceIncomplete("private storage error sink incomplete")
    os.fsync(fd)


def store(base, root, storage_id, value):
    base = Path(base)
    root, root_fd, binding = open_root(base, root, storage_id)
    target_fd = error_fd = None
    target = root / attempt_name(value)
    promoted = False
    try:
        # Nonblocking, no fallback/retry. Serializes the finite64-attempt cap.
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        names = root_entries(root)
        require(len(names) < MAX_ATTEMPTS and target.name not in names)
        os.mkdir(target.name, 0o700, dir_fd=root_fd)
        target_fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        s.check_private(os.fstat(target_fd), directory=True)
        error_fd = os.open("OS-ERROR.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=target_fd)
        os.fsync(error_fd)
        bodies = payloads(base, value)
        require(sum(map(len, bodies.values())) + MAX_ERROR + 4096 < MAX_ATTEMPT_BYTES)
        records = {}
        for name, body in bodies.items():
            write_file(target_fd, name, body)
            require(s.read_regular(target / name, len(body), private=True) == body)
            records[name] = {"bytes": len(body), "sha256": s.digest(body)}
        marker = dict(public_identity(value, binding), complete=True, files=records,
                      trust="operator-provisioned private filesystem; no lifecycle persistence observed",
                      successful_stdout_receipt_required=True)
        marker_body = s.encode(marker)
        require(len(marker_body) <= 4096)
        write_file(target_fd, "COMPLETE.pending.json", marker_body)
        os.fsync(target_fd)
        os.fsync(root_fd)
        # Sink closes before promotion; terminal failures can have unavailable originals.
        owned, error_fd = error_fd, None
        os.close(owned)
        os.rename("COMPLETE.pending.json", "COMPLETE.json", src_dir_fd=target_fd, dst_dir_fd=target_fd)
        promoted = True
        os.fsync(target_fd)
        os.fsync(root_fd)
        # No successful receipt until every owned descriptor has closed.
        owned, root_fd = root_fd, None
        os.close(owned)
        owned, target_fd = target_fd, None
        os.close(owned)
        return dict(public_identity(value, binding), status="stored", complete=True,
                    cms_sha256=records["notice.cms"]["sha256"], cms_bytes=records["notice.cms"]["bytes"],
                    seal_complete_sha256=records["SEAL-COMPLETE.json"]["sha256"],
                    caller_proof_sha256=records["caller-proof.json"]["sha256"],
                    storage_receipt_sha256=s.digest(marker_body), stored_payload_files=3,
                    stored_payload_bytes=sum(len(b) for b in bodies.values()))
    except BaseException as error:
        # Only invalidate our own promotion; never delete prior/incomplete evidence.
        failures = list(error.failures) if isinstance(error, IOFailures) else [("store", error)]
        if promoted and target_fd is not None:
            try:
                os.unlink("COMPLETE.json", dir_fd=target_fd)
            except OSError as cleanup_error:
                failures.append(("invalidate own completion", cleanup_error))
        # Close remaining directory ownership before the one private error capture,
        # preserving secondary close errors alongside the original, not replacing it.
        for label, fd in (("root", root_fd), ("attempt", target_fd)):
            if label == "root":
                root_fd = None
            else:
                target_fd = None
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as cleanup_error:
                    failures.append(("close " + label, cleanup_error))
        if error_fd is not None:
            owned, error_fd = error_fd, None
            try:
                retain_failure(owned, IOFailures(failures))
            except (OSError, s.Rejected):
                pass  # First/final sink or persistence failure remains unavailable.
            finally:
                try:
                    os.close(owned)
                except OSError:
                    pass  # Terminal sink-close uncertainty, no retry or new sink.
        raise s.EvidenceIncomplete("private storage incomplete; stopped") from None


class Arguments(argparse.ArgumentParser):
    def error(self, _message):
        raise s.Rejected("private storage arguments rejected")


def main(argv=None):
    parser = Arguments(description=__doc__)
    parser.add_argument("action", choices=("preflight", "store"))
    for flag in ("private-root", "storage-id", "run-id", "source-head", "job", "attempt"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    value = identity(args.run_id, args.source_head, args.job, args.attempt, os.environ)
    base = Path(__file__).absolute().parent.parent
    operation = preflight if args.action == "preflight" else store
    return operation(base, args.private_root, args.storage_id, value)


def cli(argv=None):
    previous = signal.signal(signal.SIGTERM, s.terminal_signal)
    try:
        print(s.encode(main(argv)).decode(), end="")
        return 0
    except (Exception, KeyboardInterrupt):
        print(s.encode({"namespace": NAMESPACE, "status": "rejected-incomplete", "complete": False,
                        "release_qualified": False}).decode(), end="")
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(cli())
