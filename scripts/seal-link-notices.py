#!/usr/bin/env python3
"""Private linked-fixture receipt sealing. No upload or publication authorization.

CMS AES256-CBC is NOT AEAD. Offline recovery requires a separately trusted
GitHub API digest of the complete artifact ZIP before parsing or decryption.
"""
import argparse
import base64
import binascii
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

MAX_FILES = 1024
MAX_FILE = 256 << 10
MAX_PAYLOAD = 8 << 20
MAX_TAR = 10 << 20
MAX_CMS = 12 << 20
MAX_ZIP = 16 << 20
MAX_MANIFEST = 256 << 10
MAX_ABSENCE = 16 << 10
RUN = re.compile(r"[a-z][a-z0-9-]{3,48}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}(?:\.json)?\Z")
JOB = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
CERT_PIN = "ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57"
LINKED_LAYOUT = "linked-calibration-v2"
DENIAL = (b"permission denied", b"operation not permitted", b"access denied", b"denied by policy", b"sandbox_extension_issue_file")


class Rejected(Exception):
    """Only fixed diagnostic text may cross the private evidence boundary."""


class EvidenceIncomplete(Rejected):
    pass


class PlatformDenied(EvidenceIncomplete):
    pass


def digest(body):
    return hashlib.sha256(body).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def parse_json(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(body, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected("nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("invalid receipt JSON") from None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def check_private(info, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not directory and info.st_nlink != 1)):
        raise Rejected("private input type, ownership or mode rejected")


def check_chain(path):
    # Reject symlinks in every existing path component, including fixed roots.
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise Rejected("directory path component rejected")


def private_root(path):
    path = Path(path)
    check_chain(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    check_private(path.lstat(), True)
    return path


def reserve(root, run):
    private_root(root)
    target = root / run
    try:
        target.mkdir(mode=0o700)  # incomplete attempts cannot be reused
    except FileExistsError:
        raise Rejected("exclusive run reservation already exists") from None
    return target


def write_private(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def reserve_receipt(directory, name):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        persist_receipt(fd, encode({"status": "reserved; no failure recorded yet", "complete": False}))
    except BaseException:
        os.close(fd)
        raise
    return fd


def persist_receipt(fd, body):
    # Already-open private descriptor: never open a new path after a denial.
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    if os.write(fd, body) != len(body):
        raise OSError(5, "private receipt short write")
    os.fsync(fd)


def reserve_operation(root, run):
    try:
        directory = reserve(root, run)
        fd = reserve_receipt(directory, "OS-ERROR.json")
    except (OSError, Rejected):
        # The first required sink is unavailable. Do not try another sink.
        raise EvidenceIncomplete("private operation reservation failed; exact evidence incomplete; stopped") from None
    return directory, fd


def retain_os_error(fd, action, error):
    # Bounded original cause/context graph, private only. No raw exception reaches
    # the public exception. Overflow is explicitly incomplete, never exact.
    nodes, pending, seen = [], [("original", error)], set()
    while pending and len(nodes) < 8:
        relation, current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        nodes.append({"relation": relation, "type": type(current).__name__,
                      "errno": getattr(current, "errno", None), "exact_text": str(current),
                      "filename": getattr(current, "filename", None),
                      "filename2": getattr(current, "filename2", None)})
        for relation, following in [("cause", current.__cause__), ("context", current.__context__)]:
            if following is not None and id(following) not in seen:
                pending.append((relation, following))
    body = encode({"action": action, "complete": not pending, "exceptions": nodes})
    complete = not pending and len(body) <= 65536
    if len(body) > 65536:
        body = encode({"action": action, "complete": False, "reported_bytes": len(body),
                       "sha256": digest(body), "captured_prefix_base64": base64.b64encode(body[:32768]).decode()})
    try:
        persist_receipt(fd, body)
    except OSError:
        raise EvidenceIncomplete("private OS-error receipt persistence failed; exact evidence incomplete; stopped") from None
    if not complete:
        raise EvidenceIncomplete("filesystem action failed; private notice bound exceeded; evidence incomplete; stopped") from None
    kind = PlatformDenied if getattr(error, "errno", None) in (1, 13) else EvidenceIncomplete
    raise kind("filesystem action failed; private OS-ERROR.json retained; stopped") from None


def prepare_complete(directory, body):
    # Keep the primary private-error sink alive through pending write/fsync/close.
    write_private(directory / "COMPLETE.pending.json", body)


def close_operation(fd, prior_failure=None):
    # Detach ownership before calling. A failed close is uncertain: never retry
    # that descriptor or open a new sink to describe its own terminal failure.
    try:
        os.close(fd)
    except OSError:
        kind = PlatformDenied if isinstance(prior_failure, PlatformDenied) else EvidenceIncomplete
        raise kind("terminal private sink close failed; exact close notice unavailable; evidence incomplete; stopped") from None


def publish_complete(directory):
    # Last filesystem operation: the error sink is already closed successfully.
    try:
        os.rename(directory / "COMPLETE.pending.json", directory / "COMPLETE.json")
    except (OSError, KeyboardInterrupt, SystemExit):
        raise EvidenceIncomplete("terminal completion failed; exact notice unavailable; evidence incomplete; stopped") from None


def terminal_signal(_signum, _frame):
    raise KeyboardInterrupt("CLI received SIGTERM")


def read_regular(path, maximum, private=False):
    check_chain(Path(path).parent)
    before = Path(path).lstat()
    if private:
        check_private(before)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise Rejected("bounded regular file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(body) > maximum or signature(before) != signature(opened) or signature(before) != signature(after) or signature(before) != signature(Path(path).lstat()):
        raise Rejected("file changed during bounded read")
    return body


def identities(run, head, pin, job, attempt, layout="fixture-v1"):
    if (not RUN.fullmatch(run) or not HEAD.fullmatch(head) or not SHA.fullmatch(pin)
            or not JOB.fullmatch(job) or not re.fullmatch(r"[1-9][0-9]{0,8}", str(attempt))):
        raise Rejected("mandatory reviewed identity rejected")
    if layout not in ("fixture-v1", LINKED_LAYOUT) or (layout == LINKED_LAYOUT and job != "links"):
        raise Rejected("reviewed layout and job rejected")
    result = {"run_id": run, "source_head": head, "recipient_sha256": pin,
              "job": job, "attempt": str(attempt)}
    if layout == LINKED_LAYOUT:
        result["layout"] = layout
    return result


def safe_relative(name):
    parts = name.split("/")
    return (name != "MANIFEST.json" and 1 <= len(parts) <= 4 and all(NAME.fullmatch(p) for p in parts)
            and len(name) <= 120 and parts[-1].endswith(".json")
            and all(not p.endswith(".json") for p in parts[:-1]))


def snapshot(root, run, *, remaining_files=MAX_FILES, remaining_bytes=MAX_PAYLOAD, include_inventory=False):
    """Read through held directory FDs; compare a second complete inventory."""
    check_chain(root)
    check_private(root.lstat(), True)
    root_signature = signature(root.lstat())
    payloads, inventory = {}, {}
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def walk(directory, prefix="", reread=False):
            check_private(os.fstat(directory), True)
            names = []
            with os.scandir(directory) as entries:
                for entry in entries:
                    if len(names) >= MAX_FILES:
                        raise Rejected("directory entry bound exceeded")
                    names.append(entry.name)
            names.sort()
            for name in names:
                relative = prefix + name
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if not NAME.fullmatch(name) or name.endswith(".json") or len(relative.split("/")) >= 4:
                        raise Rejected("input directory name or depth rejected")
                    check_private(info, True)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        if signature(info) != signature(os.fstat(child)):
                            raise Rejected("input directory changed")
                        record(relative + "/", info, reread)
                        walk(child, relative + "/", reread)
                    finally:
                        os.close(child)
                else:
                    if not safe_relative(relative):
                        raise Rejected("unexpected input filename")
                    check_private(info)
                    if info.st_size > MAX_FILE:
                        raise Rejected("receipt byte bound exceeded")
                    record(relative, info, reread)
                    if reread:
                        continue
                    if len(payloads) >= remaining_files:
                        raise Rejected("receipt count bound exceeded")
                    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                    with os.fdopen(source, "rb") as stream:
                        if signature(info) != signature(os.fstat(stream.fileno())):
                            raise Rejected("receipt changed before read")
                        body = stream.read(MAX_FILE + 1)
                        if signature(info) != signature(os.fstat(stream.fileno())):
                            raise Rejected("receipt changed during read")
                    if len(body) != info.st_size or sum(map(len, payloads.values())) + len(body) > remaining_bytes:
                        raise Rejected("receipt payload bound exceeded")
                    value = parse_json(body)
                    if not isinstance(value, dict) or ("RunID" in value and value["RunID"] != run):
                        raise Rejected("receipt run or object rejected")
                    payloads[relative] = body

        seen = set()
        def record(name, info, reread):
            if not reread:
                if len(inventory) >= 2 * MAX_FILES:
                    raise Rejected("input inventory bound exceeded")
                inventory[name] = signature(info)
            elif inventory.get(name) != signature(info):
                raise Rejected("input changed between inventories")
            else:
                seen.add(name)
        walk(fd)
        marker = parse_json(payloads.get("PRIVATE.json", b"null"))
        if marker != {"RunID": run, "Classification": "PRIVATE RAW EVIDENCE", "Publication": "withhold pending explicit redaction review"}:
            raise Rejected("private marker rejected")
        walk(fd, reread=True)
        if seen != set(inventory) or signature(os.fstat(fd)) != root_signature or signature(root.lstat()) != root_signature:
            raise Rejected("input inventory changed")
    finally:
        os.close(fd)
    return (payloads, inventory, root_signature) if include_inventory else payloads


def linked_snapshot(base, identity):
    """The two fixed roots only; absence is observed, never repaired or adopted."""
    run = identity["run_id"]
    driver = base / ".cache/link-calibration-private" / run
    fixture_parent = base / ".cache/fixtures-private"
    fixture = fixture_parent / (run + "-links")
    def fixture_state():
        # Only lstat of these two fixed root components may admit ENOENT.
        # Missing descendants, permission/unknown errors and malformed roots fail.
        check_chain(base / ".cache")
        anchor = signature((base / ".cache").lstat())
        for path in (fixture_parent, fixture):
            try:
                info = path.lstat()
            except FileNotFoundError as error:
                if error.errno != errno.ENOENT:
                    raise
                return ("absent-ENOENT", str(path), anchor), {
                    "action": "observe fixed fixture component absence", "type": type(error).__name__,
                    "errno": error.errno, "exact_text": str(error)}
            check_private(info, True)
            anchor = signature(info)
        return ("captured", anchor), None
    check_private(driver.parent.lstat(), True)
    captured_driver = snapshot(driver, run, include_inventory=True)
    driver_files = captured_driver[0]
    remaining_files = MAX_FILES - len(driver_files)
    remaining_bytes = MAX_PAYLOAD - sum(map(len, driver_files.values()))
    state, absence = fixture_state()
    captured_fixture = None
    if absence is None:
        captured_fixture = snapshot(fixture, run, remaining_files=remaining_files,
                                    remaining_bytes=remaining_bytes, include_inventory=True)
    # Recheck both components after both captures, including inode/mtime
    # inventories: byte equality alone would miss replaced identical files.
    if snapshot(driver, run, include_inventory=True) != captured_driver:
        raise Rejected("driver component changed during linked capture")
    if captured_fixture is not None:
        if snapshot(fixture, run, remaining_files=remaining_files, remaining_bytes=remaining_bytes,
                    include_inventory=True) != captured_fixture:
            raise Rejected("fixture component changed during linked capture")
    final_state, _ = fixture_state()
    if final_state != state:
        raise Rejected("fixture component availability changed during linked capture")
    payloads = {"driver/" + name: body for name, body in driver_files.items()}
    if captured_fixture is not None:
        payloads.update({"fixture/" + name: body for name, body in captured_fixture[0].items()})
    return payloads, absence


def linked_components(payloads, identity, fixture_absent):
    if type(fixture_absent) is not bool or len(payloads) > MAX_FILES or sum(map(len, payloads.values())) > MAX_PAYLOAD:
        raise Rejected("linked shared payload bounds rejected")
    groups = {"driver": {}, "fixture": {}}
    for name, body in payloads.items():
        component, separator, relative = name.partition("/")
        if not separator or component not in groups or not safe_relative(relative) or len(body) > MAX_FILE:
            raise Rejected("linked component member rejected")
        value = parse_json(body)
        if not isinstance(value, dict) or ("RunID" in value and value["RunID"] != identity["run_id"]):
            raise Rejected("linked receipt run rejected")
        groups[component][relative] = body
    marker = {"RunID": identity["run_id"], "Classification": "PRIVATE RAW EVIDENCE", "Publication": "withhold pending explicit redaction review"}
    for component in ("driver", "fixture"):
        if component == "fixture" and fixture_absent:
            if groups[component]:
                raise Rejected("absent fixture component contains receipts")
        elif parse_json(groups[component].get("PRIVATE.json", b"null")) != marker:
            raise Rejected("linked component private marker rejected")
    return {component: {"availability": "absent-ENOENT" if component == "fixture" and fixture_absent else "captured",
                        "files": len(files), "total_bytes": sum(map(len, files.values()))}
            for component, files in groups.items()}


def fixture_absence_record(body, identity):
    """Wrap the exact captured observation bytes; do not reconstruct the notice."""
    if identity.get("layout") != LINKED_LAYOUT or not isinstance(body, bytes) or not 0 < len(body) <= MAX_ABSENCE:
        raise Rejected("fixture absence observation bound or layout rejected")
    notice = parse_json(body)
    if (not isinstance(notice, dict) or set(notice) != {"action", "type", "errno", "exact_text"}
            or notice["action"] != "observe fixed fixture component absence"
            or notice["type"] != "FileNotFoundError" or type(notice["errno"]) is not int
            or notice["errno"] != errno.ENOENT or not isinstance(notice["exact_text"], str) or not notice["exact_text"]):
        raise Rejected("fixture absence observation schema rejected")
    return {"scope": "fixed-fixture-root-ENOENT", "identity": identity,
            "bytes": len(body), "sha256": digest(body), "body_base64": base64.b64encode(body).decode("ascii")}


def decode_fixture_absence(record, identity):
    if (not isinstance(record, dict) or not isinstance(record.get("body_base64"), str)
            or len(record["body_base64"]) > 4 * ((MAX_ABSENCE + 2) // 3)):
        raise Rejected("required fixture absence record missing or oversized")
    try:
        body = base64.b64decode(record["body_base64"], validate=True)
    except (binascii.Error, ValueError):
        raise Rejected("fixture absence encoding rejected") from None
    if record != fixture_absence_record(body, identity):
        raise Rejected("fixture absence hash, identity or scope rejected")
    return body


def pack(payloads, identity, *, fixture_absence_body=None):
    manifest = dict(identity, version=1, files=[{"path": name, "bytes": len(body), "sha256": digest(body)}
                    for name, body in sorted(payloads.items())], count=len(payloads),
                    total_bytes=sum(map(len, payloads.values())))
    if identity.get("layout") == LINKED_LAYOUT:
        fixture_absent = fixture_absence_body is not None
        manifest.update(version=2, components=linked_components(payloads, identity, fixture_absent),
                        fixture_absence=fixture_absence_record(fixture_absence_body, identity) if fixture_absent else None,
                        bundle_complete=not fixture_absent, release_qualified=False,
                        caller_declaration={"notice_writers_stopped_and_reaped": True, "observed_proof": False})
    elif fixture_absence_body is not None:
        raise Rejected("fixture absence requires explicit linked layout")
    manifest_body = encode(manifest)
    if len(manifest_body) > MAX_MANIFEST:
        raise Rejected("manifest bound exceeded")
    buffer = io.BytesIO()
    prefix = "link-notices/" + identity["run_id"] + "/"
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in [("MANIFEST.json", manifest_body), *sorted(payloads.items())]:
            entry = tarfile.TarInfo(prefix + name)
            entry.size, entry.mode, entry.mtime = len(body), 0o600, 0
            archive.addfile(entry, io.BytesIO(body))
    body = buffer.getvalue()
    if len(body) > MAX_TAR:
        raise Rejected("tar bound exceeded")
    return body, manifest


def openssl(args, body, directory, label, maximum):
    """One bounded stock command; private original and cleanup facts survive cancel."""
    command = ["/usr/bin/openssl", *args]
    output, stderr = bytearray(), bytearray()
    started = time.monotonic()
    status, child, original_error = None, None, None
    reaped = drained = input_closed = False
    input_accepted = 0
    cleanup = []
    receipt = reserve_receipt(directory, label + "-command.json")
    def notice(error):
        return {"type": type(error).__name__, "errno": getattr(error, "errno", None), "exact_text": str(error)}
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with selectors.DefaultSelector() as selector:
            for stream, event, kind in [(child.stdin, selectors.EVENT_WRITE, "in"), (child.stdout, selectors.EVENT_READ, "out"), (child.stderr, selectors.EVENT_READ, "err")]:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, kind)
            while selector.get_map():
                if time.monotonic() - started > 30:
                    raise Rejected("stock command timeout")
                for key, _ in selector.select(0.1):
                    if key.data == "in":
                        if input_accepted == len(body):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            input_closed = True
                        else:
                            # A zero exit cannot excuse an early stdin closure.
                            # Preserve the original EPIPE through the ordinary
                            # private failure/cleanup boundary; never retry it.
                            written = os.write(key.fd, body[input_accepted:input_accepted + 65536])
                            if written <= 0:
                                raise OSError(5, "stock command stdin accepted no bytes")
                            input_accepted += written
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        target, limit = (output, maximum) if key.data == "out" else (stderr, 65536)
                        available = limit - len(target)
                        target.extend(chunk[:available])
                        if len(chunk) > available:
                            raise Rejected("stock command output bound exceeded")
            if input_accepted != len(body) or not input_closed:
                raise EvidenceIncomplete("stock command input delivery incomplete")
            drained = True
        status = child.wait(timeout=max(0.001, 30 - (time.monotonic() - started)))
        reaped = True
    except (OSError, subprocess.TimeoutExpired, Rejected, KeyboardInterrupt, SystemExit) as error:
        original_error = error
    finally:
        if child is not None:
            if not reaped:
                action = "poll owned child"
                try:
                    if child.poll() is None:
                        action = "kill owned child"
                        child.kill()
                    action = "wait owned child"
                    status = child.wait(timeout=2)
                    reaped = True
                except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt, SystemExit) as error:
                    cleanup.append((action, error))
            for name, stream in [("stdin", child.stdin), ("stdout", child.stdout), ("stderr", child.stderr)]:
                try:
                    if not stream.closed:
                        stream.close()
                except (OSError, KeyboardInterrupt, SystemExit) as error:
                    cleanup.append(("close owned " + name, error))
        record = {"argv": command, "returncode": status,
                  "failure": notice(original_error) if original_error is not None else None,
                  "cleanup_failures": [dict(action=action, **notice(error)) for action, error in cleanup],
                  "child_pid": child.pid if child is not None else None, "child_launched": child is not None,
                  "child_reaped": reaped, "interrupted": any(isinstance(error, (KeyboardInterrupt, SystemExit)) for error in ([original_error] + [error for _, error in cleanup])),
                  "input_intended_bytes": len(body), "input_accepted_bytes": input_accepted,
                  "input_complete": input_accepted == len(body) and input_closed,
                  "stderr_base64": base64.b64encode(stderr).decode(), "stderr_bytes": len(stderr),
                  "streams_complete": drained and original_error is None and not cleanup,
                  "stdout_bytes": len(output), "stdout_sha256": digest(output)}
        encoded = encode(record)
        if len(encoded) > MAX_FILE:
            encoded = encode({"streams_complete": False, "receipt_overflow": True, "child_reaped": reaped,
                              "input_intended_bytes": len(body), "input_accepted_bytes": input_accepted,
                              "input_complete": input_accepted == len(body) and input_closed,
                              "reported_bytes": len(encoded), "captured_prefix_base64": base64.b64encode(encoded[:65536]).decode()})
            if original_error is None:
                original_error = EvidenceIncomplete("stock command notice bound exceeded")
        try:
            persist_receipt(receipt, encoded)
        except OSError as receipt_error:
            if original_error is not None:
                raise receipt_error from original_error
            raise
        finally:
            prior_failure = sys.exc_info()[1] or original_error
            try:
                os.close(receipt)
            except OSError as close_error:
                if prior_failure is not None:
                    raise close_error from prior_failure
                raise
    errors = ([original_error] if original_error is not None else []) + [error for _, error in cleanup]
    if errors:
        primary = next((error for error in errors if getattr(error, "errno", None) in (1, 13)), errors[0])
        if isinstance(primary, (OSError, KeyboardInterrupt, SystemExit)):
            other = next((error for error in errors if error is not primary), None)
            if other is not None:
                raise primary from other
            raise primary
        raise EvidenceIncomplete("stock command failed or cleanup unresolved; private receipt retained; stopped") from None
    if any(term in bytes(stderr).lower() for term in DENIAL):
        raise PlatformDenied("stock command platform denial; stopped, private receipt retained")
    if status != 0:
        raise Rejected("stock command failed; stopped, private receipt retained")
    return bytes(output)


def certificate(path, expected):
    body = read_regular(path, 16384)
    if not SHA.fullmatch(expected) or digest(body) != expected or b"PRIVATE KEY" in body or body.count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise Rejected("recipient certificate pin rejected")
    return body


def seal(base, identity, cert, expected_payloads=None, *, notice_writers_stopped_and_reaped=False):
    identity = identities(identity["run_id"], identity["source_head"], identity["recipient_sha256"], identity["job"], identity["attempt"], identity.get("layout", "fixture-v1"))
    if identity.get("layout") == LINKED_LAYOUT and notice_writers_stopped_and_reaped is not True:
        raise Rejected("linked producer requires caller writer-stop declaration; proof remains external")
    base = Path(base)
    diagnostics, error_fd = reserve_operation(base / ".cache/link-sealing-private", identity["run_id"])
    action = "read pinned recipient certificate"
    try:
        cert_body = certificate(cert, identity["recipient_sha256"])
        action = "snapshot fixed private receipt tree"
        absence_body = None
        if identity.get("layout") == LINKED_LAYOUT:
            action = "capture fixed linked driver and fixture components"
            payloads, absence = linked_snapshot(base, identity)
            if absence is not None:
                action = "bound exact admitted fixture absence observation"
                absence_body = encode(absence)
                fixture_absence_record(absence_body, identity)
                action = "persist exact admitted fixture absence observation"
                write_private(diagnostics / "fixture-absence.json", absence_body)
        else:
            payloads = snapshot(base / ".cache/fixtures-private" / (identity["run_id"] + "-links"), identity["run_id"])
        if expected_payloads is not None and payloads != expected_payloads:
            raise Rejected("captured receipt bytes differ from reviewed expected payloads")
        clear, manifest = pack(payloads, identity, fixture_absence_body=absence_body)
        action = "reserve ciphertext quarantine"
        destination = reserve(base / ".cache/link-quarantine", identity["run_id"])
        action = "write private recipient snapshot"
        write_private(diagnostics / "recipient.pem", cert_body)
        action = "encrypt and retain stock command receipt"
        encrypted = openssl(["cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-recip", str(diagnostics / "recipient.pem"),
                             "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256",
                             "-keyopt", "rsa_mgf1_md:sha256"], clear, diagnostics, "seal", MAX_CMS)
        action = "write bounded ciphertext"
        write_private(destination / "notice.cms", encrypted)
        complete = dict(identity, complete=True, cms_bytes=len(encrypted), cms_sha256=digest(encrypted),
                        files=manifest["count"], total_bytes=manifest["total_bytes"],
                        publication="DISABLED; explicit encrypted-public-quarantine exception required",
                        cipher="AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD")
        if identity.get("layout") == LINKED_LAYOUT:
            complete.update(manifest_version=2, components=manifest["components"], bundle_complete=manifest["bundle_complete"],
                            release_qualified=False, caller_declaration=manifest["caller_declaration"],
                            fixture_absence_sha256=digest(absence_body) if absence_body is not None else None,
                            completion_scope="captured bytes only; no writer-quiescence, cleanup or calibration qualification")
        action = "persist complete metadata"
        prepare_complete(destination, encode(complete))
        owned_fd, error_fd = error_fd, None
        close_operation(owned_fd)
        publish_complete(destination)
        return complete
    except (OSError, KeyboardInterrupt, SystemExit) as error:
        if error_fd is None:
            raise EvidenceIncomplete("terminal sink unavailable; exact notice unavailable; evidence incomplete; stopped") from None
        retain_os_error(error_fd, action, error)
    finally:
        if error_fd is not None:
            owned_fd, error_fd = error_fd, None
            close_operation(owned_fd, sys.exc_info()[1])


def arguments(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--recipient-sha256", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--layout", choices=("fixture-v1", LINKED_LAYOUT), default="fixture-v1")
    return parser


def main():
    parser = arguments(__doc__)
    parser.add_argument("--notice-writers-stopped-and-reaped", action="store_true")
    args = parser.parse_args()
    identity = identities(args.run_id, args.source_head, args.recipient_sha256, args.job, args.attempt, args.layout)
    if args.recipient_sha256 != CERT_PIN:
        raise Rejected("reviewed recipient pin required")
    seal(Path.cwd(), identity, Path(__file__).with_name("link-notices-recipient.pem"),
         notice_writers_stopped_and_reaped=args.notice_writers_stopped_and_reaped)
    print("sealed: complete metadata retained privately; publication disabled")


def cli():
    previous_term = signal.signal(signal.SIGTERM, terminal_signal)
    try:
        main()
        return 0
    except (EvidenceIncomplete, KeyboardInterrupt):
        print("sealing rejected; private evidence incomplete; stopped", file=sys.stderr)
        return 1
    except (Rejected, OSError, tarfile.TarError):
        print("sealing rejected; no complete output accepted; stopped", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(cli())
