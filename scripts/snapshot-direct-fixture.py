#!/usr/bin/env python3
"""Fixed direct-fixture private originals, never a lifecycle/Wait oracle.

The caller separately authenticates custody-input.json and foreground.json.
Only the image is streamed up to 512MiB; all receipt transport is <=32MiB.
These are admission/read guards, not disk quotas or reserved capacity.
"""
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import traceback

HOME = Path("/home/labrunner")
IMAGE_LIMIT, SMALL_LIMIT = 512 << 20, 32 << 20
ARCHIVE_LIMIT, FILE_LIMIT, JSON_LIMIT = 30 << 20, 1 << 20, 1 << 20
MAX_FILES, MAX_DIRECTORY, CHUNK = 1024, 1024, 1 << 20
PARENT_FILES = ("errors.jsonl", "stdout.bin", "stderr.bin", "inputs.json", "wait.json", "result.json", "inventory.json")
GO_FILES = ("errors.json", "inputs.json", "up.json", "identity.json", "cleanup.json", "absence.json", "tree.json", "result.json")
FIXTURE_FILES = ("PRIVATE.json", "startup-control.json", "identity.json", "image-broker-proof.json", "image-save-attempt.json", "image-save-complete.json")
FIXTURE_OPTIONAL = ("STOPPED.json",)
SOURCE_FILES = ("scripts/direct-fixture-guest-parent.py", "scripts/native-check-guest-parent.py",
                "scripts/snapshot-direct-fixture.py", "scripts/read-direct-fixture.py")
OUTPUTS = ("errors.jsonl", "receipts.tar", "images.tar", "manifest.json", "result.json")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode() + b"\n"


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "nonfinite JSON"))


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex64(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def directory(path):
    before = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700,
            "owned canonical 0700 directory required: " + str(path))
    return signature(before)


def open_original(path, maximum):
    require(path.resolve(strict=True) == path, "noncanonical original: " + str(path))
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= maximum,
            "owned single-link 0600 original exceeds bound or has wrong identity: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        require(signature(before) == signature(os.fstat(fd)), "original changed at open: " + str(path))
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb"), signature(before)


def read_small(path, maximum=FILE_LIMIT):
    f, before = open_original(path, maximum)
    with f:
        raw = f.read(maximum + 1)
        require(len(raw) == before[6] and before == signature(os.fstat(f.fileno())) == signature(path.lstat()),
                "original changed during read: " + str(path))
    return raw, before


def stream(path, maximum, destination=None):
    """One source pass, constant memory; destination readback is a separate pass."""
    f, before = open_original(path, maximum)
    digest, count = hashlib.sha256(), 0
    with f:
        while True:
            block = f.read(min(CHUNK, maximum - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= maximum, "stream exceeds admitted bound: " + str(path))
            digest.update(block)
            if destination is not None:
                require(destination.write(block) == len(block), "short private image write")
        require(count == before[6] and before == signature(os.fstat(f.fileno())) == signature(path.lstat()),
                "original changed during stream: " + str(path))
    return {"Bytes": count, "SHA256": digest.hexdigest(), "SourceSignature": before}


def create(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, "wb", buffering=0)


def write(f, raw):
    require(f.write(raw) == len(raw), "short private receipt write")
    os.fsync(f.fileno())


class Errors:
    def __init__(self, file):
        self.file, self.failed, self.broken, self.count = file, False, False, 0

    def record(self, path, error):
        self.failed = True
        if self.broken:
            return
        raw = encode({"Path": str(path), "Exception": repr(error), "Errno": getattr(error, "errno", None),
                      "Traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))})
        bound = min(64 << 10, (256 << 10) - self.count)
        try:
            require(bound > 0, "private error capture exhausted")
            write(self.file, raw[:bound])
            self.count += min(len(raw), bound)
            self.broken = len(raw) > bound
        except BaseException:
            self.broken = True  # never substitute another raw error sink


def close(f, errors, path):
    for operation in (lambda: os.fsync(f.fileno()), f.close):
        try:
            operation()
        except BaseException as error:
            errors.record(path, error)


class ReceiptWriter:
    """The one tar outlet: every requested write consumes fixed headroom.

    Charge before calling write: an exception can leave an unknown prefix.
    A failed/short write latches this route, including later close framing.
    """
    def __init__(self, file):
        require(os.fstat(file.fileno()).st_size == file.tell() == 0, "receipt outlet must start empty")
        self.file, self.admitted, self.stopped = file, 0, False

    def write(self, raw):
        require(not self.stopped, "receipt archive write route stopped")
        if len(raw) > ARCHIVE_LIMIT - self.admitted:
            self.stopped = True
            raise ValueError("receipt archive physical write exceeds fixed guard")
        self.admitted += len(raw)
        try:
            count = self.file.write(raw)
            if type(count) is not int or count != len(raw):
                raise OSError(errno.EIO, "short receipt archive write")
        except BaseException:
            self.stopped = True
            raise
        return count


def fixed_paths(run):
    parent = "parent-private/"
    go = "source/.cache/direct-fixture-calibration-private/" + run + "/"
    fixture = "source/.cache/fixtures-private/" + run + "-brokers/"
    required = {parent + name for name in PARENT_FILES} | {go + name for name in GO_FILES} | {fixture + name for name in FIXTURE_FILES}
    required |= {"parent-input.json", "custody-input.json", "foreground.json", "foreground.stdout", "foreground.stderr", "controller/controller-build.json",
                 "controller/direct-fixture-calibration.buildinfo", "source/.cache/direct-fixture-input.json",
                 "source/.cache/fixtures/" + run + ".json"}
    return parent, go, fixture, required


def allowed_original(name, run):
    parent, go, fixture, required = fixed_paths(run)
    if name in required or name == go + "result.pending.json" or name in {fixture + n for n in FIXTURE_OPTIONAL}:
        return True
    if name.startswith(fixture):
        tail = name[len(fixture):]
        return re.fullmatch(r"(?:docker|image-admission|image-save-control|cleanup-control|absence-control)-[0-9]+\.json", tail) is not None or re.fullmatch(r"operation-[0-9]+/docker-[0-9]+\.json", tail) is not None
    return False


def bounded_members(path):
    members = []
    with os.scandir(path) as entries:
        for entry in entries:
            require(len(members) < MAX_DIRECTORY, "too many fixed receipt members: " + str(path))
            members.append(path / entry.name)
    return sorted(members)


def select_paths(base, run, errors):
    parent, go, fixture, required = fixed_paths(run)
    selected, directories = set(required), {}
    for name in ("fixtures", "fixtures-private", "direct-fixture-calibration-private", "image-identity-data"):
        path = base / "source/.cache" / name
        try:
            directories[path] = directory(path)
        except BaseException as error:
            errors.record(path, error)
    for prefix in (parent, go, fixture):
        root = base / prefix
        try:
            directories[root] = directory(root)
            for path in bounded_members(root):
                try:
                    name = path.relative_to(base).as_posix()
                    if prefix == fixture and re.fullmatch(r"operation-[0-9]+", path.name):
                        directories[path] = directory(path)
                        for child in bounded_members(path):
                            relative = child.relative_to(base).as_posix()
                            require(allowed_original(relative, run), "unexpected operation member: " + relative)
                            require(relative in selected or len(selected) < MAX_FILES, "too many selected receipts")
                            selected.add(relative)
                    else:
                        require(allowed_original(name, run), "unexpected fixed receipt member: " + name)
                        require(name in selected or len(selected) < MAX_FILES, "too many selected receipts")
                        selected.add(name)
                except BaseException as error:
                    errors.record(path, error)
        except BaseException as error:
            errors.record(root, error)
    return sorted(selected), directories


def native_outlet(outlet):
    require(sys.platform == "linux" and os.uname().machine == "aarch64" and os.getuid() == os.geteuid() == 501,
            "selected native ARM64 UID501 required")
    # Linux64 statfs writes <=120 bytes. A larger aligned buffer avoids relying
    # on the remaining platform fields; only the filesystem magic is consumed.
    buffer = (ctypes.c_long * 32)()
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.statfs(os.fsencode(outlet), ctypes.byref(buffer)) == 0, "Btrfs outlet statfs failed errno=" + str(ctypes.get_errno()))
    require(buffer[0] == 0x9123683E, "persistent Btrfs outlet required")


def bindings(base, run, head, expected, outlet):
    raw, _ = read_small(base / "custody-input.json", 64 << 10)
    require(sha(raw) == expected, "external custody-input hash differs")
    packet = decode(raw)
    require(set(packet) == {"Version", "RunID", "SourceHead", "ParentInputSHA256", "GoInputSHA256", "ForegroundSHA256",
                            "SnapshotSHA256", "ReaderSHA256", "OutletDevice", "OutletInode", "ReleaseQualified"}, "custody packet shape differs")
    require(packet["Version"] == "1" and packet["RunID"] == run and packet["SourceHead"] == head
            and packet["ReleaseQualified"] is False and all(hex64(packet[key]) for key in ("ParentInputSHA256", "GoInputSHA256", "ForegroundSHA256", "SnapshotSHA256", "ReaderSHA256")), "external custody binding differs")
    info = outlet.lstat()
    require(type(packet["OutletDevice"]) is int and type(packet["OutletInode"]) is int
            and (info.st_dev, info.st_ino) == (packet["OutletDevice"], packet["OutletInode"]), "external persistent outlet inode differs")
    bodies = {}
    for name, key in (("parent-input.json", "ParentInputSHA256"), ("source/.cache/direct-fixture-input.json", "GoInputSHA256"), ("foreground.json", "ForegroundSHA256")):
        body, _ = read_small(base / name)
        require(sha(body) == packet[key], "externally pinned original changed: " + name)
        bodies[name] = decode(body)
    parent, go, foreground = bodies["parent-input.json"], bodies["source/.cache/direct-fixture-input.json"], bodies["foreground.json"]
    require(all(obj.get("RunID") == run and obj.get("SourceHead") == head for obj in (parent, go, foreground)), "source/run binding differs")
    require(parent["GoInputSHA256"] == packet["GoInputSHA256"] and foreground.get("ParentInputSHA256") == packet["ParentInputSHA256"], "foreground/input binding differs")
    require(foreground.get("Version") == "1" and type(foreground.get("ParentPID")) is int and foreground["ParentPID"] > 1
            and foreground.get("Waited") is True and type(foreground.get("ReturnCode")) is int
            and type(foreground.get("OutputComplete")) is bool
            and foreground.get("ProducerQuiescenceExternallyReviewed") is True and foreground.get("ReleaseQualified") is False,
            "external original parent foreground Wait/quiescence claim required; no live-producer snapshot")
    for name, prefix in (("foreground.stdout", "Stdout"), ("foreground.stderr", "Stderr")):
        body, _ = read_small(base / name, 64 << 10)
        require(type(foreground.get(prefix + "Bytes")) is int and len(body) == foreground[prefix + "Bytes"]
                and sha(body) == foreground.get(prefix + "SHA256"), "external parent foreground output differs: " + name)
    catalog = {row["Path"]: row for row in go["Files"]}
    require(len(catalog) == len(go["Files"]), "duplicate source catalog member")
    for name in SOURCE_FILES:
        body, _ = read_small(base / "source" / name)
        require(name in catalog and catalog[name]["SHA256"] == sha(body) and catalog[name]["Bytes"] == len(body), "selected source differs from Go input catalog: " + name)
        if name.endswith("snapshot-direct-fixture.py"):
            require(sha(body) == packet["SnapshotSHA256"] and Path(__file__).resolve() == base / "source" / name, "snapshot source differs")
        if name.endswith("read-direct-fixture.py"):
            require(sha(body) == packet["ReaderSHA256"], "reader source differs")
    return packet, foreground


def snapshot(run, head, expected):
    base, outlet = HOME / ("kaferry-direct-" + run), HOME / ("kaferry-direct-custody-" + run)
    directory(outlet)
    target = outlet / "snapshot"
    target.mkdir(mode=0o700)  # exclusive attempt; no reuse, cleanup or fallback
    errors = Errors(create(target / "errors.jsonl"))
    files, identities, rows, missing, directories = {}, {}, [], [], {}
    archive_started, receipt_writer = False, None
    packet, foreground, image, image_readback, capture = None, None, None, None, False
    try:
        for name in OUTPUTS[1:]:
            files[name] = create(target / name)
            identities[name] = signature(os.fstat(files[name].fileno()))[:6]
            if name == "receipts.tar":
                receipt_writer = ReceiptWriter(files[name])
        native_outlet(outlet)
        for path in (base, base / "source", base / "source/.cache", base / "controller"):
            directories[path] = directory(path)
        packet, foreground = bindings(base, run, head, expected, outlet)
        selected, receipt_directories = select_paths(base, run, errors)
        directories.update(receipt_directories)
        archive_started = True
        with tarfile.open(fileobj=receipt_writer, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for name in selected:
                try:
                    raw, before = read_small(base / name)
                    # Leave fixed headroom for manifests, errors and tar framing.
                    require(sum(row["Bytes"] for row in rows) + len(raw) + (len(rows) + 1) * 1024 <= ARCHIVE_LIMIT - 10240,
                            "small-original transport aggregate exceeds fixed guard")
                    item = tarfile.TarInfo(name)
                    item.mode, item.size = 0o600, len(raw)
                except BaseException as error:
                    missing.append(name)
                    errors.record(base / name, error)
                    continue
                try:
                    archive.addfile(item, io.BytesIO(raw))
                except BaseException as error:
                    missing.append(name)
                    errors.record(base / name, error)
                    receipt_writer.stopped = True
                    break  # no further member; close cannot write past latch
                rows.append({"Path": name, "Bytes": len(raw), "SHA256": sha(raw), "SourceSignature": before})
        close(files.pop("receipts.tar"), errors, target / "receipts.tar")
        image_path = base / "source/.cache/image-identity-data" / run / "images.tar"
        try:
            directory(image_path.parent)
            image = stream(image_path, IMAGE_LIMIT, files["images.tar"])
        except BaseException as error:
            errors.record(image_path, error)
        close(files.pop("images.tar"), errors, target / "images.tar")
        if image is not None:
            image_readback = stream(target / "images.tar", IMAGE_LIMIT)
            require(tuple(image_readback["SourceSignature"][:6]) == identities["images.tar"], "private image inode changed")
            require((image["Bytes"], image["SHA256"]) == (image_readback["Bytes"], image_readback["SHA256"]), "private image inode/hash readback differs")
        for path, before in directories.items():
            require(directory(path) == before, "selected receipt directory changed: " + str(path))
        for row in rows:
            require(signature((base / row["Path"]).lstat()) == tuple(row["SourceSignature"]), "selected original changed after capture: " + row["Path"])
        if image is not None:
            require(signature(image_path.lstat()) == tuple(image["SourceSignature"]), "source image changed after capture")
        bindings(base, run, head, expected, outlet)  # changed pins/source: no retry
        capture = not errors.failed and image is not None and not missing
    except BaseException as error:
        errors.record(base, error)
    finally:
        missing = sorted(set(missing) | (fixed_paths(run)[3] - {row["Path"] for row in rows}))
        if not archive_started and receipt_writer is not None:
            try:
                # Admission failed before archive writing: retain a valid empty
                # archive in its original reserved outlet, never rewrite one.
                with tarfile.open(fileobj=receipt_writer, mode="w|", format=tarfile.USTAR_FORMAT):
                    pass
            except BaseException as error:
                errors.record(target / "receipts.tar", error)
        for name in ("receipts.tar", "images.tar"):
            if name in files:
                close(files.pop(name), errors, target / name)
        manifest = {"Version": "1", "Scope": "private direct-fixture originals; no lifecycle/Wait/qualification oracle", "RunID": run, "SourceHead": head,
                    "CustodyInputSHA256": expected, "ExternalParentForegroundClaim": foreground,
                    "ExternalForegroundIsNotOSProof": True, "SourceCatalogSelectedBindingsOnly": True,
                    "Files": rows, "Missing": missing, "MissingMeansNotCapturedNotNecessarilyAbsent": True,
                    "Image": image, "CaptureComplete": capture and not errors.failed,
                    "SmallAggregateGuard": SMALL_LIMIT, "ImageGuard": IMAGE_LIMIT, "OwnFinalCloseProven": False, "ReleaseQualified": False}
        try:
            raw = encode(manifest)
            require(len(raw) <= JSON_LIMIT, "manifest exceeds fixed bound")
            if "manifest.json" in files:
                write(files["manifest.json"], raw)
                close(files.pop("manifest.json"), errors, target / "manifest.json")
            copied = {}
            for name, maximum in (("receipts.tar", ARCHIVE_LIMIT), ("images.tar", IMAGE_LIMIT), ("manifest.json", JSON_LIMIT)):
                if name == "images.tar" and image_readback is not None:
                    require(signature((target / name).lstat()) == tuple(image_readback["SourceSignature"]), "private image changed after readback")
                    copied[name] = image_readback
                else:
                    copied[name] = stream(target / name, maximum)
            require(all(tuple(row["SourceSignature"][:6]) == identities[name] for name, row in copied.items()), "reserved output inode changed")
            result = {"Version": "1", "RunID": run, "SourceHead": head, "CustodyInputSHA256": expected, "Files": copied,
                      "CaptureComplete": capture and not errors.failed, "OwnFinalCloseProven": False,
                      "RequiresExternalSnapshotReturnAndMacReadback": True, "ExternalForegroundIsNotOSProof": True, "ReleaseQualified": False}
            raw = encode(result)
            require(len(raw) <= 64 << 10, "selected transfer receipt too large")
            if "result.json" in files:
                write(files["result.json"], raw)
                close(files.pop("result.json"), errors, target / "result.json")
            require(sum((target / name).stat().st_size for name in OUTPUTS if name != "images.tar") <= SMALL_LIMIT, "all small output aggregate exceeds guard")
            for path in (target, outlet):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException as error:
            errors.record(target, error)
        for name, f in files.items():
            close(f, errors, target / name)
        close(errors.file, errors, target / "errors.jsonl")
    return 0 if capture and not errors.failed else 2


def main(argv):
    require(len(argv) == 6 and argv[0] == "--run-id" and argv[2] == "--source-head" and argv[4] == "--binding-sha256", "fixed direct snapshot argv required")
    run, head, expected = argv[1], argv[3], argv[5]
    require(re.fullmatch(r"[a-z][a-z0-9-]{3,48}", run) and re.fullmatch(r"[0-9a-f]{40}", head) and hex64(expected), "invalid fixed run/head/hash")
    return snapshot(run, head, expected)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
