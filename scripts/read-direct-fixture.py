#!/usr/bin/env python3
"""Offline Mac verification of the separate image and fixed receipt archive.

No extraction, subprocess, credentials, signal, Docker or publication route.
Externally hash-bound foreground records remain claims requiring provenance;
bytes/hashes cannot prove a Wait, lifecycle pass or release qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

sys.dont_write_bytecode = True


def require(value, reason):
    if not value:
        raise ValueError(reason)


def bootstrap(path, maximum, modes=(0o600,)):
    """Small bootstrap only; no unverified sibling code is imported."""
    before = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) in modes and before.st_size <= maximum,
            "private bootstrap file identity/size differs: " + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK), "rb") as f:
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(before) == identity(os.fstat(f.fileno())), "bootstrap changed at open")
        raw = f.read(maximum + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(f.fileno())) == identity(path.lstat()), "bootstrap changed during read")
    return raw


def load_snapshot(packet):
    source = Path(__file__).resolve().with_name("snapshot-direct-fixture.py")
    raw = bootstrap(source, 64 << 10, (0o600, 0o644))
    require(hashlib.sha256(raw).hexdigest() == packet["SnapshotSHA256"], "reviewed fixed custody dependency differs")
    # Exact sibling bytes were checked above; fixed non-main namespace and no
    # bytecode/import loader chosen by packet data. Snapshot main stays uncalled.
    import types
    module = types.ModuleType("fixed_direct_custody_reads")
    module.__file__ = str(source)
    exec(compile(raw, str(source), "exec"), module.__dict__)
    return module


def verify(directory, binding_sha, wait_sha):
    require(directory.is_absolute() and directory.resolve(strict=True) == directory, "canonical private local directory required")
    s = directory.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, "owned 0700 local root required")
    # The two tiny external records are copied outside the guest snapshot.
    packet_raw = bootstrap(directory / "custody-input.json", 64 << 10)
    require(hashlib.sha256(packet_raw).hexdigest() == binding_sha, "external custody packet hash differs")
    packet = json.loads(packet_raw)
    require(type(packet) is dict and re.fullmatch(r"[a-z][a-z0-9-]{3,48}", packet["RunID"])
            and re.fullmatch(r"[0-9a-f]{40}", packet["SourceHead"]) and re.fullmatch(r"[0-9a-f]{64}", packet["SnapshotSHA256"]), "external packet shape differs")
    m = load_snapshot(packet)
    packet = m.decode(packet_raw)  # reject duplicate keys as well
    reader = bootstrap(Path(__file__).resolve(), 64 << 10, (0o600, 0o644))
    require(m.sha(reader) == packet["ReaderSHA256"], "reviewed reader source differs")
    wait_raw, _ = m.read_small(directory / "snapshot-foreground.json", 64 << 10)
    require(m.sha(wait_raw) == wait_sha, "external snapshot foreground hash differs")
    foreground = m.decode(wait_raw)
    require(set(foreground) == {"Version", "RunID", "SourceHead", "SnapshotPID", "Waited", "ReturnCode", "ResultSHA256", "ErrorsSHA256", "ReleaseQualified"}
            and foreground["Version"] == "1" and foreground["RunID"] == packet["RunID"] and foreground["SourceHead"] == packet["SourceHead"]
            and type(foreground["SnapshotPID"]) is int and foreground["SnapshotPID"] > 1 and foreground["Waited"] is True
            and type(foreground["ReturnCode"]) is int and m.hex64(foreground["ResultSHA256"]) and m.hex64(foreground["ErrorsSHA256"])
            and foreground["ReleaseQualified"] is False,
            "externally bound snapshot foreground return record required")
    require(set(p.name for p in m.bounded_members(directory)) == set(m.OUTPUTS) | {"custody-input.json", "snapshot-foreground.json"}, "unexpected/missing local transfer members")
    small = sum((directory / name).lstat().st_size for name in m.OUTPUTS if name != "images.tar")
    small += len(packet_raw) + len(wait_raw)
    require(small <= m.SMALL_LIMIT, "local small receipt aggregate exceeds 32MiB")
    result_raw, _ = m.read_small(directory / "result.json", 64 << 10)
    require(m.sha(result_raw) == foreground["ResultSHA256"], "snapshot result differs from external foreground pin")
    result = m.decode(result_raw)
    require(result["Version"] == "1" and result["RunID"] == packet["RunID"] and result["SourceHead"] == packet["SourceHead"]
            and result["CustodyInputSHA256"] == binding_sha and result["OwnFinalCloseProven"] is False and result["ReleaseQualified"] is False,
            "selected result binding differs")
    require(set(result["Files"]) == {"receipts.tar", "images.tar", "manifest.json"}, "selected output list differs")
    for name, maximum in (("receipts.tar", m.ARCHIVE_LIMIT), ("images.tar", m.IMAGE_LIMIT), ("manifest.json", m.JSON_LIMIT)):
        actual = m.stream(directory / name, maximum)
        require(all(actual[key] == result["Files"][name][key] for key in ("Bytes", "SHA256")), "copied output bytes differ: " + name)
    # Retain the original error stream as bytes; malformed/truncated prefixes
    # can describe a failed attempt and must never be parsed into success.
    error_raw, _ = m.read_small(directory / "errors.jsonl", 256 << 10)
    require(m.sha(error_raw) == foreground["ErrorsSHA256"], "final error original differs from external foreground pin")
    manifest_raw, _ = m.read_small(directory / "manifest.json", m.JSON_LIMIT)
    manifest = m.decode(manifest_raw)
    require(manifest["Version"] == "1" and manifest["RunID"] == packet["RunID"] and manifest["SourceHead"] == packet["SourceHead"]
            and manifest["CustodyInputSHA256"] == binding_sha and manifest["OwnFinalCloseProven"] is False
            and manifest["ReleaseQualified"] is False and manifest["SmallAggregateGuard"] == m.SMALL_LIMIT
            and manifest["ImageGuard"] == m.IMAGE_LIMIT, "manifest binding/profile differs")
    rows = manifest["Files"]
    require(type(rows) is list and len(rows) <= m.MAX_FILES, "receipt count exceeds guard")
    indexed = {row["Path"]: row for row in rows}
    require(len(indexed) == len(rows) and all(m.allowed_original(name, packet["RunID"]) for name in indexed), "duplicate/foreign selected original")
    _, _, fixture, required = m.fixed_paths(packet["RunID"])
    require(type(manifest["Missing"]) is list and len(manifest["Missing"]) <= m.MAX_FILES
            and len(set(manifest["Missing"])) == len(manifest["Missing"])
            and all(m.allowed_original(name, packet["RunID"]) for name in manifest["Missing"])
            and required - set(indexed) <= set(manifest["Missing"]), "missing-original declaration differs")
    original_total, observed, bodies = 0, set(), {}
    archive_file, archive_before = m.open_original(directory / "receipts.tar", m.ARCHIVE_LIMIT)
    with archive_file:
        with tarfile.open(fileobj=archive_file, mode="r:") as archive:
            for member in archive:
                require(len(observed) < m.MAX_FILES and member.name in indexed and member.name not in observed
                        and member.type == tarfile.REGTYPE and not member.pax_headers and member.mode == 0o600 and 0 <= member.size <= m.FILE_LIMIT,
                        "foreign/duplicate/nonregular/oversize receipt archive member")
                row = indexed[member.name]
                require(member.size == row["Bytes"], "archive member length differs")
                body = archive.extractfile(member).read(m.FILE_LIMIT + 1)
                require(len(body) == row["Bytes"] and m.sha(body) == row["SHA256"], "archive original corruption: " + member.name)
                original_total += len(body)
                require(original_total <= m.ARCHIVE_LIMIT, "receipt original aggregate exceeds guard")
                observed.add(member.name)
                if member.name in ("custody-input.json", "foreground.json", "foreground.stdout", "foreground.stderr", "parent-input.json", "source/.cache/direct-fixture-input.json", fixture + "image-broker-proof.json"):
                    bodies[member.name] = body
        require(archive_before == m.signature(os.fstat(archive_file.fileno())) == m.signature((directory / "receipts.tar").lstat()), "receipt archive changed during verification")
    require(observed == set(indexed), "manifest originals absent from archive")
    pins = {"custody-input.json": binding_sha, "foreground.json": packet["ForegroundSHA256"],
            "parent-input.json": packet["ParentInputSHA256"], "source/.cache/direct-fixture-input.json": packet["GoInputSHA256"]}
    binding_issues = [name for name, pin in pins.items() if name not in bodies or m.sha(bodies[name]) != pin]
    if "foreground.json" in bodies:
        parent_foreground = m.decode(bodies["foreground.json"])
        require(parent_foreground == manifest["ExternalParentForegroundClaim"], "manifest foreground claim differs from archived original")
        for name, prefix in (("foreground.stdout", "Stdout"), ("foreground.stderr", "Stderr")):
            if name not in bodies or len(bodies[name]) != parent_foreground.get(prefix + "Bytes") or m.sha(bodies[name]) != parent_foreground.get(prefix + "SHA256"):
                binding_issues.append(name)
    image = manifest["Image"]
    if image is not None:
        require(all(image[key] == result["Files"]["images.tar"][key] for key in ("Bytes", "SHA256")), "source image/copy binding differs")
    proof_binding = False
    if fixture + "image-broker-proof.json" in bodies and image is not None:
        try:
            proof = m.decode(bodies[fixture + "image-broker-proof.json"])
            proof_binding = (type(proof) is dict and proof.get("RunID") == packet["RunID"] and proof.get("ArchiveBytes") == image["Bytes"]
                             and proof.get("ArchiveSHA256") == image["SHA256"]
                             and proof.get("ArchivePath") == "/home/labrunner/kaferry-direct-" + packet["RunID"] + "/source/.cache/image-identity-data/" + packet["RunID"] + "/images.tar")
        except (ValueError, UnicodeError, TypeError):
            pass  # failed raw proof stays retained, never becomes authority
    capture = (manifest["CaptureComplete"] is True and result["CaptureComplete"] is True and foreground["ReturnCode"] == 0
               and not error_raw and not manifest["Missing"] and not binding_issues and required <= observed and image is not None)
    return {"Version": "1", "RunID": packet["RunID"], "SourceHead": packet["SourceHead"], "CustodyBytesVerified": True,
            "SourceCaptureComplete": capture, "OriginalFilesVerified": len(observed), "OriginalReceiptBytes": original_total,
            "ImageBytes": result["Files"]["images.tar"]["Bytes"], "ImageSourceCaptured": image is not None,
            "Missing": manifest["Missing"], "InputBindingIssues": binding_issues,
            "ImageProofArchiveBindingMatchesControllerClaim": proof_binding,
            "SnapshotForegroundExternalClaim": foreground, "ParentForegroundExternalClaim": manifest["ExternalParentForegroundClaim"],
            "ForegroundRecordsRequireIndependentProvenanceReview": True, "NoWaitOrLifecycleVerdictDerivedFromHashes": True,
            "ReleaseQualified": False, "PublicationAuthorized": False}


def main(argv):
    require(len(argv) == 6 and argv[0] == "--directory" and argv[2] == "--binding-sha256" and argv[4] == "--snapshot-wait-sha256"
            and re.fullmatch(r"[0-9a-f]{64}", argv[3]) and re.fullmatch(r"[0-9a-f]{64}", argv[5]), "fixed offline readback argv required")
    result = verify(Path(argv[1]), argv[3], argv[5])
    print(json.dumps(result, sort_keys=True))  # selected receipt only; originals stay private
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
