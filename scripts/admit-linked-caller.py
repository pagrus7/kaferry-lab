#!/usr/bin/env python3
"""Admit an already returned native guest linked driver; execute nothing.

The guest foreground caller must write foreground.exit only after its actual
command returns. This reader cannot create that observation, attest its own
final close, or prove the Mac/Orb caller returned. No GitHub identity is inferred.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

SCOPE = "Reviewed driver final marker after actual wait/tree closure and primary sink sync/close; no ACK or Kaferry qualification."
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"links-[a-z0-9][a-z0-9-]{0,95}\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z")


class Rejected(Exception):
    pass


class IOFailures(Exception):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("linked caller I/O incomplete")


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("linked caller arguments rejected")


def require(value):
    if not value:
        raise Rejected("linked caller admission rejected")


def boolean(value):
    require(type(value) is bool)
    return value


def integer(value, low=0, high=1 << 63):
    require(type(value) is int and low <= value <= high)
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def private(info, directory=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and info.st_uid == os.getuid() and (directory or info.st_nlink == 1))


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, maximum=256 << 10, executable=False):
    before = path.lstat()
    if executable:
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o555
                and before.st_uid == os.getuid() and before.st_nlink == 1)
    else:
        private(before)
    require(0 < before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    stream, errors, body = os.fdopen(fd, "rb"), [], None
    try:
        require(signature(before) == signature(os.fstat(stream.fileno())))
        body = stream.read(maximum + 1)
        require(len(body) == before.st_size
                and signature(before) == signature(os.fstat(stream.fileno()))
                and signature(before) == signature(path.lstat()))
    except BaseException as error:
        errors.append(("read/validate " + path.name, error))
    finally:
        try:
            stream.close()
        except BaseException as error:
            errors.append(("close " + path.name, error))
    if errors:
        raise IOFailures(errors)
    return body



def receipt(path):
    return json.loads(read(path), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Rejected("nonfinite JSON")))


def native_build(repository, run, head, attempt):
    kernel = os.uname()
    require(kernel.sysname == "Linux" and kernel.machine == "aarch64")
    build = receipt(repository / ".cache/links/build.json")
    require(build["namespace"] == "calibration/linked-build"
            and build["source_head"] == head and build["run_id"] == run
            and build["job"] == "links" and build["attempt"] == attempt
            and build["kernel_system"] == kernel.sysname and build["kernel_machine"] == kernel.machine
            and not boolean(build["release_qualified"]) and boolean(build["runtime_requested"]))
    directory = repository / ".cache/link-calibration-build" / run
    private(directory.parent.lstat(), True)
    private(directory.lstat(), True)
    for name, package, metadata in [
            ("campaign.test", "github.com/pagrus7/kaferry-lab/internal/campaign.test", "test-buildinfo.txt"),
            ("link-calibration", "github.com/pagrus7/kaferry-lab/cmd/link-calibration", "driver-buildinfo.txt")]:
        entry = build["executables"][name]
        require(entry["source_head"] == head and boolean(entry["source_clean"])
                and entry["goos"] == "linux" and entry["goarch"] == "arm64"
                and entry["package"] == package and entry["mode"] == "0555"
                and type(entry["sha256"]) is str and HEX64.fullmatch(entry["sha256"]))
        body = read(directory / name, 128 << 20, executable=True)
        require(integer(entry["bytes"], 1, 128 << 20) == len(body)
                and hashlib.sha256(body).hexdigest() == entry["sha256"])
        # ELF64 little endian executable/shared Go image, EM_AARCH64. The Go
        # driver separately verifies actual embedded build info before launch.
        require(len(body) >= 64 and body[:7] == b"\x7fELF\x02\x01\x01"
                and struct.unpack_from("<H", body, 16)[0] in (2, 3)
                and struct.unpack_from("<H", body, 18)[0] == 183)
        text = read(directory / metadata, 64 << 10).decode("utf-8")
        require(text.count("\tpath\t" + package + "\n") == 1)
        settings = {}
        for line in text.splitlines():
            if line.startswith("\tbuild\t"):
                key, separator, value = line[7:].partition("=")
                require(separator and key not in settings)
                settings[key] = value
        require(all(settings.get(key) == value for key, value in {
            "GOOS": "linux", "GOARCH": "arm64", "vcs.revision": head, "vcs.modified": "false"}.items()))
    require(read(directory / "BuiltAfterUTC", 128).decode("utf-8") == build["built_after_utc"] + "\n")
    return build


def admit(repository, run, head, attempt, cancelled):
    """Read fixed guest files and return an allowlisted projection, never raw errors."""
    repository = Path(repository)
    require(repository.is_absolute() and repository.resolve() == repository
            and HEX40.fullmatch(head) and RUN.fullmatch(run) and NUMBER.fullmatch(attempt)
            and cancelled == "false")
    for parent in (repository / ".cache", repository / ".cache/links"):
        private(parent.lstat(), True)
    build = native_build(repository, run, head, attempt)
    foreground = read(repository / ".cache/links/foreground.exit", 4)
    require(re.fullmatch(rb"[0-9]{1,3}\n", foreground))
    code = integer(int(foreground), 0, 255)
    public = repository / ".cache/link-calibration" / run
    for parent in (public.parent, public):
        private(parent.lstat(), True)
    require(not (public / "INCOMPLETE.json").exists() and not (public / "result.pending.json").exists())
    r = receipt(public / "WRITERS_QUIESCENT.json")
    require(r["Version"] == "1" and r["RunID"] == run and r["ReviewedHead"] == head
            and r["TestSHA256"] == build["executables"]["campaign.test"]["sha256"])
    require(boolean(r["Synthetic"]) and not boolean(r["ReleaseQualified"]))
    require(not boolean(r["SealingReady"]) and not boolean(r["PublicationAuthorized"]))
    require(boolean(r["WritersQuiescent"]) and boolean(r["PrivateCaptureComplete"]) and boolean(r["SetupReturned"]))
    driver_private = repository / ".cache/link-calibration-private" / run
    require(r["DriverPrivate"] == str(driver_private)
            and r["PrivateReference"] == str(driver_private / "driver-errors.json")
            and r["FixturePrivate"] == str(repository / ".cache/fixtures-private" / (run + "-links")))
    attempted, returned = boolean(r["CleanupAttempted"]), boolean(r["CleanupReturned"])
    require(attempted == returned)
    w, tree = r["Wait"], r["Tree"]
    require(boolean(tree["SubreaperEnabled"]) and boolean(tree["Closed"])
            and boolean(tree["NoChildren"]) and not boolean(tree["ControlFailed"]))
    require(type(tree["Adopted"]) is list or tree["Adopted"] is None)
    adopted = tree["Adopted"] or []
    require(len(adopted) <= 16)
    for child in adopted:
        integer(child["PID"], 1)
        status = integer(child["Status"], 0, (1 << 32) - 1)
        require(boolean(child["Terminal"]) and (os.WIFEXITED(status) or os.WIFSIGNALED(status)))
    if boolean(tree["AnchorStarted"]):
        integer(tree["AnchorPID"], 1)
        require(type(tree["AnchorStartTicks"]) is str and re.fullmatch(r"[0-9]{1,32}", tree["AnchorStartTicks"]))
        require(boolean(tree["AnchorWaitReturned"]) and boolean(tree["AnchorReaped"]) and boolean(tree["SignalsClosed"]))
        status = integer(tree["AnchorStatus"], 0, (1 << 32) - 1)
        require(os.WIFEXITED(status) or os.WIFSIGNALED(status))
    else:
        require(not boolean(tree["AnchorWaitReturned"]) and not boolean(tree["AnchorReaped"]) and tree["AnchorPID"] == 0)
    if boolean(w["Started"]):
        integer(w["PID"], 1)
        require(type(w["StartTicks"]) is str and re.fullmatch(r"[0-9]{1,32}", w["StartTicks"]))
        require(boolean(w["WaitReturned"]) and boolean(w["Reaped"])
                and boolean(w["StreamCopiesJoined"]) and boolean(w["OutputComplete"]))
        integer(w["ExitCode"], -1, 255)
        integer(w["SignalNumber"], 0, 64)
        require((w["SignalNumber"] == 0 and w["ExitCode"] >= 0)
                or (w["SignalNumber"] > 0 and w["ExitCode"] == -1))
        integer(w["WaitElapsedNS"], 1)
        for channel in ("Stdout", "Stderr"):
            require(integer(w[channel + "Bytes"], 0, 65536) == integer(w["Captured" + channel + "Bytes"], 0, 65536))
            require(integer(w["DroppedObserved" + channel + "Bytes"]) == 0)
    else:
        require(not boolean(w["WaitReturned"]) and not boolean(w["Reaped"])
                and not boolean(w["StreamCopiesJoined"]) and w["PID"] == 0 and w["StartTicks"] == "")
    require(r["Status"] in ("INCOMPLETE", "CALIBRATION_PASSED_NOT_QUALIFICATION"))
    passed = r["Status"] == "CALIBRATION_PASSED_NOT_QUALIFICATION"
    require((code == 0) == passed)
    require(not passed or (boolean(w["TestsPassed"]) and boolean(r["ResourcesCleaned"])
                          and boolean(r["FixtureCleanupSucceeded"]) and attempted and returned))
    return {"namespace": "calibration/linked-caller", "identity_source": "explicit-caller",
            "run_id": run, "source_head": head, "job": "links", "attempt": attempt,
            "kernel_system": "Linux", "kernel_machine": "aarch64", "goos": "linux", "goarch": "arm64",
            "driver_sha256": build["executables"]["link-calibration"]["sha256"],
            "test_sha256": build["executables"]["campaign.test"]["sha256"],
            "foreground_return_observed": True, "foreground_exit_code": code,
            "caller_cancelled_at_admission": False, "writers_quiescent": True,
            "private_capture_complete": True, "setup_returned": True,
            "cleanup_attempted": attempted, "cleanup_returned": returned,
            "resources_cleaned": boolean(r["ResourcesCleaned"]),
            "fixture_cleanup_succeeded": boolean(r["FixtureCleanupSucceeded"]),
            "child_started": w["Started"], "child_wait_returned": w["WaitReturned"],
            "child_reaped": w["Reaped"], "stream_copies_joined": w["StreamCopiesJoined"],
            "anchor_started": tree["AnchorStarted"], "anchor_wait_returned": tree["AnchorWaitReturned"],
            "anchor_reaped": tree["AnchorReaped"], "subreaper_enabled": True,
            "terminal_adopted_waits": len(adopted), "actual_ECHILD_observed_by_driver": True,
            "calibration_passed": passed, "release_qualified": False, "scope": SCOPE}


def write_proof(path, proof):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    stream, errors = os.fdopen(fd, "wb"), []
    try:
        body = encode(proof)
        require(stream.write(body) == len(body))
        stream.flush()
        os.fsync(stream.fileno())
    except BaseException as error:
        errors.append(("write/sync caller-proof.json", error))
    finally:
        try:
            stream.close()
        except BaseException as error:
            errors.append(("close caller-proof.json", error))
    if errors:
        raise IOFailures(errors)



def main(argv=None):
    # The caller reserves/inherits the sole private error FD before invocation.
    # No alternate sink, traceback or raw exception reaches stdout/stderr.
    parser = QuietParser(add_help=False, exit_on_error=False)
    for name in ("repository", "run-id", "source-head", "attempt", "caller-cancelled", "error-fd"):
        parser.add_argument("--" + name, required=True)
    error_fd = None
    try:
        args, extra = parser.parse_known_args(argv)
        require(not extra and re.fullmatch(r"[0-9]{1,9}", args.error_fd))
        candidate = int(args.error_fd)
        require(candidate > 2)
        info = os.fstat(candidate)
        private(info)
        require(info.st_size == 0 and os.lseek(candidate, 0, os.SEEK_CUR) == 0)
        error_fd = candidate
        proof = admit(args.repository, args.run_id, args.source_head, args.attempt, args.caller_cancelled)
        write_proof(Path(args.repository) / ".cache/links/caller-proof.json", proof)
        owned, error_fd = error_fd, None
        os.close(owned)
        result = "linked-caller-admitted" if proof["calibration_passed"] else "linked-caller-failed-quiescent"
        status = 0 if proof["calibration_passed"] else 2
    except BaseException as error:
        if error_fd is not None:
            try:
                def record(action, current):
                    return {"action": action, "type": type(current).__name__,
                            "errno": getattr(current, "errno", None), "exact_text": str(current),
                            "filename": getattr(current, "filename", None), "filename2": getattr(current, "filename2", None)}
                if isinstance(error, IOFailures):
                    value = {"complete": len(error.errors) <= 8,
                             "failures": [record(action, current) for action, current in error.errors[:8]]}
                else:
                    value = record("linked caller admission", error)
                body = encode(value)
                require(len(body) <= 65536 and os.write(error_fd, body) == len(body))
                os.fsync(error_fd)
            except BaseException:
                pass
            finally:
                try:
                    os.close(error_fd)
                except BaseException:
                    pass
        result, status = "linked-caller-incomplete", 1
    try:
        print(json.dumps({"status": result, "release_qualified": False}, separators=(",", ":")), flush=True)
    except BaseException:
        return 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
