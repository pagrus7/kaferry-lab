#!/usr/bin/env python3
"""One fixed native controller, one guest Wait, private bounded originals.

--input /home/labrunner/kaferry-native-ci-RUN/parent-input.json --input-sha256 SHA
Input/head/build provenance and the Orb machine ID require external admission.
OwnFinalCloseProven is always false; actual parent return and Mac readback remain
required. This is neither a builder, general runner, inner oracle nor CI claim.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
import traceback

JSON_LIMIT, INPUT_LIMIT, STREAM_LIMIT = 256 << 10, 1 << 20, 64 << 10
WAIT_SECONDS, TERM_SECONDS, KILL_SECONDS, EOF_SECONDS = 360, 30, 10, 2
SDK = "bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd"
MACHINE, MACHINE_ID = "kaferry-lab-arm64-20261026", "01M5XVQQ4GRX6H79K1SE76R0X1"
GUEST_ROOT = Path("/home/labrunner")
ENV = {"HOME": "/home/labrunner", "PATH": "/usr/local/go/bin:/usr/bin:/bin", "LC_ALL": "C"}
FILES = ("errors.jsonl", "stdout.bin", "stderr.bin", "inputs.json", "wait.json", "result.json", "inventory.json")
GO_FILES = {"errors.json": JSON_LIMIT, "inputs.json": INPUT_LIMIT, "stdout.bin": 16 << 20,
            "stderr.bin": 16 << 20, "command.json": JSON_LIMIT, "tree.json": JSON_LIMIT,
            "result.json": JSON_LIMIT, "result.pending.json": JSON_LIMIT}


def require(value):
    if not value:
        raise ValueError("fixed native parent admission/custody rejected")


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode() + b"\n"


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def directory(path):
    s = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode)
            and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700)


def read_file(path, maximum=JSON_LIMIT, mode=0o600, expected=None):
    """The reviewed regular-file read/close pattern; atime is not identity."""
    require(path.resolve(strict=True) == path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == mode and 0 <= before.st_size <= maximum)
    f, failures, raw = None, [], b""
    try:
        f = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK), "rb")
        require(signature(before) == signature(os.fstat(f.fileno())))
        raw = f.read(maximum + 1)
        require(len(raw) == before.st_size and signature(before) == signature(os.fstat(f.fileno()))
                == signature(path.lstat()))
    except BaseException as error:
        failures.append(error)
    finally:
        if f is not None:
            try:
                f.close()
            except BaseException as error:
                failures.append(error)
    if failures:
        raise RuntimeError("bounded original read/close:\n" + "".join(
            "".join(traceback.format_exception(type(e), e, e.__traceback__)) for e in failures))
    sha = digest(raw)
    require(expected is None or sha == expected)
    return raw, {"Path": str(path), "Bytes": len(raw), "SHA256": sha}


def create(path):
    f = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), "wb", buffering=0)
    try:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600)
    except BaseException as error:
        failures = [error]
        try:
            f.close()
        except BaseException as close_error:
            failures.append(close_error)
        raise RuntimeError("private creation identity/close:\n" + "".join(
            "".join(traceback.format_exception(type(e), e, e.__traceback__)) for e in failures))
    return f


def write_file(f, raw):
    require(f.write(raw) == len(raw))
    os.fsync(f.fileno())


def close_file(f, record):
    for operation in (lambda: os.fsync(f.fileno()), f.close):
        try:
            operation()
        except BaseException as error:
            record(error)


class Errors:
    """One reserved sink, no replacement, no write after its last close."""
    def __init__(self, f):
        self.file, self.failed, self.broken, self.closed, self.bytes = f, False, False, False, 0

    def record(self, error):
        self.failed = True
        if self.broken or self.closed:
            return
        body = encode({"Exception": repr(error), "Traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))})
        bound = min(64 << 10, JSON_LIMIT - self.bytes)
        if bound <= 0:
            self.broken = True
            return
        complete = len(body) <= bound
        try:
            write_file(self.file, body[:bound])
            self.bytes += min(bound, len(body))
        except BaseException:
            self.broken = True
        self.broken = self.broken or not complete

    def close(self):
        self.closed = True
        # A last Sync/Close failure cannot write another copy of its own cause.
        close_file(self.file, lambda _: setattr(self, "failed", True))


def native_platform():
    u = os.uname()
    require(os.getuid() == os.geteuid() == 501 and u.sysname == "Linux" and u.machine == "aarch64"
            and u.nodename == MACHINE and u.release == "7.0.14-orbstack-00380-ga7e0a2dc9535")
    require(os.environ.get("HOME") == ENV["HOME"] and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
    require(resource.getrlimit(resource.RLIMIT_FSIZE) == (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    # Never raise a finite inherited limit, create another home or redirect caches.


def bind_inputs(base, expected):
    source, controller = base / "source", base / "controller"
    directory(source)
    directory(source / ".cache")
    directory(controller)
    raw, row = read_file(base / "parent-input.json", expected=expected)
    m = decode(raw)
    require(set(m) == {"Version", "RunID", "SourceHead", "GuestName", "GuestMachineID", "ControllerSHA256",
                       "ControllerBytes", "ControllerBuildSHA256", "NativeInputSHA256", "ParentSHA256"})
    require(m["Version"] == "1" and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", m["RunID"])
            and re.fullmatch(r"[0-9a-f]{40}", m["SourceHead"]) and m["GuestName"] == MACHINE and m["GuestMachineID"] == MACHINE_ID)
    require(base == GUEST_ROOT / ("kaferry-native-ci-" + m["RunID"]))
    for key in ("ControllerSHA256", "ControllerBuildSHA256", "NativeInputSHA256", "ParentSHA256"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{64}", m[key]))
    require(type(m["ControllerBytes"]) is int and 64 < m["ControllerBytes"] <= 32 << 20)
    bound = [row]
    bodies = {}
    for path, sha, maximum, mode in (
        (controller / "native-check", m["ControllerSHA256"], 32 << 20, 0o700),
        (controller / "controller-build.json", m["ControllerBuildSHA256"], JSON_LIMIT, 0o600),
        (source / ".cache/native-check-input.json", m["NativeInputSHA256"], INPUT_LIMIT, 0o600),
        (source / "scripts/native-check-guest-parent.py", m["ParentSHA256"], 64 << 10, 0o600),
    ):
        body, row = read_file(path, maximum, mode, sha)
        bodies[path.name] = body
        bound.append(row)
    require(Path(__file__).absolute() == source / "scripts/native-check-guest-parent.py")
    image = bodies["native-check"]
    require(len(image) == m["ControllerBytes"] and image[:6] == b"\x7fELF\x02\x01"
            and int.from_bytes(image[16:18], "little") == 2 and int.from_bytes(image[18:20], "little") == 183)
    build = decode(bodies["controller-build.json"])
    require(set(build) == {"Version", "SourceHead", "SourceCleanBefore", "SourceCleanAfter", "GoVersion", "GOOS", "GOARCH",
                           "SDKArchiveSHA256", "GoBinarySHA256", "ControllerSHA256", "ControllerBytes", "BuildInfoSHA256", "CompilerWait", "ReleaseQualified"})
    require(all(build.get(k) == v for k, v in {"Version": "1", "SourceHead": m["SourceHead"], "GoVersion": "go1.26.0",
            "GOOS": "linux", "GOARCH": "arm64", "SDKArchiveSHA256": SDK, "ControllerSHA256": m["ControllerSHA256"],
            "ControllerBytes": m["ControllerBytes"]}.items()) and build["SourceCleanBefore"] is True
            and build["SourceCleanAfter"] is True and build["ReleaseQualified"] is False)
    wait = build["CompilerWait"]
    require(set(wait) == {"PID", "WaitReturned", "ExitCode"} and type(wait["PID"]) is int and wait["PID"] > 1
            and wait["WaitReturned"] is True and type(wait["ExitCode"]) is int and wait["ExitCode"] == 0)
    require(type(build["BuildInfoSHA256"]) is str and re.fullmatch(r"[0-9a-f]{64}", build["BuildInfoSHA256"]))
    info, row = read_file(controller / "native-check.buildinfo", 64 << 10, expected=build["BuildInfoSHA256"])
    bound.append(row)
    lines = info.decode().splitlines()
    require(lines and lines[0].endswith(": go1.26.0"))
    required = {"\tpath\tgithub.com/pagrus7/kaferry-lab/cmd/native-check", "\tbuild\tGOOS=linux", "\tbuild\tGOARCH=arm64",
                "\tbuild\tvcs.revision=" + m["SourceHead"], "\tbuild\tvcs.modified=false"}
    require(required <= set(lines) and len(lines) == len(set(lines)))
    native = decode(bodies["native-check-input.json"])
    require(set(native) == {"Version", "RunID", "SourceHead", "Repository", "GuestName", "GuestMachineID", "SDKArchiveSHA256", "GoBinarySHA256", "Files"})
    require(all(native.get(k) == v for k, v in {"Version": "1", "RunID": m["RunID"], "SourceHead": m["SourceHead"],
            "Repository": str(source), "GuestName": MACHINE, "GuestMachineID": MACHINE_ID, "SDKArchiveSHA256": SDK,
            "GoBinarySHA256": build["GoBinarySHA256"]}.items()) and re.fullmatch(r"[0-9a-f]{64}", native["GoBinarySHA256"]))
    rows = native["Files"]
    require(type(rows) is list and 3 <= len(rows) <= 1024)
    last, total, own = "", 0, False
    for file in rows:
        require(set(file) == {"Path", "SHA256", "Bytes", "Mode"})
        path = file["Path"]
        require(type(path) is str and path > last and str(PurePosixPath(path)) == path and not path.startswith("/")
                and not any(part in ("..", ".git", ".cache") for part in PurePosixPath(path).parts)
                and re.fullmatch(r"[0-9a-f]{64}", file["SHA256"]) and type(file["Bytes"]) is int and 0 <= file["Bytes"] <= 16 << 20
                and type(file["Mode"]) is int and file["Mode"] in (0o600, 0o700))
        last, total = path, total + file["Bytes"]
        if path == "scripts/native-check-guest-parent.py":
            require(file["SHA256"] == m["ParentSHA256"])
            own = True
    require(own and total <= 16 << 20)
    # Go owns complete source-file membership/hash and SDK validation before it
    # executes check.sh. These claims/pins need external approved-head provenance.
    return m, bound


def open_child_handle(pid):
    return os.pidfd_open(pid, 0)  # selected Linux facility; no numeric-PID fallback


def signal_child(handle, value):
    signal.pidfd_send_signal(handle, value, None, 0)


def observe_cancellation(cancelled, record):
    # The handler only sets the first flag. Latch its cause once, through the
    # original sink; Errors.record still rejects success after that sink closes.
    if cancelled[0] and not cancelled[1]:
        cancelled[1] = True
        record(InterruptedError("parent cancellation requested"))
    return cancelled[0]


def wait_controller(argv, source, out, err, record, cancelled):
    """One Popen/Wait owner; pidfd readability precedes the sole actual Wait."""
    r = {"LaunchAttempted": False, "Started": False, "LaunchUncertain": False, "PID": None,
         "WaitAttempted": False, "Waited": False, "ReturnCode": None, "Timeout": False,
         "SignalHandleAcquired": False, "Signals": [], "SignalRouteClosed": False,
         "OutputWriteUncertain": False,
         "StdoutEOF": False, "StderrEOF": False, "OutputComplete": False,
         "StdoutBytes": 0, "StderrBytes": 0, "CapturedStdoutBytes": 0, "CapturedStderrBytes": 0}
    child, handle, selector, pipes = None, None, None, {}
    handle_registered = False
    origin, eof_end, cleanup_end, kill_at = time.monotonic(), None, None, None
    fault = False

    def stop(cause):
        nonlocal fault, kill_at, cleanup_end
        previous_fault, fault = fault, True
        record(cause)
        if previous_fault or r["WaitAttempted"]:
            return
        if handle is None or r["SignalRouteClosed"]:
            cleanup_end = time.monotonic() + TERM_SECONDS
            return
        try:
            signal_child(handle, signal.SIGTERM)
            r["Signals"].append({"Signal": int(signal.SIGTERM), "Succeeded": True})
            kill_at = time.monotonic() + TERM_SECONDS
            cleanup_end = kill_at + KILL_SECONDS
        except BaseException as error:
            r["Signals"].append({"Signal": int(signal.SIGTERM), "Succeeded": False})
            r["SignalRouteClosed"] = True
            record(error)
            cleanup_end = time.monotonic() + TERM_SECONDS

    def actual_wait(timeout):
        nonlocal eof_end
        require(not r["WaitAttempted"])
        r["WaitAttempted"], r["SignalRouteClosed"] = True, True
        try:
            r["ReturnCode"] = child.wait(timeout=timeout)
            r["Waited"] = True
            r["WaitObservedNS"] = time.monotonic_ns()
        except BaseException as error:
            record(error)  # no other Wait/poll/signal facility after uncertainty
        eof_end = time.monotonic() + EOF_SECONDS

    try:
        r["LaunchAttempted"] = True
        child = subprocess.Popen(argv, cwd=source, env=dict(ENV), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, bufsize=0)
        r.update(Started=True, PID=child.pid)
        pipes = {"Stdout": child.stdout, "Stderr": child.stderr}
        try:
            handle = open_child_handle(child.pid)
            r["SignalHandleAcquired"] = True
        except BaseException as error:
            record(error)
            r["SignalRouteClosed"] = True
        selector = selectors.DefaultSelector()
        for label, pipe, target in (("Stdout", child.stdout, out), ("Stderr", child.stderr, err)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, (label, target))
        try:
            if handle is not None:
                selector.register(handle, selectors.EVENT_READ, ("Wait", None))
                handle_registered = True
        except BaseException as error:
            record(error)
            r["SignalRouteClosed"] = True  # same-child capture/Wait only, no alternate signaling
        while True:
            now = time.monotonic()
            observe_cancellation(cancelled, stop)
            if not r["WaitAttempted"]:
                if not fault and now - origin >= WAIT_SECONDS:
                    r["Timeout"] = True
                    stop(TimeoutError("fixed native controller wait budget expired"))
                if kill_at is not None and now >= kill_at and not r["SignalRouteClosed"]:
                    kill_at = None
                    try:
                        signal_child(handle, signal.SIGKILL)
                        r["Signals"].append({"Signal": int(signal.SIGKILL), "Succeeded": True})
                    except BaseException as error:
                        r["Signals"].append({"Signal": int(signal.SIGKILL), "Succeeded": False})
                        record(error)
                    r["SignalRouteClosed"] = True
                if cleanup_end is not None and now >= cleanup_end:
                    actual_wait(0.001)
                elif not handle_registered and not pipes:
                    actual_wait(max(0.001, cleanup_end - now if cleanup_end is not None else WAIT_SECONDS - (now - origin)))
            if r["WaitAttempted"] and (not pipes or time.monotonic() >= eof_end):
                if pipes:
                    record(TimeoutError("controller output EOF deadline expired after direct Wait"))
                break
            for key, _ in selector.select(0.05):
                label, target = key.data
                if label == "Wait":
                    selector.unregister(key.fileobj)
                    if not r["WaitAttempted"]:
                        actual_wait(1)
                    continue
                try:
                    body = os.read(key.fd, 8192)
                    if not body:
                        r[label + "EOF"] = True
                        pipe = pipes.pop(label)
                        try:
                            selector.unregister(key.fileobj)
                        except BaseException as close_error:
                            stop(close_error)
                        try:
                            pipe.close()
                        except BaseException as close_error:
                            stop(close_error)
                        continue
                    r[label + "Bytes"] += len(body)
                    keep = min(len(body), STREAM_LIMIT - r["Captured" + label + "Bytes"])
                    if keep:
                        r["OutputWriteUncertain"] = True
                        written = target.write(body[:keep])
                        require(type(written) is int and 0 <= written <= keep)
                        r["Captured" + label + "Bytes"] += written
                        r["OutputWriteUncertain"] = False
                        require(written == keep)
                    if keep != len(body) and not fault:
                        stop(OverflowError("fixed controller " + label + " capture bound exceeded"))
                except BlockingIOError:
                    continue
                except BaseException as error:
                    stop(error)
                    try:
                        selector.unregister(key.fileobj)
                    except BaseException as cleanup_error:
                        record(cleanup_error)
                    pipe = pipes.pop(label, None)
                    if pipe is not None:
                        try:
                            pipe.close()
                        except BaseException as close_error:
                            record(close_error)
    except BaseException as error:
        record(error)
        if child is None:
            r["LaunchUncertain"] = r["LaunchAttempted"]
        elif not r["WaitAttempted"]:
            # Preserve sole same-child Wait even if pipe/selector construction
            # failed. No second launch or numeric-PID signaling is available.
            stop(error)
            actual_wait(TERM_SECONDS if handle is not None else WAIT_SECONDS)
    finally:
        for pipe in pipes.values():
            try:
                pipe.close()
            except BaseException as error:
                fault = True
                record(error)
        if selector is not None:
            try:
                selector.close()
            except BaseException as error:
                fault = True
                record(error)
        if handle is not None:
            try:
                os.close(handle)
            except BaseException as error:
                fault = True
                record(error)
    observe_cancellation(cancelled, stop)
    r["ElapsedNS"] = int((time.monotonic() - origin) * 1_000_000_000)
    r["OutputComplete"] = not fault and r["Waited"] and r["StdoutEOF"] and r["StderrEOF"] and all(
        r[label + "Bytes"] == r["Captured" + label + "Bytes"] <= STREAM_LIMIT for label in ("Stdout", "Stderr"))
    return r


def producer_files(base, m):
    """Read fixed Go originals after actual Wait; do not rederive its inner oracle."""
    path = base / "source/.cache/native-check-private" / m["RunID"]
    directory(path)
    bodies, rows = {}, []
    with os.scandir(path) as entries:
        for entry in entries:
            require(len(rows) < len(GO_FILES) and entry.name in GO_FILES)
            body, row = read_file(path / entry.name, GO_FILES[entry.name])
            bodies[entry.name] = body
            rows.append(row)
    require(set(bodies) == set(GO_FILES) - {"result.pending.json"})
    result = decode(bodies["result.json"])
    require(all(result.get(k) == v for k, v in {"Version": "1", "Namespace": "harness/native-unit-check", "RunID": m["RunID"],
            "SourceHead": m["SourceHead"], "InputSHA256": m["NativeInputSHA256"],
            "Status": "HARNESS_CHECKS_PASSED_EXTERNAL_CUSTODY_REQUIRED"}.items()))
    require(result.get("NativeHarnessChecksPassed") is True and result.get("CommandWritersStopped") is True
            and result.get("OwnFinalCloseProven") is False and result.get("RequiresExternalWaitAndMacReadback") is True
            and result.get("ReleaseQualified") is False)
    return rows


def run_attempt(base, expected):
    directory(base)
    attempt = base / "parent-private"
    attempt.mkdir(mode=0o700)
    directory(attempt)
    errors = Errors(create(attempt / "errors.jsonl"))  # first reserved sink
    files, bound, go_rows, result, wait, code, handlers = {}, [], [], {}, {}, 2, {}
    cancelled = [False, False]  # requested, cause already observed
    def cancel(_number, _frame):
        cancelled[0] = True
    try:
        for name in FILES[1:]:
            files[name] = create(attempt / name)
        for value in (signal.SIGTERM, signal.SIGINT):
            handlers[value] = signal.signal(value, cancel)
        native_platform()
        m, bound = bind_inputs(base, expected)
        require(not observe_cancellation(cancelled, errors.record) and set(os.listdir(base / "source/.cache")) == {"native-check-input.json"})
        write_file(files["inputs.json"], encode({"ParentInputSHA256": expected, "Input": m, "Bindings": bound,
                   "ExternalApprovedHeadAndMachineBindingRequired": True}))
        argv = [str(base / "controller/native-check"), "--repository", str(base / "source"), "--run-id", m["RunID"],
                "--reviewed-head", m["SourceHead"], "--input-sha256", m["NativeInputSHA256"]]
        wait = wait_controller(argv, base / "source", files["stdout.bin"], files["stderr.bin"], errors.record, cancelled)
        write_file(files["wait.json"], encode({"Argv": argv, "GuestParentPID": os.getpid(), **wait}))
        for name in ("stdout.bin", "stderr.bin", "inputs.json", "wait.json"):
            close_file(files.pop(name), errors.record)
        observe_cancellation(cancelled, errors.record)
        require(wait["Waited"] and wait["ReturnCode"] == 0 and wait["OutputComplete"] and not wait["Timeout"] and not errors.failed)
        require(bind_inputs(base, expected) == (m, bound))
        require(not observe_cancellation(cancelled, errors.record))
        go_rows = producer_files(base, m)
        require(not observe_cancellation(cancelled, errors.record))
        result = {"RunID": m["RunID"], "Status": "CONTROLLER_RETURN_CORROBORATED_EXTERNAL_CUSTODY_REQUIRED",
                  "ControllerReturnCorroborated": True, "OwnFinalCloseProven": False,
                  "RequiresExternalReturnAndMacReadback": True, "GuardReleaseAuthorized": False, "ReleaseQualified": False}
        code = 0
    except BaseException as error:
        errors.record(error)
    finally:
        for name in ("stdout.bin", "stderr.bin", "inputs.json", "wait.json"):
            if name in files:
                close_file(files.pop(name), errors.record)
        observe_cancellation(cancelled, errors.record)
        for value, handler in handlers.items():
            try:
                signal.signal(value, handler)
            except BaseException as error:
                errors.record(error)
        observe_cancellation(cancelled, errors.record)
        if errors.failed:
            result = {"Status": "INCOMPLETE", "ControllerReturnCorroborated": False,
                      "ControllerLaunchAttempted": wait.get("LaunchAttempted", False), "ControllerWaited": wait.get("Waited", False),
                      "PrimaryErrorSinkBroken": errors.broken,
                      "OwnFinalCloseProven": False, "RequiresExternalReturnAndMacReadback": True,
                      "GuardReleaseAuthorized": False, "ReleaseQualified": False}
        if "result.json" in files:
            try:
                write_file(files["result.json"], encode(result))
            except BaseException as error:
                errors.record(error)
            close_file(files.pop("result.json"), errors.record)
        # A candidate already serialized/closed is never rewritten. A newly
        # observed cancellation rejects it through the actual external return.
        observe_cancellation(cancelled, errors.record)
        errors.close()
        observe_cancellation(cancelled, errors.record)
        # The final inventory cannot attest its own close. An error now has no
        # replacement sink; actual parent return/Mac readback must reject it.
        if not errors.failed and code == 0:
            try:
                rows = [read_file(attempt / name, STREAM_LIMIT if name.endswith(".bin") else JSON_LIMIT)[1]
                        for name in FILES if name != "inventory.json"]
                write_file(files["inventory.json"], encode({"Files": rows, "ProducerFiles": go_rows,
                           "OwnFinalCloseProven": False, "RequiresExternalReturnAndMacReadback": True}))
            except BaseException:
                errors.failed = True
        observe_cancellation(cancelled, errors.record)
        if "inventory.json" in files:
            close_file(files.pop("inventory.json"), lambda _: setattr(errors, "failed", True))
        observe_cancellation(cancelled, errors.record)
    return 2 if errors.failed or cancelled[0] else code


def main(argv):
    require(len(argv) == 4 and argv[0] == "--input" and argv[2] == "--input-sha256" and re.fullmatch(r"[0-9a-f]{64}", argv[3]))
    path = Path(argv[1])
    require(path.is_absolute() and path.name == "parent-input.json" and path.parent.parent == GUEST_ROOT
            and re.fullmatch(r"kaferry-native-ci-[a-z0-9][a-z0-9-]{0,63}", path.parent.name))
    return run_attempt(path.parent, argv[3])


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except BaseException:
        status = 2  # unavailable first/final sink is never replaced by public raw errors
    sys.exit(status)
