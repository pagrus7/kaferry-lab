#!/usr/bin/env python3
"""Hosted Linux-only synthetic child calibration; never contacts the provider.

No local native claim follows from reading or parsing this file. The specimen is
an ordinary no-fork Python process, visibly separate from the Go diagnostic.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
try:
    spec = importlib.util.spec_from_file_location("metadata_calibration_caller", Path.cwd() / "scripts/capture-metadata.py")
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
except (Exception, KeyboardInterrupt, SystemExit):
    print('{"namespace":"calibration/metadata-native-controls","complete":false,"release_qualified":false}', flush=True)
    raise SystemExit(1) from None

# Literal reviewed synthetic producer. It validates the actual caller's flags,
# cwd-relative output contract, private file persistence and fixed stdout. It
# neither imports Kaferry nor makes sockets, children, shell calls or requests.
SPECIMEN = r'''
import argparse, json, os, signal, sys, time
p = argparse.ArgumentParser()
for key in ("run-id", "source-head", "job", "attempt", "output"):
    p.add_argument("--" + key, required=True)
a = p.parse_args()
assert a.output == ".cache/fixtures-private/" + a.run_id + "-links/metadata.json"
assert not os.path.isabs(a.output) and a.job == "metadata"
with open("SPECIMEN.json", "rb") as f:
    specimen = json.load(f)
receipt = specimen["receipt"]
assert receipt["RunID"] == a.run_id and receipt["source_head"] == a.source_head
assert receipt["attempt"] == a.attempt
mode = specimen["mode"]
if mode in ("timeout", "cancel"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    fd = os.open("READY.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b'{"synthetic_ready":true}\n')
    os.close(fd)
    os.write(1, b"synthetic ready\n")
    time.sleep(30)
    sys.exit(1)
if mode == "overflow":
    raw = b"x" * 65537
    while raw:
        raw = raw[os.write(2, raw):]
    time.sleep(30)
    sys.exit(1)
fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n"
assert os.write(fd, raw) == len(raw)
os.fsync(fd)
os.close(fd)
os.write(2, b"synthetic private stderr:\x00\xff\n")
os.write(1, b"metadata diagnostic observation closed\n")
time.sleep(0.1)
sys.exit(0 if receipt["capture_complete"] else 2)
'''
STDERR = b"synthetic private stderr:\x00\xff\n"
BODY = b"synthetic provider explanation:\x00\xff"


def check(value):
    if not value:
        raise AssertionError("synthetic metadata calibration assertion failed")


def frame(*values):
    return b"".join(len(value).to_bytes(8, "big") + value for value in values)


def fixture(value, status=403, complete=True, attempts=1):
    def observed(raw, done=True):
        return {"prefix_base64": base64.b64encode(raw).decode(), "observed_bytes_lower_bound": len(raw),
                "complete": done, "overflow": False, "traversal_guard_reached": False}
    headers = frame(str(status).encode() + (b" Forbidden" if status == 403 else b" OK"), b"HTTP/2.0",
                    b"headers", b"X-Synthetic", b"1", b"binary:\x00\xff")
    # These literal schema/representation fields are independent of the Go
    # producer and the caller's validators, so drift does not update the oracle.
    return dict(RunID=value["run_id"], source_head=value["source_head"], github_run_id=value["run_id"].split("-")[1],
                job="metadata", attempt=value["attempt"], namespace="calibration/metadata-diagnostic",
                release_qualified=False, platform="linux/amd64", method="GET",
                url="https://api.github.com/repos/pagrus7/kaferry/git/ref/tags/v0.6.0",
                accept="application/vnd.github+json", user_agent="kaferry-lab-artifact", attempt_count=attempts,
                started_utc="2026-10-27T00:00:00Z", elapsed_ns_monotonic=123,
                response_available=complete, status_code=status if complete else 0,
                headers_representation="CLIENT-DECODED net/http fields; uint64be-length frames: status,protocol, then section,name,value-count,values; sections=headers,trailers; sorted names; not wire octets",
                headers=observed(headers if complete else b"", complete),
                body_representation="net/http exposed response-body bytes; may be transparently decompressed; not wire octets",
                body=observed(BODY if complete else b"", complete),
                errors_representation="uint64be-length frames: node-path,Go-type,Error()-bytes; root 0=setup/transport,1=body-read,2=body-close,3=context; bounded unwrap graph",
                errors=observed(b"" if complete else frame(b"0", b"*errors.errorString", b"synthetic setup failure")),
                body_close_attempted=complete, body_close_succeeded=complete, net_http_uncompressed=False,
                capture_complete=complete)


def prepare(root, name, value, receipt, mode="receipt"):
    base = c.s.reserve(root, name)
    (base / ".cache").mkdir(mode=0o700)
    (base / ".cache/metadata-build").mkdir(mode=0o700)
    directory = c.s.reserve(base / ".cache/metadata-build", value["run_id"])
    executable = directory / "metadata-capture"
    c.s.write_private(executable, ("#!" + sys.executable + "\n" + SPECIMEN).encode())
    executable.chmod(0o700)
    c.s.write_private(base / "SPECIMEN.json", c.s.encode({"mode": mode, "receipt": receipt}))
    return base, hashlib.sha256(executable.read_bytes()).hexdigest()


def closure(base, value):
    root = base / ".cache/fixtures-private" / (value["run_id"] + "-links")
    return c.s.parse_json(c.s.read_regular(root / "capture-closure.json", c.s.MAX_FILE, private=True))


def assert_terminal(record):
    wait = record["child_wait"]
    check(record["child_started"] and type(record["child_pid"]) is int and record["child_start_ticks"] > 0)
    check(wait["wait_returned"] and wait["selector_closed"])
    check(record["private_sinks_synced_closed"] and record["error_sink_synced_closed"])
    check(all(stream["eof"] and stream["pipe_closed"] for stream in record["streams"].values()))
    # waitpid on the exact retained child must now report ECHILD, independently
    # of the caller's receipt. Do not enumerate or signal any other process.
    try:
        os.waitpid(record["child_pid"], os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError("exact synthetic child was not terminally reaped")


@contextmanager
def injected(owner, attribute, replacement):
    original = getattr(owner, attribute)
    setattr(owner, attribute, replacement)
    try:
        yield original
    finally:
        setattr(owner, attribute, original)


def receipt_case(root, name, value, *, status=403, complete=True, attempts=1, fault=None):
    expected = fixture(value, status, complete, attempts)
    base, sha = prepare(root, name, value, expected)

    def checked_run():
        original, handles = subprocess.Popen, []
        def launched(*args, **kwargs):
            handle = original(*args, **kwargs)
            handles.append(handle)
            return handle
        with injected(c.subprocess, "Popen", launched):
            result = c.run_capture(base, value, sha)
        check(len(handles) == 1)
        handle = handles[0]
        check(handle.returncode in (0, 2) and handle.stdout.closed and handle.stderr.closed)
        try:
            os.waitpid(handle.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("synthetic receipt child not reaped")
        return result

    if fault is None:
        result = checked_run()
    elif fault == "final-write":
        original = c.s.persist_receipt
        def final_write(fd, raw):
            if os.readlink("/proc/self/fd/" + str(fd)).endswith("/capture-closure.json"):
                raise OSError(5, "synthetic injected final receipt write failure")
            return original(fd, raw)
        with injected(c.s, "persist_receipt", final_write):
            result = checked_run()
        check(not result.get("snapshot_admissible", False) and not result["capture_complete"])
        return {"passed": True, "injected_final_sink": True, "reaped": True}
    elif fault == "final-close":
        original = os.close
        attempts_seen = []
        def final_close(fd):
            target = os.readlink("/proc/self/fd/" + str(fd))
            if target.endswith("/capture-closure.json"):
                attempts_seen.append(fd)
                original(fd)
                raise OSError(5, "synthetic injected final receipt close failure")
            return original(fd)
        with injected(c.os, "close", final_close):
            result = checked_run()
        check(len(attempts_seen) == 1 and not result.get("snapshot_admissible", False) and not result["capture_complete"])
        # The on-disk receipt can look successful after a failed final close;
        # actual foreground result remains the mandatory external gate.
        check(closure(base, value)["snapshot_admissible"])
        return {"passed": True, "injected_final_sink": True, "reaped": True}
    elif fault == "metadata-read":
        original = c.s.read_regular
        def failed_read(path, maximum, private=False):
            if Path(path).name == "metadata.json":
                raise PermissionError(13, "synthetic injected metadata read denial", str(path))
            return original(path, maximum, private=private)
        with injected(c.s, "read_regular", failed_read):
            result = checked_run()
        record = closure(base, value)
        assert_terminal(record)
        check(not result.get("snapshot_admissible", False) and not record["producer_receipt_valid"])
        notice = record["errors"][0]["exceptions"][0]
        check(notice["errno"] == 13 and "synthetic injected metadata read denial" in notice["exact_text"])
        raw_notice = c.s.parse_json(c.s.read_regular(base / ".cache/metadata-capture-private" / value["run_id"] / "OS-ERROR.json", c.MAX_ERROR, private=True))
        check(raw_notice["errors"][0]["exceptions"][0] == notice)
        return {"passed": True, "injected_metadata_read": True, "reaped": True}
    else:
        raise AssertionError("unknown synthetic fault")
    record = closure(base, value)
    assert_terminal(record)
    check(result["snapshot_admissible"] and result["finite_snapshot_closed"])
    check(result["capture_complete"] == complete == record["capture_complete"])
    check(record["child_wait"]["returncode"] == (0 if complete else 2))
    check(base64.b64decode(record["streams"]["stdout"]["prefix"], validate=True) == b"metadata diagnostic observation closed\n")
    check(base64.b64decode(record["streams"]["stderr"]["prefix"], validate=True) == STDERR)
    path = base / ".cache/fixtures-private" / (value["run_id"] + "-links") / "metadata.json"
    actual = c.s.parse_json(c.s.read_regular(path, c.s.MAX_FILE, private=True))
    check(actual == expected)
    check(base64.b64decode(actual["body"]["prefix_base64"], validate=True) == (BODY if complete else b""))
    check(actual["status_code"] == (status if complete else 0) and actual["attempt_count"] == attempts)
    # Verify the actual closed files are admitted by unchanged fixture-v1.
    payloads = c.s.snapshot(path.parent, value["run_id"])
    check(set(payloads) == {"PRIVATE.json", "metadata.json", "capture-closure.json"})
    return {"passed": True, "reaped": True, "capture_complete": complete, "status_code": actual["status_code"],
            "attempt_count": attempts, "stderr_bytes": len(STDERR), "body_bytes": len(BODY) if complete else 0}


def drive_case(root, name, value, mode):
    base, sha = prepare(root, name, value, fixture(value), mode)
    executable, _ = c.binary(base, value, sha)
    directory, error_fd = c.s.reserve_operation(base / ".cache/direct-private", value["run_id"])
    sinks, errors, child = {}, [], None
    def record(action, error):
        errors.append(c.exception_record(action, error))
        c.s.persist_receipt(error_fd, c.s.encode({"errors": errors, "complete": True}))
    try:
        for stream in ("stdout", "stderr"):
            sinks[stream] = os.open(directory / (stream + ".bin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        child = subprocess.Popen([str(executable), "--run-id", value["run_id"], "--source-head", value["source_head"],
                                  "--job", "metadata", "--attempt", value["attempt"],
                                  "--output", ".cache/fixtures-private/" + value["run_id"] + "-links/metadata.json"],
                                 cwd=base, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, shell=False)
        ticks = c.start_ticks(child.pid)
        if mode in ("timeout", "cancel"):
            ready_deadline = time.monotonic() + 3
            while not (base / "READY.json").exists():
                check(time.monotonic() < ready_deadline and child.poll() is None)
                time.sleep(0.01)
        if mode == "timeout":
            first = [True]
            def crossed_deadline():
                if first[0]:
                    first[0] = False
                    return time.monotonic()
                return time.monotonic() + 46
            wait, streams = c.drive(child, sinks, record, monotonic=crossed_deadline)
        elif mode == "cancel":
            def cancelled(_fd, _size):
                raise KeyboardInterrupt("synthetic injected caller cancellation")
            wait, streams = c.drive(child, sinks, record, read=cancelled)
        else:
            wait, streams = c.drive(child, sinks, record)
        check(ticks > 0 and wait["wait_returned"] and wait["returncode"] < 0)
        check(wait["selector_closed"] and all(stream["pipe_closed"] for stream in streams.values()))
        try:
            os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("synthetic direct child not reaped")
        check(not c.closed_capture(wait, streams, True, errors)[1])
        if mode == "timeout":
            check(wait["deadline_reached"] and wait["terminate_requested"] and wait["kill_requested"])
        elif mode == "cancel":
            check(wait["cancelled"] and wait["terminate_requested"] and wait["kill_requested"] and errors)
        else:
            check(streams["stderr"]["overflow"] and len(streams["stderr"]["prefix"]) == 65536)
        return {"passed": True, "reaped": True, "terminate_requested": wait["terminate_requested"],
                "kill_requested": wait["kill_requested"], "cancelled": wait["cancelled"],
                "deadline_reached": wait["deadline_reached"], "stderr_overflow": streams["stderr"]["overflow"],
                "injected_clock_or_cancellation": mode in ("timeout", "cancel")}
    finally:
        # Exact owned Popen fallback remains bounded even if a calibration
        # assertion fails before drive starts. Never enumerate other processes.
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
            finally:
                child.stdout.close()
                child.stderr.close()
        for fd in sinks.values():
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        try:
            os.fsync(error_fd)
        finally:
            os.close(error_fd)


def main():
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise c.s.Rejected("synthetic calibration arguments rejected")
    parser = Parser(description=__doc__)
    for key in ("run-id", "source-head", "attempt"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    value = c.identity(args.run_id, args.source_head, "metadata", args.attempt, os.environ)
    check(sys.platform == "linux" and os.uname().machine == "x86_64")
    root, fd = c.s.reserve_operation(Path.cwd() / ".cache/metadata-native-private", value["run_id"])
    began = time.monotonic()
    def budget_expired(_signum, _frame):
        raise KeyboardInterrupt("synthetic native calibration wall budget reached")
    prior_alarm = signal.signal(signal.SIGALRM, budget_expired)
    signal.setitimer(signal.ITIMER_REAL, 100)
    try:
        results = {}
        for name, options in (("complete403", {}), ("complete200", {"status": 200}),
                              ("transport-incomplete", {"complete": False}),
                              ("setup-unreached", {"complete": False, "attempts": 0}),
                              ("metadata-read-denial", {"fault": "metadata-read"}),
                              ("final-write-failure", {"fault": "final-write"}),
                              ("final-close-failure", {"fault": "final-close"})):
            check(time.monotonic() - began < 90)
            results[name] = receipt_case(root, name, value, **options)
        for mode in ("timeout", "cancel", "overflow"):
            check(time.monotonic() - began < 90)
            results[mode] = drive_case(root, mode, value, mode)
        check(time.monotonic() - began < 115)
        report = {"namespace": "calibration/metadata-native-controls", "release_qualified": False,
                  "provider_requests": 0, "case_count": len(results), "cases": results,
                  "elapsed_ns": int((time.monotonic() - began) * 1e9), "complete": True}
        public = c.s.private_root(Path.cwd() / ".cache/metadata-public")
        c.s.write_private(public / "native-controls.json", c.s.encode(report))
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        c.s.persist_receipt(fd, c.s.encode(c.exception_record("synthetic native metadata calibration", error)))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior_alarm)
        os.close(fd)
    print('{"namespace":"calibration/metadata-native-controls","complete":true,"release_qualified":false}', flush=True)
    return 0


if __name__ == "__main__":
    # All unexpected diagnostics stay out of public logs. First sink failure
    # can leave originals unavailable; no fallback path or retry is attempted.
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print('{"namespace":"calibration/metadata-native-controls","complete":false,"release_qualified":false}', flush=True)
        raise SystemExit(1) from None
