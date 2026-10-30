#!/usr/bin/env python3
"""One already-built native synthetic wrapper; private regular-file custody.

Run from the reviewed hardware checkout: SCRIPT RUN INPUT_SHA256.
This caller neither sets up GDB nor attests its own final close/readback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import time
import traceback

HEAD = "664fbbf5dbff0f2a8ed17b20967c1889d8521e54"
SDK = "bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd"
GDB = "0a7a6c0c020f1bb52054f89444aba5f2ba813b0ef4a1ff01f72ef97f7185d93c"
LIMIT, JSON_LIMIT = 2 << 20, 256 << 10
CASES = {
    "normal": ("TestNativeFixedStockGDBCalibration", "synthetic native hardware calibration completed; private retained attempt "),
    "cancel": ("TestNativeGDBCancellationAtValidatedHardwareHit", "fixed native cancellation detected and cleaned; calibration run remains nonpassing; private retained attempt "),
    "early-cancel": ("TestNativeGDBCancellationBeforeReadyCleansEarlyInferior", "fixed pre-READY cancellation retained actual early-inferior cleanup; experiment remains nonpassing; private attempt "),
    "pre-admission-cancel": ("TestNativeGDBPreAdmissionCancellationKeepsEarlyTargetHandle", "fixed pre-admission cancellation retained original target wait and all owned terminal cleanup; experiment remains nonpassing; private attempt "),
}
SOURCE = {
    ".gitignore": "8d1cf780e4633dca9740a025c1fba663663838f2a4a6f64c8d10de0971e6da45",
    "go.mod": "dbc200c448b9db988753c9e543b881f135555400a8f23f0c5e1e188d7baae88e",
    "go.sum": "5056407e3b8b9a63063af7ee77c4962d5db7aa7b35dadf20fc22b629245552ad",
    "cmd/hardware-wait-specimen/main.go": "430a34a7f3bf779a7a49730bd16e32e6cb81a474b512da273ef68099eecb72ed",
    "internal/hardwarecalibration/gdb_controller_linux.go": "e9cd476586869f312314b0aa81370c10c0f380217fff06ecfea7a27b19c9a796",
    "internal/hardwarecalibration/gdb_controller_linux_test.go": "50896e7384e102abd63c65d1d0312068b92db6b33af4751118b8c54ce6c55cc8",
    "internal/hardwarecalibration/gdb_presentation_linux.go": "c0a2ce754778be8af4e017a6518a4ccb414d4568a9ec32eae4bf95ee1786c83b",
    "internal/hardwarecalibration/gdb_presentation_linux_test.go": "e0eb920eb33b43b44f18f743b8d6bc93fd212ed884d1a0d70d9d729bc7f60a21",
    "internal/hardwarecalibration/wait_parent_linux.go": "8143eee406c75766e4007d8a4f4c93ae1424ae4a6075216cf023568213369ede",
    "internal/hardwarecalibration/wait_parent_other.go": "61cd89fd8395f7dcb13c0dbe3ea091ff53234c04275da23c6f4a795b326611f0",
    "internal/hardwarecalibration/wait_parent_test.go": "4fe4231e71b59a18fd7c8a196b3d5f43a1eb3ac4b03e7cdc86b1d06f9fb99389",
    "internal/hardwarecalibration/marker_thread_test.go": "d00eeb932fed041f10dbb53c7f8ef9538b59b3457b5364456f1f6ba6425bffaa",
}
HARDWARE = {name: 1 << 20 for name in ("mi.log", "gdb-stderr.bin", "inferior-tty.bin", "marker-stdout.txt", "marker-stderr.txt")}
HARDWARE.update({"controller-report.json": JSON_LIMIT, "controller-failures.json": JSON_LIMIT,
                 "parent-failures.json": JSON_LIMIT, "parent-receipts.json": 64 << 10,
                 "parent-fifo.bin": 64 << 10, "parent-commands.bin": 64 << 10, "PRIVATE.json": 4096})
FILES = ("errors.jsonl", "stdout.bin", "stderr.bin", "inputs.json", "wait.json", "result.json", "inventory.json")


def require(value):
    if not value:
        raise ValueError("fixed hardware calibration custody rejected")


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode() + b"\n"


def unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj)
        obj[key] = value
    return obj


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False))


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def directory(path):
    s = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode)
            and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700)


def read_file(path, maximum=JSON_LIMIT, mode=None, expected=None):
    require(path.resolve(strict=True) == path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
            and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum
            and (mode is None or stat.S_IMODE(before.st_mode) == mode))
    f, failures, raw = None, [], b""
    try:
        f = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK), "rb")
        require(signature(before) == signature(os.fstat(f.fileno())))
        raw = f.read(maximum + 1)
        require(len(raw) == before.st_size and signature(before) == signature(os.fstat(f.fileno()))
                and signature(before) == signature(path.lstat()))
    except BaseException as error:
        failures.append(error)
    finally:
        if f is not None:
            try:
                f.close()
            except BaseException as error:
                failures.append(error)
    if failures:
        raise RuntimeError("bounded private read/close:\n" + "".join(
            "".join(traceback.format_exception(type(e), e, e.__traceback__)) for e in failures))
    sha = hashlib.sha256(raw).hexdigest()
    require(expected is None or sha == expected)
    return raw, {"Path": str(path), "Bytes": len(raw), "SHA256": sha}


def write_file(f, raw):
    require(f.write(raw) == len(raw))
    os.fsync(f.fileno())


def close_file(f, record, sync=True):
    try:
        if sync:
            os.fsync(f.fileno())
    except BaseException as error:
        record(error)
    try:
        f.close()
    except BaseException as error:
        record(error)


def bind_inputs(root, run, expected):
    raw, _ = read_file(root / ".cache/hardware-gdb-caller-input.json", mode=0o600)
    require(hashlib.sha256(raw).hexdigest() == expected)
    m = decode(raw)
    require(set(m) == {"RunID", "Case", "RepoRoot", "SourceHead", "GuestName", "GuestMachineID", "CallerSHA256",
                       "TestSHA256", "TestBytes", "SpecimenSHA256", "SpecimenBytes", "BuildSHA256", "PlanSHA256", "AuditSHA256"})
    require(m["RunID"] == run and m["Case"] in CASES and m["RepoRoot"] == str(root) and m["SourceHead"] == HEAD
            and root == Path("/run/user/501") / ("kaferry-hardware-" + HEAD[:7] + "-" + run) / "source"
            and m["GuestName"] == "kaferry-lab-arm64-20261026" and m["GuestMachineID"] == "01M5XVQQ4GRX6H79K1SE76R0X1")
    for key in ("CallerSHA256", "TestSHA256", "SpecimenSHA256", "BuildSHA256", "PlanSHA256", "AuditSHA256"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{64}", m[key]))
    pins = dict(SOURCE)
    pins.update({".cache/run-hardware-calibration.py": m["CallerSHA256"],
                 ".cache/hardware-build/hardwarecalibration.test": m["TestSHA256"],
                 ".cache/hardware-build/hardware-wait-specimen": m["SpecimenSHA256"],
                 ".cache/hardware-build/build-binding.json": m["BuildSHA256"],
                 ".cache/hardware-gdb-calibration-plan.json": m["PlanSHA256"],
                 ".cache/hardware-gdb-audit/" + m["AuditSHA256"] + ".json": m["AuditSHA256"]})
    require(Path(__file__).absolute() == root / ".cache/run-hardware-calibration.py")
    bound, bodies = [], {}
    for name, sha in pins.items():
        body, meta = read_file(root / name, 32 << 20 if name.endswith((".test", "hardware-wait-specimen")) else JSON_LIMIT if name.endswith(".json") else 1 << 20,
                               0o600 if name.endswith(".json") else None, sha)
        bound.append(meta)
        bodies[name] = body
    for name, prefix in (("hardwarecalibration.test", "Test"), ("hardware-wait-specimen", "Specimen")):
        path = root / ".cache/hardware-build" / name
        body = bodies[".cache/hardware-build/" + name]
        require(type(m[prefix + "Bytes"]) is int and len(body) == m[prefix + "Bytes"] > 64
                and body[:6] == b"\x7fELF\x02\x01" and int.from_bytes(body[18:20], "little") == 183
                and path.stat().st_mode & 0o111)
    require(m["TestSHA256"] == "d1b22517cd90ecc1a58291ca0106892b2a29a02eeb634fdf85f23c90e8b17a9f" and m["TestBytes"] == 6582220
            and m["SpecimenSHA256"] == "29e4625a8061f78319114469cd3770fe5fe2767560a8664c8ab786d2fb1c5384" and m["SpecimenBytes"] == 3993134)
    build = decode(bodies[".cache/hardware-build/build-binding.json"])
    require(all(build.get(k) == v for k, v in {"SourceHead": HEAD, "GoVersion": "go1.26.0", "GOOS": "linux",
            "GOARCH": "arm64", "SDKArchiveSHA256": SDK, "TestSHA256": m["TestSHA256"], "SpecimenSHA256": m["SpecimenSHA256"]}.items()))
    plan = decode(bodies[".cache/hardware-gdb-calibration-plan.json"])
    require(set(plan) == {"RunID", "Nonce", "SpecimenPath", "SpecimenSHA256", "GDB", "CancelAtFirstHardwareHit", "CancelBeforeParentReady", "CancelBeforeMarkerAdmission"})
    require(plan["RunID"] == run and re.fullmatch(r"[0-9a-f]{64}", plan["Nonce"])
            and plan["SpecimenPath"] == str(root / ".cache/hardware-build/hardware-wait-specimen")
            and plan["SpecimenSHA256"] == m["SpecimenSHA256"] and plan["GDB"] == {
                "SHA256": GDB, "PackageVersion": "15.1-1ubuntu1~24.04.1", "SourceAuditSHA256": m["AuditSHA256"]})
    require(all(plan[key] is (m["Case"] == case) for key, case in (("CancelAtFirstHardwareHit", "cancel"),
                ("CancelBeforeParentReady", "early-cancel"), ("CancelBeforeMarkerAdmission", "pre-admission-cancel"))))
    return m, bound


def lower_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    require(all(value == resource.RLIM_INFINITY or value >= LIMIT for value in (soft, hard)))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    require(resource.getrlimit(resource.RLIMIT_FSIZE) == (LIMIT, LIMIT))


def native_platform():
    u = os.uname()
    require(os.getuid() == os.geteuid() == 501 and u.sysname == "Linux" and u.machine == "aarch64"
            and u.nodename == "kaferry-lab-arm64-20261026" and u.release == "7.0.14-orbstack-00380-ga7e0a2dc9535")


def wait_child(argv, root, env, out, err, record, budget=90):
    result = {"LaunchAttempted": False, "Started": False, "Waited": False, "CallerPID": os.getpid(), "PID": None, "ReturnCode": None, "Timeout": False}
    child, origin = None, time.monotonic_ns()
    try:
        result["LaunchAttempted"] = True
        child = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, close_fds=True)
        result.update(Started=True, PID=child.pid)
        result["ReturnCode"] = child.wait(timeout=budget)
        result["Waited"] = True
    except BaseException as error:
        result["Timeout"] = isinstance(error, subprocess.TimeoutExpired)
        record(error)
        if child is not None and isinstance(error, subprocess.TimeoutExpired):
            try:
                child.terminate()  # Only the actual direct child, never a group/inner PID.
                try:
                    result["ReturnCode"] = child.wait(timeout=5)
                except subprocess.TimeoutExpired as expired:
                    record(expired)
                    child.kill()  # Preselected escalation; a terminate refusal never reaches here.
                    result["ReturnCode"] = child.wait(timeout=5)
                result["Waited"] = True
            except BaseException as cleanup_error:
                record(cleanup_error)  # No alternate signal/wait facility.
    result["ElapsedNS"] = time.monotonic_ns() - origin
    return result


def witness(out, err, case, run):
    test, message = CASES[case]
    pattern = (r"=== RUN   " + re.escape(test) + r"\n    gdb_controller_linux_test\.go:[0-9]+: "
               + re.escape(message + run) + r"\n--- PASS: " + re.escape(test) + r" \([0-9]+\.[0-9]+s\)\nPASS\n")
    require(len(out) < LIMIT and not err and re.fullmatch(pattern.encode(), out))


def hardware_inventory(root, run, case):
    path = root / ".cache/hardware-wait-private" / run
    directory(path)
    names, fifos = set(os.listdir(path)), {"commands.fifo", "receipts.fifo"}
    optional = {"parent-failures.json", "parent-receipts.json"} if case == "early-cancel" else set()
    require(set(HARDWARE) - optional | fifos <= names <= set(HARDWARE) | fifos)
    rows = []
    for name in sorted(names):
        if name in fifos:
            s = (path / name).lstat()
            require(stat.S_ISFIFO(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600)
            rows.append({"Path": str(path / name), "FIFO": True, "Device": s.st_dev, "Inode": s.st_ino})
        else:
            raw, meta = read_file(path / name, HARDWARE[name], 0o600)
            require(name != "controller-report.json" or len(raw) > 0)
            rows.append(meta)
    require(sum(row.get("Bytes", 0) for row in rows) <= 6 << 20)
    return rows


def run_attempt(root, run, input_sha):
    directory(root / ".cache/hardware-outer-private")
    attempt = root / ".cache/hardware-outer-private" / run
    attempt.mkdir(mode=0o700)
    directory(attempt)
    files, state, result, code, wait = {}, {"Error": False, "Stopped": False, "Bytes": 0}, {}, 2, {"LaunchAttempted": False, "Started": False}
    def record(error):
        state["Error"] = True
        if state["Stopped"] or "errors.jsonl" not in files:
            return
        raw = encode({"Exception": repr(error), "Traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))})
        remaining = min(64 << 10, JSON_LIMIT - state["Bytes"])
        if remaining <= 0:
            state["Stopped"] = True
            return
        if len(raw) > remaining:
            raw, state["Stopped"] = raw[:remaining], True
        try:
            write_file(files["errors.jsonl"], raw)
            state["Bytes"] += len(raw)
        except BaseException:
            state["Stopped"] = True  # No alternate sink, original may be unavailable.
    try:
        for name in FILES:
            files[name] = os.fdopen(os.open(attempt / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600), "wb", buffering=0)
            s = os.fstat(files[name].fileno())
            require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600)
        native_platform()
        m, bound = bind_inputs(root, run, input_sha)
        directory(root / ".cache/hardware-wait-private")
        require(not os.path.lexists(root / ".cache/hardware-wait-private" / run))
        write_file(files["inputs.json"], encode({"InputSHA256": input_sha, "Input": m, "Bindings": bound}))
        lower_limit()  # Lower this one-shot process once; inherit, never restore/increase.
        argv = [str(root / ".cache/hardware-build/hardwarecalibration.test"), "-test.run=^" + CASES[m["Case"]][0] + "$",
                "-test.count=1", "-test.parallel=1", "-test.timeout=75s", "-test.v"]
        wait = wait_child(argv, root, {"LC_ALL": "C", "LAB_HARDWARE_GDB": "1", "LAB_HARDWARE_GDB_CASE": m["Case"]}, files["stdout.bin"], files["stderr.bin"], record)
        write_file(files["wait.json"], encode({"Argv": argv, **wait}))
        for name in ("stdout.bin", "stderr.bin", "inputs.json", "wait.json"):
            close_file(files.pop(name), record)
        require(wait["Waited"] and wait["ReturnCode"] == 0 and not wait["Timeout"] and not state["Error"])
        out, _ = read_file(attempt / "stdout.bin", LIMIT, 0o600)
        err, _ = read_file(attempt / "stderr.bin", LIMIT, 0o600)
        witness(out, err, m["Case"], run)
        require(bind_inputs(root, run, input_sha) == (m, bound))
        require(set(os.listdir(attempt)) == set(FILES))
        rows = hardware_inventory(root, run, m["Case"])
        result = {"RunID": run, "Case": m["Case"], "NormalCalibrationComplete": m["Case"] == "normal",
                  "CancellationControlDetected": m["Case"] != "normal", "ExperimentPassing": m["Case"] == "normal",
                  "ReleaseQualified": False, "Incomplete": False, "RequiresExternalWaitAndMacReadback": True}
        code = 0
    except BaseException as error:
        record(error)
    finally:
        for name in ("stdout.bin", "stderr.bin", "inputs.json", "wait.json"):
            if name in files:
                close_file(files.pop(name), record)
        if state["Error"]:
            code, result = 2, {"RunID": run, "ReleaseQualified": False, "Incomplete": True, "InnerCleanupUnresolved": wait["LaunchAttempted"]}
        try:
            if "result.json" in files:
                write_file(files["result.json"], encode(result))
        except BaseException as error:
            record(error)
        finally:
            if "result.json" in files:
                close_file(files.pop("result.json"), record)
        if "errors.jsonl" in files:
            close_file(files.pop("errors.jsonl"), lambda _: state.update(Error=True, Stopped=True), not state["Stopped"])
        try:
            if code == 0 and not state["Error"]:
                rows += [read_file(attempt / name, LIMIT if name.endswith(".bin") else JSON_LIMIT, 0o600)[1] for name in FILES if name != "inventory.json"]
                write_file(files["inventory.json"], encode({"RunID": run, "Files": rows, "OwnFinalCloseProven": False}))
        except BaseException:
            state["Error"] = True  # Primary already closed: no alternate sink.
        if "inventory.json" in files:
            close_file(files.pop("inventory.json"), lambda _: state.update(Error=True))
    return 2 if state["Error"] else code


def main(argv):
    require(len(argv) == 2 and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", argv[0]) and re.fullmatch(r"[0-9a-f]{64}", argv[1]))
    root = Path.cwd()
    require(root.resolve(strict=True) == root)
    return run_attempt(root, *argv)


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except BaseException:
        status = 2  # No public raw error or alternate sink before reservation.
    sys.exit(status)
