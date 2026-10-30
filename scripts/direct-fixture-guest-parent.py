#!/usr/bin/env python3
"""One fixed direct-fixture controller; private originals, not Mac custody.

The unchanged native-check parent supplies only its verified wait primitives.
Its native-check bind/run entry points are never called. No builder, arbitrary
command, fixture/image transport or qualification is selected by this script.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys
import traceback
import types

GUEST_ROOT = Path("/home/labrunner")
WAIT_SHA256 = "0bd893b00de5ad6dec81497af4cdae003f065081a46303dd7aa0925e304f52ab"
ENV = {"HOME": "/home/labrunner", "PATH": "/usr/local/go/bin:/usr/bin:/bin", "LC_ALL": "C"}
MACHINE, MACHINE_ID = "kaferry-lab-arm64-20261026", "01M5XVQQ4GRX6H79K1SE76R0X1"
SDK = "bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd"
MODULE = "github.com/pagrus7/kaferry-lab/cmd/direct-fixture-calibration"
JSON_LIMIT, INPUT_LIMIT, STREAM_LIMIT = 256 << 10, 1 << 20, 64 << 10
FILES = ("errors.jsonl", "stdout.bin", "stderr.bin", "inputs.json", "wait.json", "result.json", "inventory.json")
GO_FILES = {"errors.json": JSON_LIMIT, "inputs.json": INPUT_LIMIT, "up.json": JSON_LIMIT,
            "identity.json": JSON_LIMIT, "cleanup.json": JSON_LIMIT, "absence.json": JSON_LIMIT,
            "tree.json": JSON_LIMIT, "result.json": JSON_LIMIT, "result.pending.json": JSON_LIMIT}


def require(value):
    if not value:
        raise ValueError("fixed direct parent admission/custody rejected")


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
    # This bootstrap reader must precede loading the hash-bound wait module.
    require(path.resolve(strict=True) == path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == mode and 0 <= before.st_size <= maximum)
    f, failures, raw = None, [], b""
    try:
        f = os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK), "rb")
        require(signature(before) == signature(os.fstat(f.fileno())))
        raw = f.read(maximum + 1)
        require(len(raw) == before.st_size and signature(before) == signature(os.fstat(f.fileno())) == signature(path.lstat()))
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
    require(expected is None or digest(raw) == expected)
    return raw, {"Path": str(path), "Bytes": len(raw), "SHA256": digest(raw)}


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
    """Audited first-cause pattern, available before the fixed dependency read."""
    def __init__(self, f):
        self.file, self.failed, self.broken, self.closed, self.bytes = f, False, False, False, 0

    def record(self, error):
        self.failed = True
        if self.broken or self.closed:
            return
        body = encode({"Exception": repr(error), "Traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))})
        bound = min(STREAM_LIMIT, JSON_LIMIT - self.bytes)
        if bound <= 0:
            self.broken = True
            return
        try:
            write_file(self.file, body[:bound])
            self.bytes += min(bound, len(body))
        except BaseException:
            self.broken = True
        self.broken = self.broken or len(body) > bound

    def close(self):
        self.closed = True
        close_file(self.file, lambda _: setattr(self, "failed", True))


def parent_input(base, expected):
    raw, row = read_file(base / "parent-input.json", expected=expected)
    m = decode(raw)
    require(set(m) == {"Version", "RunID", "SourceHead", "GuestName", "GuestMachineID", "ControllerSHA256",
                       "ControllerBytes", "ControllerBuildSHA256", "GoInputSHA256", "ParentSHA256", "WaitPrimitivesSHA256"})
    require(m["Version"] == "1" and re.fullmatch(r"[a-z][a-z0-9-]{3,48}", m["RunID"])
            and re.fullmatch(r"[0-9a-f]{40}", m["SourceHead"]) and m["GuestName"] == MACHINE and m["GuestMachineID"] == MACHINE_ID
            and base == GUEST_ROOT / ("kaferry-direct-" + m["RunID"]))
    for key in ("ControllerSHA256", "ControllerBuildSHA256", "GoInputSHA256", "ParentSHA256", "WaitPrimitivesSHA256"):
        require(type(m[key]) is str and re.fullmatch(r"[0-9a-f]{64}", m[key]))
    require(m["WaitPrimitivesSHA256"] == WAIT_SHA256 and type(m["ControllerBytes"]) is int and 64 < m["ControllerBytes"] <= 32 << 20)
    return m, [row]


def bind_inputs(base, expected):
    m, bound = parent_input(base, expected)
    source, controller = base / "source", base / "controller"
    for path in (source, source / ".cache", source / "scripts", controller):
        directory(path)
    bodies = {}
    for path, sha, maximum, mode in (
        (controller / "direct-fixture-calibration", m["ControllerSHA256"], 32 << 20, 0o700),
        (controller / "controller-build.json", m["ControllerBuildSHA256"], JSON_LIMIT, 0o600),
        (source / ".cache/direct-fixture-input.json", m["GoInputSHA256"], INPUT_LIMIT, 0o600),
        (source / "scripts/direct-fixture-guest-parent.py", m["ParentSHA256"], 64 << 10, 0o600),
        (source / "scripts/native-check-guest-parent.py", WAIT_SHA256, 64 << 10, 0o600),
    ):
        body, row = read_file(path, maximum, mode, sha)
        bodies[path.name] = body
        bound.append(row)
    require(Path(__file__).absolute() == source / "scripts/direct-fixture-guest-parent.py")
    image = bodies["direct-fixture-calibration"]
    require(len(image) == m["ControllerBytes"] and image[:7] == b"\x7fELF\x02\x01\x01"
            and int.from_bytes(image[16:18], "little") in (2, 3) and int.from_bytes(image[18:20], "little") == 183)
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
    info, row = read_file(controller / "direct-fixture-calibration.buildinfo", 64 << 10, expected=build["BuildInfoSHA256"])
    bound.append(row)
    lines = info.decode().splitlines()
    required = {"\tpath\t" + MODULE, "\tbuild\tGOOS=linux", "\tbuild\tGOARCH=arm64", "\tbuild\tvcs=git",
                "\tbuild\tvcs.revision=" + m["SourceHead"], "\tbuild\tvcs.modified=false"}
    require(lines and lines[0].endswith(": go1.26.0") and required <= set(lines) and len(lines) == len(set(lines)))
    native = decode(bodies["direct-fixture-input.json"])
    require(set(native) == {"Version", "RunID", "SourceHead", "Repository", "GuestName", "GuestMachineID", "SDKArchiveSHA256",
                            "GoBinarySHA256", "ControllerSHA256", "ControllerBytes", "Files"})
    require(all(native.get(k) == v for k, v in {"Version": "1", "RunID": m["RunID"], "SourceHead": m["SourceHead"], "Repository": str(source),
            "GuestName": MACHINE, "GuestMachineID": MACHINE_ID, "SDKArchiveSHA256": SDK, "ControllerSHA256": m["ControllerSHA256"],
            "ControllerBytes": m["ControllerBytes"], "GoBinarySHA256": build["GoBinarySHA256"]}.items())
            and re.fullmatch(r"[0-9a-f]{64}", native["GoBinarySHA256"]))
    catalog, total, last = {}, 0, ""
    require(type(native["Files"]) is list and 7 <= len(native["Files"]) <= 1024)
    for file in native["Files"]:
        require(set(file) == {"Path", "SHA256", "Bytes", "Mode"})
        path = file["Path"]
        require(type(path) is str and path > last and str(PurePosixPath(path)) == path and not path.startswith("/")
                and not any(part in ("..", ".git", ".cache") for part in PurePosixPath(path).parts)
                and re.fullmatch(r"[0-9a-f]{64}", file["SHA256"]) and type(file["Bytes"]) is int and 0 <= file["Bytes"] <= 16 << 20
                and type(file["Mode"]) is int and file["Mode"] in (0o600, 0o700))
        catalog[path], last, total = file, path, total + file["Bytes"]
    require(total <= 16 << 20)
    for name, sha in {"scripts/direct-fixture-guest-parent.py": m["ParentSHA256"], "scripts/native-check-guest-parent.py": WAIT_SHA256}.items():
        require(catalog[name]["SHA256"] == sha and catalog[name]["Bytes"] == len(bodies[Path(name).name]) and catalog[name]["Mode"] == 0o600)
    for name in ("go.mod", "go.sum", "scripts/check.sh", "cmd/direct-fixture-calibration/main.go", "internal/campaign/direct_fixture_calibration.go", "internal/fixture/direct_absence.go", "internal/fixture/image_save.go"):
        require(name in catalog)
    # Whole source membership/hash and installed SDK are independently checked
    # by the admitted Go controller; approved HEAD/catalog provenance is external.
    return m, bound, bodies["native-check-guest-parent.py"]


def load_wait_primitives(source, raw):
    require(digest(raw) == WAIT_SHA256)
    module = types.ModuleType("fixed_direct_wait_primitives")
    module.__file__ = str(source / "scripts/native-check-guest-parent.py")
    # Fixed verified sibling only: no input-selected module/path/function. This
    # avoids SourceFileLoader bytecode writes into the admitted source tree.
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    require(module.__name__ != "__main__" and module.ENV == ENV
            and (module.WAIT_SECONDS, module.TERM_SECONDS, module.KILL_SECONDS, module.EOF_SECONDS) == (360, 30, 10, 2))
    return module


def fixed_argv(base, m):
    return [str(base / "controller/direct-fixture-calibration"), "--repository", str(base / "source"), "--run-id", m["RunID"],
            "--reviewed-head", m["SourceHead"], "--input-sha256", m["GoInputSHA256"]]


def producer_files(base, m, errors):
    """Retain every available fixed Go original, also on nonzero/partial runs."""
    root = base / "source/.cache/direct-fixture-calibration-private" / m["RunID"]
    rows, missing, bodies, names = [], [], {}, []
    try:
        directory(root)
        with os.scandir(root) as entries:
            for entry in entries:
                require(len(names) < len(GO_FILES) and entry.name in GO_FILES)
                names.append(entry.name)
        for name in sorted(GO_FILES):
            if name == "result.pending.json" and name not in names:
                continue
            try:
                body, row = read_file(root / name, GO_FILES[name])
                rows.append(row)
                bodies[name] = body
            except FileNotFoundError as error:
                missing.append({"Path": str(root / name), "Notice": repr(error)})
            except BaseException as error:
                errors.record(error)
    except BaseException as error:
        errors.record(error)
    result, inner_ok, profile, selected_tree = {}, False, None, None
    try:
        if "result.json" in bodies:
            result = decode(bodies["result.json"])
            require(all(result.get(k) == v for k, v in {"Version": "1", "Namespace": "calibration/native-direct-fixture", "RunID": m["RunID"],
                    "SourceHead": m["SourceHead"], "InputSHA256": m["GoInputSHA256"], "OwnFinalCloseProven": False, "ReleaseQualified": False,
                    "RequiresExternalWaitAndMacReadback": True, "ExternalImageOutletProfileImplemented": False,
                    "PlannedExternalImageMaximumBytes": 512 << 20, "PlannedExternalReceiptAggregateBytes": 32 << 20}.items()))
            require(all(result.get(k) is False for k in ("OwnFinalCloseProven", "ReleaseQualified", "ExternalImageOutletProfileImplemented"))
                    and result.get("RequiresExternalWaitAndMacReadback") is True)
            require(result["ImageArchive"] == str(base / "source/.cache/image-identity-data" / m["RunID"] / "images.tar"))
            tree = result["Tree"]
            inner_ok = result.get("NativeDirectFixturePassed") is True and result.get("Status") == "DIRECT_FIXTURE_PASSED_EXTERNAL_CUSTODY_REQUIRED"
            if inner_ok:
                require(set(bodies) == set(GO_FILES) - {"result.pending.json"})
                require(all(result.get(k) is True for k in ("Synthetic", "SourceAdmitted", "SourceUnchanged", "UpAttempted", "UpReturned", "ReloadReturned",
                        "IdentityAdmitted", "DownAttempted", "DownReturned", "CleanupSucceeded", "AbsenceAttempted", "ResourcesAbsent", "PriorPayloadFilesClosed")))
                require(all(tree.get(k) is True for k in ("SubreaperEnabled", "NoChildren", "Closed"))
                        and tree.get("ControlFailed") is False and tree.get("AnchorStarted") is False)
                adopted = tree.get("Adopted") or []
                require(type(adopted) is list and len(adopted) <= 16)
                for child in adopted:
                    require(type(child["PID"]) is int and child["PID"] > 1 and type(child["Status"]) is int
                            and child["Terminal"] is True and (os.WIFEXITED(child["Status"]) or os.WIFSIGNALED(child["Status"])))
                selected_tree = {"SubreaperEnabled": True, "Closed": True, "NoChildren": True, "Adopted": adopted}
                state = result["State"]
                require(state["run_id"] == m["RunID"] and state.get("proxy") is None and not state.get("worker_source") and not state.get("worker_destination"))
                identity = state["direct"]
                require(identity["RunID"] == m["RunID"] and re.fullmatch(r"[0-9a-f]{64}", identity["ManifestSHA256"])
                        and re.fullmatch(r"[0-9a-f]{64}", identity["NetworkID"])
                        and len(identity["BrokerIDs"]) == 2 and identity["BrokerIDs"][0] != identity["BrokerIDs"][1]
                        and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in identity["BrokerIDs"])
                        and identity["Image"]["Mode"] == "native-arm64-manifest-v1" and re.fullmatch(r"[0-9a-f]{64}", identity["Image"]["ProofSHA256"]))
                image = identity["Image"]
                require(image["RuntimeImageID"] == "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02"
                        and image["ConfigDigest"] == "sha256:5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f"
                        and image["Manifest"] == {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", "size": 2201,
                            "platform": {"os": "linux", "architecture": "arm64"}})
                profile = {key: identity[key] for key in ("RunID", "ManifestSHA256", "NetworkID", "BrokerIDs", "Image")}
            # No image body is read here: its <=512MiB stream and the <=32MiB
            # fixture-original profile require separate future transport/readback.
    except BaseException as error:
        errors.record(error)
        inner_ok = False
        result = {}
        profile, selected_tree = None, None
    return rows, missing, {"InnerStatus": result.get("Status"), "InnerClaimConsistent": inner_ok,
                           "InnerTreeAndFixtureFactsAreControllerClaims": True, "ImageHashVerifiedHere": False,
                           "Profile": profile, "Tree": selected_tree,
                           "ProducerInventoryComplete": bool(rows) and not missing and len(rows) == len(names)}


def run_attempt(base, expected):
    directory(base)
    attempt = base / "parent-private"
    attempt.mkdir(mode=0o700)
    directory(attempt)
    errors = Errors(create(attempt / "errors.jsonl"))
    files, handlers, cancelled = {}, {}, [False, False]
    wait, bound, rows, missing, inner, m, kernel = {}, [], [], [], {}, None, None
    corroborated = False
    def cancel(_number, _frame):
        cancelled[0] = True
    def observe():
        if cancelled[0] and not cancelled[1]:
            cancelled[1] = True
            errors.record(InterruptedError("parent cancellation requested"))
        return cancelled[0]
    try:
        for name in FILES[1:]:
            files[name] = create(attempt / name)
        for value in (signal.SIGTERM, signal.SIGINT):
            handlers[value] = signal.signal(value, cancel)
        m, bound, raw = bind_inputs(base, expected)
        kernel = load_wait_primitives(base / "source", raw)
        kernel.native_platform()
        require(not observe() and set(os.listdir(base / "source/.cache")) == {"direct-fixture-input.json"})
        write_file(files["inputs.json"], encode({"ParentInputSHA256": expected, "Input": m, "Bindings": bound,
                   "ExternalApprovedHeadAndMachineBindingRequired": True}))
        argv = fixed_argv(base, m)
        wait = kernel.wait_controller(argv, base / "source", files["stdout.bin"], files["stderr.bin"], errors.record, cancelled)
        write_file(files["wait.json"], encode({"Argv": argv, "GuestParentPID": os.getpid(), **wait}))
    except BaseException as error:
        errors.record(error)
    finally:
        for name in ("stdout.bin", "stderr.bin", "inputs.json", "wait.json"):
            if name in files:
                close_file(files.pop(name), errors.record)
        observe()
        if m is not None and wait.get("Waited"):
            try:
                require(bind_inputs(base, expected)[:2] == (m, bound))
            except BaseException as error:
                errors.record(error)
            try:
                rows, missing, inner = producer_files(base, m, errors)
            except BaseException as error:
                errors.record(error)
        observe()
        corroborated = (not errors.failed and wait.get("Waited") is True and wait.get("ReturnCode") == 0
                        and wait.get("OutputComplete") is True and not wait.get("Timeout") and inner.get("InnerClaimConsistent") is True)
        for value, handler in handlers.items():
            try:
                signal.signal(value, handler)
            except BaseException as error:
                errors.record(error)
        observe()
        result = {"Version": "1", "Namespace": "calibration/direct-fixture-parent", "RunID": m.get("RunID") if m else None,
                  "Status": "CONTROLLER_RETURN_CORROBORATED_EXTERNAL_CUSTODY_REQUIRED" if corroborated and not errors.failed else "INCOMPLETE",
                  "ControllerReturnCorroborated": corroborated and not errors.failed,
                  "ControllerLaunchAttempted": wait.get("LaunchAttempted", False), "ControllerWaited": wait.get("Waited", False),
                  "PrimaryErrorSinkBroken": errors.broken, "OwnFinalCloseProven": False,
                  "RequiresExternalReturnAndMacReadback": True, "ExternalImageOutletProfileImplemented": False, "ReleaseQualified": False,
                  "Inner": inner}
        if "result.json" in files:
            try:
                write_file(files["result.json"], encode(result))
            except BaseException as error:
                errors.record(error)
            close_file(files.pop("result.json"), errors.record)
        observe()
        errors.close()
        observe()
        # Inventory is pre-reserved, even failure/constructor/nonzero prefixes
        # get hashes. It is never an alternate raw error sink or its own close proof.
        if "inventory.json" in files:
            try:
                originals = [read_file(attempt / name, STREAM_LIMIT if name.endswith(".bin") else JSON_LIMIT)[1]
                             for name in FILES if name != "inventory.json"]
                write_file(files["inventory.json"], encode({"ParentFiles": originals, "ProducerFiles": rows, "MissingProducerFiles": missing,
                           "ProducerInventoryComplete": inner.get("ProducerInventoryComplete", False), "OwnFinalCloseProven": False,
                           "ProducerInventoryAttemptedAfterActualWait": wait.get("Waited", False),
                           "RequiresExternalReturnAndMacReadback": True, "ImageBodyIncluded": False, "FixtureOriginalTreeIncluded": False,
                           "ExternalImageOutletProfileImplemented": False}))
            except BaseException:
                errors.failed = True
            close_file(files.pop("inventory.json"), lambda _: setattr(errors, "failed", True))
        observe()
    return 0 if corroborated and not errors.failed and not cancelled[0] else 2


def main(argv):
    require(len(argv) == 4 and argv[0] == "--input" and argv[2] == "--input-sha256" and re.fullmatch(r"[0-9a-f]{64}", argv[3]))
    path = Path(argv[1])
    require(path.is_absolute() and path.name == "parent-input.json" and path.parent.parent == GUEST_ROOT
            and re.fullmatch(r"kaferry-direct-[a-z][a-z0-9-]{3,48}", path.parent.name))
    return run_attempt(path.parent, argv[3])


if __name__ == "__main__":
    try:
        status = main(sys.argv[1:])
    except BaseException:
        status = 2  # unavailable first/final sink has no replacement/public traceback
    sys.exit(status)
