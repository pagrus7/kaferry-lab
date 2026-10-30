#!/usr/bin/env python3
"""Actual inert-child connection controls; no Go, Docker or native fixture.

ELF/build/source/inner-result records are visibly literal calibration DATA.
Only Popen/sole Wait/EOF/private retention observations are actual here. The
production parent has no inert command, environment, handle or timeout input.
"""
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True  # test-only; do not create source-tree bytecode
SCRIPT = Path(__file__).resolve().with_name("direct-fixture-guest-parent.py")
WAIT_SCRIPT = SCRIPT.with_name("native-check-guest-parent.py")
spec = importlib.util.spec_from_file_location("direct_parent_under_test", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_POPEN = subprocess.Popen
EVIDENCE_ROOT = None
MAX_CASES, MAX_CASE_ENTRIES, MAX_DEPTH = 64, 128, 12
CASE_LIMIT, FILE_LIMIT, RUN_LIMIT = 4 << 20, 1 << 20, 64 << 20


def evidence_root():
    """One exclusive ignored invocation root; never delete prior measurements."""
    global EVIDENCE_ROOT
    if EVIDENCE_ROOT is None:
        storage = SCRIPT.parents[1] / ".cache/direct-fixture-parent-controls"
        storage.mkdir(mode=0o700, parents=True, exist_ok=True)
        m.directory(storage)
        EVIDENCE_ROOT = Path(tempfile.mkdtemp(prefix="run-", dir=storage)).resolve()
        marker = {"Scope": "inert actual-child controls; no Go/Docker/native fixture", "TestProcessPID": os.getpid(),
                  "ScriptSHA256": m.digest(Path(__file__).read_bytes()), "ParentSHA256": m.digest(SCRIPT.read_bytes()),
                  "WaitPrimitivesSHA256": m.digest(WAIT_SCRIPT.read_bytes()), "MaximumCases": MAX_CASES,
                  "CaseByteGuard": CASE_LIMIT, "RunByteGuard": RUN_LIMIT, "PublicationAuthorized": False}
        with (EVIDENCE_ROOT / "RUN.json").open("xb") as f:
            os.chmod(f.name, 0o600)
            f.write(m.encode(marker)); f.flush(); os.fsync(f.fileno())
    return EVIDENCE_ROOT


def admit_case(root):
    m.directory(root)
    cases, entries, total = 0, 0, 0
    for path in root.iterdir():
        if path.name != "RUN.json": cases += 1
    m.require(cases < MAX_CASES)
    for current, dirs, files in os.walk(root, followlinks=False):
        parent = Path(current)
        m.require(len(parent.relative_to(root).parts) <= MAX_DEPTH + 1)
        for name in dirs + files:
            info = (parent / name).lstat()
            entries += 1
            m.require(entries <= MAX_CASES * (MAX_CASE_ENTRIES + 1) and not stat.S_ISLNK(info.st_mode))
            if (parent / name).is_file(): total += info.st_size
    # Admission guards only, not a filesystem quota or an allocated reserve.
    m.require(total <= RUN_LIMIT - CASE_LIMIT - m.JSON_LIMIT)


class DirectParentControls(unittest.TestCase):
    def patch(self, obj, name, value):
        patch = mock.patch.object(obj, name, value)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)

    def setUp(self):
        storage = evidence_root()
        admit_case(storage)
        label = getattr(self, "evidence_label", self._testMethodName)
        prefix = "case-" + "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:96] + '-"quoted"-'
        self.scope = Path(tempfile.mkdtemp(prefix=prefix, dir=storage)).resolve()
        # Registered first: this runs after fixture-owned reconciliation, all
        # monkeypatch restoration and descriptor cleanup even on failed tests.
        self.addCleanup(self.retain_case_evidence)
        self.base = self.scope / "kaferry-direct-inert"
        self.base.mkdir(mode=0o700)
        self.source, self.build = self.base / "source", self.base / "controller"
        # parents=True applies mode only to the leaf. Create every owned
        # intermediate explicitly so the later custody check observes 0700.
        for path in (self.source, self.source / ".cache", self.source / "scripts", self.source / "cmd",
                     self.source / "cmd/direct-fixture-calibration", self.source / "internal",
                     self.source / "internal/campaign", self.source / "internal/fixture", self.build):
            path.mkdir(mode=0o700)
        self.run, self.head = "inert", "a" * 40
        self.calls, self.waits, self.signals, self.children = [], [], [], []
        self.notify_r, self.notify_w = os.pipe()
        self.addCleanup(os.close, self.notify_r)
        self.addCleanup(os.close, self.notify_w)
        self.addCleanup(self.reap_fixture_children)
        self.write(self.source / "scripts/direct-fixture-guest-parent.py", SCRIPT.read_bytes())
        self.write(self.source / "scripts/native-check-guest-parent.py", WAIT_SCRIPT.read_bytes())
        for name in ("go.mod", "go.sum", "scripts/check.sh", "cmd/direct-fixture-calibration/main.go",
                     "internal/campaign/direct_fixture_calibration.go", "internal/fixture/direct_absence.go", "internal/fixture/image_save.go"):
            path = self.source / name
            self.write(path, b"INERT SOURCE CATALOG DATA ONLY\n")
        image = bytearray(80)
        image[:7], image[16:18], image[18:20] = b"\x7fELF\x02\x01\x01", b"\x02\x00", b"\xb7\x00"
        image[64:] = b"INERT IMAGE DATA!"
        self.write(self.build / "direct-fixture-calibration", image, 0o700)
        self.info = ("INERT direct-fixture-calibration: go1.26.0\n\tpath\t" + m.MODULE + "\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=arm64\n"
                     "\tbuild\tvcs=git\n\tbuild\tvcs.revision=" + self.head + "\n\tbuild\tvcs.modified=false\n").encode()
        self.write(self.build / "direct-fixture-calibration.buildinfo", self.info)
        self.build_claim = {"Version": "1", "SourceHead": self.head, "SourceCleanBefore": True, "SourceCleanAfter": True,
                            "GoVersion": "go1.26.0", "GOOS": "linux", "GOARCH": "arm64", "SDKArchiveSHA256": m.SDK,
                            "GoBinarySHA256": "b" * 64, "ControllerSHA256": m.digest(image), "ControllerBytes": len(image),
                            "BuildInfoSHA256": m.digest(self.info), "CompilerWait": {"PID": 123, "WaitReturned": True, "ExitCode": 0}, "ReleaseQualified": False}
        self.write(self.build / "controller-build.json", m.encode(self.build_claim))
        catalog = [{"Path": str(path.relative_to(self.source)), "Bytes": path.stat().st_size, "SHA256": m.digest(path.read_bytes()), "Mode": 0o600}
                   for path in sorted(self.source.rglob("*")) if path.is_file()]
        go_input = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "Repository": str(self.source), "GuestName": m.MACHINE,
                    "GuestMachineID": m.MACHINE_ID, "SDKArchiveSHA256": m.SDK, "GoBinarySHA256": "b" * 64,
                    "ControllerSHA256": m.digest(image), "ControllerBytes": len(image), "Files": catalog}
        self.write(self.source / ".cache/direct-fixture-input.json", m.encode(go_input))
        self.input = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "GuestName": m.MACHINE, "GuestMachineID": m.MACHINE_ID,
                      "ControllerSHA256": m.digest(image), "ControllerBytes": len(image), "ControllerBuildSHA256": m.digest(m.encode(self.build_claim)),
                      "GoInputSHA256": m.digest(m.encode(go_input)), "ParentSHA256": m.digest(SCRIPT.read_bytes()), "WaitPrimitivesSHA256": m.WAIT_SHA256}
        self.write(self.base / "parent-input.json", m.encode(self.input))
        self.patch(m, "GUEST_ROOT", self.scope)
        self.patch(m, "__file__", str(self.source / "scripts/direct-fixture-guest-parent.py"))
        self.kernel = None
        actual_load = m.load_wait_primitives
        def load(source, raw):
            kernel = actual_load(source, raw)  # execute the actual hash-bound loader
            self.kernel = kernel
            kernel.native_platform = lambda: None  # explicit inert platform seam
            kernel.WAIT_SECONDS, kernel.TERM_SECONDS, kernel.KILL_SECONDS, kernel.EOF_SECONDS = 1.0, 0.15, 0.3, 0.04
            kernel.open_child_handle = lambda _: os.dup(self.notify_r)
            kernel.signal_child = lambda handle, number: self.signals.append((handle, number))
            kernel.subprocess.Popen = self.launch
            return kernel
        self.patch(m, "load_wait_primitives", load)
        # subprocess is a shared standard module. Restore it explicitly after
        # fixture reaping, without changing the selected production waiter.
        self.addCleanup(setattr, subprocess, "Popen", REAL_POPEN)
        self.helper = self.base / "inert-child.py"
        self.producer()

    def retain_case_evidence(self):
        rows, total, entries, failure = [], 0, 0, None
        relative, operation, observed = Path("."), "enumerate case", None
        try:
            for path in self.scope.rglob("*"):
                entries += 1
                relative = path.relative_to(self.scope)
                operation, observed = "entry count/depth", None
                m.require(entries <= MAX_CASE_ENTRIES and len(relative.parts) <= MAX_DEPTH)
                operation = "lstat"
                before = path.lstat()
                observed = {"UID": before.st_uid, "Mode": oct(stat.S_IMODE(before.st_mode)),
                            "Type": oct(stat.S_IFMT(before.st_mode)), "Links": before.st_nlink, "Bytes": before.st_size}
                operation = "owned nonsymlink entry"
                m.require(before.st_uid == os.geteuid() and not stat.S_ISLNK(before.st_mode))
                if stat.S_ISDIR(before.st_mode):
                    operation = "directory mode must be 0700"
                    m.require(stat.S_IMODE(before.st_mode) == 0o700)
                    continue
                operation = "regular single-link file mode/size"
                m.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= FILE_LIMIT
                          and stat.S_IMODE(before.st_mode) in (0o600, 0o700))
                operation = "stable bounded file read"
                body, _ = m.read_file(path, FILE_LIMIT, stat.S_IMODE(before.st_mode))
                m.require(len(body) == before.st_size and m.signature(before) == m.signature(path.lstat()))
                total += len(body)
                operation = "case byte guard"
                m.require(total <= CASE_LIMIT)
                rows.append({"Path": str(relative), "Bytes": len(body), "SHA256": m.digest(body), "OriginalSignature": m.signature(before)})
                operation = "enumerate next entry"
        except BaseException as error:
            failure = {"Path": str(relative)[:2048], "Operation": operation, "Observed": observed, "Exception": repr(error)[:2048]}
        outcome = getattr(self, "_outcome", None)
        result = getattr(outcome, "result", None)
        failed = result is not None and any(test is self for test, _ in result.failures + result.errors)
        observation = {"Case": self.id(), "Label": getattr(self, "evidence_label", self._testMethodName), "TestProcessPID": os.getpid(),
                       "Verdict": "FAILED" if failed else "SEE_TEST_TRANSCRIPT" if result is not None else "MANUAL_SUBCASE_NO_OWN_VERDICT",
                       "ActualFixturePIDs": [child.pid for child in getattr(self, "children", [])],
                       "OriginalParentWaitCalls": list(getattr(self, "waits", [])), "FixtureReturnCodesAfterReconciliation": [child.returncode for child in getattr(self, "children", [])],
                       "FixtureReconciliationDoesNotUpgradeOriginalParent": True, "Files": rows, "PayloadBytes": total,
                       "InventoryComplete": failure is None, "InventoryError": failure, "PublicationAuthorized": False}
        body = m.encode(observation)
        m.require(len(body) <= m.JSON_LIMIT)
        with (self.scope / "CASE-EVIDENCE.json").open("xb") as f:
            os.chmod(f.name, 0o600)
            f.write(body); f.flush(); os.fsync(f.fileno())
        if failure is not None:
            raise AssertionError("bounded inert case evidence incomplete; originals retained: " + repr(failure))

    def producer(self, body="os.write(1,b'\\x00\\xffexact');os.write(2,b'\\xfeerror')", exit_code=0, inner=True):
        # Literal inner candidate cannot establish Go/Docker/fixture success;
        # the actual child only exercises the outer Wait and retention path.
        result = {"Version": "1", "Namespace": "calibration/native-direct-fixture", "RunID": self.run, "SourceHead": self.head,
                  "InputSHA256": self.input["GoInputSHA256"], "Status": "DIRECT_FIXTURE_PASSED_EXTERNAL_CUSTODY_REQUIRED", "Synthetic": True,
                  "NativeDirectFixturePassed": True, "OwnFinalCloseProven": False, "ReleaseQualified": False,
                  "RequiresExternalWaitAndMacReadback": True, "ExternalImageOutletProfileImplemented": False,
                  "PlannedExternalImageMaximumBytes": 512 << 20, "PlannedExternalReceiptAggregateBytes": 32 << 20,
                  "ImageArchive": str(self.source / ".cache/image-identity-data" / self.run / "images.tar"),
                  "Tree": {"SubreaperEnabled": True, "NoChildren": True, "Closed": True, "ControlFailed": False, "AnchorStarted": False},
                  "State": {"run_id": self.run, "direct": {"RunID": self.run, "ManifestSHA256": "f" * 64, "NetworkID": "d" * 64, "BrokerIDs": ["a" * 64, "b" * 64],
                            "Image": {"Mode": "native-arm64-manifest-v1", "ProofSHA256": "e" * 64,
                                "RuntimeImageID": "sha256:05b4616e0702ef2729327705d54ad6b50ea70b271c4b730fabd2320789fb7b02",
                                "ConfigDigest": "sha256:5b8b0495077ca724c06b253f7d94ed27a36a3211c6c6e84ff54a758f109d3d0f",
                                "Manifest": {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "digest": "sha256:ddc235acd57d0fec5b21eedd46dcaf4e89a7569ff1c9890c5597c6d9561c59b0", "size": 2201,
                                    "platform": {"os": "linux", "architecture": "arm64"}}}}}}
        for key in ("SourceAdmitted", "SourceUnchanged", "UpAttempted", "UpReturned", "ReloadReturned", "IdentityAdmitted", "DownAttempted", "DownReturned",
                    "CleanupSucceeded", "AbsenceAttempted", "ResourcesAbsent", "PriorPayloadFilesClosed"):
            result[key] = True
        code = "import os,pathlib,time,sys,json\n"
        code += "p=pathlib.Path(" + repr(str(self.base / "actual-body.json")) + ");p.write_text(json.dumps({'PID':os.getpid(),'Environment':dict(os.environ)}));p.chmod(0o600)\n"
        if inner:
            code += "p=pathlib.Path(" + repr(str(self.source / ".cache/direct-fixture-calibration-private" / self.run)) + ");p.parent.mkdir(mode=0o700);p.mkdir(mode=0o700)\n"
            for name in m.GO_FILES:
                if name != "result.pending.json":
                    code += "(p/" + repr(name) + ").write_bytes(" + repr(m.encode(result) if name == "result.json" else b"{}\n") + ");(p/" + repr(name) + ").chmod(0o600)\n"
        code += body + "\nos.write(" + str(self.notify_w) + ",b'x');os._exit(" + str(exit_code) + ")\n"
        self.write(self.helper, code.encode())

    def launch(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        self.assertEqual(argv, m.fixed_argv(self.base, self.input))
        self.assertEqual(kwargs["env"], m.ENV)
        self.assertNotIn("shell", kwargs)
        kwargs["pass_fds"] = (self.notify_w,)
        child = REAL_POPEN([sys.executable, "-S", "-B", str(self.helper)], **kwargs)
        self.children.append(child)
        self.write(self.base / ("actual-fixture-launch-" + str(child.pid) + ".json"), m.encode({"PID": child.pid, "ParentPID": os.getpid(), "Waited": False,
                   "SyntheticInertChild": True, "ProductionRequestedArgv": argv, "SuppliedEnvironment": kwargs["env"]}))
        actual_wait = child.wait
        child._fixture_wait = actual_wait
        def waited(*args, **kw):
            self.waits.append(child.pid)
            return actual_wait(*args, **kw)
        child.wait = waited
        return child

    def reap_fixture_children(self):
        for child in self.children:
            # A separate fixture owner accounts for constructor/denied-Wait
            # specimens; this never changes the original parent's false facts.
            if child.returncode is None:
                child.wait = child._fixture_wait
                if child.stdout.closed and child.stderr.closed:
                    child.wait(timeout=3)
                    out, err = b"", b""
                else:
                    out, err = child.communicate(timeout=3)
                self.write(self.base / ("independent-fixture-wait-" + str(child.pid) + ".json"), m.encode({"PID": child.pid, "Waited": True, "ReturnCode": child.returncode,
                           "Stdout": out.hex(), "Stderr": err.hex(), "OriginalParentUpgraded": False}))

    def run_parent(self):
        return m.run_attempt(self.base, m.digest((self.base / "parent-input.json").read_bytes()))

    def saved(self, name):
        return (self.base / "parent-private" / name).read_bytes()

    def test_actual_child_wait_corroborates_only_literal_inner_claim(self):
        self.assertEqual(self.run_parent(), 0)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Waited"] and wait["StdoutEOF"] and wait["StderrEOF"] and wait["OutputComplete"])
        self.assertEqual(wait["PID"], m.decode((self.base / "actual-body.json").read_bytes())["PID"])
        self.assertEqual(self.waits, [wait["PID"]])
        self.assertEqual(self.saved("stdout.bin"), b"\x00\xffexact")
        self.assertEqual(self.saved("stderr.bin"), b"\xfeerror")
        result, inventory = m.decode(self.saved("result.json")), m.decode(self.saved("inventory.json"))
        self.assertTrue(result["ControllerReturnCorroborated"])
        self.assertTrue(result["Inner"]["InnerTreeAndFixtureFactsAreControllerClaims"])
        self.assertFalse(result["OwnFinalCloseProven"] or result["ReleaseQualified"] or result["ExternalImageOutletProfileImplemented"] or result["Inner"]["ImageHashVerifiedHere"])
        self.assertTrue(inventory["ProducerInventoryComplete"])
        self.assertFalse(inventory["ImageBodyIncluded"])
        self.assertEqual(self.signals, [])
        self.assertFalse(any(self.source.rglob("__pycache__")))

    def test_source_dependency_controller_and_module_refuse_before_spawn(self):
        # Given fixed admission, When one bound program/source fact changes,
        # Then the initial private sink retains the refusal and launch is absent.
        for fault in ("dependency", "controller", "source-head", "wrong-module", "import-refusal"):
            with self.subTest(fault=fault):
                case = DirectParentControls("test_actual_child_wait_corroborates_only_literal_inner_claim")
                case.evidence_label = "admission-" + fault
                case.setUp()
                try:
                    if fault == "dependency":
                        marker = case.base / "dependency-executed"
                        case.write(case.source / "scripts/native-check-guest-parent.py", ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('MUST NEVER EXECUTE')\n").encode())
                    if fault == "controller": case.write(case.build / "direct-fixture-calibration", b"foreign", 0o700)
                    if fault == "source-head":
                        case.input["SourceHead"] = "f" * 40; case.write(case.base / "parent-input.json", m.encode(case.input))
                    if fault == "wrong-module":
                        info = case.info.replace(m.MODULE.encode(), b"github.com/pagrus7/kaferry-lab/cmd/native-check")
                        case.write(case.build / "direct-fixture-calibration.buildinfo", info)
                        case.build_claim["BuildInfoSHA256"] = m.digest(info)
                        case.write(case.build / "controller-build.json", m.encode(case.build_claim))
                        case.input["ControllerBuildSHA256"] = m.digest(m.encode(case.build_claim))
                        case.write(case.base / "parent-input.json", m.encode(case.input))
                    if fault == "import-refusal":
                        patch = mock.patch.object(m, "compile", side_effect=ImportError("SYNTHETIC fixed dependency import refusal"), create=True)
                        patch.start(); case.addCleanup(patch.stop)
                    self.assertEqual(case.run_parent(), 2)
                    self.assertEqual(case.calls, [])
                    self.assertFalse((case.base / "dependency-executed").exists())
                    self.assertTrue(case.saved("errors.jsonl"))
                    self.assertTrue(case.saved("inventory.json"))
                finally:
                    case.doCleanups()

    def test_extra_argv_is_not_an_arbitrary_runner(self):
        with self.assertRaises(ValueError):
            m.main(["--input", str(self.base / "parent-input.json"), "--input-sha256", m.digest((self.base / "parent-input.json").read_bytes()), "--command", "foreign"])
        self.assertEqual(self.calls, [])

    def test_first_sink_failure_has_no_alternate_or_spawn(self):
        called = []
        def refused(path):
            called.append(path.name)
            raise PermissionError(errno.EACCES, "SYNTHETIC first sink refusal")
        self.patch(m, "create", refused)
        with self.assertRaises(PermissionError): self.run_parent()
        self.assertEqual(called, ["errors.jsonl"])
        self.assertEqual(self.calls, [])
        self.assertEqual(list((self.base / "parent-private").iterdir()), [])

    def test_reused_attempt_keeps_originals_and_cannot_launch_again(self):
        self.assertEqual(self.run_parent(), 0)
        original = self.saved("result.json")
        with self.assertRaises(FileExistsError): self.run_parent()
        self.assertEqual(self.saved("result.json"), original)
        self.assertEqual(len(self.calls), 1)

    def test_actual_nonzero_and_missing_inner_keep_originals_and_inventory(self):
        self.producer("os.write(1,b'PASS\\x00\\xff')", exit_code=7, inner=False)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Waited"])
        self.assertEqual(wait["ReturnCode"], 7)
        self.assertEqual(self.saved("stdout.bin"), b"PASS\x00\xff")
        self.assertTrue(self.saved("inventory.json"))
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])

    def test_actual_postlaunch_constructor_uncertainty_is_not_retried(self):
        actual = self.launch
        def uncertain(*args, **kwargs):
            actual(*args, **kwargs)
            raise OSError(errno.EIO, "SYNTHETIC constructor threw after actual launch")
        self.patch(self, "launch", uncertain)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["LaunchUncertain"])
        self.assertFalse(wait["Waited"])
        self.assertEqual(len(self.children), 1)
        self.assertEqual(self.waits, [])
        self.assertTrue(self.saved("inventory.json"))

    def test_actual_denied_wait_has_no_second_wait_or_postwait_signal(self):
        actual = self.launch
        def denied(*args, **kwargs):
            child = actual(*args, **kwargs)
            def refuse(*unused, **ignored):
                self.waits.append(child.pid)
                raise PermissionError(errno.EPERM, "SYNTHETIC selected Wait refusal")
            child.wait = refuse
            return child
        self.patch(self, "launch", denied)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["WaitAttempted"])
        self.assertFalse(wait["Waited"])
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])
        self.assertIn(b"selected Wait refusal", self.saved("errors.jsonl"))

    def test_actual_output_private_write_failure_keeps_prefix_incomplete(self):
        actual_create = m.create
        class RefusedOutput:
            def __init__(self, f): self.f = f
            def __getattr__(self, key): return getattr(self.f, key)
            def write(self, body):
                self.f.write(body[:1])
                raise OSError(errno.EIO, "SYNTHETIC output write failed after prefix")
        def create(path):
            f = actual_create(path)
            return RefusedOutput(f) if path.name == "stdout.bin" else f
        self.patch(m, "create", create)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        # The audited waiter reports the current write flag, not a sticky
        # history: a later successful stderr write may clear it. The exact EIO,
        # unknown stdout count/prefix and failed EOF/capture are the oracle.
        self.assertTrue(wait["Waited"])
        self.assertEqual(wait["ReturnCode"], 0)
        self.assertFalse(wait["OutputComplete"])
        self.assertFalse(wait["StdoutEOF"])
        self.assertEqual(wait["CapturedStdoutBytes"], 0)
        self.assertEqual(self.saved("stdout.bin"), b"\x00")
        causes = [m.decode(raw)["Exception"] for raw in self.saved("errors.jsonl").splitlines()]
        self.assertEqual(causes, ["OSError(5, 'SYNTHETIC output write failed after prefix')"])
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])
        self.assertEqual(len(self.waits), 1)

    def cancel_after_wait(self):
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.children[0].returncode, 0)
        self.handler(signal.SIGINT, None)
        self.handler(signal.SIGINT, None)

    def test_actual_postwait_and_serialized_candidate_cancellation(self):
        # Reached actual Wait is kept; repeated late delivery has one cause and
        # never obtains another signal/Wait or rewrites a closed candidate.
        actual = m.producer_files
        def producer(*args):
            result = actual(*args)
            self.handler = signal.getsignal(signal.SIGINT)
            self.cancel_after_wait()
            return result
        self.patch(m, "producer_files", producer)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.signals, [])
        causes = [m.decode(raw)["Exception"] for raw in self.saved("errors.jsonl").splitlines()]
        self.assertEqual(causes, ["InterruptedError('parent cancellation requested')"])

    def test_late_result_write_and_final_close_cannot_authorize_success(self):
        actual_producer, actual_write = m.producer_files, m.write_file
        def producer(*args):
            result = actual_producer(*args)
            self.handler = signal.getsignal(signal.SIGINT)
            return result
        def write(f, raw):
            actual_write(f, raw)
            if b'"Namespace": "calibration/direct-fixture-parent"' in raw: self.cancel_after_wait()
        self.patch(m, "producer_files", producer)
        self.patch(m, "write_file", write)
        self.assertEqual(self.run_parent(), 2)
        self.assertTrue(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])
        self.assertTrue(self.saved("inventory.json"))

    def test_actual_last_error_sink_close_failure_rejects_unchanged_candidate(self):
        actual_create = m.create
        closed = []
        class CloseFailed:
            def __init__(self, f): self.f = f
            def __getattr__(self, name): return getattr(self.f, name)
            def close(self):
                self.f.close()
                closed.append(True)
                raise OSError(errno.EIO, "SYNTHETIC last error sink close failed")
        def create(path):
            f = actual_create(path)
            return CloseFailed(f) if path.name == "errors.jsonl" else f
        self.patch(m, "create", create)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(closed, [True])
        self.assertTrue(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])
        self.assertFalse(m.decode(self.saved("result.json"))["OwnFinalCloseProven"])
        self.assertEqual(self.saved("errors.jsonl"), b"")  # no replacement after its last close
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])

    def test_actual_late_inventory_cancellation_after_error_close_is_not_lost(self):
        actual_producer, actual_write = m.producer_files, m.write_file
        def producer(*args):
            result = actual_producer(*args)
            self.handler = signal.getsignal(signal.SIGINT)
            return result
        def write(f, raw):
            actual_write(f, raw)
            if b'"ParentFiles"' in raw: self.cancel_after_wait()
        self.patch(m, "producer_files", producer)
        self.patch(m, "write_file", write)
        self.assertEqual(self.run_parent(), 2)
        self.assertTrue(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])
        self.assertEqual(self.saved("errors.jsonl"), b"")  # last sink already closed
        self.assertTrue(self.saved("inventory.json"))
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "actual selected Linux pidfd route only")
    def test_actual_native_pidfd_waits_the_inert_owned_child(self):
        actual = m.load_wait_primitives
        def load(*args):
            kernel = actual(*args)
            kernel.open_child_handle = os.pidfd_open
            kernel.signal_child = signal.pidfd_send_signal
            return kernel
        self.patch(m, "load_wait_primitives", load)
        self.assertEqual(self.run_parent(), 0)
        self.assertEqual(len(self.waits), 1)

    @unittest.skipUnless(sys.platform == "linux", "owned adopted-holder reconciliation requires Linux")
    def test_actual_held_pipe_is_separately_reaped_and_never_claims_eof(self):
        result = subprocess.run([sys.executable, "-S", "-B", str(Path(__file__).resolve()), "--owned-held-output", str(self.scope)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


def owned_held_output(scope):
    # One isolated test-only subreaper. The original parent's false EOF and its
    # actual direct Wait remain unchanged by this exact adopted holder Wait.
    signal.alarm(6)
    libc = ctypes.CDLL(None, use_errno=True)
    require = m.require
    initial = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(initial), 0, 0, 0) == 0 and initial.value == 0)
    require(libc.prctl(36, 1, 0, 0, 0) == 0)
    observed = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(observed), 0, 0, 0) == 0 and observed.value == 1)
    global EVIDENCE_ROOT
    EVIDENCE_ROOT = Path(scope).parent
    case = DirectParentControls("test_actual_child_wait_corroborates_only_literal_inner_claim")
    case.evidence_label = "owned-descendant-held-output"
    case.setUp()
    code, failure, waited, status, pid = None, None, None, None, None
    holder = case.base / "holder.pid"
    try:
        case.producer("pid=os.fork()\nif pid==0:\n os.close(" + str(case.notify_w) + ");time.sleep(0.3);os._exit(0)\n"
                      "p=pathlib.Path(" + repr(str(holder)) + ");p.write_text(str(pid));p.chmod(0o600);os.write(1,b'held-prefix')")
        code = case.run_parent()
    except BaseException as error:
        failure = error
    finally:
        case.doCleanups()
        if holder.exists():
            pid = int(holder.read_text())
            waited, status = os.waitpid(pid, 0)
        # Fixture-owned reaping precedes assertions and cannot upgrade the
        # original parent or conceal an earlier failure.
        case.write(Path(scope) / "held-output-reconcile.json", m.encode({"HolderPID": pid, "WaitPID": waited, "RawStatus": status,
                   "OriginalParentReturn": code, "Failure": repr(failure), "OriginalParentUpgraded": False}))
    if failure is not None:
        raise failure
    wait = m.decode(case.saved("wait.json"))
    require(code == 2 and wait["Waited"] and wait["ReturnCode"] == 0 and not wait["OutputComplete"]
            and not wait["StdoutEOF"] and not wait["StderrEOF"] and len(case.waits) == 1 and not case.signals
            and waited == pid and pid is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--owned-held-output":
        sys.exit(owned_held_output(Path(sys.argv[2])))
    print(m.encode({"InertTestEvidenceRoot": str(evidence_root()), "PublicationAuthorized": False}).decode(), end="", flush=True)
    unittest.main(verbosity=2)
