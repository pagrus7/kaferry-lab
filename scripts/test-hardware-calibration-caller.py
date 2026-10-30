#!/usr/bin/env python3
"""Inert caller calibration only; no Go/GDB/specimen/native plan is executed.

Source authored first; execution requires the coordinator's test barrier.
"""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hardware_caller", Path(__file__).with_name("run-hardware-calibration.py"))
caller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(caller)


def specimen_output(case, run):
    name, text = caller.CASES[case]
    return ("=== RUN   " + name + "\n    gdb_controller_linux_test.go:693: " + text + run
            + "\n--- PASS: " + name + " (0.12s)\nPASS\n").encode()


class CallerControls(unittest.TestCase):
    def setUp(self):
        (ROOT / ".cache").mkdir(exist_ok=True)
        controls = ROOT / ".cache/hardware-caller-controls"
        controls.mkdir(mode=0o700, exist_ok=True)
        caller.directory(controls)
        # Preserve exact finite synthetic prefixes/refusals for review; every
        # invocation gets fresh exclusive names, never old-attempt adoption.
        self.root = Path(tempfile.mkdtemp(prefix="inert-", dir=controls)).resolve()
        self.cache = self.root / ".cache"
        self.cache.mkdir(mode=0o700)
        for name in ("hardware-outer-private", "hardware-wait-private", "hardware-build"):
            (self.cache / name).mkdir(mode=0o700)
        self.run = "inert-unit-control"

    def test_reviewed_source_directory_reaches_pins_and_stale_prefix_does_not(self):
        # Literal fixed workspace for664; do not
        # derive its prefix from the production expression being exercised.
        valid = Path("/run/user/501/kaferry-hardware-664fbbf-inert-unit-control/source")
        stale = Path("/run/user/501/kaferry-hardware-eb0fd52-inert-unit-control/source")
        old_af5 = Path("/run/user/501/kaferry-hardware-af5e4b2-inert-unit-control/source")
        wrong_run = Path("/run/user/501/kaferry-hardware-664fbbf-other-run/source")
        old_home = Path("/home/labrunner/kaferry-hardware-664fbbf-inert-unit-control/source")
        class ReachedSourcePin(Exception):
            pass
        for root, admitted in ((valid, True), (stale, False), (old_af5, False), (wrong_run, False), (old_home, False)):
            with self.subTest(root=str(root)):
                manifest = {"RunID": self.run, "Case": "normal", "RepoRoot": str(root),
                            "SourceHead": caller.HEAD, "GuestName": "kaferry-lab-arm64-20261026",
                            "GuestMachineID": "01M5XVQQ4GRX6H79K1SE76R0X1",
                            "TestBytes": 6582220, "SpecimenBytes": 3993134}
                for field in ("CallerSHA256", "TestSHA256", "SpecimenSHA256", "BuildSHA256", "PlanSHA256", "AuditSHA256"):
                    manifest[field] = "a" * 64
                raw = caller.encode(manifest)
                calls = []
                def read(path, *args, **kwargs):
                    calls.append(path)
                    if len(calls) == 1:
                        self.assertEqual(path, root / ".cache/hardware-gdb-caller-input.json")
                        return raw, {}
                    self.assertEqual(path, root / ".gitignore")
                    raise ReachedSourcePin()
                with mock.patch.object(caller, "read_file", read), mock.patch.object(caller, "__file__", str(root / ".cache/run-hardware-calibration.py")):
                    with self.assertRaises(ReachedSourcePin if admitted else ValueError):
                        caller.bind_inputs(root, self.run, hashlib.sha256(raw).hexdigest())
                self.assertEqual(len(calls), 2 if admitted else 1)

    def file(self, path, raw, mode=0o600):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as f:
            self.assertEqual(f.write(raw), len(raw))
            f.flush()
            os.fsync(f.fileno())
        return path

    def process(self, helper, label, budget):
        path = self.root / label
        path.mkdir(mode=0o700)
        helper_bytes = helper.read_bytes()
        self.file(path / "inert-helper.py", helper_bytes)
        failures, files = [], {}
        for name in ("errors.json", "stdout.bin", "stderr.bin", "wait.json"):
            files[name] = os.fdopen(os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb", buffering=0)
        try:
            result = caller.wait_child([str(helper)], self.root, {"LC_ALL": "C"}, files["stdout.bin"], files["stderr.bin"], failures.append, budget=budget)
            caller.write_file(files["wait.json"], caller.encode({"Argv": [str(helper)], **result}))
        finally:
            for name in ("stdout.bin", "stderr.bin", "wait.json"):
                caller.close_file(files.pop(name), failures.append)
        original_errors = [{"Exception": repr(e), "Traceback": "".join(traceback.format_exception(type(e), e, e.__traceback__))} for e in failures]
        caller.write_file(files["errors.json"], caller.encode(original_errors))
        caller.close_file(files.pop("errors.json"), failures.append)
        rows = []
        for name in ("stdout.bin", "stderr.bin", "wait.json", "errors.json"):
            raw, row = caller.read_file(path / name, caller.LIMIT, 0o600)
            rows.append(row)
        self.file(path / "receipt.json", caller.encode({"InertControl": True, "Label": label, "ReleaseQualified": False,
                  "HelperPath": str(helper), "HelperSHA256": hashlib.sha256(helper_bytes).hexdigest(),
                  "CallerSHA256": hashlib.sha256(Path(caller.__file__).read_bytes()).hexdigest(),
                  "ActualWait": result, "ObservedErrors": len(failures), "Files": rows}))
        return result, (path / "stdout.bin").read_bytes(), (path / "stderr.bin").read_bytes(), failures

    def helper(self, body):
        # This distinct Python specimen is admitted only through ordinary unit
        # seams; production binding requires the real pinned Go ELF bytes.
        return self.file(self.cache / "hardware-build/hardwarecalibration.test",
                         ("#!" + sys.executable + "\n" + body).encode(), 0o700)

    def hardware(self, case="normal"):
        path = self.cache / "hardware-wait-private" / self.run
        path.mkdir(mode=0o700)
        for name in caller.HARDWARE:
            if case == "early-cancel" and name.startswith("parent-") and name.endswith(".json"):
                continue
            self.file(path / name, b"INERT synthetic custody bytes\x00\xff\n")
        for name in ("commands.fifo", "receipts.fifo"):
            os.mkfifo(path / name, 0o600)
        return path

    def inert_attempt(self, case="normal", output=None, close=None):
        raw = specimen_output(case, self.run) if output is None else output
        # The finite helper creates only its own exact synthetic files, then
        # prints visibly test-authored wrapper text. It launches nothing else.
        body = ("import os,pathlib\nroot=pathlib.Path.cwd()\np=root/'.cache/hardware-wait-private/" + self.run + "'\np.mkdir(mode=0o700)\n"
                + "names=" + repr(caller.HARDWARE) + "\n"
                + "for name in names:\n"
                + (" if name.startswith('parent-') and name.endswith('.json'): continue\n" if case == "early-cancel" else "")
                + " f=p/name; f.write_bytes(b'INERT synthetic data\\x00\\xff'); f.chmod(0o600)\n"
                + "for name in ['commands.fifo','receipts.fifo']: os.mkfifo(p/name,0o600)\n"
                + "os.write(1," + repr(raw) + ")\n")
        self.helper(body)
        self.file(self.root / (self.run + "-inert-helper.py"), (self.cache / "hardware-build/hardwarecalibration.test").read_bytes())
        binding = ({"Case": case, "RunID": self.run, "Purpose": "INERT UNIT SEAM ONLY"}, [])
        with mock.patch.object(caller, "native_platform"), mock.patch.object(caller, "lower_limit"), \
                mock.patch.object(caller, "bind_inputs", return_value=binding):
            if close is None:
                code = caller.run_attempt(self.root, self.run, "a" * 64)
            else:
                with mock.patch.object(caller, "close_file", side_effect=close):
                    code = caller.run_attempt(self.root, self.run, "a" * 64)
        self.file(self.root / (self.run + "-control.json"), caller.encode({"InertControl": True, "RunID": self.run,
                  "FunctionReturnCode": code, "RealOuterProcessWait": False, "PrivateInputSeams": True, "ReleaseQualified": False,
                  "HelperSHA256": hashlib.sha256((self.root / (self.run + "-inert-helper.py")).read_bytes()).hexdigest(),
                  "CallerSHA256": hashlib.sha256(Path(caller.__file__).read_bytes()).hexdigest()}))
        return code

    def test_four_exact_wrapper_controls_keep_cancel_experiments_nonpassing(self):
        for case in caller.CASES:
            with self.subTest(case=case):
                self.run = "inert-unit-" + case
                self.assertEqual(self.inert_attempt(case), 0)
                path = self.cache / "hardware-outer-private" / self.run
                result = json.loads((path / "result.json").read_bytes())
                self.assertIs(result["NormalCalibrationComplete"], case == "normal")
                self.assertIs(result["CancellationControlDetected"], case != "normal")
                self.assertIs(result["ExperimentPassing"], case == "normal")
                self.assertIs(result["ReleaseQualified"], False)
                inventory = json.loads((path / "inventory.json").read_bytes())
                self.assertIs(inventory["OwnFinalCloseProven"], False)
                self.assertEqual((path / "errors.jsonl").read_bytes(), b"")
                for name in caller.FILES:
                    self.assertEqual(stat.S_IMODE((path / name).stat().st_mode), 0o600)

    def test_pass_text_without_exact_postclose_case_witness_never_hashes_hardware(self):
        changes = [lambda _: b"PASS\n", lambda raw: raw.replace(b"--- PASS:", b"--- SKIP:"),
                   lambda raw: raw.replace(b"retained attempt", b"unrelated message"),
                   lambda raw: raw + b"=== RUN   AnotherTest\n",
                   lambda _: specimen_output("cancel", self.run)]
        for index, change in enumerate(changes):
            self.run = "inert-refusal-" + str(index)
            original = change(specimen_output("normal", self.run))
            with mock.patch.object(caller, "hardware_inventory", side_effect=AssertionError("must not snapshot refused output")):
                self.assertEqual(self.inert_attempt(output=original), 2)
            path = self.cache / "hardware-outer-private" / self.run
            self.assertEqual((path / "stdout.bin").read_bytes(), original)
            self.assertEqual((path / "inventory.json").read_bytes(), b"")
            self.assertIs(json.loads((path / "result.json").read_bytes())["Incomplete"], True)

    def test_missing_and_substituted_input_blocks_real_spawn_and_retains_original_errno(self):
        with mock.patch.object(caller, "native_platform"), mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
            spawn.assert_not_called()
        attempt = self.cache / "hardware-outer-private" / self.run
        original = (attempt / "errors.jsonl").read_bytes()
        self.assertIn(b"FileNotFoundError", original)
        self.assertIn(b"hardware-gdb-caller-input.json", original)
        self.assertIn(b"[Errno 2]", original)
        self.run = "inert-substituted-input"
        self.file(self.cache / "hardware-gdb-caller-input.json", b'{"Case":"normal"}\n')
        with mock.patch.object(caller, "native_platform"), mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "0" * 64), 2)
            spawn.assert_not_called()

    def test_whole_byte_pin_symlink_hardlink_mode_and_bound_refusals(self):
        raw = b"fixed synthetic image\x00\xff"
        path = self.file(self.cache / "literal.bin", raw)
        pin = hashlib.sha256(raw).hexdigest()
        self.assertEqual(caller.read_file(path, len(raw), 0o600, pin)[0], raw)
        self.file(path, raw[:-1] + b"X")
        with self.assertRaises(ValueError):
            caller.read_file(path, len(raw), 0o600, pin)
        with self.assertRaises(ValueError):
            caller.read_file(path, len(raw) - 1)
        path.chmod(0o622)
        with self.assertRaises(ValueError):
            caller.read_file(path)
        path.chmod(0o600)
        link = self.cache / "alias.bin"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            caller.read_file(link)
        link.unlink()
        os.link(path, link)
        with self.assertRaises(ValueError):
            caller.read_file(path)

    def test_available_read_and_close_failures_are_both_retained_on_python39(self):
        path = self.file(self.cache / "read-close.bin", b"inert")
        original = caller.os.fdopen
        closed = []
        class RefusingRead:
            def __init__(self, fd, mode):
                self.actual = original(fd, mode)
            def fileno(self):
                return self.actual.fileno()
            def read(self, _):
                raise OSError(errno.EIO, "E1 inert read failure")
            def close(self):
                self.actual.close()
                closed.append(True)
                raise OSError(errno.EBADF, "E2 inert close failure")
        with mock.patch.object(caller.os, "fdopen", side_effect=RefusingRead):
            with self.assertRaises(RuntimeError) as caught:
                caller.read_file(path)
        text = str(caught.exception)
        self.assertIn("E1 inert read failure", text)
        self.assertIn("E2 inert close failure", text)
        self.assertLess(text.index("E1 inert read failure"), text.index("E2 inert close failure"))
        self.assertEqual(closed, [True])

    def test_actual_direct_wait_records_pid_original_binary_streams_and_nonzero(self):
        helper = self.helper("import os,time\nos.write(1,('PID='+str(os.getpid())).encode()+b'\\x00\\xff')\nos.write(2,b'original\\x00stderr')\ntime.sleep(0.05)\nraise SystemExit(7)\n")
        result, out, err, failures = self.process(helper, "actual-direct-wait", 5)
        self.assertTrue(result["Started"] and result["Waited"])
        self.assertEqual(result["ReturnCode"], 7)
        self.assertFalse(result["Timeout"])
        self.assertGreaterEqual(result["ElapsedNS"], 40_000_000)
        self.assertEqual(out, ("PID=" + str(result["PID"])).encode() + b"\x00\xff")
        self.assertEqual(err, b"original\x00stderr")
        self.assertEqual(failures, [])

    def test_actual_timeout_stays_incomplete_after_owned_direct_child_wait(self):
        helper = self.helper("import time\ntime.sleep(5)\n")
        result, _, _, failures = self.process(helper, "actual-timeout", 0.05)
        self.assertTrue(result["Waited"] and result["Timeout"])
        self.assertEqual(result["ReturnCode"], -signal.SIGTERM)
        self.assertIsInstance(failures[0], subprocess.TimeoutExpired)
        self.assertEqual(len(failures), 1)

    def test_signal_refusal_has_no_alternate_or_second_spawn(self):
        child = mock.Mock(pid=123)
        child.wait.side_effect = subprocess.TimeoutExpired(["inert"], 1)
        child.terminate.side_effect = PermissionError(errno.EPERM, "inert signal refusal")
        failures = []
        with mock.patch.object(caller.subprocess, "Popen", return_value=child) as spawn:
            result = caller.wait_child(["inert"], self.root, {}, None, None, failures.append)
        self.assertFalse(result["Waited"])
        spawn.assert_called_once()
        child.terminate.assert_called_once()
        child.kill.assert_not_called()
        self.assertEqual(child.wait.call_count, 1)
        self.assertEqual(failures[1].errno, errno.EPERM)
        child.reset_mock()
        child.wait.side_effect = PermissionError(errno.EPERM, "inert wait refusal")
        with mock.patch.object(caller.subprocess, "Popen", return_value=child):
            refused = caller.wait_child(["inert"], self.root, {}, None, None, failures.append)
        self.assertFalse(refused["Waited"])
        child.wait.assert_called_once()
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_constructor_failure_retains_launch_uncertainty_without_another_route(self):
        original = OSError(errno.EAGAIN, "INERT constructor refusal after attempt")
        binding = ({"Case": "normal", "RunID": self.run, "Purpose": "INERT UNIT SEAM ONLY"}, [])
        with mock.patch.object(caller, "native_platform"), mock.patch.object(caller, "lower_limit"), \
                mock.patch.object(caller, "bind_inputs", return_value=binding), \
                mock.patch.object(caller.subprocess, "Popen", side_effect=original) as spawn, \
                mock.patch.object(caller, "hardware_inventory") as inventory:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
        spawn.assert_called_once()
        inventory.assert_not_called()
        path = self.cache / "hardware-outer-private" / self.run
        wait = json.loads((path / "wait.json").read_bytes())
        self.assertTrue(wait.get("LaunchAttempted"))
        self.assertFalse(wait["Started"] or wait["Waited"])
        self.assertIsNone(wait["PID"])
        result = json.loads((path / "result.json").read_bytes())
        self.assertTrue(result["Incomplete"] and result["InnerCleanupUnresolved"])
        errors = [json.loads(line) for line in (path / "errors.jsonl").read_bytes().splitlines()]
        self.assertEqual(sum(row["Exception"] == repr(original) for row in errors), 1)
        self.assertEqual((path / "inventory.json").read_bytes(), b"")
        self.run = "inert-preflight-no-launch"
        with mock.patch.object(caller, "native_platform", side_effect=ValueError("INERT preflight refusal")), \
                mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
        spawn.assert_not_called()
        result = json.loads((self.cache / "hardware-outer-private" / self.run / "result.json").read_bytes())
        self.assertFalse(result["InnerCleanupUnresolved"])

    def test_primary_failure_and_output_close_failure_cannot_complete_or_switch_sink(self):
        attempts = []
        def refuse(f, raw):
            attempts.append(raw)
            raise OSError(errno.EIO, "inert selected primary/write failure")
        with mock.patch.object(caller, "native_platform", side_effect=ValueError("inert initial failure")), \
                mock.patch.object(caller, "write_file", side_effect=refuse), \
                mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
            spawn.assert_not_called()
        # Primary is tried exactly once; a later result write is metadata, never
        # an alternate copy of the original exception.
        self.assertEqual(sum(b"inert initial failure" in raw for raw in attempts), 1)
        self.run = "inert-output-close"
        actual_close = caller.close_file
        def close(f, record, sync=True):
            target = self.cache / "hardware-outer-private" / self.run / "stdout.bin"
            bad = os.fstat(f.fileno()).st_ino == target.stat().st_ino
            actual_close(f, record, sync)
            if bad:
                record(OSError(errno.EIO, "inert stdout final close failure"))
        self.assertEqual(self.inert_attempt(close=close), 2)
        attempt = self.cache / "hardware-outer-private" / self.run
        self.assertIn(b"inert stdout final close failure", (attempt / "errors.jsonl").read_bytes())
        self.assertEqual((attempt / "inventory.json").read_bytes(), b"")

    def test_first_and_final_primary_failures_have_no_alternate_or_success(self):
        original_open = caller.os.open
        def denied(path, *args, **kwargs):
            if Path(path).name == "errors.jsonl":
                raise PermissionError(errno.EACCES, "inert first sink refusal", str(path))
            return original_open(path, *args, **kwargs)
        with mock.patch.object(caller.os, "open", side_effect=denied), mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
            spawn.assert_not_called()
        attempt = self.cache / "hardware-outer-private" / self.run
        self.assertEqual(list(attempt.iterdir()), [])
        self.run = "inert-final-primary-close"
        actual_close = caller.close_file
        def close(f, record, sync=True):
            target = self.cache / "hardware-outer-private" / self.run / "errors.jsonl"
            final = os.fstat(f.fileno()).st_ino == target.stat().st_ino
            actual_close(f, record, sync)
            if final:
                record(OSError(errno.EIO, "inert primary final close failure"))
        self.assertEqual(self.inert_attempt(close=close), 2)
        attempt = self.cache / "hardware-outer-private" / self.run
        self.assertEqual((attempt / "inventory.json").read_bytes(), b"")
        # An earlier result cannot establish its own subsequent final close.
        self.assertFalse(json.loads((attempt / "result.json").read_bytes())["Incomplete"])
        self.assertNotIn(b"inert primary final close failure", (attempt / "errors.jsonl").read_bytes())

    def test_large_original_keeps_one_bounded_prefix_and_never_starts_child(self):
        with mock.patch.object(caller, "native_platform", side_effect=ValueError("inert original " + "Z" * (70 << 10))), \
                mock.patch.object(caller.subprocess, "Popen") as spawn:
            self.assertEqual(caller.run_attempt(self.root, self.run, "a" * 64), 2)
            spawn.assert_not_called()
        attempt = self.cache / "hardware-outer-private" / self.run
        self.assertEqual((attempt / "errors.jsonl").stat().st_size, 64 << 10)
        self.assertIn(b"inert original", (attempt / "errors.jsonl").read_bytes()[:128])
        self.assertEqual((attempt / "inventory.json").read_bytes(), b"")

    def test_owned_inventory_never_opens_fifo_and_refuses_extra_missing_or_linked_members(self):
        path = self.hardware()
        original = caller.read_file
        def read(p, *args, **kwargs):
            self.assertFalse(p.name.endswith(".fifo"))
            return original(p, *args, **kwargs)
        with mock.patch.object(caller, "read_file", side_effect=read):
            rows = caller.hardware_inventory(self.root, self.run, "normal")
        self.assertEqual(sum(row.get("FIFO", False) for row in rows), 2)
        extra = self.file(path / "foreign.bin", b"unexpected")
        with self.assertRaises(ValueError):
            caller.hardware_inventory(self.root, self.run, "normal")
        extra.unlink()
        (path / "controller-report.json").unlink()
        with self.assertRaises(ValueError):
            caller.hardware_inventory(self.root, self.run, "normal")
        self.file(path / "controller-report.json", b"INERT restored data")
        os.link(path / "controller-report.json", self.cache / "outside-hardlink")
        with self.assertRaises(ValueError):
            caller.hardware_inventory(self.root, self.run, "normal")

    def test_exclusive_attempt_is_never_reopened_or_truncated(self):
        attempt = self.cache / "hardware-outer-private" / self.run
        attempt.mkdir(mode=0o700)
        original = self.file(attempt / "errors.jsonl", b"stopped prior original\x00")
        with mock.patch.object(caller.subprocess, "Popen") as spawn:
            with self.assertRaises(FileExistsError):
                caller.run_attempt(self.root, self.run, "a" * 64)
            spawn.assert_not_called()
        self.assertEqual(original.read_bytes(), b"stopped prior original\x00")

    def test_lower_limit_refuses_preexisting_lower_bound_without_increase_or_restore(self):
        with mock.patch.object(caller.resource, "getrlimit", return_value=(1024, 1024)), \
                mock.patch.object(caller.resource, "setrlimit") as setting:
            with self.assertRaises(ValueError):
                caller.lower_limit()
            setting.assert_not_called()
        infinity = caller.resource.RLIM_INFINITY
        with mock.patch.object(caller.resource, "getrlimit", side_effect=[(infinity, infinity), (caller.LIMIT, caller.LIMIT)]), \
                mock.patch.object(caller.resource, "setrlimit") as setting:
            caller.lower_limit()
            setting.assert_called_once_with(caller.resource.RLIMIT_FSIZE, (caller.LIMIT, caller.LIMIT))

    @unittest.skipUnless(sys.platform == "linux", "actual inherited FSIZE calibration is Linux only")
    def test_actual_finite_fsize_cap_preserves_exact_prefix_and_small_positive(self):
        # Only the finite inert child lowers its own cap. Never lower this test
        # parent's limit or consume more than2MiB output plus a short notice.
        source = Path(caller.__file__).resolve()
        prefix = ("import importlib.util,os,sys,json,errno\nsys.dont_write_bytecode=True\ns=importlib.util.spec_from_file_location('c'," + repr(str(source))
                  + ")\nc=importlib.util.module_from_spec(s);s.loader.exec_module(c)\nc.lower_limit()\n")
        for amount in (4096, caller.LIMIT + 4096):
            helper = self.helper(prefix + "data=b'Z'*" + str(amount) + "\nw=0\ntry:\n while w<len(data):\n  n=os.write(1,data[w:]); assert n>0; w+=n\nexcept OSError as e:\n os.write(2,json.dumps({'errno':e.errno,'written':w}).encode()); sys.exit(7)\n")
            result, actual, err, failures = self.process(helper, "actual-fsize-" + str(amount), 10)
            self.assertTrue(result["Waited"] and not result["Timeout"])
            self.assertEqual(failures, [])
            self.assertEqual(len(actual), min(amount, caller.LIMIT))
            self.assertEqual(hashlib.sha256(actual).hexdigest(), hashlib.sha256(b"Z" * min(amount, caller.LIMIT)).hexdigest())
            if amount < caller.LIMIT:
                self.assertEqual(result["ReturnCode"], 0)
                self.assertEqual(err, b"")
            else:
                self.assertEqual(result["ReturnCode"], 7)
                self.assertEqual(json.loads(err), {"errno": errno.EFBIG, "written": caller.LIMIT})


if __name__ == "__main__":
    unittest.main()
