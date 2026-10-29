#!/usr/bin/env python3
"""Inert parent controls only. No Go/controller/build/CI/product is run.

Preserve synthetic originals beneath .cache/native-check-parent-controls.
Production admission has no specimen path, alternate argv or handle fallback.
"""
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().with_name("native-check-guest-parent.py")
TEST_SCRIPT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("fixed_native_parent", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL_POPEN = subprocess.Popen
REAL_NATIVE_PLATFORM = m.native_platform


class DelegatedFile:
    def __init__(self, actual, read_error=False, close_error=False):
        self.actual, self.read_error, self.close_error = actual, read_error, close_error

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def read(self, amount):
        if self.read_error:
            raise OSError(errno.EIO, "SYNTHETIC original read failure")
        return self.actual.read(amount)

    def close(self):
        self.actual.close()
        if self.close_error:
            raise OSError(errno.EIO, "SYNTHETIC final close failure")


class ParentControls(unittest.TestCase):
    def setUp(self):
        storage = SCRIPT.parents[1] / ".cache/native-check-parent-controls"
        storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        m.directory(storage)
        self.scope = Path(tempfile.mkdtemp(prefix="inert-", dir=storage)).resolve()
        self.base = self.scope / "kaferry-native-ci-inert"
        self.base.mkdir(mode=0o700)
        self.source, self.build = self.base / "source", self.base / "controller"
        for directory in (self.source, self.source / ".cache", self.source / "scripts", self.build):
            directory.mkdir(mode=0o700)
        self.head, self.run = "a" * 40, "inert"
        self.calls, self.waits, self.signals, self.externally_owned = [], [], [], []
        self.notify_r, self.notify_w = os.pipe()
        self.addCleanup(os.close, self.notify_r)
        self.addCleanup(os.close, self.notify_w)
        self.addCleanup(self.reap_constructor_specimens)
        self.write(self.source / "scripts/native-check-guest-parent.py", SCRIPT.read_bytes())
        self.write(self.source / "go.mod", b"module synthetic/native-parent\n")
        self.write(self.source / "go.sum", b"")
        self.write(self.source / "scripts/check.sh", b"#!/bin/sh\nexit 0\n")
        image = bytearray(64)
        image[:6], image[16:18], image[18:20] = b"\x7fELF\x02\x01", b"\x02\x00", b"\xb7\x00"
        image.extend(b"INERT DATA, NOT A GO EXECUTABLE\n")
        self.write(self.build / "native-check", bytes(image), 0o700)
        info = ("INERT native-check: go1.26.0\n\tpath\tgithub.com/pagrus7/kaferry-lab/cmd/native-check\n"
                "\tbuild\tGOOS=linux\n\tbuild\tGOARCH=arm64\n\tbuild\tvcs.revision=" + self.head + "\n\tbuild\tvcs.modified=false\n").encode()
        self.write(self.build / "native-check.buildinfo", info)
        catalog = [{"Path": str(p.relative_to(self.source)), "Bytes": p.stat().st_size, "SHA256": m.digest(p.read_bytes()), "Mode": 0o600}
                   for p in sorted(self.source.rglob("*")) if p.is_file()]
        native = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "Repository": str(self.source),
                  "GuestName": m.MACHINE, "GuestMachineID": m.MACHINE_ID, "SDKArchiveSHA256": m.SDK,
                  "GoBinarySHA256": "b" * 64, "Files": catalog}
        self.write(self.source / ".cache/native-check-input.json", m.encode(native))
        build = {"Version": "1", "SourceHead": self.head, "SourceCleanBefore": True, "SourceCleanAfter": True,
                 "GoVersion": "go1.26.0", "GOOS": "linux", "GOARCH": "arm64", "SDKArchiveSHA256": m.SDK,
                 "GoBinarySHA256": "b" * 64, "ControllerSHA256": m.digest(image), "ControllerBytes": len(image),
                 "BuildInfoSHA256": m.digest(info), "CompilerWait": {"PID": 123, "WaitReturned": True, "ExitCode": 0}, "ReleaseQualified": False}
        self.write(self.build / "controller-build.json", m.encode(build))
        self.inputs = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "GuestName": m.MACHINE,
                       "GuestMachineID": m.MACHINE_ID, "ControllerSHA256": m.digest(image), "ControllerBytes": len(image),
                       "ControllerBuildSHA256": m.digest(m.encode(build)), "NativeInputSHA256": m.digest(m.encode(native)),
                       "ParentSHA256": m.digest(SCRIPT.read_bytes())}
        self.write(self.base / "parent-input.json", m.encode(self.inputs))
        self.patch(m, "GUEST_ROOT", self.scope)
        self.patch(m, "__file__", str(self.source / "scripts/native-check-guest-parent.py"))
        self.patch(m, "native_platform", lambda: None)  # explicit inert-platform seam
        self.patch(m, "WAIT_SECONDS", 1.0)
        self.patch(m, "TERM_SECONDS", 0.08)
        self.patch(m, "KILL_SECONDS", 0.4)
        self.patch(m, "EOF_SECONDS", 0.05)
        self.patch(m, "open_child_handle", lambda _: os.dup(self.notify_r))
        self.patch(m, "signal_child", self.inert_signal)
        self.patch(m.subprocess, "Popen", self.inert_launch)
        self.specimen = self.base / "inert-producer.py"
        self.producer("os.write(1,b'\\x00\\xffexact\\x00');os.write(2,b'\\xfeerror\\x00')\n")

    def patch(self, obj, name, value):
        p = mock.patch.object(obj, name, value)
        p.start()
        self.addCleanup(p.stop)

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)

    def reap_constructor_specimens(self):
        for child in self.externally_owned:
            # This is the independent inert-fixture owner, not a parent fallback.
            if hasattr(child, "_inert_reconcile_wait"):
                child.wait = child._inert_reconcile_wait
            if child.returncode is not None:
                continue
            out, err, failure = b"", b"", None
            try:
                if child.stdout.closed and child.stderr.closed:
                    child.wait(timeout=3)
                else:
                    out, err = child.communicate(timeout=3)
            except BaseException as error:
                failure = error
                if isinstance(error, subprocess.TimeoutExpired):
                    out, err = error.output or b"", error.stderr or b""
            self.write(self.base / "external-constructor-reconciliation.json", m.encode({"PID": child.pid, "ReturnCode": child.returncode,
                       "Waited": failure is None, "Failure": repr(failure) if failure is not None else None,
                       "Stdout": out.hex(), "Stderr": err.hex(), "Scope": "independent inert fixture Wait only; no signals or parent-result upgrade"}))
            if failure is not None:
                raise failure

    def inert_signal(self, handle, value):
        self.signals.append((handle, value))  # no real signal; finite specimen self-exit

    def start_inert(self, kwargs):
        # -S excludes unsolicited user-site probing of the production Linux
        # HOME on a Mac automount. -B excludes Python bytecode writes. Neither
        # changes the fixed production environment, HOME, caches or limits.
        argv = [sys.executable, "-S", "-B", str(self.specimen)]
        child = REAL_POPEN(argv, **kwargs)
        self.externally_owned.append(child)
        # The fixture owner records this actual PID BEFORE a test can throw a
        # synthetic constructor error or the parent can time out. This is no
        # Wait/closure claim and cannot repair the original parent's evidence.
        receipt = {"PID": child.pid, "FixtureOwnerPID": os.getpid(), "Argv": argv,
                   "Environment": dict(kwargs["env"]), "InheritedFSIZE": list(resource.getrlimit(resource.RLIMIT_FSIZE)),
                   "Waited": False, "Scope": "independent inert fixture launch only"}
        fd = os.open(self.base / "fixture-launch.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(m.encode(receipt))
            f.flush()
            os.fsync(f.fileno())
        return child

    def inert_launch(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        require = self.assertTrue
        require(argv[0] == str(self.build / "native-check"))
        # The ELF-shaped fixture is DATA only. The sole test seam executes this
        # separately visible inert Python specimen; production cannot select it.
        kwargs["pass_fds"] = (self.notify_w,)
        child = self.start_inert(kwargs)
        original_wait = child.wait
        def waited(*args, **kw):
            self.waits.append(child.pid)
            return original_wait(*args, **kw)
        child.wait = waited
        return child

    def producer(self, body, go_result=True, exit_code=0, claims=None):
        code = "import os,json,pathlib,time,resource,signal,sys\n"
        # A separate private file proves actual fixture-body entry. It is not
        # the terminal notification pipe, so it cannot trigger premature Wait.
        code += "fd=os.open(" + repr(str(self.base / "inert-body-start.json")) + ",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
        code += "os.write(fd,json.dumps({'PID':os.getpid(),'NoSite':sys.flags.no_site,'NoBytecode':sys.dont_write_bytecode,'Environment':dict(os.environ),'InheritedFSIZE':resource.getrlimit(resource.RLIMIT_FSIZE)}).encode());os.fsync(fd);os.close(fd)\n"
        if go_result:
            path = str(self.source / ".cache/native-check-private" / self.run)
            result = {"Version": "1", "Namespace": "harness/native-unit-check", "RunID": self.run, "SourceHead": self.head,
                      "InputSHA256": self.inputs["NativeInputSHA256"], "Status": "HARNESS_CHECKS_PASSED_EXTERNAL_CUSTODY_REQUIRED",
                      "NativeHarnessChecksPassed": True, "CommandWritersStopped": True, "OwnFinalCloseProven": False,
                      "RequiresExternalWaitAndMacReadback": True, "ReleaseQualified": False}
            result.update(claims or {})
            code += "p=pathlib.Path(" + repr(path) + ");p.mkdir(mode=0o700,parents=True);p.parent.chmod(0o700)\n"
            code += "\n".join("(p/" + repr(name) + ").write_bytes(" + repr(m.encode(result) if name == "result.json" else b"{}\n") + ");(p/" + repr(name) + ").chmod(0o600)"
                              for name in m.GO_FILES if name != "result.pending.json") + "\n"
        code += body + "\nos.write(" + str(self.notify_w) + ",b'x');os._exit(" + str(exit_code) + ")\n"
        self.write(self.specimen, code.encode())

    def run_parent(self, expected=None):
        return m.run_attempt(self.base, expected or m.digest((self.base / "parent-input.json").read_bytes()))

    def saved(self, name):
        return (self.base / "parent-private" / name).read_bytes()

    def assert_body_environment(self, actual):
        # Preserve and check the actual body observation, distinct from the
        # three-key environment supplied to Popen. Darwin's measured automatic
        # CF key is the only platform addition; no ambient key is filtered out.
        expected = dict(m.ENV)
        if sys.platform == "darwin":
            expected["__CF_USER_TEXT_ENCODING"] = "0x{:X}:0x0:0x0".format(os.getuid())
        self.assertEqual(actual, expected)

    def test_actual_one_wait_binary_bytes_and_external_boundary(self):
        self.assertEqual(self.run_parent(), 0)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.saved("stdout.bin"), b"\x00\xffexact\x00")
        self.assertEqual(self.saved("stderr.bin"), b"\xfeerror\x00")
        wait, result = m.decode(self.saved("wait.json")), m.decode(self.saved("result.json"))
        self.assertTrue(wait["Waited"] and wait["StdoutEOF"] and wait["StderrEOF"] and wait["OutputComplete"])
        self.assertEqual(wait["PID"], self.waits[0])
        launch = m.decode((self.base / "fixture-launch.json").read_bytes())
        started = m.decode((self.base / "inert-body-start.json").read_bytes())
        self.assertEqual(launch["PID"], wait["PID"])
        self.assertFalse(launch["Waited"])
        self.assertEqual(launch["Argv"], [sys.executable, "-S", "-B", str(self.specimen)])
        self.assertEqual(launch["Environment"], m.ENV)
        self.assertEqual(self.calls[0][1]["env"], m.ENV)
        self.assertEqual(started["PID"], wait["PID"])
        self.assertEqual(started["NoSite"], 1)
        self.assertTrue(started["NoBytecode"])
        self.assert_body_environment(started["Environment"])
        self.assertEqual(started["InheritedFSIZE"], list(resource.getrlimit(resource.RLIMIT_FSIZE)))
        self.assertFalse(result["OwnFinalCloseProven"] or result["GuardReleaseAuthorized"] or result["ReleaseQualified"])
        self.assertTrue(result["RequiresExternalReturnAndMacReadback"])
        self.assertEqual(self.signals, [])

    def test_fake_pass_nonzero_is_failed_but_original_bytes_remain(self):
        self.producer("os.write(1,b'PASS\\x00\\xff')", go_result=False, exit_code=7)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.saved("stdout.bin"), b"PASS\x00\xff")
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Waited"])
        self.assertEqual(wait["ReturnCode"], 7)
        self.assertEqual(len(self.waits), 1)
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])

    def test_timeout_has_one_selected_route_and_one_actual_wait(self):
        self.patch(m, "WAIT_SECONDS", 0.15)
        # This route records fake handle signals; it never actually terminates
        # the child. Allow bounded Python startup plus its finite self-exit,
        # rather than confusing the independent fixture owner's later Wait
        # with the production parent's own Wait. Actual Linux pidfd is separate.
        self.patch(m, "KILL_SECONDS", 2.0)
        self.producer("os.write(1,b'finite-prefix');time.sleep(0.35)", go_result=False)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Timeout"] and wait["Waited"])
        self.assertEqual([s for _, s in self.signals], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(len({fd for fd, _ in self.signals}), 1)
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.saved("stdout.bin"), b"finite-prefix")
        started = m.decode((self.base / "inert-body-start.json").read_bytes())
        launch = m.decode((self.base / "fixture-launch.json").read_bytes())
        self.assertEqual(started["PID"], wait["PID"])
        self.assertEqual(started["NoSite"], 1)
        self.assertTrue(started["NoBytecode"])
        self.assertEqual(launch["Environment"], m.ENV)
        self.assertEqual(self.calls[0][1]["env"], m.ENV)
        self.assert_body_environment(started["Environment"])

    def test_synthetic_handle_refusal_never_selects_another_signal(self):
        self.patch(m, "WAIT_SECONDS", 0.15)
        self.producer("time.sleep(0.2)", go_result=False)
        def denied(fd, value):
            self.signals.append((fd, value))
            raise PermissionError(errno.EPERM, "SYNTHETIC pidfd signal refusal")
        self.patch(m, "signal_child", denied)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual([s for _, s in self.signals], [signal.SIGTERM])
        self.assertEqual(len(self.waits), 1)
        self.assertIn(b"SYNTHETIC pidfd signal refusal", self.saved("errors.jsonl"))

    def test_handle_construction_refusal_preserves_original_wait_only(self):
        def denied(_pid):
            raise PermissionError(errno.EPERM, "SYNTHETIC pidfd open refusal")
        self.patch(m, "open_child_handle", denied)
        self.assertEqual(self.run_parent(), 2)
        self.assertTrue(m.decode(self.saved("wait.json"))["Waited"])
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])
        self.assertIn(b"SYNTHETIC pidfd open refusal", self.saved("errors.jsonl"))

    def test_constructor_uncertainty_is_not_declared_prelaunch_or_retried(self):
        self.producer("time.sleep(0.1)", go_result=False)
        def uncertain(argv, **kwargs):
            self.calls.append((argv, kwargs))
            kwargs["pass_fds"] = (self.notify_w,)
            self.start_inert(kwargs)
            raise OSError("SYNTHETIC constructor failure after separately owned inert launch")
        self.patch(m.subprocess, "Popen", uncertain)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["LaunchAttempted"] and wait["LaunchUncertain"])
        self.assertFalse(wait["Started"] or wait["Waited"])
        launch = m.decode((self.base / "fixture-launch.json").read_bytes())
        self.assertEqual(launch["PID"], self.externally_owned[0].pid)
        self.assertFalse(launch["Waited"])
        self.assertIsNone(wait["PID"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.signals, [])

    def test_controller_and_input_changes_fail_before_launch(self):
        self.write(self.build / "native-check", b"changed controller", 0o700)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.calls, [])

    def test_missing_controller_fails_before_launch(self):
        (self.build / "native-check").unlink()
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.calls, [])

    def test_missing_actual_wait_does_not_become_a_return_witness(self):
        def wait_fault(argv, **kwargs):
            child = self.inert_launch(argv, **kwargs)
            child._inert_reconcile_wait = child.wait
            def failed_wait(*args, **kw):
                self.waits.append(child.pid)
                raise OSError(errno.EIO, "SYNTHETIC direct Wait failure")
            child.wait = failed_wait
            return child
        self.patch(m.subprocess, "Popen", wait_fault)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Started"] and wait["WaitAttempted"])
        self.assertFalse(wait["Waited"] or wait["OutputComplete"])
        self.assertEqual(len(self.waits), 1)
        self.assertEqual(self.signals, [])
        self.assertIn(b"SYNTHETIC direct Wait failure", self.saved("errors.jsonl"))

    def test_wrong_input_hash_fails_before_launch(self):
        self.assertEqual(self.run_parent("f" * 64), 2)
        self.assertEqual(self.calls, [])

    def test_missing_native_input_fails_before_launch(self):
        (self.source / ".cache/native-check-input.json").unlink()
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.calls, [])

    def test_wrong_controller_build_head_fails_before_launch(self):
        path = self.build / "controller-build.json"
        build = m.decode(path.read_bytes())
        build["SourceHead"] = "c" * 40
        self.write(path, m.encode(build))
        self.inputs["ControllerBuildSHA256"] = m.digest(m.encode(build))
        self.write(self.base / "parent-input.json", m.encode(self.inputs))
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.calls, [])

    def test_overflow_keeps_exact_binary_prefix_and_fails_capture(self):
        self.producer("os.write(1,b'\\x00\\xff'*40000)", go_result=False)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertTrue(wait["Waited"])
        self.assertFalse(wait["OutputComplete"])
        self.assertEqual(self.saved("stdout.bin"), (b"\x00\xff" * 40000)[:m.STREAM_LIMIT])
        self.assertGreater(wait["StdoutBytes"], wait["CapturedStdoutBytes"])

    def test_zero_exit_without_producer_result_is_not_an_inner_pass(self):
        self.producer("os.write(1,b'PASS')", go_result=False)
        self.assertEqual(self.run_parent(), 2)
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])

    def test_declared_unresolved_producer_cannot_be_corroborated(self):
        self.producer("", claims={"CommandWritersStopped": False})
        self.assertEqual(self.run_parent(), 2)
        self.assertTrue(m.decode(self.saved("wait.json"))["Waited"])
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])

    def test_changed_postlaunch_input_cannot_be_corroborated(self):
        self.producer("pathlib.Path(" + repr(str(self.base / "parent-input.json")) + ").write_text('{}')")
        self.assertEqual(self.run_parent(), 2)
        self.assertFalse(m.decode(self.saved("result.json"))["ControllerReturnCorroborated"])

    def test_reused_attempt_cannot_overwrite_originals(self):
        self.assertEqual(self.run_parent(), 0)
        before = {p.name: p.read_bytes() for p in (self.base / "parent-private").iterdir()}
        with self.assertRaises(FileExistsError):
            self.run_parent()
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.base / "parent-private").iterdir()})
        self.assertEqual(len(self.calls), 1)

    def test_first_sink_failure_has_no_alternate_or_launch(self):
        actual = m.create
        def denied(path):
            if path.name == "errors.jsonl":
                raise PermissionError(errno.EACCES, "SYNTHETIC first sink refusal")
            return actual(path)
        self.patch(m, "create", denied)
        with self.assertRaises(PermissionError):
            self.run_parent()
        self.assertEqual(list((self.base / "parent-private").iterdir()), [])
        self.assertEqual(self.calls, [])

    def test_last_sink_close_cannot_authorize_parent_success(self):
        actual = m.create
        self.patch(m, "create", lambda p: DelegatedFile(actual(p), close_error=True) if p.name == "errors.jsonl" else actual(p))
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.saved("inventory.json"), b"")
        self.assertEqual(set(p.name for p in (self.base / "parent-private").iterdir()), set(m.FILES))
        self.assertFalse(m.decode(self.saved("result.json"))["OwnFinalCloseProven"])

    def test_primary_sink_write_failure_has_no_alternate_copy(self):
        actual = m.create
        class BrokenWrite(DelegatedFile):
            def write(self, _body):
                raise OSError(errno.ENOSPC, "SYNTHETIC primary write refusal")
        self.patch(m, "create", lambda p: BrokenWrite(actual(p)) if p.name == "errors.jsonl" else actual(p))
        self.assertEqual(self.run_parent("f" * 64), 2)
        self.assertEqual(self.saved("errors.jsonl"), b"")
        self.assertTrue(m.decode(self.saved("result.json"))["PrimaryErrorSinkBroken"])
        self.assertEqual(self.calls, [])
        self.assertEqual(set(p.name for p in (self.base / "parent-private").iterdir()), set(m.FILES))

    def test_original_read_and_close_failures_are_both_retained(self):
        actual = m.os.fdopen
        self.patch(m.os, "fdopen", lambda fd, mode, **kw: DelegatedFile(actual(fd, mode, **kw), read_error=True, close_error=True)
                   if mode == "rb" else actual(fd, mode, **kw))
        self.assertEqual(self.run_parent(), 2)
        self.assertIn(b"SYNTHETIC original read failure", self.saved("errors.jsonl"))
        self.assertIn(b"SYNTHETIC final close failure", self.saved("errors.jsonl"))
        self.assertEqual(self.calls, [])

    def test_final_inventory_read_failure_has_no_replacement_sink(self):
        actual = m.read_file
        def denied(path, *args, **kwargs):
            if path.parent.name == "parent-private":
                raise OSError("SYNTHETIC post-primary-close read failure")
            return actual(path, *args, **kwargs)
        self.patch(m, "read_file", denied)
        self.assertEqual(self.run_parent(), 2)
        self.assertEqual(self.saved("errors.jsonl"), b"")
        self.assertEqual(self.saved("inventory.json"), b"")

    def test_child_environment_and_fsize_are_ordinary_and_parent_unchanged(self):
        before_limits, before_env = resource.getrlimit(resource.RLIMIT_FSIZE), dict(os.environ)
        before_handlers = [signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)]
        self.producer("os.write(1,json.dumps({'env':dict(os.environ),'limits':resource.getrlimit(resource.RLIMIT_FSIZE)}).encode())")
        self.patch(m.resource, "setrlimit", mock.Mock(side_effect=AssertionError("must not mutate FSIZE")))
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "SYNTHETIC", "LAB_LINKS": "1", "GOCACHE": "/SYNTHETIC"}):
            ambient = dict(os.environ)
            self.assertEqual(self.run_parent(), 0)
            self.assertEqual(dict(os.environ), ambient)
        child = m.decode(self.saved("stdout.bin"))
        started = m.decode((self.base / "inert-body-start.json").read_bytes())
        launch = m.decode((self.base / "fixture-launch.json").read_bytes())
        self.assertEqual(launch["Environment"], m.ENV)
        self.assertEqual(self.calls[0][1]["env"], m.ENV)
        self.assert_body_environment(child["env"])
        self.assertEqual(child["limits"], list(before_limits))
        self.assert_body_environment(started["Environment"])
        self.assertEqual(started["InheritedFSIZE"], list(before_limits))
        self.assertEqual(started["NoSite"], 1)
        self.assertTrue(started["NoBytecode"])
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE), before_limits)
        self.assertEqual(dict(os.environ), before_env)
        self.assertEqual([signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)], before_handlers)

    def test_hardware_fsize_inheritance_is_rejected_without_raising_it(self):
        u = types.SimpleNamespace(sysname="Linux", machine="aarch64", nodename=m.MACHINE,
                                  release="7.0.14-orbstack-00380-ga7e0a2dc9535")
        with mock.patch.object(m.os, "uname", return_value=u), mock.patch.object(m.os, "getuid", return_value=501), \
                mock.patch.object(m.os, "geteuid", return_value=501), mock.patch.object(m.signal, "getsignal", return_value=signal.SIG_DFL), \
                mock.patch.object(m.resource, "getrlimit", return_value=(2 << 20, 2 << 20)), \
                mock.patch.object(m.resource, "setrlimit") as setting, mock.patch.dict(os.environ, {"HOME": m.ENV["HOME"]}):
            with self.assertRaises(ValueError):
                REAL_NATIVE_PLATFORM()
            setting.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                         "actual selected pidfd control requires Linux Python support")
    def test_actual_native_pidfd_route_waits_the_owned_inert_child(self):
        self.patch(m, "WAIT_SECONDS", 0.2)
        self.patch(m, "open_child_handle", lambda pid: os.pidfd_open(pid, 0))
        self.patch(m, "signal_child", lambda fd, value: signal.pidfd_send_signal(fd, value, None, 0))
        self.producer("os.write(1,b'native-ready');time.sleep(2)", go_result=False)
        self.assertEqual(self.run_parent(), 2)
        wait = m.decode(self.saved("wait.json"))
        self.assertEqual(self.saved("stdout.bin"), b"native-ready")
        self.assertTrue(wait["SignalHandleAcquired"] and wait["Waited"] and wait["Timeout"])
        self.assertEqual(wait["ReturnCode"], -signal.SIGTERM)
        self.assertEqual(wait["Signals"], [{"Signal": int(signal.SIGTERM), "Succeeded": True}])
        self.assertEqual(len(self.waits), 1)
        started = m.decode((self.base / "inert-body-start.json").read_bytes())
        self.assertEqual(started["PID"], wait["PID"])

    @unittest.skipUnless(sys.platform == "linux", "owned descendant reaping control requires Linux subreaper")
    def test_actual_direct_wait_cannot_replace_descendant_held_output_eof(self):
        # Only this dedicated, finite INERT helper becomes a subreaper. Neither
        # the production guest parent nor the shared unittest process does so.
        argv = [sys.executable, "-S", "-B", str(TEST_SCRIPT), "--owned-held-output-control", str(self.base)]
        child = REAL_POPEN(argv,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(m.ENV), close_fds=True)
        self.externally_owned.append(child)
        fd = os.open(self.base / "owned-held-control-launch.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(m.encode({"PID": child.pid, "FixtureOwnerPID": os.getpid(), "Argv": argv, "Waited": False,
                              "Scope": "dedicated inert foreground launch only; no closure claim"}))
            f.flush()
            os.fsync(f.fileno())
        stdout, stderr = child.communicate(timeout=8)
        self.write(self.base / "owned-held-control-foreground.json", m.encode({"PID": child.pid, "ReturnCode": child.returncode,
                   "Stdout": stdout.hex(), "Stderr": stderr.hex(), "Scope": "dedicated inert control foreground Wait"}))
        self.assertEqual(child.returncode, 0, "owned held-output control failed; inspect private originals")
        report = m.decode(stdout)
        self.assertTrue(report["ActualControllerWaited"] and report["ActualHolderWaited"])
        self.assertFalse(report["ParentCorroborated"] or report["OutputComplete"] or report["ReleaseQualified"])


def owned_held_output_control(ledger_root):
    """Finite isolated unit owner reaps its adopted holder; no production route."""
    signal.alarm(6)
    m.directory(ledger_root)
    errors = m.Errors(m.create(ledger_root / "owned-held-control-errors.jsonl"))
    case = None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        initial = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(initial), 0, 0, 0) != 0 or initial.value != 0:
            raise OSError(ctypes.get_errno(), "inert subreaper initial readback failed")
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "inert selected subreaper setup failed")
        observed = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(observed), 0, 0, 0) != 0 or observed.value != 1:
            raise OSError(ctypes.get_errno(), "inert selected subreaper readback failed")
        case = ParentControls("test_actual_one_wait_binary_bytes_and_external_boundary")
        case.setUp()
        holder_file = case.base / "holder.pid"
        case.producer("pid=os.fork()\nif pid==0:\n time.sleep(0.4);os._exit(0)\n"
                      "pathlib.Path(" + repr(str(holder_file)) + ").write_text(str(pid));os.write(1,b'held-prefix')")
        code = case.run_parent()
        wait, result = m.decode(case.saved("wait.json")), m.decode(case.saved("result.json"))
        require = m.require
        require(code == 2 and wait["Waited"] and wait["ReturnCode"] == 0 and not wait["OutputComplete"]
                and not wait["StdoutEOF"] and not wait["StderrEOF"] and len(case.waits) == 1 and not case.signals)
        holder = int(holder_file.read_text())
        returned, status = os.waitpid(holder, 0)  # exact adopted INERT child only
        require(returned == holder and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
        report = {"ParentRoot": str(case.base), "ActualControllerWaited": wait["Waited"], "ActualHolderWaited": returned == holder,
                  "HolderPID": holder, "HolderRawStatus": status, "ParentCorroborated": result["ControllerReturnCorroborated"],
                  "OutputComplete": wait["OutputComplete"], "OriginalParentStatus": result["Status"], "ReleaseQualified": False,
                  "Scope": "dedicated inert subreaper reconciliation; original incomplete parent capture unchanged"}
        f = m.create(ledger_root / "owned-held-control-reconcile.json")
        m.write_file(f, m.encode(report))
        m.close_file(f, errors.record)
        print(json.dumps(report))
        return 0
    except BaseException as error:
        errors.record(error)
        return 1
    finally:
        if case is not None:
            case.doCleanups()
        errors.close()


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--owned-held-output-control":
        sys.exit(owned_held_output_control(Path(sys.argv[2])))
    unittest.main(verbosity=2)
