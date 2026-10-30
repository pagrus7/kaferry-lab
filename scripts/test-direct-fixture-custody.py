#!/usr/bin/env python3
"""Filesystem/transport controls with literal DATA, no actual fixture/Wait.

No controller, Kafka, Docker, native parent or platform admission is performed.
The final-close and refusal controls own finite inert Python children; other
foreground records remain visibly literal calibration claims.
"""
import importlib.util
import errno
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import traceback
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("direct_custody_test", ROOT / "snapshot-direct-fixture.py")
r = load("direct_readback_test", ROOT / "read-direct-fixture.py")


class DirectCustodyControls(unittest.TestCase):
    def write(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def wait_inert_child(self, child, name):
        def failed(error):
            return {"PID": child.pid, "Waited": False, "ReturnCode": None, "STOP": True,
                    "Exception": repr(error), "Errno": getattr(error, "errno", None),
                    "Traceback": "".join(traceback.format_exception(type(error), error, error.__traceback__))[:64 << 10],
                    "InertPythonOnly": True, "CPythonFinalizationNotControlled": True}
        with m.create(self.home / (name + "-wait.json")) as report:
            try:
                code = child.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                m.write(report, m.encode(failed(error)))
                # Only the actual bounded timeout authorizes this fixture
                # cleanup. Any refusal here also stops without another route.
                with m.create(self.home / (name + "-timeout-cleanup.json")) as cleanup:
                    try:
                        child.kill()
                        cleanup_code = child.wait(timeout=3)
                    except BaseException as cleanup_error:
                        m.write(cleanup, m.encode({**failed(cleanup_error), "OriginalWaitUpgraded": False}))
                        raise
                    m.write(cleanup, m.encode({"PID": child.pid, "Waited": True, "ReturnCode": cleanup_code,
                                              "OriginalWaitUpgraded": False, "InertPythonOnly": True}))
                raise
            except BaseException as error:
                m.write(report, m.encode(failed(error)))
                raise  # no signal, second Wait, or producer read after refusal
            m.write(report, m.encode({"PID": child.pid, "Waited": True, "ReturnCode": code,
                                     "Observation": "actual subprocess.Popen.wait returned", "InertPythonOnly": True}))
            return code

    def setUp(self):
        storage = ROOT.parent / ".cache/direct-fixture-custody-controls"
        storage.mkdir(mode=0o700, parents=True, exist_ok=True)
        m.directory(storage)
        # Ignored originals persist on both failed and successful controls.
        self.home = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=storage)).resolve()
        self.run, self.head = "inert-custody", "a" * 40
        self.base = self.home / ("kaferry-direct-" + self.run)
        self.outlet = self.home / ("kaferry-direct-custody-" + self.run)
        for path in (self.base, self.outlet):
            path.mkdir(mode=0o700)
        self.required = m.fixed_paths(self.run)[3]
        # Create each ancestor explicitly; parents=True would give intermediate
        # directories the host umask, not the requested private leaf mode.
        for name in sorted(self.required | {"source/.cache/image-identity-data/" + self.run + "/images.tar"}
                           | {"source/" + name for name in m.SOURCE_FILES}):
            path = self.base / name
            for directory in reversed(path.parent.parents):
                if directory == self.base or self.base in directory.parents:
                    directory.mkdir(mode=0o700, exist_ok=True)
            path.parent.mkdir(mode=0o700, exist_ok=True)
            self.write(path, b"INERT ORIGINAL DATA ONLY\n")
        for name in m.SOURCE_FILES:
            self.write(self.base / "source" / name, (ROOT / Path(name).name).read_bytes())
        self.image = self.base / "source/.cache/image-identity-data" / self.run / "images.tar"
        self.write(self.image, b"INERT IMAGE TRANSPORT DATA ONLY\x00\xff")
        catalog = [{"Path": name, "Bytes": (self.base / "source" / name).stat().st_size,
                    "SHA256": m.sha((self.base / "source" / name).read_bytes())} for name in m.SOURCE_FILES]
        go = {"RunID": self.run, "SourceHead": self.head, "Files": catalog, "SyntheticLiteralData": True}
        self.go_raw = m.encode(go)
        self.write(self.base / "source/.cache/direct-fixture-input.json", self.go_raw)
        parent = {"RunID": self.run, "SourceHead": self.head, "GoInputSHA256": m.sha(self.go_raw), "SyntheticLiteralData": True}
        self.parent_raw = m.encode(parent)
        self.write(self.base / "parent-input.json", self.parent_raw)
        self.foreground = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "ParentPID": 123,
                           "ParentInputSHA256": m.sha(self.parent_raw), "Waited": True, "ReturnCode": 0,
                           "OutputComplete": True, "StdoutBytes": 0, "StdoutSHA256": m.sha(b""),
                           "StderrBytes": 0, "StderrSHA256": m.sha(b""),
                           "ProducerQuiescenceExternallyReviewed": True, "ReleaseQualified": False, "SyntheticLiteralData": True}
        self.write(self.base / "foreground.stdout", b"")
        self.write(self.base / "foreground.stderr", b"")
        self.packet = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "ParentInputSHA256": m.sha(self.parent_raw),
                       "GoInputSHA256": m.sha(self.go_raw), "ForegroundSHA256": "", "SnapshotSHA256": m.sha((ROOT / "snapshot-direct-fixture.py").read_bytes()),
                       "ReaderSHA256": m.sha((ROOT / "read-direct-fixture.py").read_bytes()),
                       "OutletDevice": self.outlet.stat().st_dev, "OutletInode": self.outlet.stat().st_ino, "ReleaseQualified": False}
        self.update_binding()
        self.target = self.outlet / "snapshot"

    def update_binding(self):
        self.write(self.base / "foreground.json", m.encode(self.foreground))
        self.packet["ForegroundSHA256"] = m.sha(m.encode(self.foreground))
        self.packet_raw = m.encode(self.packet)
        self.write(self.base / "custody-input.json", self.packet_raw)

    def capture(self):
        # Explicit test-only native/root/source-location seams. Production has
        # no alternate UID, platform, root, argv or filesystem selection.
        with mock.patch.object(m, "HOME", self.home), mock.patch.object(m, "native_outlet", lambda _: None), \
             mock.patch.object(m, "__file__", str(self.base / "source/scripts/snapshot-direct-fixture.py")):
            return m.snapshot(self.run, self.head, m.sha(self.packet_raw))

    def transfer(self, snapshot_return, snapshot_pid=456):
        local = self.home / "mac-private-copy"
        local.mkdir(mode=0o700)
        for name in m.OUTPUTS:
            self.write(local / name, (self.target / name).read_bytes())
        self.write(local / "custody-input.json", self.packet_raw)
        external = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "SnapshotPID": snapshot_pid,
                    "Waited": True, "ReturnCode": snapshot_return, "ResultSHA256": m.sha((local / "result.json").read_bytes()),
                    "ErrorsSHA256": m.sha((local / "errors.jsonl").read_bytes()), "ReleaseQualified": False}
        self.write(local / "snapshot-foreground.json", m.encode(external))
        return local, m.sha(m.encode(external))

    def rebind_archive(self, local, raw):
        # Deliberately rebind the outer envelope: the independent member and
        # physical-framing checks must still reject a bad archive's contents.
        path = local / "receipts.tar"
        self.write(path, raw)
        result = m.decode((local / "result.json").read_bytes())
        result["Files"]["receipts.tar"] = m.stream(path, m.ARCHIVE_LIMIT)
        self.write(local / "result.json", m.encode(result))
        foreground = m.decode((local / "snapshot-foreground.json").read_bytes())
        foreground["ResultSHA256"] = m.sha(m.encode(result))
        self.write(local / "snapshot-foreground.json", m.encode(foreground))
        return m.sha(m.encode(foreground))

    def assert_framing_refused(self, local, wait_sha):
        try:
            accepted = r.verify(local, m.sha(self.packet_raw), wait_sha)
        except ValueError as error:
            self.write(self.home / "physical-framing-observation.json", m.encode({"ReaderReturned": False, "Exception": repr(error)}))
            self.assertIn("fixed USTAR", str(error))
        else:
            self.write(self.home / "physical-framing-observation.json", m.encode({"ReaderReturned": True, "ActualReaderResult": accepted}))
            self.fail("reader accepted physically invalid archive after the outer envelope was rebound")

    def test_given_fixed_originals_when_copied_then_image_is_separate_and_bytes_verify(self):
        self.assertEqual(self.capture(), 0)
        local, wait_sha = self.transfer(0)
        result = r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.assertTrue(result["CustodyBytesVerified"] and result["SourceCaptureComplete"])
        self.assertFalse(result["ReleaseQualified"])
        self.assertTrue(result["NoWaitOrLifecycleVerdictDerivedFromHashes"])
        self.assertEqual((local / "images.tar").read_bytes(), self.image.read_bytes())
        with tarfile.open(local / "receipts.tar") as archive:
            self.assertNotIn("images.tar", archive.getnames())
            self.assertEqual(set(archive.getnames()), self.required)

    def test_given_failed_parent_when_captured_then_return_claim_stays_failed(self):
        self.foreground["ReturnCode"] = 2
        self.update_binding()
        self.assertEqual(self.capture(), 0)  # complete custody of failed evidence
        local, wait_sha = self.transfer(0)
        result = r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.assertEqual(result["ParentForegroundExternalClaim"]["ReturnCode"], 2)
        self.assertFalse(result["ReleaseQualified"])

    def test_given_missing_original_when_captured_then_failure_and_available_bytes_survive(self):
        missing = "parent-private/wait.json"
        (self.base / missing).unlink()
        self.assertEqual(self.capture(), 2)
        local, wait_sha = self.transfer(2)
        result = r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.assertTrue(result["CustodyBytesVerified"])
        self.assertFalse(result["SourceCaptureComplete"])
        self.assertIn(missing, result["Missing"])
        self.assertIn(b"FileNotFoundError", (local / "errors.jsonl").read_bytes())

    def test_given_symlink_original_when_captured_then_target_is_not_read(self):
        path = self.base / "parent-private/stdout.bin"
        path.unlink()
        secret = self.home / "unselected-secret"
        self.write(secret, b"UNSELECTED SECRET MUST NOT BE COPIED")
        path.symlink_to(secret)
        self.assertEqual(self.capture(), 2)
        with tarfile.open(self.target / "receipts.tar") as archive:
            self.assertNotIn("parent-private/stdout.bin", archive.getnames())
        self.assertNotIn(secret.read_bytes(), (self.target / "receipts.tar").read_bytes())

    def test_given_changed_source_pin_when_captured_then_admission_refuses_before_originals(self):
        self.write(self.base / "source/scripts/direct-fixture-guest-parent.py", b"CHANGED SOURCE DATA")
        self.assertEqual(self.capture(), 2)
        with tarfile.open(self.target / "receipts.tar") as archive:
            self.assertEqual(archive.getnames(), [])
        self.assertIn(b"selected source differs", (self.target / "errors.jsonl").read_bytes())

    def test_given_unknown_foreground_wait_when_captured_then_no_live_producer_read(self):
        self.foreground["Waited"] = False
        self.update_binding()
        self.assertEqual(self.capture(), 2)
        self.assertEqual((self.target / "images.tar").read_bytes(), b"")

    def test_given_oversize_stream_when_admitted_then_no_prefix_or_broad_read(self):
        self.write(self.image, b"12345")
        sink = io.BytesIO()
        with self.assertRaisesRegex(ValueError, "exceeds bound"):
            m.stream(self.image, 4, sink)
        self.assertEqual(sink.getvalue(), b"")
        self.assertEqual(m.IMAGE_LIMIT, 512 << 20)
        self.assertEqual(m.SMALL_LIMIT, 32 << 20)

    def test_given_image_mutation_during_stream_when_finished_then_no_stability_claim(self):
        original = self.image.read_bytes()
        case = self
        class Changed(io.BytesIO):
            def write(self, block):
                result = super().write(block)
                case.write(case.image, original + b"changed")
                return result
        with self.assertRaisesRegex(ValueError, "changed during stream"):
            m.stream(self.image, m.IMAGE_LIMIT, Changed())

    def test_given_corrupt_image_or_error_copy_when_read_back_then_refused(self):
        self.assertEqual(self.capture(), 0)
        local, wait_sha = self.transfer(0)
        self.write(local / "images.tar", b"CORRUPT TRANSPORT")
        with self.assertRaisesRegex(ValueError, "copied output bytes differ"):
            r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.write(local / "images.tar", self.image.read_bytes())
        self.write(local / "errors.jsonl", b"changed late error")
        with self.assertRaisesRegex(ValueError, "final error original differs"):
            r.verify(local, m.sha(self.packet_raw), wait_sha)

    def test_given_archive_body_corruption_when_outer_digest_rebound_then_inner_hash_refuses(self):
        self.assertEqual(self.capture(), 0)
        local, _ = self.transfer(0)
        path = local / "receipts.tar"
        raw = path.read_bytes()
        needle = b"INERT ORIGINAL DATA ONLY"
        self.assertIn(needle, raw)
        wait_sha = self.rebind_archive(local, raw.replace(needle, b"CHANGED ORIGINAL BYTES! ", 1))
        with self.assertRaisesRegex(ValueError, "archive original corruption"):
            r.verify(local, m.sha(self.packet_raw), wait_sha)

    def test_given_appended_second_archive_when_envelope_rebound_then_physical_eof_refuses(self):
        self.assertEqual(self.capture(), 0)
        local, _ = self.transfer(0)
        raw = (local / "receipts.tar").read_bytes()
        wait_sha = self.rebind_archive(local, raw + raw)
        self.assert_framing_refused(local, wait_sha)

    def test_given_nonzero_tail_when_envelope_rebound_then_zero_padding_refuses(self):
        self.assertEqual(self.capture(), 0)
        local, _ = self.transfer(0)
        raw = (local / "receipts.tar").read_bytes()
        self.assertEqual(raw[-512:], bytes(512))
        wait_sha = self.rebind_archive(local, raw[:-1] + b"!")
        self.assert_framing_refused(local, wait_sha)

    def test_given_truncated_record_padding_when_envelope_rebound_then_refused(self):
        self.assertEqual(self.capture(), 0)
        local, _ = self.transfer(0)
        raw = (local / "receipts.tar").read_bytes()
        wait_sha = self.rebind_archive(local, raw[:-512])
        self.assert_framing_refused(local, wait_sha)

    def test_given_missing_terminator_when_envelope_rebound_then_physical_eof_refuses(self):
        self.assertEqual(self.capture(), 0)
        local, _ = self.transfer(0)
        raw = (local / "receipts.tar").read_bytes()
        with tarfile.open(local / "receipts.tar") as archive:
            end = max(member.offset_data + ((member.size + 511) // 512) * 512 for member in archive)
        wait_sha = self.rebind_archive(local, raw[:end])
        self.assert_framing_refused(local, wait_sha)

    def test_given_reused_snapshot_when_called_again_then_originals_are_not_replaced(self):
        self.assertEqual(self.capture(), 0)
        before = (self.target / "errors.jsonl").stat().st_ino
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual((self.target / "errors.jsonl").stat().st_ino, before)

    def test_given_first_private_sink_denial_when_started_then_no_alternate_sink_exists(self):
        actual = m.create
        def create(path):
            if path.name == "errors.jsonl":
                raise PermissionError(errno.EACCES, "SYNTHETIC first private sink refused")
            return actual(path)
        with mock.patch.object(m, "create", create):
            with self.assertRaisesRegex(PermissionError, "SYNTHETIC first private sink refused"):
                self.capture()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_given_image_write_failure_after_prefix_when_read_back_then_no_image_claim(self):
        actual = m.create
        class Failed:
            def __init__(self, f): self.f = f
            def __getattr__(self, name): return getattr(self.f, name)
            def write(self, block):
                self.f.write(block[:1])
                raise OSError(errno.EIO, "SYNTHETIC private image write failed after prefix")
        def create(path):
            f = actual(path)
            return Failed(f) if path.name == "images.tar" else f
        with mock.patch.object(m, "create", create):
            self.assertEqual(self.capture(), 2)
        local, wait_sha = self.transfer(2)
        result = r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.assertTrue(result["CustodyBytesVerified"])
        self.assertFalse(result["ImageSourceCaptured"] or result["SourceCaptureComplete"])
        self.assertEqual((local / "images.tar").read_bytes(), self.image.read_bytes()[:1])
        self.assertIn(b"SYNTHETIC private image write failed after prefix", (local / "errors.jsonl").read_bytes())

    def receipt_write_fault(self, short_return):
        actual_create, actual_add = m.create, tarfile.TarFile.addfile
        writes, late_members, prefix, failed = [], [], [], []
        class Failed:
            def __init__(self, file): self.file = file
            def __getattr__(self, name): return getattr(self.file, name)
            def write(self, raw):
                writes.append(len(raw))
                if not failed:
                    failed.append(True)
                    prefix.append(raw[:512])
                    count = self.file.write(prefix[0])  # real retained bytes
                    if short_return:
                        return count
                    raise OSError(errno.EIO, "SYNTHETIC receipt append failed after prefix")
                return self.file.write(raw)
        def create(path):
            file = actual_create(path)
            return Failed(file) if path.name == "receipts.tar" else file
        def add(archive, member, *args, **kwargs):
            if failed:
                late_members.append(member.name)
            return actual_add(archive, member, *args, **kwargs)
        with mock.patch.object(m, "create", create), mock.patch.object(tarfile.TarFile, "addfile", add):
            code = self.capture()
        retained = (self.target / "receipts.tar").read_bytes()
        small = sum((self.target / name).stat().st_size for name in m.OUTPUTS if name != "images.tar")
        self.write(self.home / "receipt-write-observation.json", m.encode({"ActualSnapshotFunctionReturn": code,
                   "InjectedShortReturn": short_return, "UnderlyingRequestedWriteBytes": writes, "LaterMemberNames": late_members,
                   "RetainedArchiveBytes": len(retained), "RetainedArchiveSHA256": m.sha(retained), "ArchiveGuard": m.ARCHIVE_LIMIT,
                   "SmallAggregateBytes": small, "SmallAggregateGuard": m.SMALL_LIMIT,
                   "InjectedPrefixBytes": len(prefix[0]) if prefix else 0, "InjectedPrefixSHA256": m.sha(prefix[0]) if prefix else None}))
        self.assertEqual(code, 2)
        self.assertEqual(len(failed), 1)  # actual backend write was reached
        self.assertTrue(retained and retained.startswith(prefix[0]))
        self.assertEqual(late_members, [], "no member after uncertain append")
        self.assertEqual(len(writes), 1, "no backend/footer write after failure")
        self.assertEqual(retained, prefix[0])
        self.assertLessEqual(len(retained), m.ARCHIVE_LIMIT)
        self.assertLessEqual(small, m.SMALL_LIMIT)
        self.assertFalse(m.decode((self.target / "manifest.json").read_bytes())["CaptureComplete"])
        self.assertFalse(m.decode((self.target / "result.json").read_bytes())["CaptureComplete"])
        first = m.decode((self.target / "errors.jsonl").read_bytes().splitlines()[0])
        self.assertIn("short receipt archive write" if short_return else "SYNTHETIC receipt append failed after prefix", first["Exception"])

    def test_given_receipt_append_exception_after_prefix_then_no_later_member_or_write(self):
        self.receipt_write_fault(False)

    def test_given_receipt_short_write_after_prefix_then_no_later_member_or_write(self):
        self.receipt_write_fault(True)

    def test_given_final_close_failure_after_candidate_then_actual_wait2_rejects_upgrade(self):
        # A finite inert Python process owns the actual snapshot call and file
        # close. Root/platform/source-location seams remain explicitly test-only.
        child_source = """import importlib.util,os,pathlib,sys
source=pathlib.Path(SOURCE)
spec=importlib.util.spec_from_file_location('inert_snapshot_close_control',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
home=pathlib.Path(HOME);base=home/BASE;target=home/OUTLET/'snapshot'
actual=m.create
class CloseFailed:
 def __init__(self,file):self.file=file
 def __getattr__(self,name):return getattr(self.file,name)
 def close(self):
  raw=(target/'result.json').read_bytes()
  m.require(m.decode(raw)['CaptureComplete'] is True,'success candidate not reached')
  with actual(home/'candidate-before-close.json') as saved:m.write(saved,raw)
  self.file.close()
  raise OSError(5,'SYNTHETIC final private error close failed')
def create(path):
 file=actual(path)
 return CloseFailed(file) if path.name=='errors.jsonl' else file
m.create=create;m.HOME=home;m.native_outlet=lambda _:None
m.__file__=str(base/'source/scripts/snapshot-direct-fixture.py')
code=m.snapshot(RUN,HEAD,BINDING)
with actual(home/'actual-snapshot-function-return.json') as saved:m.write(saved,m.encode({'PID':os.getpid(),'ReturnCode':code}))
sys.exit(code)
"""
        values = {"SOURCE": str(ROOT / "snapshot-direct-fixture.py"), "HOME": str(self.home),
                  "BASE": self.base.name, "OUTLET": self.outlet.name, "RUN": self.run, "HEAD": self.head, "BINDING": m.sha(self.packet_raw)}
        # Fixed Python literal assignments, never a shell command or input code.
        helper = "\n".join(name + "=" + repr(value) for name, value in values.items()) + "\n" + child_source
        with (self.home / "final-close-child.stdout").open("xb") as stdout, (self.home / "final-close-child.stderr").open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600); os.fchmod(stderr.fileno(), 0o600)
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", helper], stdout=stdout, stderr=stderr,
                                     env={"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            code = self.wait_inert_child(child, "final-close-child")
        self.assertEqual(code, 2)
        actual_return = m.decode((self.home / "actual-snapshot-function-return.json").read_bytes())
        self.assertEqual(actual_return, {"PID": child.pid, "ReturnCode": code})
        candidate = (self.home / "candidate-before-close.json").read_bytes()
        self.assertTrue(m.decode(candidate)["CaptureComplete"])
        self.assertEqual((self.target / "result.json").read_bytes(), candidate)
        local, wait_sha = self.transfer(code, snapshot_pid=child.pid)
        result = r.verify(local, m.sha(self.packet_raw), wait_sha)
        self.assertTrue(result["CustodyBytesVerified"])
        self.assertFalse(result["SourceCaptureComplete"])
        self.assertEqual(result["SnapshotForegroundExternalClaim"]["ReturnCode"], 2)
        self.assertEqual((local / "errors.jsonl").read_bytes(), b"")  # no replacement after final close

    def test_given_selected_wait_refusal_then_stop_and_separate_owner_does_not_upgrade(self):
        waits, signals, producer_reads = [], [], []
        refusal = PermissionError(errno.EACCES, "SYNTHETIC selected inert child Wait refused")
        original_error, owner_error, owner_code, original_before, owner_waits = None, None, None, None, 0
        self.write(self.home / "stale-producer.json", b'{"MustNotReadAfterRefusal":true}\n')
        with m.create(self.home / "wait-refusal-child.stdout") as stdout, m.create(self.home / "wait-refusal-child.stderr") as stderr:
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import time;time.sleep(0.05)"],
                                     stdout=stdout, stderr=stderr, env={"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            real_wait = child.wait  # separate fixture owner only, never selected fallback
            def denied(*args, **kwargs):
                waits.append({"Args": list(args), "Kwargs": kwargs})
                raise refusal
            def signal_refused(*args, **kwargs):
                signals.append({"Args": list(args), "Kwargs": kwargs})
                raise AssertionError("signal attempted after selected Wait refusal")
            def stale_read(*args, **kwargs):
                producer_reads.append(str(args[0]))
                raise AssertionError("producer read after selected Wait refusal")
            try:
                with mock.patch.object(child, "wait", denied), mock.patch.object(child, "kill", signal_refused), \
                     mock.patch.object(child, "terminate", signal_refused), mock.patch.object(child, "send_signal", signal_refused), \
                     mock.patch.object(m, "read_small", stale_read):
                    try:
                        self.wait_inert_child(child, "wait-refusal-child")
                        m.read_small(self.home / "stale-producer.json")
                    except BaseException as error:
                        original_error = error
                original_before = (self.home / "wait-refusal-child-wait.json").read_bytes()
            finally:
                # Deliberately artificial refusal only: this separately named
                # owner invokes its saved public Wait once, with no signal.
                # It cannot rewrite or upgrade the selected owner's STOP.
                with m.create(self.home / "wait-refusal-fixture-owner.json") as owner:
                    if original_error is refusal:
                        owner_waits += 1
                        try:
                            owner_code = real_wait(timeout=3)
                        except BaseException as error:
                            owner_error = error
                    else:
                        owner_error = RuntimeError("synthetic selected refusal not observed; fixture Wait not attempted")
                    m.write(owner, m.encode({"PID": child.pid, "Waited": owner_error is None, "ReturnCode": owner_code,
                            "Exception": repr(owner_error) if owner_error else None, "Errno": getattr(owner_error, "errno", None),
                            "WaitInvocations": owner_waits, "OriginalSelectedWaitUpgraded": False,
                            "Scope": "separate fixture owner after SYNTHETIC refusal only", "SignalsAttempted": False}))
        self.write(self.home / "wait-refusal-observation.json", m.encode({"PID": child.pid, "SelectedWaitCalls": waits,
                   "SelectedSignals": signals, "ProducerReadsAfterRefusal": producer_reads, "OriginalException": repr(original_error),
                   "FixtureOwnerException": repr(owner_error), "FixtureOwnerReturnCode": owner_code,
                   "OriginalReportBeforeOwnerSHA256": m.sha(original_before) if original_before is not None else None,
                   "OriginalReportAfterOwnerSHA256": m.sha((self.home / "wait-refusal-child-wait.json").read_bytes()),
                   "OriginalWaitUpgraded": False, "CPythonFinalizationNotControlled": True}))
        self.assertIs(original_error, refusal)
        self.assertEqual(len(waits), 1)
        self.assertEqual(signals, [])
        self.assertEqual(producer_reads, [])
        self.assertIsNone(owner_error)
        self.assertEqual(owner_waits, 1)
        self.assertEqual(owner_code, 0)
        self.assertEqual((self.home / "wait-refusal-child-wait.json").read_bytes(), original_before)
        original = m.decode(original_before)
        self.assertEqual(original["PID"], child.pid)
        self.assertFalse(original["Waited"])
        self.assertIsNone(original["ReturnCode"])
        self.assertTrue(original["STOP"])
        self.assertEqual(original["Exception"], repr(refusal))
        self.assertEqual(original["Errno"], errno.EACCES)
        self.assertFalse((self.home / "wait-refusal-child-timeout-cleanup.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
