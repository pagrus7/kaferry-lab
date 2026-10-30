#!/usr/bin/env python3
"""Filesystem/transport controls with literal DATA, no actual fixture/Wait.

No controller, Kafka, Docker, native parent, platform admission or OS Wait is
performed by these tests. All foreground records are visibly inert claims.
"""
import importlib.util
import errno
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
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

    def transfer(self, snapshot_return):
        local = self.home / "mac-private-copy"
        local.mkdir(mode=0o700)
        for name in m.OUTPUTS:
            self.write(local / name, (self.target / name).read_bytes())
        self.write(local / "custody-input.json", self.packet_raw)
        external = {"Version": "1", "RunID": self.run, "SourceHead": self.head, "SnapshotPID": 456,
                    "Waited": True, "ReturnCode": snapshot_return, "ResultSHA256": m.sha((local / "result.json").read_bytes()),
                    "ErrorsSHA256": m.sha((local / "errors.jsonl").read_bytes()), "ReleaseQualified": False}
        self.write(local / "snapshot-foreground.json", m.encode(external))
        return local, m.sha(m.encode(external))

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
        self.write(path, raw.replace(needle, b"CHANGED ORIGINAL BYTES! ", 1))
        result = m.decode((local / "result.json").read_bytes())
        result["Files"]["receipts.tar"] = m.stream(path, m.ARCHIVE_LIMIT)
        self.write(local / "result.json", m.encode(result))
        foreground = m.decode((local / "snapshot-foreground.json").read_bytes())
        foreground["ResultSHA256"] = m.sha(m.encode(result))
        self.write(local / "snapshot-foreground.json", m.encode(foreground))
        with self.assertRaisesRegex(ValueError, "archive original corruption"):
            r.verify(local, m.sha(self.packet_raw), m.sha(m.encode(foreground)))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
