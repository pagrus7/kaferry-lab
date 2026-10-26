#!/usr/bin/env python3
"""Synthetic temporary-file controls only: no crypto, keys, network or runtime."""
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("notice_private_store", Path(__file__).with_name("store-link-notices-private.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RUN = "links-123456-2"
HEAD = "a" * 40
PIN = "ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57"
CMS = b"SYNTHETIC-CMS-not-encrypted\x00\xff\n"
SENTINEL = "PRIVATE-synthetic-original-never-public"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def put(path, body):
    with path.open("xb") as f:
        f.write(body)
    path.chmod(0o600)


class StorageControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="private-store-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.base, self.root = self.home / "repo", self.home / "external-private"
        self.base.mkdir(mode=0o700)
        self.root.mkdir(mode=0o700)
        info = self.root.stat()
        self.descriptor = {"version": 1, "storage_id": "synthetic-mount", "root_device": info.st_dev,
                           "root_inode": info.st_ino, "operator_confirmed_persistent": True, "private": True,
                           "exclusive_trusted_writer": True, "repository": "pagrus7/kaferry-lab", "repository_id": "1432555755"}
        put(self.root / "PRIVATE-STORE.json", encoded(self.descriptor))
        self.value = {"run_id": RUN, "source_head": HEAD, "job": "links", "attempt": "2",
                      "recipient_sha256": PIN, "layout": "linked-calibration-v2"}
        self.environment = {"GITHUB_REPOSITORY": "pagrus7/kaferry-lab", "GITHUB_REPOSITORY_ID": "1432555755",
                            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/codex/resilience-release-lab",
                            "GITHUB_JOB": "links", "GITHUB_SHA": HEAD, "GITHUB_RUN_ATTEMPT": "2", "GITHUB_RUN_ID": "123456"}
        self.quarantine = self.base / ".cache/link-quarantine" / RUN
        for directory in (self.base / ".cache", self.quarantine.parent, self.quarantine, self.base / ".cache/links"):
            directory.mkdir(mode=0o700)
        self.proof = {"namespace": "calibration/linked-caller", "run_id": RUN, "source_head": HEAD, "job": "links", "attempt": "2",
                      "foreground_return_observed": True, "foreground_exit_code": 0, "caller_cancelled_at_admission": False,
                      "writers_quiescent": True, "private_capture_complete": True, "setup_returned": True,
                      "cleanup_attempted": True, "cleanup_returned": True, "resources_cleaned": True,
                      "fixture_cleanup_succeeded": True, "child_started": True, "child_wait_returned": True,
                      "child_reaped": True, "stream_copies_joined": True, "anchor_started": True,
                      "anchor_wait_returned": True, "anchor_reaped": True, "subreaper_enabled": True,
                      "terminal_adopted_waits": 1, "actual_ECHILD_observed_by_driver": True,
                      "calibration_passed": True, "release_qualified": False,
                      "scope": "Reviewed driver final marker after actual wait/tree closure and primary sink sync/close; no ACK or Kaferry qualification."}
        self.metadata = dict(self.value, complete=True, cms_bytes=len(CMS), cms_sha256=hashlib.sha256(CMS).hexdigest(),
                             files=2, total_bytes=40, publication="DISABLED; explicit encrypted-public-quarantine exception required",
                             cipher="AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD", manifest_version=2,
                             components={"driver": {"availability": "captured", "files": 1, "total_bytes": 20},
                                         "fixture": {"availability": "captured", "files": 1, "total_bytes": 20}},
                             bundle_complete=True, release_qualified=False,
                             caller_declaration={"notice_writers_stopped_and_reaped": True, "observed_proof": False},
                             fixture_absence_sha256=None,
                             completion_scope="captured bytes only; no writer-quiescence, cleanup or calibration qualification")
        put(self.quarantine / "notice.cms", CMS)
        put(self.quarantine / "COMPLETE.json", encoded(self.metadata))
        put(self.base / ".cache/links/caller-proof.json", encoded(self.proof))
        self.target = self.root / (RUN + "--" + HEAD + "--links--2")

    def replace(self, path, value):
        path.write_bytes(encoded(value))

    def store(self):
        return m.store(self.base, self.root, "synthetic-mount", self.value)

    def no_complete(self):
        self.assertFalse((self.target / "COMPLETE.json").exists())

    def test_readonly_preflight_and_exact_literal_copy(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        selected = m.preflight(self.base, self.root, "synthetic-mount", self.value)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertEqual(selected["status"], "preflight-ready")
        self.assertIs(selected["complete"], False)
        self.assertEqual(selected["retention_limit_attempts"], 64)
        self.assertEqual(selected["retention_limit_bytes_per_attempt"], 13631488)
        result = self.store()
        self.assertEqual(result["status"], "stored")
        self.assertIs(result["complete"], True)
        expected = {"notice.cms": CMS, "SEAL-COMPLETE.json": encoded(self.metadata), "caller-proof.json": encoded(self.proof)}
        for name, body in expected.items():
            self.assertEqual((self.target / name).read_bytes(), body)
            self.assertEqual((self.target / name).stat().st_mode & 0o777, 0o600)
        marker_body = (self.target / "COMPLETE.json").read_bytes()
        marker = json.loads(marker_body)
        self.assertEqual(marker["files"], {name: {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()} for name, body in expected.items()})
        self.assertEqual(result["cms_sha256"], hashlib.sha256(CMS).hexdigest())
        self.assertEqual(result["storage_receipt_sha256"], hashlib.sha256(marker_body).hexdigest())
        self.assertEqual(result["stored_payload_bytes"], sum(map(len, expected.values())))
        self.assertEqual(set(p.name for p in self.target.iterdir()), set(expected) | {"COMPLETE.json", "OS-ERROR.json"})
        public = encoded(result)
        self.assertNotIn(str(self.root).encode(), public)
        self.assertNotIn(CMS, public)
        self.assertIs(marker["successful_stdout_receipt_required"], True)

    def test_collision_preserves_every_prior_byte(self):
        self.store()
        before = {p.name: p.read_bytes() for p in self.target.iterdir()}
        with self.assertRaises(m.s.Rejected):
            m.preflight(self.base, self.root, "synthetic-mount", self.value)
        with self.assertRaises(m.s.Rejected):
            self.store()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.target.iterdir()})

    def test_failed_calibration_with_closed_writers_still_stores(self):
        self.proof.update(foreground_exit_code=1, calibration_passed=False, resources_cleaned=False, fixture_cleanup_succeeded=False)
        self.replace(self.base / ".cache/links/caller-proof.json", self.proof)
        result = self.store()
        self.assertIs(result["complete"], True)
        self.assertIs(json.loads((self.target / "caller-proof.json").read_bytes())["calibration_passed"], False)

    def test_metadata_failures_stop_before_capsule_copy(self):
        edits = [lambda d: d.update(source_head="b" * 40), lambda d: d.update(run_id="links-123457-2"),
                 lambda d: d.update(attempt="3"), lambda d: d.update(recipient_sha256="0" * 64),
                 lambda d: d.update(cms_bytes=len(CMS) + 1), lambda d: d.update(cms_sha256="0" * 64),
                 lambda d: d.update(complete=False), lambda d: d.update(extra=SENTINEL),
                 lambda d: d.update(caller_declaration={"notice_writers_stopped_and_reaped": 1, "observed_proof": 0})]
        for edit in edits:
            with self.subTest(edit=edits.index(edit)):
                case = StorageControls("test_readonly_preflight_and_exact_literal_copy")
                case.setUp()
                try:
                    edit(case.metadata)
                    case.replace(case.quarantine / "COMPLETE.json", case.metadata)
                    with self.assertRaises(m.s.Rejected):
                        case.store()
                    case.no_complete()
                    self.assertFalse((case.target / "notice.cms").exists())
                finally:
                    case.doCleanups()

    def test_missing_and_invalid_closure_stop_before_copy(self):
        for key in ["writers_quiescent", "private_capture_complete", "foreground_return_observed", "actual_ECHILD_observed_by_driver"]:
            with self.subTest(key=key):
                proof = copy.deepcopy(self.proof)
                proof[key] = False
                self.assertRaises(m.s.Rejected, m.closure, encoded(proof), self.value)
        proof = copy.deepcopy(self.proof)
        proof["caller_cancelled_at_admission"] = True
        self.assertRaises(m.s.Rejected, m.closure, encoded(proof), self.value)
        proof = copy.deepcopy(self.proof)
        proof["child_reaped"] = False
        self.assertRaises(m.s.Rejected, m.closure, encoded(proof), self.value)
        (self.base / ".cache/links/caller-proof.json").unlink()
        with self.assertRaises(m.s.Rejected):
            self.store()
        self.no_complete()
        self.assertFalse((self.target / "notice.cms").exists())

    def test_root_admission_missing_inside_symlink_and_wrong_descriptor(self):
        unknown = self.home / "unknown-root"
        with self.assertRaises(OSError):
            m.preflight(self.base, unknown, "synthetic-mount", self.value)
        self.assertFalse(unknown.exists())
        with self.assertRaises(m.s.Rejected):
            m.preflight(self.base, self.base / ".cache", "synthetic-mount", self.value)
        link = self.home / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.s.Rejected):
            m.preflight(self.base, link, "synthetic-mount", self.value)
        self.descriptor["operator_confirmed_persistent"] = False
        self.replace(self.root / "PRIVATE-STORE.json", self.descriptor)
        with self.assertRaises(m.s.Rejected):
            m.preflight(self.base, self.root, "synthetic-mount", self.value)
        self.no_complete()

    def test_symlink_hardlink_and_oversize_source_rejected(self):
        extra = self.quarantine / "unexpected.json"
        put(extra, b"synthetic unexpected member")
        with self.assertRaises(m.s.Rejected):
            m.payloads(self.base, self.value)
        extra.unlink()
        original = self.quarantine / "notice.cms"
        original.unlink()
        other = self.home / "synthetic.cms"
        put(other, CMS)
        original.symlink_to(other)
        with self.assertRaises(m.s.Rejected):
            m.payloads(self.base, self.value)
        original.unlink()
        os.link(other, original)
        with self.assertRaises(m.s.Rejected):
            m.payloads(self.base, self.value)
        original.unlink()
        with original.open("xb") as f:
            f.truncate(12582913)
        original.chmod(0o600)
        with self.assertRaises(m.s.Rejected):
            m.payloads(self.base, self.value)
        self.no_complete()

    def test_quota_is_finite_and_does_not_delete_prior_attempts(self):
        for i in range(64):
            (self.root / ("links-" + str(200000 + i) + "-2--" + "b" * 40 + "--links--2")).mkdir(mode=0o700)
        before = sorted(p.name for p in self.root.iterdir())
        with self.assertRaises(m.s.Rejected):
            m.preflight(self.base, self.root, "synthetic-mount", self.value)
        with self.assertRaises(m.s.Rejected):
            self.store()
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))

    def test_short_write_has_no_completion_or_fallback(self):
        write = os.write
        calls = []
        def short(fd, body):
            if body == CMS:
                calls.append("capsule")
                return write(fd, body[:3])
            return write(fd, body)
        with mock.patch.object(m.os, "write", side_effect=short):
            with self.assertRaises(m.s.Rejected):
                self.store()
        self.no_complete()
        self.assertEqual(calls, ["capsule"])
        self.assertEqual((self.target / "notice.cms").read_bytes(), CMS[:3])
        self.assertEqual(len(list(self.root.iterdir())), 2)

    def test_literal_write_and_close_errors_both_retained_privately(self):
        write, close = os.write, os.close
        broken = {"fd": None, "closed": False}
        first = OSError(errno.EPERM, SENTINEL + "-write")
        second = OSError(errno.EIO, SENTINEL + "-close")
        def refuse(fd, body):
            if body == CMS:
                broken["fd"] = fd
                raise first  # Injected literal; no real permission denial.
            return write(fd, body)
        def failed_close(fd):
            if fd == broken["fd"] and not broken["closed"]:
                broken["closed"] = True
                close(fd)
                raise second
            return close(fd)
        with mock.patch.object(m.os, "write", side_effect=refuse), mock.patch.object(m.os, "close", side_effect=failed_close):
            with self.assertRaises(m.s.Rejected):
                self.store()
        self.no_complete()
        saved = json.loads((self.target / "OS-ERROR.json").read_bytes())
        self.assertTrue(saved["complete"])
        self.assertEqual([x["exact_text"] for x in saved["failures"][:2]], [str(first), str(second)])

    def test_terminal_sync_failure_invalidates_own_completion(self):
        rename, fsync = os.rename, os.fsync
        state = {"promoted": False, "failed": False}
        def promote(*args, **kwargs):
            result = rename(*args, **kwargs)
            state["promoted"] = True
            return result
        def sync(fd):
            if state["promoted"] and not state["failed"]:
                state["failed"] = True
                raise OSError(errno.EIO, SENTINEL + "-terminal-sync")
            return fsync(fd)
        with mock.patch.object(m.os, "rename", side_effect=promote), mock.patch.object(m.os, "fsync", side_effect=sync):
            with self.assertRaises(m.s.Rejected):
                self.store()
        self.assertTrue(state["failed"])
        self.no_complete()

    def test_error_sink_close_failure_stops_before_promotion(self):
        opened, close = os.open, os.close
        state = {"sink": None, "failed": False}
        def remember(path, *args, **kwargs):
            fd = opened(path, *args, **kwargs)
            if path == "OS-ERROR.json":
                state["sink"] = fd
            return fd
        def refuse(fd):
            if fd == state["sink"] and not state["failed"]:
                state["failed"] = True
                close(fd)
                raise OSError(errno.EIO, SENTINEL + "-terminal-sink-close")
            return close(fd)
        with mock.patch.object(m.os, "open", side_effect=remember), mock.patch.object(m.os, "close", side_effect=refuse):
            with self.assertRaises(m.s.Rejected):
                self.store()
        self.assertTrue(state["failed"])
        self.no_complete()
        self.assertTrue((self.target / "COMPLETE.pending.json").exists())

    def test_terminal_directory_close_has_no_success_receipt(self):
        opened, close = os.open, os.close
        state = {"target": None, "failed": False}
        def remember(path, *args, **kwargs):
            fd = opened(path, *args, **kwargs)
            if path == self.target.name and args and args[0] & os.O_DIRECTORY:
                state["target"] = fd
            return fd
        def refuse(fd):
            if fd == state["target"] and not state["failed"]:
                state["failed"] = True
                close(fd)
                raise OSError(errno.EIO, SENTINEL + "-terminal-directory-close")
            return close(fd)
        with mock.patch.object(m.os, "open", side_effect=remember), mock.patch.object(m.os, "close", side_effect=refuse):
            with self.assertRaises(m.s.Rejected):
                self.store()
        self.assertTrue(state["failed"])
        # Last-close uncertainty may leave a marker. A consumer must also have
        # the successful exact-attempt stdout receipt, which this run never returns.
        marker = json.loads((self.target / "COMPLETE.json").read_bytes())
        self.assertIs(marker["successful_stdout_receipt_required"], True)

    def test_untrusted_context_and_public_failure_never_print_original(self):
        for key, bad in [("GITHUB_REPOSITORY_ID", "foreign"), ("GITHUB_REPOSITORY", "fork/repo"),
                         ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/other"),
                         ("GITHUB_SHA", "b" * 40), ("GITHUB_RUN_ATTEMPT", "3")]:
            environment = dict(self.environment, **{key: bad})
            with self.assertRaises(m.s.Rejected):
                m.identity(RUN, HEAD, "links", "2", environment)
        self.assertEqual(m.identity(RUN, HEAD, "links", "2", self.environment), self.value)
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(m, "main", side_effect=OSError(errno.EPERM, SENTINEL)), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(m.cli([]), 1)
        self.assertEqual(json.loads(output.getvalue()), {"namespace": "calibration/private-notice-store", "status": "rejected-incomplete", "complete": False, "release_qualified": False})
        self.assertNotIn(SENTINEL, output.getvalue() + errors.getvalue())


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StorageControls)
    capture = io.StringIO()
    result = unittest.TextTestRunner(stream=capture, verbosity=0).run(suite)
    names = sorted(name for name in dir(StorageControls) if name.startswith("test_"))
    failed = set()
    for case, _detail in result.failures + result.errors:
        parent = getattr(case, "test_case", case)
        failed.add(parent._testMethodName)
    sources = {}
    for name in ("store-link-notices-private.py", "test-link-notice-storage.py", "seal-link-notices.py"):
        sources[name] = hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
    report = {"namespace": "calibration/private-storage-controls", "synthetic": True,
              "status": "passed" if result.wasSuccessful() else "failed",
              "controls": [{"case": name, "passed": name not in failed} for name in names],
              "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "source_sha256": sources, "release_qualified": False}
    try:
        parent = Path(".cache/m2/private-notice-storage-controls")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        m.s.check_chain(parent)
        m.s.check_private(parent.lstat(), directory=True)
        directory = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
        if not result.wasSuccessful():
            put(directory / "PRIVATE-FAILURES.txt", capture.getvalue().encode())
        put(directory / "public-report.json", encoded(report))
    except Exception:
        print('{"namespace":"calibration/private-storage-controls","status":"failed-incomplete-report","release_qualified":false}')
        return 1
    print(json.dumps({"namespace": "calibration/private-storage-controls", "status": report["status"],
                      "tests_run": result.testsRun, "failures": report["failures"], "errors": report["errors"],
                      "release_qualified": False}, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        status = main()
    except (Exception, KeyboardInterrupt):
        print('{"namespace":"calibration/private-storage-controls","status":"failed-incomplete-report","release_qualified":false}')
        status = 1
    raise SystemExit(status)
