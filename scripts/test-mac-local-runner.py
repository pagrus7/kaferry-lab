#!/usr/bin/env python3
"""Data-only controls. Temporary synthetic roots live beneath ignored .cache."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('mac_local_runner', Path(__file__).with_name('mac-local-runner.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CustodyControls(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).absolute().parent.parent / '.cache/m2/mac-local-return-20261027/controls'
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-', dir=base)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        info = self.root.stat()
        self.env = {'GITHUB_REPOSITORY': m.REPOSITORY, 'GITHUB_REPOSITORY_ID': m.REPOSITORY_ID,
                    'GITHUB_REF': m.REF, 'GITHUB_JOB': m.JOB, 'RUNNER_OS': 'macOS',
                    'RUNNER_ARCH': 'ARM64', 'GITHUB_EVENT_NAME': 'push',
                    'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        descriptor = {'version': 1, 'repository': m.REPOSITORY, 'repository_id': m.REPOSITORY_ID,
                      'ref': m.REF, 'job': m.JOB, 'root_device': info.st_dev,
                      'root_inode': info.st_ino, 'owner_uid': os.getuid(),
                      'approved_source_heads': ['a' * 40]}
        m.write(self.root / m.DESCRIPTOR, m.encode(descriptor))
        self.space = patch.object(m.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=1 << 40, f_frsize=1))
        self.space.start()
        self.addCleanup(self.space.stop)

    def op(self, action, env=None):
        return m.operate(action, self.root, env or self.env)

    def target(self):
        return self.root / m.leaf(m.identity(self.env))

    def failed(self, action):
        with self.assertRaises((m.Rejected, m.IOFailures, OSError, ValueError)):
            self.op(action)
        self.assertTrue((self.root / 'INFLIGHT.json').exists())

    def test_success_retains_originals_and_separate_callback_scope(self):
        self.op('start')
        self.op('calibrate')
        original = {p.name: p.read_bytes() for p in self.target().iterdir()}
        self.op('finish')
        self.assertFalse((self.root / 'INFLIGHT.json').exists())
        for name, body in original.items():
            self.assertEqual((self.target() / name).read_bytes(), body)
        proof = json.loads((self.target() / 'VERIFIED.json').read_bytes())
        self.assertFalse(proof['release_qualified'])
        self.assertNotIn('writers_quiescent', proof)
        self.assertNotIn('child_reaped', proof)
        next_env = dict(self.env, GITHUB_RUN_ID='124')
        self.op('start', next_env)
        self.assertEqual((self.target() / 'sample.bin').read_bytes(), m.PAYLOADS['sample.bin'])

    def test_missing_finish_blocks_next_run(self):
        self.op('start')
        self.op('calibrate')
        with self.assertRaises(m.Rejected):
            self.op('start', dict(self.env, GITHUB_RUN_ID='124'))
        self.assertEqual(len(list(self.root.glob('*local-retention*'))), 1)

    def test_collision_after_finished_attempt_rejected(self):
        for action in ('start', 'calibrate', 'finish'):
            self.op(action)
        with self.assertRaises(m.Rejected):
            self.op('start')

    def test_tampered_original_retained_failure_blocks_reuse(self):
        self.op('start')
        self.op('calibrate')
        (self.target() / 'sample.bin').write_bytes(b'tampered synthetic bytes')
        self.failed('finish')
        self.assertEqual((self.target() / 'sample.bin').read_bytes(), b'tampered synthetic bytes')
        error = json.loads((self.target() / 'OS-ERROR.json').read_bytes())
        self.assertEqual(error['failures'][0]['type'], 'Rejected')
        self.assertTrue((self.target() / 'CALLBACK.json').exists())
        self.assertFalse((self.target() / 'VERIFIED.json').exists())

    def test_wrong_head_repository_pr_and_arch_rejected_before_sink(self):
        for change in ({'GITHUB_SHA': 'b' * 40}, {'GITHUB_REPOSITORY_ID': '99'},
                       {'GITHUB_EVENT_NAME': 'pull_request'}, {'RUNNER_ARCH': 'X64'}):
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                self.op('start', dict(self.env, **change))
        self.assertEqual(set(p.name for p in self.root.iterdir()), {m.DESCRIPTOR})

    def test_descriptor_symlink_hardlink_and_owner_rejected(self):
        original = self.root / m.DESCRIPTOR
        saved = self.root.parent / (self.root.name + '-descriptor')
        original.rename(saved)
        self.addCleanup(lambda: saved.unlink(missing_ok=True))
        original.symlink_to(saved)
        with self.assertRaises(m.Rejected):
            self.op('start')
        original.unlink()
        os.link(saved, original)
        with self.assertRaises(m.Rejected):
            self.op('start')
        original.unlink()
        saved.rename(original)
        real_uid = os.getuid()
        with patch.object(m.os, 'getuid', return_value=real_uid + 1), self.assertRaises(m.Rejected):
            self.op('start')

    def test_payload_symlink_and_hardlink_never_finalized(self):
        self.op('start')
        self.op('calibrate')
        file = self.target() / 'sample.bin'
        file.unlink()
        file.symlink_to(self.target() / 'sample.json')
        self.failed('finish')
        self.assertTrue(file.is_symlink())
        error = json.loads((self.target() / 'OS-ERROR.json').read_bytes())
        self.assertEqual(error['failures'][0]['type'], 'Rejected')

    def test_hardlinked_payload_never_finalized(self):
        self.op('start')
        self.op('calibrate')
        os.link(self.target() / 'sample.bin', self.target() / 'extra.bin')
        self.failed('finish')
        self.assertEqual((self.target() / 'sample.bin').stat().st_nlink, 2)

    def test_missing_calibration_records_callback_but_no_success(self):
        self.op('start')
        self.failed('finish')
        self.assertTrue((self.target() / 'CALLBACK.json').exists())
        self.assertFalse((self.target() / 'VERIFIED.json').exists())

    def test_short_write_preserves_partial_bytes_and_original_error(self):
        self.op('start')
        actual = m.os.write
        once = [False]
        def short(fd, body):
            if body == m.PAYLOADS['sample.bin'] and not once[0]:
                once[0] = True
                return actual(fd, body[:7])
            return actual(fd, body)
        with patch.object(m.os, 'write', side_effect=short):
            self.failed('calibrate')
        self.assertEqual((self.target() / 'sample.bin').read_bytes(), m.PAYLOADS['sample.bin'][:7])
        error = json.loads((self.target() / 'OS-ERROR.json').read_bytes())
        self.assertIn('short write', error['failures'][0]['exact_text'])

    def test_write_sync_and_secondary_close_failures_both_retained(self):
        self.op('start')
        actual_sync, actual_close = m.os.fsync, m.os.close
        failed_fd = [None]
        def fail_sync(fd):
            if failed_fd[0] is None and os.fstat(fd).st_size == len(m.PAYLOADS['sample.bin']):
                failed_fd[0] = fd
                raise OSError(5, 'synthetic sync failure')
            return actual_sync(fd)
        def fail_close(fd):
            actual_close(fd)
            if fd == failed_fd[0]:
                failed_fd[0] = -1
                raise OSError(5, 'synthetic close failure')
        with patch.object(m.os, 'fsync', side_effect=fail_sync), patch.object(m.os, 'close', side_effect=fail_close):
            self.failed('calibrate')
        errors = json.loads((self.target() / 'OS-ERROR.json').read_bytes())['failures']
        self.assertEqual([row['exact_text'] for row in errors],
                         ['[Errno 5] synthetic sync failure', '[Errno 5] synthetic close failure'])
        self.assertEqual((self.target() / 'sample.bin').read_bytes(), m.PAYLOADS['sample.bin'])

    def test_free_space_guard_does_not_create_attempt(self):
        with patch.object(m.os, 'statvfs', return_value=types.SimpleNamespace(f_bavail=0, f_frsize=1)):
            with self.assertRaises(m.Rejected):
                self.op('start')
        self.assertEqual(set(p.name for p in self.root.iterdir()), {m.DESCRIPTOR})

    def test_read_failure_and_secondary_close_denial_both_retained(self):
        # Given an owned retained payload, when its read and final close both
        # fail, neither original may be replaced by the secondary failure.
        self.op('start')
        actual_read, actual_close = m.os.read, m.os.close
        failed_fd = [None]
        def fail_read(fd, maximum):
            if os.fstat(fd).st_size == len(m.PAYLOADS['sample.bin']):
                failed_fd[0] = fd
                raise OSError(5, 'synthetic original read failure')
            return actual_read(fd, maximum)
        def fail_close(fd):
            actual_close(fd)
            if fd == failed_fd[0]:
                failed_fd[0] = -1
                raise PermissionError(1, 'synthetic secondary close denial')
        with patch.object(m.os, 'read', side_effect=fail_read), patch.object(m.os, 'close', side_effect=fail_close):
            self.failed('calibrate')
        errors = json.loads((self.target() / 'OS-ERROR.json').read_bytes())['failures']
        self.assertEqual([row['exact_text'] for row in errors],
                         ['[Errno 5] synthetic original read failure',
                          '[Errno 1] synthetic secondary close denial'])
        self.assertEqual([row['errno'] for row in errors], [5, 1])
        self.assertEqual((self.target() / 'sample.bin').read_bytes(), m.PAYLOADS['sample.bin'])
        self.assertFalse((self.target() / 'MANIFEST.json').exists())
        self.assertFalse((self.target() / 'VERIFIED.json').exists())

    def test_attempt_cap_rejects_before_new_reservation(self):
        for number in range(1, 17):
            path = self.root / (str(number) + '-1-local-retention-' + 'a' * 40)
            path.mkdir(mode=0o700)
        with self.assertRaises(m.Rejected):
            self.op('start')
        self.assertFalse((self.root / 'INFLIGHT.json').exists())
        self.assertEqual(len(list(self.root.glob('*local-retention*'))), 16)

    def test_oversized_file_and_unsafe_mode_rejected(self):
        self.op('start')
        file = self.target() / 'oversized.bin'
        m.write(file, b'')
        with file.open('r+b') as stream:
            stream.truncate(m.MAX_FILE + 1)
        with self.assertRaises(m.Rejected):
            self.op('calibrate')
        self.assertEqual(file.stat().st_size, m.MAX_FILE + 1)
        self.assertTrue((self.root / 'INFLIGHT.json').exists())

    def test_unsafe_mode_rejected_and_denial_retained(self):
        self.op('start')
        (self.target() / 'INCOMPLETE.json').chmod(0o644)
        self.failed('calibrate')
        error = json.loads((self.target() / 'OS-ERROR.json').read_bytes())
        self.assertEqual(error['failures'][0]['type'], 'Rejected')

    def test_cli_rejects_unknown_arguments_with_fixed_status_only(self):
        output = io.StringIO()
        with patch.object(m.sys, 'stdout', output):
            self.assertEqual(m.main(['untrusted-private-text']), 1)
        self.assertEqual(json.loads(output.getvalue()),
                         {'status': 'local-calibration-incomplete-stopped', 'release_qualified': False})
        self.assertNotIn('untrusted-private-text', output.getvalue())

    def test_lost_latch_still_blocks_incomplete_attempt(self):
        self.op('start')
        (self.root / 'INFLIGHT.json').unlink()  # Synthetic loss; production never autounlocks.
        with self.assertRaises(m.Rejected):
            self.op('start', dict(self.env, GITHUB_RUN_ID='124'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
