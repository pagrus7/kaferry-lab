#!/usr/bin/env python3
"""Bounded SYNTHETIC controls. No Go, Docker, real HTTPS or upload.

Keys and all synthetic plaintext stay below excluded owner-only
.cache/private-notice-tests, never the public .cache/unit artifact tree.
"""
import importlib.util
import contextlib
import copy
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import threading
import time
import uuid
from unittest import mock
import zipfile

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("unseal", Path(__file__).with_name("unseal-link-notices.py"))
u = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(u)
s = u.s


def run():
    os.umask(0o077)
    root = s.private_root(Path.cwd() / ".cache/private-notice-tests") / ("run-" + uuid.uuid4().hex[:12])
    root.mkdir(mode=0o700)
    report = {"scope": "SYNTHETIC CALIBRATION ONLY; no real HTTPS, release execution or publication approval",
              "environment": {"os": os.uname().sysname, "machine": os.uname().machine, "python": sys.version.split()[0]},
              "run_directory": str(root), "controls": [], "status": "incomplete"}
    def passed(name, **data):
        report["controls"].append(dict(case=name, passed=True, **data))
    def base(name):
        path = root / name
        path.mkdir(mode=0o700)
        (path / ".cache").mkdir(mode=0o700)
        return path
    run_id, head = "notice-test", "a" * 40
    def input_tree(name):
        path = base(name)
        parent = s.private_root(path / ".cache/fixtures-private")
        directory = parent / (run_id + "-links")
        directory.mkdir(mode=0o700)
        marker = s.encode({"RunID": run_id, "Classification": "PRIVATE RAW EVIDENCE", "Publication": "withhold pending explicit redaction review"})
        s.write_private(directory / "PRIVATE.json", marker)
        return path, directory
    def reject(name, action, calls=0):
        with mock.patch.object(s, "openssl", wraps=s.openssl) as command:
            try:
                action()
            except s.PlatformDenied:
                raise  # actual denial stops the complete run; no alternate route
            except s.Rejected as error:
                assert command.call_count == calls, (name, command.call_count)
                passed(name, stock_commands=command.call_count, rejection=str(error))
            else:
                raise AssertionError("control failed to reject: " + name)
    def artifact(name, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            for member, body, mode in entries:
                info = zipfile.ZipInfo(member)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, body)
        body = buffer.getvalue()
        path = root / (name + ".zip")
        s.write_private(path, body)
        return path, s.digest(body)
    try:
        version = s.openssl(["version"], b"", root, "version", 65536)
        report["stock_tool"] = {"path": "/usr/bin/openssl", "version": version.decode().strip()}
        key, cert = root / "recipient.key.pem", root / "recipient.cert.pem"
        wrong, wrong_cert = root / "wrong.key.pem", root / "wrong.cert.pem"
        for label, key_path, cert_path in [("recipient", key, cert), ("wrong", wrong, wrong_cert)]:
            s.openssl(["req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1", "-subj", "/CN=LOCAL-SYNTHETIC-ONLY",
                       "-keyout", str(key_path), "-out", str(cert_path)], b"", root, label, 65536)
            s.check_private(key_path.lstat())
        identity = s.identities(run_id, head, s.digest(cert.read_bytes()), "synthetic", "1")
        source, directory = input_tree("positive")
        nested = directory / "operation-123" / "network" / "nested"
        nested.mkdir(mode=0o700, parents=True)
        # Actual JSON receipt one byte below the 256KiB maximum.
        value = {"RunID": run_id, "CauseText": ""}
        value["CauseText"] = "synthetic-notice-" * ((s.MAX_FILE - len(s.encode(value)) - 1) // 17)
        remaining = s.MAX_FILE - 1 - len(s.encode(value))
        value["CauseText"] += "x" * remaining
        receipt = s.encode(value)
        assert len(receipt) == s.MAX_FILE - 1
        s.write_private(nested / "docker-123.json", receipt)
        expected = s.snapshot(directory, run_id)
        complete = s.seal(source, identity, cert)
        quarantine = source / ".cache/link-quarantine" / run_id
        cms = (quarantine / "notice.cms").read_bytes()
        zip_path, trusted = artifact("positive", [("notice.cms", cms, stat.S_IFREG | 0o600)])
        recovered = u.unseal(base("recovery"), identity, zip_path, trusted, key, cert)
        assert recovered == expected
        passed("nested near-256KiB receipt exact-byte roundtrip", receipt_bytes=len(receipt), depth=4,
               files=complete["files"], payload_bytes=complete["total_bytes"], cms_bytes=len(cms))
        assert {p.name for p in quarantine.iterdir()} == {"notice.cms", "COMPLETE.json"}
        assert b"PRIVATE KEY" not in cms and b"synthetic-notice-" not in cms
        passed("quarantine has sole ciphertext plus complete metadata; raw stderr and keys separate")
        reject("exclusive output reservation forbids reseal", lambda: s.seal(source, identity, cert))
        reject("exclusive recovery reservation", lambda: u.unseal(root / "recovery", identity, zip_path, trusted, key, cert))
        # These are wrapper admission controls; neither OpenSSL nor ZIP parsing may run.
        for name, expected_hash in [("missing trusted ZIP digest", None), ("changed trusted ZIP digest", "0" * 64)]:
            with mock.patch.object(u.zipfile, "ZipFile", side_effect=AssertionError("ZIP parsed before trust gate")):
                reject(name, lambda h=expected_hash: u.unseal(base(name.replace(" ", "-")), identity, zip_path, h, key, cert))
        corrupt = bytearray(zip_path.read_bytes())
        corrupt[len(corrupt) // 2] ^= 1
        corrupt_path = root / "corrupt.zip"
        s.write_private(corrupt_path, corrupt)
        reject("corrupt envelope ZIP digest failure before decrypt", lambda: u.unseal(base("corrupt"), identity, corrupt_path, trusted, key, cert))
        for name, entries in [
            ("extra", [("notice.cms", cms, stat.S_IFREG | 0o600), ("extra", b"x", stat.S_IFREG | 0o600)]),
            ("traversal", [("../notice.cms", cms, stat.S_IFREG | 0o600)]),
            ("symlink", [("notice.cms", b"elsewhere", stat.S_IFLNK | 0o777)]),
            ("duplicate", [("notice.cms", cms, stat.S_IFREG | 0o600)] * 2),
        ]:
            path, hashed = artifact(name, entries)
            reject("ZIP " + name, lambda p=path, h=hashed, n=name: u.unseal(base("zip-" + n), identity, p, h, key, cert))
        reject("same certificate wrong actual private key", lambda: u.unseal(base("wrong-key"), identity, zip_path, trusted, wrong, cert), calls=1)
        assert not (root / "wrong-key/.cache/unsealed-link-notices" / run_id / "COMPLETE.json").exists()
        for name in ["oversize", "symlink", "unexpected", "reserved", "wrong-run", "permissions", "count", "total"]:
            path, tree = input_tree("input-" + name)
            if name == "oversize":
                s.write_private(tree / "docker-1.json", b"x" * (s.MAX_FILE + 1))
            elif name == "symlink":
                (tree / "docker-1.json").symlink_to(cert)
            elif name == "unexpected":
                s.write_private(tree / "raw.txt", b"x")
            elif name == "reserved":
                s.write_private(tree / "MANIFEST.json", s.encode({"RunID": run_id}))
            elif name == "wrong-run":
                s.write_private(tree / "docker-1.json", s.encode({"RunID": "another-run"}))
            elif name == "permissions":
                (tree / "PRIVATE.json").chmod(0o644)
            elif name == "count":
                for number in range(s.MAX_FILES):
                    s.write_private(tree / ("docker-" + str(number) + ".json"), b"{}")
            else:
                content = s.encode({"notice": "x" * (s.MAX_FILE - 20)})
                for number in range(33):
                    s.write_private(tree / ("docker-" + str(number) + ".json"), content)
            reject("input " + name + " before encryption", lambda p=path: s.seal(p, identity, cert))
        path, tree = input_tree("changed")
        target = tree / "docker-1.json"
        s.write_private(target, s.encode({"notice": "before"}))
        original, marker_reads = s.parse_json, 0
        def change_during_snapshot(body):
            nonlocal marker_reads
            result = original(body)
            if isinstance(result, dict) and result.get("Classification") == "PRIVATE RAW EVIDENCE":
                marker_reads += 1
                if marker_reads == 2:
                    with target.open("wb") as stream:
                        stream.write(s.encode({"notice": "after"}))
            return result
        with mock.patch.object(s, "parse_json", side_effect=change_during_snapshot):
            reject("changed input inventory before encryption", lambda: s.seal(path, identity, cert))
        clear, _ = s.pack(expected, identity)
        wrong_identity = dict(identity, source_head="b" * 40)
        reject("inner source identity mismatch", lambda: u.unpack(clear, wrong_identity))
        reject("inner trailing archive data", lambda: u.unpack(clear + b"untrusted", identity))
        for name, kind in [("../outside.json", tarfile.REGTYPE), ("docker.json", tarfile.SYMTYPE)]:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                entry = tarfile.TarInfo("link-notices/" + run_id + "/" + name)
                entry.type, entry.mode = kind, 0o600
                archive.addfile(entry, io.BytesIO())
            reject("inner unsafe member " + ("traversal" if ".." in name else "symlink"), lambda b=buffer.getvalue(): u.unpack(b, identity))
        # Representative real sink shapes: success summaries omit RunID.
        shapes_base, shapes_tree = input_tree("actual-shapes")
        (shapes_tree / "operation-42").mkdir(mode=0o700)
        shapes = {
            "operation-42/docker-intent.json": {"RunID": run_id, "Argv": ["docker", "info"], "StartedAt": "synthetic", "Classification": "PRIVATE RAW EVIDENCE"},
            "operation-42/docker-success.json": {"Intent": "private-intent-ref", "Status": "successful bounded command; raw success output discarded", "SHA256": "0" * 64, "Bytes": 0},
            "docker-log.json": {"RunID": run_id, "ContainerID": "synthetic-container", "Classification": "PRIVATE RAW EVIDENCE", "Stream": "combined stdout/stderr", "Bytes": "UFJJVkFURS1zeW50aGV0aWM="},
            "docker-readiness.json": {"RunID": run_id, "Endpoint": "127.0.0.1:1", "Attempt": 1, "Observation": {"Opened": False}, "CauseText": "UFJJVkFURS1zeW50aGV0aWM="},
            "network-notice.json": {"RunID": run_id, "Action": ["synthetic-network-action"], "Classification": "PRIVATE RAW EVIDENCE", "Notice": "UFJJVkFURS1zeW50aGV0aWM=", "CauseText": "UFJJVkFURS1zeW50aGV0aWM=", "NoticeSHA256": "0" * 64, "CauseSHA256": "0" * 64, "ReportedNoticeBytes": 17, "ReportedCauseBytes": 17, "NoticeComplete": True, "CauseComplete": True, "Cause": {}},
        }
        for name, shape in shapes.items():
            s.write_private(shapes_tree / name, s.encode(shape))
        shaped = s.snapshot(shapes_tree, run_id)
        shape_clear, _ = s.pack(shaped, identity)
        assert u.unpack(shape_clear, identity)[0] == shaped
        passed("actual fixture intent success-without-RunID log readiness network shapes")

        # Injected literal OS failures on the actual CLI entrypoints. The flag
        # rejects EVERY later os.open, proving retention uses the reserved FD.
        cli_cert = root / "link-notices-recipient.pem"
        s.write_private(cli_cert, cert.read_bytes())
        def cli_os_failure(name, consumer=False, point="read", number=errno.EACCES, expected_commands=0, sink_failure=False):
            case_base, _ = input_tree("os-" + name)
            action_started = False
            operation_fd, terminal_closes, preserved_denial = None, 0, False
            original_notice = "PRIVATE-SENTINEL original literal OS notice " + name
            private_path = "/private/PRIVATE-SENTINEL/" + name
            error = OSError(number, original_notice, private_path)
            error.__cause__ = OSError(errno.EIO, "PRIVATE-SENTINEL original cause", private_path + "-cause")
            error.__context__ = ValueError("PRIVATE-SENTINEL original context")
            original_read, original_write = s.read_regular, s.write_private
            original_open, original_persist = s.os.open, s.persist_receipt
            original_close, original_close_operation = s.os.close, s.close_operation
            original_reserve, original_rename = s.reserve, s.os.rename
            def fail():
                nonlocal action_started
                action_started = True
                raise error
            def opened(path, *args, **kwargs):
                if action_started:
                    raise AssertionError("new path opened after injected denial")
                if point == "open" and str(path).endswith(run_id + "-links"):
                    fail()
                result = original_open(path, *args, **kwargs)
                if Path(path).name == "OS-ERROR.json":
                    nonlocal operation_fd
                    operation_fd = result
                return result
            def closed(fd):
                nonlocal terminal_closes
                if fd == operation_fd and point in ("terminal-close", "prior-failure-close"):
                    terminal_closes += 1
                    original_close(fd)  # simulate uncertain close after releasing fixture FD
                    fail()
                return original_close(fd)
            def closed_operation(fd, prior_failure=None):
                nonlocal preserved_denial
                try:
                    return original_close_operation(fd, prior_failure)
                except s.PlatformDenied:
                    preserved_denial = isinstance(prior_failure, s.PlatformDenied)
                    raise
            def read(path, *args, **kwargs):
                if point in ("read", "prior-failure-close") or (point == "key" and Path(path) == key):
                    fail()
                return original_read(path, *args, **kwargs)
            def write(path, body):
                if ((point == "write" and Path(path).name == "notice.cms")
                        or (point == "recovered" and "receipts" in Path(path).parts)):
                    fail()
                if point == "pending-close" and Path(path).name == "COMPLETE.pending.json":
                    original_write(path, body)
                    fail()  # a supplied pending-file close error, before terminal FD close
                if point == "complete" and Path(path).name == "COMPLETE.pending.json":
                    # Fully written bytes then fsync denial must not publish COMPLETE.
                    with mock.patch.object(s.os, "fsync", side_effect=error):
                        try:
                            original_write(path, body)
                        except OSError:
                            nonlocal action_started
                            action_started = True
                            raise
                return original_write(path, body)
            def reserved(path, run_name):
                if point == "reservation":
                    fail()
                return original_reserve(path, run_name)
            def persisted(fd, body):
                if point == "receipt-initial":
                    fail()
                if point == "receipt-write" and b'"argv"' in body:
                    fail()
                if point == "receipt-failed" and b'"exceptions"' in body:
                    raise OSError(errno.EPERM, "PRIVATE-SENTINEL receipt sink failure", private_path)
                return original_persist(fd, body)
            def renamed(source, destination):
                if point == "rename":
                    fail()
                return original_rename(source, destination)
            # Receipt-failure case first triggers an original read failure.
            def selected_read(path, *args, **kwargs):
                if point == "receipt-failed":
                    fail()
                return read(path, *args, **kwargs)
            argv = ["unseal" if consumer else "seal", "--run-id", run_id, "--source-head", head,
                    "--recipient-sha256", identity["recipient_sha256"], "--job", identity["job"], "--attempt", identity["attempt"]]
            if consumer:
                argv += ["--artifact-zip", str(zip_path), "--trusted-artifact-zip-sha256", trusted, "--private-key", str(key)]
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(s, "CERT_PIN", identity["recipient_sha256"]))
                stack.enter_context(mock.patch.object(s, "__file__", str(root / "seal-link-notices.py")))
                stack.enter_context(mock.patch.object(u, "__file__", str(root / "unseal-link-notices.py")))
                stack.enter_context(mock.patch.object(Path, "cwd", return_value=case_base))
                stack.enter_context(mock.patch.object(sys, "argv", argv))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                stack.enter_context(mock.patch.object(s.os, "open", side_effect=opened))
                stack.enter_context(mock.patch.object(s.os, "close", side_effect=closed))
                stack.enter_context(mock.patch.object(s, "close_operation", side_effect=closed_operation))
                stack.enter_context(mock.patch.object(s, "read_regular", side_effect=selected_read))
                stack.enter_context(mock.patch.object(s, "write_private", side_effect=write))
                stack.enter_context(mock.patch.object(s, "persist_receipt", side_effect=persisted))
                stack.enter_context(mock.patch.object(s, "reserve", side_effect=reserved))
                stack.enter_context(mock.patch.object(s.os, "rename", side_effect=renamed))
                commands = stack.enter_context(mock.patch.object(s, "openssl", wraps=s.openssl))
                assert (u.cli() if consumer else s.cli()) == 1
                assert commands.call_count == expected_commands
            public = stdout.getvalue() + stderr.getvalue()
            assert "rejected" in public and "private evidence incomplete" in public
            assert "PRIVATE-SENTINEL" not in public and private_path not in public
            operation = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-sealing-private") / run_id
            complete_path = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-quarantine") / run_id / "COMPLETE.json"
            assert not complete_path.exists()
            if sink_failure:
                if (operation / "OS-ERROR.json").exists():
                    saved = (operation / "OS-ERROR.json").read_bytes()
                    assert b'"complete":true' not in saved
            else:
                saved = json.loads((operation / "OS-ERROR.json").read_bytes())
                assert saved["complete"] is True and original_notice in saved["exceptions"][0]["exact_text"]
                assert saved["exceptions"][0]["filename"] == private_path
                assert any("original cause" in e["exact_text"] for e in saved["exceptions"])
                assert any("original context" in e["exact_text"] for e in saved["exceptions"])
            if point in ("terminal-close", "prior-failure-close"):
                assert terminal_closes == 1
            if point == "prior-failure-close":
                assert preserved_denial
            passed("actual CLI OS boundary " + name, injected=True, errno=number, stock_commands=expected_commands,
                   evidence_incomplete=sink_failure, no_new_path_after_fault=True, no_complete=True)
        for name, consumer, point, number, commands, sink in [
            ("producer-cert-read-EACCES", False, "read", errno.EACCES, 0, False),
            ("producer-snapshot-open-EPERM", False, "open", errno.EPERM, 0, False),
            ("consumer-ZIP-read-EACCES", True, "read", errno.EACCES, 0, False),
            ("consumer-key-read-EPERM", True, "key", errno.EPERM, 0, False),
            ("producer-ciphertext-write-EACCES", False, "write", errno.EACCES, 1, False),
            ("consumer-recovered-write-EPERM", True, "recovered", errno.EPERM, 1, False),
            ("producer-complete-fsync-EACCES", False, "complete", errno.EACCES, 1, False),
            ("consumer-complete-fsync-EACCES", True, "complete", errno.EACCES, 1, False),
            ("producer-complete-rename-EPERM", False, "rename", errno.EPERM, 1, True),
            ("consumer-complete-rename-EPERM", True, "rename", errno.EPERM, 1, True),
            ("producer-pending-close-EIO", False, "pending-close", errno.EIO, 1, False),
            ("consumer-pending-close-EIO", True, "pending-close", errno.EIO, 1, False),
            ("producer-terminal-close-EIO", False, "terminal-close", errno.EIO, 1, True),
            ("consumer-terminal-close-EIO", True, "terminal-close", errno.EIO, 1, True),
            ("producer-prior-denial-terminal-close", False, "prior-failure-close", errno.EACCES, 0, False),
            ("consumer-prior-denial-terminal-close", True, "prior-failure-close", errno.EACCES, 0, False),
            ("initial-reservation-EACCES", False, "reservation", errno.EACCES, 0, True),
            ("initial-receipt-persistence-EPERM", True, "receipt-initial", errno.EPERM, 0, True),
            ("original-notice-receipt-failure", False, "receipt-failed", errno.EACCES, 0, True),
            ("stock-command-receipt-write-EACCES", False, "receipt-write", errno.EACCES, 1, False),
        ]:
            cli_os_failure(name, consumer, point, number, commands, sink)
        # Real entrypoints and pipe descriptors; fake child methods expose exact
        # kill/wait/close counts without launching a process or denying a facility.
        original_selector = s.selectors.DefaultSelector
        class PipeStream:
            def __init__(self, fd, name, fault):
                self.stream, self.name, self.fault = os.fdopen(fd, "wb" if name == "stdin" else "rb", buffering=0), name, fault
                self.closes = 0
            def fileno(self):
                return self.stream.fileno()
            @property
            def closed(self):
                return self.stream.closed
            def close(self):
                self.closes += 1
                self.stream.close()
                if self.fault == "stream" and self.name == "stderr":
                    raise OSError(errno.EIO, "PRIVATE-CANCEL original stream close")
        class OwnedChild:
            pid = 999999991  # synthetic identity only; never an actual kill target
            returncode = None
            def __init__(self, fault):
                self.fault, self.kills, self.waits, self.polls = fault, 0, 0, 0
                read_in, write_in = os.pipe()
                read_out, write_out = os.pipe()
                read_err, write_err = os.pipe()
                self.child_ends = [read_in, write_out, write_err]
                assert len(b"PRIVATE-CANCEL exact captured stderr") < 512
                assert os.write(write_err, b"PRIVATE-CANCEL exact captured stderr") == len(b"PRIVATE-CANCEL exact captured stderr")
                self.stdin, self.stdout, self.stderr = PipeStream(write_in, "stdin", fault), PipeStream(read_out, "stdout", fault), PipeStream(read_err, "stderr", fault)
            def poll(self):
                self.polls += 1
                if self.fault == "poll":
                    raise OSError(errno.EIO, "PRIVATE-CANCEL original poll")
                return self.returncode
            def kill(self):
                self.kills += 1
                if self.fault == "kill":
                    raise OSError(errno.EACCES, "PRIVATE-CANCEL original kill denial")
            def wait(self, timeout):
                self.waits += 1
                if self.fault == "wait":
                    raise s.subprocess.TimeoutExpired("PRIVATE-CANCEL owned wait", timeout)
                self.returncode = -9
                return self.returncode
            def release_fixture(self):
                for fd in self.child_ends:
                    os.close(fd)
                for stream in (self.stdin, self.stdout, self.stderr):
                    if not stream.closed:
                        stream.stream.close()
        def cancelled_cli(name, consumer=False, fault="", cancellation="keyboard"):
            case_base, _ = input_tree("cancel-" + name)
            child = OwnedChild(fault)
            interrupted = False
            original_open = s.os.open
            def opened(*args, **kwargs):
                if interrupted:
                    raise AssertionError("new path opened after child cancellation")
                return original_open(*args, **kwargs)
            class Selector:
                def __init__(self):
                    self.real, self.calls = original_selector(), 0
                def __enter__(self):
                    self.real.__enter__()
                    return self
                def __exit__(self, *args):
                    return self.real.__exit__(*args)
                def register(self, *args):
                    return self.real.register(*args)
                def unregister(self, *args):
                    return self.real.unregister(*args)
                def get_map(self):
                    return self.real.get_map()
                def select(self, timeout):
                    nonlocal interrupted
                    self.calls += 1
                    if self.calls == 1:
                        key = next(key for key in self.real.get_map().values() if key.data == "err")
                        return [(key, s.selectors.EVENT_READ)]
                    interrupted = True
                    if cancellation == "term":
                        s.signal.raise_signal(s.signal.SIGTERM)
                    if cancellation == "exit":
                        raise SystemExit("PRIVATE-CANCEL original SystemExit")
                    raise KeyboardInterrupt("PRIVATE-CANCEL original KeyboardInterrupt")
            argv = ["unseal" if consumer else "seal", "--run-id", run_id, "--source-head", head,
                    "--recipient-sha256", identity["recipient_sha256"], "--job", identity["job"], "--attempt", identity["attempt"]]
            if consumer:
                argv += ["--artifact-zip", str(zip_path), "--trusted-artifact-zip-sha256", trusted, "--private-key", str(key)]
            stdout, stderr = io.StringIO(), io.StringIO()
            previous_term = s.signal.getsignal(s.signal.SIGTERM)
            try:
                with contextlib.ExitStack() as stack:
                    for module, name_, value in [(s, "CERT_PIN", identity["recipient_sha256"]), (s, "__file__", str(root / "seal-link-notices.py")), (u, "__file__", str(root / "unseal-link-notices.py")), (Path, "cwd", lambda: case_base), (sys, "argv", argv)]:
                        stack.enter_context(mock.patch.object(module, name_, value))
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    stack.enter_context(mock.patch.object(s.os, "open", side_effect=opened))
                    stack.enter_context(mock.patch.object(s.selectors, "DefaultSelector", Selector))
                    popen = stack.enter_context(mock.patch.object(s.subprocess, "Popen", return_value=child))
                    assert (u.cli() if consumer else s.cli()) == 1
                    assert popen.call_count == 1
                assert s.signal.getsignal(s.signal.SIGTERM) == previous_term
                public = stdout.getvalue() + stderr.getvalue()
                assert "private evidence incomplete" in public and "PRIVATE-CANCEL" not in public
                directory = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-sealing-private") / run_id
                record = json.loads((directory / ("unseal-command.json" if consumer else "seal-command.json")).read_bytes())
                assert record["interrupted"] and not record["streams_complete"]
                assert s.base64.b64decode(record["stderr_base64"]) == b"PRIVATE-CANCEL exact captured stderr"
                assert record["failure"]["type"] == ("SystemExit" if cancellation == "exit" else "KeyboardInterrupt")
                expected_notice = "CLI received SIGTERM" if cancellation == "term" else "PRIVATE-CANCEL original " + ("SystemExit" if cancellation == "exit" else "KeyboardInterrupt")
                assert record["failure"]["exact_text"] == expected_notice
                os_notice = json.loads((directory / "OS-ERROR.json").read_bytes())
                assert os_notice["complete"] and any(node["type"] == record["failure"]["type"] for node in os_notice["exceptions"])
                assert record["child_reaped"] == (fault not in ("poll", "kill", "wait"))
                assert child.polls == 1 and child.kills == (0 if fault == "poll" else 1)
                assert child.waits == (0 if fault in ("poll", "kill") else 1)
                assert bool(record["cleanup_failures"]) == bool(fault)
                if fault:
                    assert "PRIVATE-CANCEL" in record["cleanup_failures"][0]["exact_text"]
                assert all(stream.closes == 1 for stream in (child.stdin, child.stdout, child.stderr))
                marker = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-quarantine") / run_id / "COMPLETE.json"
                assert not marker.exists()
                passed("actual CLI cancellation " + name, synthetic_child=True, actual_network=False,
                       kills=child.kills, waits=child.waits, reaped=record["child_reaped"], no_new_path_after_interrupt=True)
            finally:
                child.release_fixture()
        for name, consumer, fault, cancellation in [
            ("producer-keyboard", False, "", "keyboard"),
            ("consumer-system-exit", True, "", "exit"),
            ("producer-own-SIGTERM", False, "", "term"),
            ("consumer-own-SIGTERM", True, "", "term"),
            ("poll-failure-retains-original", False, "poll", "keyboard"),
            ("kill-denial-retains-original", False, "kill", "keyboard"),
            ("wait-timeout-retains-original", True, "wait", "keyboard"),
            ("stream-close-retains-original", True, "stream", "keyboard"),
        ]:
            cancelled_cli(name, consumer, fault, cancellation)
        # Reproduce early stdin closure with genuine local-pipe EPIPE and an
        # already-zero-exited fake child. A valid tiny recovery tar makes the
        # consumer control fail on the old swallowed-EPIPE implementation too.
        tiny_recovery, _ = s.pack({"PRIVATE.json": expected["PRIVATE.json"]}, identity)
        class StdinChild:
            pid = 999999992  # synthetic; never passed to an actual kill
            returncode = None
            def __init__(self, mode, response, small_pipe=False):
                self.mode, self.kills, self.waits, self.polls = mode, 0, 0, 0
                self.reader, write_in = os.pipe()
                read_out, write_out = os.pipe()
                read_err, write_err = os.pipe()
                self.pipe_capacity = None
                try:
                    if small_pipe:
                        action = "read owned stdout pipe capacity"
                        current = fcntl.fcntl(write_out, fcntl.F_GETPIPE_SZ)
                        if current > 8192:
                            action = "reduce owned stdout pipe capacity to8192"
                            fcntl.fcntl(write_out, fcntl.F_SETPIPE_SZ, 8192)
                        action = "read back owned stdout pipe capacity"
                        self.pipe_capacity = fcntl.fcntl(write_out, fcntl.F_GETPIPE_SZ)
                        assert 0 < self.pipe_capacity <= 8192, "native small-pipe capacity not established"
                except BaseException as error:
                    report["native_pipe_capacity_failure"] = {"action": action, "type": type(error).__name__,
                            "errno": getattr(error, "errno", None), "exact_text": str(error), "retry": False}
                    cleanup = []
                    for fd in (self.reader, write_in, read_out, write_out, read_err, write_err):
                        try:
                            os.close(fd)
                        except OSError as close_error:
                            cleanup.append({"errno": close_error.errno, "exact_text": str(close_error)})
                    report["native_pipe_capacity_failure"]["cleanup_failures"] = cleanup
                    raise s.EvidenceIncomplete("owned native pipe capacity control failed; exact private notice retained; route stopped") from None
                # Only fixed stderr literals smaller than the512byte POSIX
                # PIPE_BUF minimum are synchronously written to fresh pipes.
                assert len(b"PRIVATE-EPIPE exact stderr") < 512
                assert os.write(write_err, b"PRIVATE-EPIPE exact stderr") == len(b"PRIVATE-EPIPE exact stderr")
                os.close(write_err)
                self.stdin, self.stdout, self.stderr = PipeStream(write_in, "stdin", ""), PipeStream(read_out, "stdout", ""), PipeStream(read_err, "stderr", "")
                self.writer_stop = threading.Event()
                self.writer_result = {"intended_bytes": len(response), "written_bytes": 0,
                                      "failure": None, "close_failure": None, "closed": False,
                                      "cancelled": False, "timed_out": False}
                raw_write, raw_close = os.write, os.close
                os.set_blocking(write_out, False)
                def write_response():
                    # Test-local producer only: never preload a capacity-sized
                    # blocking write before the production reader can run.
                    deadline = time.monotonic() + 5
                    try:
                        with original_selector() as selector:
                            selector.register(write_out, s.selectors.EVENT_WRITE)
                            while self.writer_result["written_bytes"] < len(response):
                                if self.writer_stop.is_set():
                                    self.writer_result["cancelled"] = True
                                    break
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    self.writer_result["timed_out"] = True
                                    break
                                if not selector.select(min(remaining, 0.05)):
                                    continue
                                offset = self.writer_result["written_bytes"]
                                try:
                                    count = raw_write(write_out, response[offset:offset + 512])
                                except BlockingIOError:
                                    continue
                                if count <= 0:
                                    raise OSError(errno.EIO, "synthetic stdout writer made no progress")
                                self.writer_result["written_bytes"] += count
                    except BaseException as error:
                        self.writer_result["failure"] = {"type": type(error).__name__,
                                "errno": getattr(error, "errno", None), "exact_text": str(error)}
                    finally:
                        try:
                            raw_close(write_out)
                            self.writer_result["closed"] = True
                        except OSError as error:
                            self.writer_result["close_failure"] = {"errno": error.errno, "exact_text": str(error)}
                self.writer = threading.Thread(target=write_response, name="notice-synthetic-stdout")
                self.writer.start()
                self.stdin_fd = write_in
                self.consumed = bytearray()
                if mode == "closed":
                    self.drop_reader()
            def drop_reader(self):
                if self.reader is not None:
                    os.close(self.reader)
                    self.reader = None
            def poll(self):
                self.polls += 1
                self.returncode = 0
                return 0
            def kill(self):
                self.kills += 1
                raise AssertionError("zero-exited fake child must not be killed")
            def wait(self, timeout):
                self.waits += 1
                if self.mode == "full":
                    while True:
                        chunk = os.read(self.reader, 65536)
                        if not chunk:
                            break
                        self.consumed.extend(chunk)
                self.returncode = 0
                return 0
            def release_fixture(self):
                self.writer_stop.set()
                self.drop_reader()
                for stream in (self.stdin, self.stdout, self.stderr):
                    if not stream.closed:
                        stream.stream.close()
                self.writer.join(timeout=2)
                self.writer_result["joined"] = not self.writer.is_alive()
                report.setdefault("fake_stdout_writers", []).append(dict(self.writer_result, pipe_capacity=self.pipe_capacity))
                assert self.writer_result["joined"] and self.writer_result["closed"]
                assert not self.writer_result["timed_out"] and self.writer_result["close_failure"] is None
                if self.writer_result["failure"] is not None:
                    assert self.mode != "full" and self.writer_result["failure"]["errno"] == errno.EPIPE
                if self.mode == "full":
                    assert self.writer_result["failure"] is None
                    assert self.writer_result["written_bytes"] == self.writer_result["intended_bytes"]
        class InputSelector:
            def __init__(self):
                self.real, self.calls = original_selector(), 0
            def __enter__(self):
                self.real.__enter__()
                return self
            def __exit__(self, *args):
                return self.real.__exit__(*args)
            def register(self, *args):
                return self.real.register(*args)
            def unregister(self, *args):
                return self.real.unregister(*args)
            def get_map(self):
                return self.real.get_map()
            def select(self, timeout):
                self.calls += 1
                ready = self.real.select(timeout)
                if not ready:
                    return []
                wanted = "err" if self.calls == 1 else "in"
                return [next((item for item in ready if item[0].data == wanted), ready[0])]
        def early_stdin_cli(name, consumer=False, partial=False):
            case_base, tree = input_tree("stdin-" + name)
            if partial:
                s.write_private(tree / "large.json", s.encode({"notice": "x" * 150000}))
            child = StdinChild("partial" if partial else "closed", tiny_recovery if consumer else b"synthetic zero-exit output")
            original_write, original_open = s.os.write, s.os.open
            attempts, accepted, original_pipe_error = 0, 0, None
            def written(fd, body):
                nonlocal attempts, accepted, original_pipe_error
                if fd != child.stdin_fd:
                    return original_write(fd, body)
                attempts += 1
                try:
                    count = original_write(fd, body)
                except BrokenPipeError as error:
                    original_pipe_error = error
                    raise
                accepted += count
                if partial:
                    child.drop_reader()
                return count
            def opened(*args, **kwargs):
                if original_pipe_error is not None:
                    raise AssertionError("new path opened after original EPIPE")
                return original_open(*args, **kwargs)
            argv = ["unseal" if consumer else "seal", "--run-id", run_id, "--source-head", head,
                    "--recipient-sha256", identity["recipient_sha256"], "--job", identity["job"], "--attempt", identity["attempt"]]
            if consumer:
                argv += ["--artifact-zip", str(zip_path), "--trusted-artifact-zip-sha256", trusted, "--private-key", str(key)]
            stdout, stderr = io.StringIO(), io.StringIO()
            try:
                with contextlib.ExitStack() as stack:
                    for module, name_, value in [(s, "CERT_PIN", identity["recipient_sha256"]), (s, "__file__", str(root / "seal-link-notices.py")), (u, "__file__", str(root / "unseal-link-notices.py")), (Path, "cwd", lambda: case_base), (sys, "argv", argv)]:
                        stack.enter_context(mock.patch.object(module, name_, value))
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    stack.enter_context(mock.patch.object(s.os, "write", side_effect=written))
                    stack.enter_context(mock.patch.object(s.os, "open", side_effect=opened))
                    stack.enter_context(mock.patch.object(s.selectors, "DefaultSelector", InputSelector))
                    popen = stack.enter_context(mock.patch.object(s.subprocess, "Popen", return_value=child))
                    commands = stack.enter_context(mock.patch.object(s, "openssl", wraps=s.openssl))
                    assert (u.cli() if consumer else s.cli()) == 1
                    assert popen.call_count == commands.call_count == 1
                    intended = len(commands.call_args.args[1])
                assert original_pipe_error is not None and original_pipe_error.errno == errno.EPIPE
                assert attempts == (2 if partial else 1)
                assert (0 < accepted < intended) if partial else accepted == 0
                assert child.polls == child.waits == 1 and child.kills == 0
                assert all(stream.closes == 1 for stream in (child.stdin, child.stdout, child.stderr))
                public = stdout.getvalue() + stderr.getvalue()
                assert "private evidence incomplete" in public and "PRIVATE-EPIPE" not in public
                assert str(original_pipe_error) not in public
                directory = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-sealing-private") / run_id
                record = json.loads((directory / ("unseal-command.json" if consumer else "seal-command.json")).read_bytes())
                assert record["failure"] == {"type": "BrokenPipeError", "errno": errno.EPIPE, "exact_text": str(original_pipe_error)}
                assert record["input_intended_bytes"] == intended and record["input_accepted_bytes"] == accepted
                assert not record["input_complete"] and not record["streams_complete"]
                assert record["child_reaped"] and record["returncode"] == 0
                assert not record["cleanup_failures"] and s.base64.b64decode(record["stderr_base64"]) == b"PRIVATE-EPIPE exact stderr"
                notice = json.loads((directory / "OS-ERROR.json").read_bytes())
                assert notice["complete"] and any(node["errno"] == errno.EPIPE and node["exact_text"] == str(original_pipe_error) for node in notice["exceptions"])
                marker = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-quarantine") / run_id / "COMPLETE.json"
                assert not marker.exists()
                passed("actual CLI early stdin zero-exit " + name, synthetic_child=True, real_pipe_EPIPE=True,
                       intended_bytes=intended, accepted_bytes=accepted, write_attempts=attempts, waits=child.waits, kills=child.kills)
            finally:
                child.release_fixture()
        early_stdin_cli("producer-empty-acceptance")
        early_stdin_cli("consumer-empty-acceptance", consumer=True)
        early_stdin_cli("producer-partial-acceptance", partial=True)
        version_receipt = json.loads((root / "version-command.json").read_bytes())
        assert version_receipt["input_intended_bytes"] == version_receipt["input_accepted_bytes"] == 0
        assert version_receipt["input_complete"] and version_receipt["streams_complete"]
        passed("zero-input real stock version retains complete zero counts")
        full_body = b"reviewed bounded synthetic full input\n" * 10
        full_child = StdinChild("full", b"reviewed full-input response")
        try:
            with mock.patch.object(s.subprocess, "Popen", return_value=full_child):
                with mock.patch.object(s.selectors, "DefaultSelector", InputSelector):
                    full_output = s.openssl(["version"], full_body, root, "full-input-control", 65536)
            assert full_output == b"reviewed full-input response" and full_child.consumed == full_body
            full_receipt = json.loads((root / "full-input-control-command.json").read_bytes())
            assert full_receipt["input_intended_bytes"] == full_receipt["input_accepted_bytes"] == len(full_body)
            assert full_receipt["input_complete"] and full_receipt["streams_complete"] and full_receipt["child_reaped"]
            assert full_child.waits == 1 and full_child.polls == full_child.kills == 0
            passed("full real-pipe input accepted and independently consumed exactly", intended_bytes=len(full_body), synthetic_child=True)
        finally:
            full_child.release_fixture()
        if sys.platform == "linux":
            # On the native Linux CI route this control is mandatory, never a
            # green skip: actual capacity/readback must be <=8KiB, without
            # enlarging the pipe or retrying any denied operation.
            assert hasattr(fcntl, "F_GETPIPE_SZ") and hasattr(fcntl, "F_SETPIPE_SZ")
            small_child = StdinChild("full", tiny_recovery, small_pipe=True)
            try:
                assert len(tiny_recovery) > small_child.pipe_capacity
                with mock.patch.object(s.subprocess, "Popen", return_value=small_child):
                    with mock.patch.object(s.selectors, "DefaultSelector", InputSelector):
                        actual = s.openssl(["synthetic-small-pipe-fixture"], full_body, root, "small-pipe-control", s.MAX_TAR)
                assert actual == tiny_recovery
                assert u.unpack(actual, identity)[0] == {"PRIVATE.json": expected["PRIVATE.json"]}
                assert small_child.consumed == full_body and small_child.waits == 1
                assert small_child.kills == small_child.polls == 0
            finally:
                small_child.release_fixture()
            passed("native small-pipe valid recovery stdout fully drained and writer joined", synthetic_child=True,
                   actual_pipe_capacity=small_child.pipe_capacity, stdout_bytes=len(tiny_recovery), writer_joined=True)
        else:
            report.setdefault("unexercised_controls", []).append({"case": "native small-pipe valid recovery stdout", "status": "UNEXERCISED",
                    "reason": "Linux F_GETPIPE_SZ/F_SETPIPE_SZ unavailable on this route", "native_acceptance_required": True})
        for consumer in [False, True]:
            argv = ["unseal" if consumer else "seal", "--run-id", "../PRIVATE-SENTINEL", "--source-head", head,
                    "--recipient-sha256", identity["recipient_sha256"], "--job", identity["job"], "--attempt", identity["attempt"]]
            if consumer:
                argv += ["--artifact-zip", str(zip_path), "--trusted-artifact-zip-sha256", trusted, "--private-key", str(key)]
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "argv", argv), mock.patch.object(s, "reserve_operation") as reserved:
                with mock.patch.object(s.os, "open", side_effect=AssertionError("filesystem write before pure identity validation")):
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        assert (u.cli() if consumer else s.cli()) == 1
                assert reserved.call_count == 0
            assert "PRIVATE-SENTINEL" not in stdout.getvalue() + stderr.getvalue()
            passed("actual CLI pure identity admission before filesystem " + ("consumer" if consumer else "producer"))
        # Operational retrieval uses only literal metadata and a stub TLS
        # transport here. No test can create a real HTTPS connection.
        retrieval_spec = importlib.util.spec_from_file_location("retrieve_notices", Path(__file__).with_name("retrieve-link-notices.py"))
        r = importlib.util.module_from_spec(retrieval_spec)
        retrieval_spec.loader.exec_module(r)
        github_run, job_id, artifact_id = 90210, 8123, 2345
        synthetic_token = "LOCAL_SYNTHETIC_TOKEN_NEVER_PERSIST"
        repository = {"id": r.REPOSITORY_ID, "full_name": r.REPOSITORY, "fork": False}
        run_info = {"id": github_run, "run_attempt": 1, "head_sha": head, "head_branch": r.BRANCH,
                    "path": r.WORKFLOW, "event": "workflow_dispatch", "pull_requests": [], "status": "completed",
                    "workflow_id": 395476803, "repository": repository, "head_repository": copy.deepcopy(repository)}
        job_info = {"id": job_id, "run_id": github_run, "run_attempt": 1, "head_sha": head,
                    "name": identity["job"], "status": "completed", "conclusion": "failure", "url": r.ROOT + "/jobs/" + str(job_id)}
        artifact_info = {"id": artifact_id,
                "name": "encrypted-link-notices-" + identity["job"] + "-" + head + "-" + str(github_run) + "-1",
                "size_in_bytes": zip_path.stat().st_size, "expired": False, "digest": "sha256:" + trusted,
                "archive_download_url": r.ROOT + "/artifacts/" + str(artifact_id) + "/zip",
                "workflow_run": {"id": github_run, "repository_id": r.REPOSITORY_ID, "head_repository_id": r.REPOSITORY_ID,
                                 "head_branch": r.BRANCH, "head_sha": head}}
        fixtures = {"run": run_info, "attempt": copy.deepcopy(run_info), "jobs": {"total_count": 1, "jobs": [job_info]},
                    "artifacts": {"total_count": 1, "artifacts": [artifact_info]}, "artifact": copy.deepcopy(artifact_info)}
        api_run = r.ROOT + "/runs/" + str(github_run)
        cdn_url = "https://synthetic.blob.core.windows.net/notices/artifact.zip?signed=LOCAL-SYNTHETIC"
        routes = {api_run: "run", api_run + "/attempts/1": "attempt", api_run + "/attempts/1/jobs?per_page=100": "jobs",
                  api_run + "/artifacts?per_page=100": "artifacts", r.ROOT + "/artifacts/" + str(artifact_id): "artifact"}
        def retrieved_case(name, changed=None, *, success=False, downloads=0, corrupt=False, reflected_error=False, http_failure=False, malformed=False, close_fault=False, rename_fault=False, term=False):
            data = copy.deepcopy(fixtures)
            if changed is not None:
                changed(data)
            case_base = base("api-" + name)
            download_calls, request_calls = 0, 0
            terminal_fd, terminal_closes, fault_reached, preserved_denial = None, 0, False, False
            original_reserve_operation, original_close = r.s.reserve_operation, r.s.os.close
            original_open, original_rename, original_close_operation = r.s.os.open, r.s.os.rename, r.s.close_operation
            def reserved_operation(path, run_name):
                nonlocal terminal_fd
                result = original_reserve_operation(path, run_name)
                if Path(path).name == "retrieved-link-notices":
                    terminal_fd = result[1]
                return result
            def closed(fd):
                nonlocal terminal_closes, fault_reached
                if close_fault and fd == terminal_fd:
                    terminal_closes += 1
                    original_close(fd)
                    fault_reached = True
                    raise OSError(errno.EIO, "PRIVATE HTTP terminal close original")
                return original_close(fd)
            def closed_operation(fd, prior_failure=None):
                nonlocal preserved_denial
                try:
                    return original_close_operation(fd, prior_failure)
                except r.s.PlatformDenied:
                    preserved_denial = isinstance(prior_failure, r.s.PlatformDenied)
                    raise
            def opened(*args, **kwargs):
                if fault_reached:
                    raise AssertionError("new path after terminal retrieval failure")
                return original_open(*args, **kwargs)
            def renamed(source, destination):
                nonlocal fault_reached
                if rename_fault and Path(source).parent.parent.name == "retrieved-link-notices":
                    fault_reached = True
                    raise OSError(errno.EPERM, "PRIVATE HTTP terminal rename original")
                return original_rename(source, destination)
            def transport(url, token, maximum, deadline, download=False):
                nonlocal download_calls, request_calls
                request_calls += 1
                assert token == synthetic_token
                if term:
                    r.signal.raise_signal(r.signal.SIGTERM)
                if reflected_error or http_failure:
                    error = OSError(errno.EACCES, "PRIVATE HTTP original status notice", "/private/HTTP-SENTINEL")
                    error.__cause__ = ValueError("original protocol context")
                    if reflected_error:
                        error.__context__ = ValueError(synthetic_token)
                    raise error
                if download:
                    download_calls += 1
                    if url == artifact_info["archive_download_url"]:
                        return 302, cdn_url, b""
                    assert url == cdn_url
                    body = bytearray(zip_path.read_bytes())
                    if corrupt:
                        body[len(body) // 2] ^= 1
                    return 200, None, bytes(body)
                assert url in routes
                if malformed:
                    return 200, None, b"PRIVATE HTTP original non-JSON response"
                return 200, None, s.encode(data[routes[url]])
            expected_consumers = 1 if success or ((close_fault or rename_fault) and not http_failure) else 0
            stdout, stderr = io.StringIO(), io.StringIO()
            previous_term = r.signal.getsignal(r.signal.SIGTERM)
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(r, "https_get", side_effect=transport))
                stack.enter_context(mock.patch.object(r.http.client, "HTTPSConnection", side_effect=AssertionError("real network forbidden")))
                stack.enter_context(mock.patch.object(r.s, "reserve_operation", side_effect=reserved_operation))
                stack.enter_context(mock.patch.object(r.s.os, "close", side_effect=closed))
                stack.enter_context(mock.patch.object(r.s.os, "open", side_effect=opened))
                stack.enter_context(mock.patch.object(r.s.os, "rename", side_effect=renamed))
                stack.enter_context(mock.patch.object(r.s, "close_operation", side_effect=closed_operation))
                consumer = stack.enter_context(mock.patch.object(r.u, "unseal", wraps=r.u.unseal))
                if close_fault or rename_fault or term:
                    argv = ["retrieve", "--run-id", run_id, "--source-head", head, "--recipient-sha256", identity["recipient_sha256"],
                            "--job", identity["job"], "--attempt", identity["attempt"], "--github-run-id", str(github_run), "--token-stdin", "--private-key", str(key)]
                    for module, name_, value in [(r.s, "CERT_PIN", identity["recipient_sha256"]), (r, "__file__", str(root / "retrieve-link-notices.py")), (Path, "cwd", lambda: case_base), (sys, "argv", argv)]:
                        stack.enter_context(mock.patch.object(module, name_, value))
                    stack.enter_context(mock.patch.object(r, "token_from_stdin", return_value=synthetic_token))
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    assert r.cli() == 1
                else:
                    try:
                        result = r.retrieve(case_base, identity, str(github_run), key, cert, synthetic_token)
                    except r.s.Rejected as error:
                        assert not success, name
                        assert "PRIVATE HTTP" not in str(error) and "HTTP-SENTINEL" not in str(error) and synthetic_token not in str(error)
                    else:
                        assert success and result == expected, name
                assert consumer.call_count == expected_consumers, name
            assert r.signal.getsignal(r.signal.SIGTERM) == previous_term
            if close_fault or rename_fault or term:
                public = stdout.getvalue() + stderr.getvalue()
                assert "private evidence incomplete" in public and "PRIVATE HTTP" not in public and synthetic_token not in public
            if close_fault:
                assert terminal_closes == 1
                if http_failure:
                    assert preserved_denial
            assert download_calls == downloads, (name, download_calls)
            operation = case_base / ".cache/retrieved-link-notices" / run_id
            assert (operation / "COMPLETE.json").exists() == success
            assert not any(synthetic_token.encode() in path.read_bytes() for path in operation.rglob("*") if path.is_file())
            if http_failure:
                notice = json.loads((operation / "OS-ERROR.json").read_bytes())
                assert notice["complete"] and "PRIVATE HTTP original status notice" in notice["exceptions"][0]["exact_text"]
            if reflected_error:
                assert json.loads((operation / "OS-ERROR.json").read_bytes())["complete"] is False
            if malformed:
                assert (operation / "run.json").read_bytes() == b"PRIVATE HTTP original non-JSON response"
            passed("authenticated retrieval synthetic " + name, download_requests=download_calls,
                   requests=request_calls, consumer_calls=expected_consumers, actual_network=False)
        for name, mutate in [
            ("wrong-repository", lambda d: d["run"]["repository"].update(full_name="other/repository")),
            ("wrong-head-repository", lambda d: d["run"]["head_repository"].update(id=1)),
            ("wrong-run", lambda d: d["run"].update(id=github_run + 1)),
            ("wrong-head", lambda d: d["run"].update(head_sha="b" * 40)),
            ("wrong-workflow-path", lambda d: d["run"].update(path=".github/workflows/untrusted.yml")),
            ("PR-event", lambda d: d["run"].update(event="pull_request")),
            ("PR-list", lambda d: d["run"].update(pull_requests=[{"id": 1}])),
            ("wrong-branch", lambda d: d["run"].update(head_branch="untrusted")),
            ("wrong-run-attempt", lambda d: d["run"].update(run_attempt=2)),
            ("wrong-attempt-metadata", lambda d: d["attempt"].update(run_attempt=2)),
            ("wrong-workflow-ID", lambda d: d["attempt"].update(workflow_id=1)),
            ("wrong-job-name", lambda d: d["jobs"]["jobs"][0].update(name="other")),
            ("wrong-job-attempt", lambda d: d["jobs"]["jobs"][0].update(run_attempt=2)),
            ("wrong-job-ID", lambda d: d["jobs"]["jobs"][0].update(id=0)),
            ("wrong-artifact-name", lambda d: d["artifacts"]["artifacts"][0].update(name="encrypted-link-notices-wrong")),
            ("wrong-artifact-ID", lambda d: d["artifacts"]["artifacts"][0].update(id=0)),
            ("missing-API-digest", lambda d: d["artifacts"]["artifacts"][0].pop("digest")),
            ("unknown-API-digest", lambda d: d["artifacts"]["artifacts"][0].update(digest="md5:untrusted")),
            ("expired-artifact", lambda d: d["artifacts"]["artifacts"][0].update(expired=True)),
            ("artifact-wrong-run", lambda d: d["artifacts"]["artifacts"][0]["workflow_run"].update(id=1)),
            ("detail-wrong-digest", lambda d: d["artifact"].update(digest="sha256:" + "0" * 64)),
            ("credential-reflected-body", lambda d: d["run"].update(reflection=synthetic_token)),
        ]:
            retrieved_case(name, mutate)
        def extra_artifact(data):
            second = copy.deepcopy(data["artifacts"]["artifacts"][0])
            second["id"] += 1
            data["artifacts"]["artifacts"].append(second)
            data["artifacts"]["total_count"] = 2
        retrieved_case("extra-encrypted-artifact", extra_artifact)
        retrieved_case("correct-reviewed-tuple", success=True, downloads=2)
        # A syntactically valid wrong API digest cannot be disproved until bytes
        # arrive: download is necessary, parsing/decryption must remain zero.
        def wrong_zip_digest(data):
            for value in [data["artifacts"]["artifacts"][0], data["artifact"]]:
                value["digest"] = "sha256:" + "0" * 64
        with mock.patch.object(r.u.zipfile, "ZipFile", side_effect=AssertionError("ZIP parsed before digest")):
            retrieved_case("wrong-ZIP-digest", wrong_zip_digest, downloads=2)
            retrieved_case("corrupt-ZIP", downloads=2, corrupt=True)
        retrieved_case("malformed-HTTP-response-private", malformed=True)
        retrieved_case("original-HTTP-failure-private", http_failure=True)
        retrieved_case("credential-in-HTTP-context-withheld", reflected_error=True)
        retrieved_case("terminal-close-success-path", close_fault=True, downloads=2)
        retrieved_case("terminal-close-prior-denial", close_fault=True, http_failure=True)
        retrieved_case("terminal-rename-unavailable", rename_fault=True, downloads=2)
        retrieved_case("actual-own-CLI-SIGTERM", term=True)

        # Exercise the real header-selection code with a fake HTTPSConnection.
        # No CA override or alternate transport is available in production code.
        captured_headers = []
        class Response:
            status, reason = 200, "OK"
            def __init__(self):
                self.body = io.BytesIO(b"{}")
            def getheader(self, name):
                return "2" if name == "Content-Length" else None
            def read(self, size):
                return self.body.read(size)
        class Connection:
            sock = None
            def __init__(self, host, **kwargs):
                self.host = host
                assert "context" in kwargs
            def request(self, method, path, headers):
                captured_headers.append((self.host, dict(headers)))
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with mock.patch.object(r.http.client, "HTTPSConnection", Connection):
            with mock.patch.object(r.ssl, "create_default_context", return_value=object()):
                r.https_get(r.ROOT + "/runs/90210", synthetic_token, 1024, r.time.monotonic() + 5)
                r.https_get(cdn_url, synthetic_token, 1024, r.time.monotonic() + 5, download=True)
        assert captured_headers[0][1]["Authorization"] == "Bearer " + synthetic_token
        assert "Authorization" not in captured_headers[1][1]
        passed("HTTPS Authorization fixed API only; cross-origin download has no token", actual_network=False)
        for url in ["http://api.github.com/", "https://untrusted.example/artifact", "https://user:password@api.github.com/"]:
            with mock.patch.object(r.http.client, "HTTPSConnection", side_effect=AssertionError("unsafe URL reached connection")):
                try:
                    r.https_get(url, synthetic_token, 1024, r.time.monotonic() + 5, download=True)
                except r.s.Rejected:
                    pass
                else:
                    raise AssertionError("unsafe HTTPS destination accepted")
        passed("unsafe scheme origin and credentialed URL fail before connection", actual_network=False)
        with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": "/private/UNOPENED-SYNTHETIC-keylog"}):
            with mock.patch.object(r.http.client, "HTTPSConnection", side_effect=AssertionError("TLS key logging reached connection")):
                try:
                    r.https_get(r.ROOT, synthetic_token, 1024, r.time.monotonic() + 5)
                except r.s.Rejected:
                    pass
                else:
                    raise AssertionError("TLS key logging accepted")
        passed("TLS key logging environment refused before context or connection", actual_network=False)
        class StalledConnection(Connection):
            def getresponse(self):
                r.time.sleep(0.2)  # synthetic local stall, no socket/network
                raise AssertionError("absolute HTTPS deadline failed to interrupt")
        previous_handler = r.signal.getsignal(r.signal.SIGALRM)
        started = r.time.monotonic()
        with mock.patch.object(r.http.client, "HTTPSConnection", StalledConnection):
            with mock.patch.object(r.ssl, "create_default_context", return_value=object()):
                try:
                    r.https_get(r.ROOT, synthetic_token, 1024, r.time.monotonic() + 0.03)
                except TimeoutError as error:
                    assert str(error) == "bounded HTTPS operation deadline reached"
                else:
                    raise AssertionError("stalled HTTPS call unexpectedly completed")
        assert r.time.monotonic() - started < 0.5
        assert r.signal.getsignal(r.signal.SIGALRM) == previous_handler
        assert r.signal.getitimer(r.signal.ITIMER_REAL)[0] == 0
        passed("absolute HTTPS deadline interrupts stalled headers and restores timer", actual_network=False)
        # Reviewed fixed transport calibration: production public cert encryption
        # only. This block never reads/decrypts with the coordinator task key.
        sample_spec = importlib.util.spec_from_file_location("create_transport_sample", Path(__file__).with_name("create-notice-transport-sample.py"))
        c = importlib.util.module_from_spec(sample_spec)
        sample_spec.loader.exec_module(c)
        sample_run = "transport-sample"
        def sample_case(name, mode):
            case_base = base("sample-" + name)
            tree = case_base / ".cache/fixtures-private" / (sample_run + "-links")
            marker = {"RunID": sample_run, "Classification": "PRIVATE RAW EVIDENCE", "Publication": "withhold pending explicit redaction review"}
            reviewed = {"RunID": sample_run, "SourceHead": head, "Job": "unit", "Attempt": "1",
                        "namespace": "calibration/private-notice-transport", "synthetic": True,
                        "release_qualified": False, "notice": "Reviewed fixed synthetic notice transport sample."}
            if mode in ("existing-unknown", "existing-identical"):
                c.s.private_root(tree.parent)
                tree.mkdir(mode=0o700)
                c.s.write_private(tree / "PRIVATE.json", c.s.encode(marker))
                c.s.write_private(tree / ("unknown.json" if mode == "existing-unknown" else "transport-sample.json"),
                                  c.s.encode({"PRIVATE-UNKNOWN": "must never be sealed"}) if mode == "existing-unknown" else c.s.encode(reviewed))
            original_write, original_close, original_reserve = c.s.write_private, c.s.os.close, c.s.reserve_operation
            original_producer = c.s.seal
            sample_fd, close_calls = None, 0
            def written(path, body):
                if mode == "write-denied" and Path(path).name == "transport-sample.json":
                    raise OSError(errno.EACCES, "PRIVATE-SAMPLE exact creation write notice", "/private/PRIVATE-SAMPLE")
                original_write(path, body)
                if Path(path).parent == tree and Path(path).name == "transport-sample.json":
                    if mode == "injected-extra":
                        original_write(tree / "unknown.json", c.s.encode({"PRIVATE-UNKNOWN": "must never be sealed"}))
                    if mode == "changed-literal":
                        (tree / "transport-sample.json").write_bytes(c.s.encode(dict(reviewed, notice="PRIVATE-UNKNOWN changed literal")))
            def reserved(path, run_name):
                nonlocal sample_fd
                result = original_reserve(path, run_name)
                if Path(path).name == "notice-transport-samples":
                    sample_fd = result[1]
                return result
            def closed(fd):
                nonlocal close_calls
                if mode == "terminal-close" and fd == sample_fd:
                    close_calls += 1
                    original_close(fd)
                    raise OSError(errno.EIO, "PRIVATE-SAMPLE uncertain final close")
                return original_close(fd)
            def produced(*args, **kwargs):
                if mode == "late-extra":
                    original_write(tree / "unknown.json", c.s.encode({"PRIVATE-UNKNOWN": "late piggyback must not be sealed"}))
                if mode == "late-change":
                    changed = c.s.encode(dict(reviewed, notice="X" * len(reviewed["notice"])))
                    assert len(changed) == len(c.s.encode(reviewed))
                    (tree / "transport-sample.json").write_bytes(changed)
                return original_producer(*args, **kwargs)
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["sample", "--run-id", sample_run, "--source-head", head, "--job", "unit", "--attempt", "1", "--reviewed-synthetic-transport-only"]
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(Path, "cwd", return_value=case_base))
                stack.enter_context(mock.patch.object(sys, "argv", argv))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                stack.enter_context(mock.patch.object(c.s, "write_private", side_effect=written))
                stack.enter_context(mock.patch.object(c.s, "reserve_operation", side_effect=reserved))
                stack.enter_context(mock.patch.object(c.s.os, "close", side_effect=closed))
                snapshots = stack.enter_context(mock.patch.object(c.s, "snapshot", wraps=c.s.snapshot))
                producer = stack.enter_context(mock.patch.object(c.s, "seal", side_effect=produced))
                commands = stack.enter_context(mock.patch.object(c.s, "openssl", wraps=c.s.openssl))
                reads = stack.enter_context(mock.patch.object(c.s, "read_regular", wraps=c.s.read_regular))
                if mode == "wrong-pin":
                    stack.enter_context(mock.patch.object(c.s, "CERT_PIN", "0" * 64))
                code = c.cli()
                assert code == (0 if mode == "positive" else 1)
                assert commands.call_count == (1 if mode == "positive" else 0)
                assert producer.call_count == (1 if mode in ("positive", "wrong-pin", "late-extra", "late-change") else 0)
                if mode in ("existing-unknown", "existing-identical"):
                    assert snapshots.call_count == 0
                if mode == "positive":
                    assert snapshots.call_count == 2
                    assert producer.call_args.kwargs["expected_payloads"] == {"PRIVATE.json": c.s.encode(marker), "transport-sample.json": c.s.encode(reviewed)}
                    args = commands.call_args.args[0]
                    assert "-encrypt" in args and "-decrypt" not in args and "-inkey" not in args
                    assert all(Path(call.args[0]).name == "link-notices-recipient.pem" for call in reads.call_args_list)
            public = stdout.getvalue() + stderr.getvalue()
            assert "PRIVATE-SAMPLE" not in public and "PRIVATE-UNKNOWN" not in public
            complete = case_base / ".cache/link-quarantine" / sample_run / "COMPLETE.json"
            assert complete.exists() == (mode == "positive")
            if mode == "positive":
                result = json.loads(stdout.getvalue())
                assert result["namespace"] == "calibration/private-notice-transport" and result["synthetic"] is True
                assert result["release_qualified"] is False and result["complete"] is True
                assert result["sample_files"] == ["PRIVATE.json", "transport-sample.json"]
                assert {path.name for path in tree.iterdir()} == {"PRIVATE.json", "transport-sample.json"}
                assert json.loads((tree / "PRIVATE.json").read_bytes()) == marker
                assert (tree / "transport-sample.json").read_bytes() == c.s.encode(reviewed)
                assert json.loads(complete.read_bytes())["files"] == 2
                assert (complete.parent / "notice.cms").stat().st_size > 0
            else:
                assert "rejected" in public and not stdout.getvalue()
            if mode == "write-denied":
                receipt = case_base / ".cache/notice-transport-samples" / sample_run / "OS-ERROR.json"
                notice = json.loads(receipt.read_bytes())
                assert notice["complete"] and "PRIVATE-SAMPLE exact creation write notice" in notice["exceptions"][0]["exact_text"]
            if mode == "terminal-close":
                assert close_calls == 1 and "private evidence incomplete" in public
            passed("reviewed fixed sample creator " + name, actual_network=False, public_certificate_only=True,
                   stock_encryptions=1 if mode == "positive" else 0, release_qualified=False)
        for name, mode in [("positive-real-stock-public-cert-encryption", "positive"),
                           ("refuse-existing-unknown-tree", "existing-unknown"),
                           ("refuse-existing-identical-tree", "existing-identical"),
                           ("reject-added-unknown-file", "injected-extra"),
                           ("reject-changed-reviewed-literal", "changed-literal"),
                           ("reject-late-extra-at-actual-seal-snapshot", "late-extra"),
                           ("reject-late-same-size-change-at-actual-seal-snapshot", "late-change"),
                           ("pinned-public-cert-mismatch", "wrong-pin"),
                           ("private-original-write-denial", "write-denied"),
                           ("terminal-close-no-sealer-or-complete", "terminal-close")]:
            sample_case(name, mode)
        for name, run_value, job_value, allowed in [("invalid-run", "../PRIVATE-SAMPLE", "unit", True),
                                                    ("wrong-job", sample_run, "runtime", True),
                                                    ("missing-calibration-gate", sample_run, "unit", False)]:
            with mock.patch.object(c.s, "reserve_operation", side_effect=AssertionError("creator gate reached filesystem")) as reserved:
                try:
                    c.create_sample(root / "must-not-exist", run_value, head, job_value, "1", allowed)
                except c.s.Rejected:
                    pass
                else:
                    raise AssertionError("creator identity/calibration gate accepted")
                assert reserved.call_count == 0
            passed("reviewed sample pure gate " + name, filesystem_actions=0, release_qualified=False)
        # Small independent stock ASN.1 inspection, avoiding huge OCTET STRING output.
        mini, _ = s.pack({"PRIVATE.json": expected["PRIVATE.json"]}, identity)
        encoded = s.openssl(["cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-recip", str(cert),
                            "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"], mini, root, "algorithm-envelope", s.MAX_CMS)
        inspected = s.openssl(["asn1parse", "-inform", "DER", "-i"], encoded, root, "algorithm-inspection", 65536)
        oids = re.findall(r"OBJECT\s+:([^\r\n]+)", inspected.decode("ascii"))
        assert "rsaesOaep" in oids and "mgf1" in oids and "aes-256-cbc" in oids and oids.count("sha256") == 2
        passed("stock ASN.1 confirms AES256-CBC RSA-OAEP SHA256 MGF1-SHA256", object_identifiers=oids, aead=False)
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "FAILED"
        report["failure"] = {"type": type(error).__name__, "fixed_message": "synthetic control failed; retain this run before fixing"}
        raise
    finally:
        report["source_sha256"] = {p.name: s.digest(p.read_bytes()) for p in [Path(__file__), Path(__file__).with_name("seal-link-notices.py"), Path(__file__).with_name("unseal-link-notices.py"), Path(__file__).with_name("link-notices-recipient.pem"), Path(__file__).with_name("retrieve-link-notices.py"), Path(__file__).with_name("create-notice-transport-sample.py")]}
        report["limits"] = ["Synthetic digest generated locally; external GitHub trust not established", "This self-report does not authenticate the runner; native identity requires collected CI bindings", "Recipient custody/backup not established by certificate or this test", "CBC is not AEAD; digest trust cannot be supplied by adjacent manifest", "No actual platform denial or stock-command timeout/output-overflow injection; deadline transport is synthetic", "Caller must stop notice writers before sealing; consistency checks detect observed changes, not hostile concurrent writers", "No publication exception or workflow enabled"]
        s.write_private(root / "report.json", s.encode(report))
        out = s.private_root(Path.cwd() / ".cache/m2/notice-sealing-implementation")
        s.write_private(out / (root.name + "-report.json"), s.encode(report))
    print(json.dumps({"status": report["status"], "controls": len(report["controls"]), "report": str(root / "report.json")}))


if __name__ == "__main__":
    run()
