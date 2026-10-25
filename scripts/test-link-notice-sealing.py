#!/usr/bin/env python3
"""Bounded SYNTHETIC controls. No Go, Docker, real HTTPS or upload.

Keys and all synthetic plaintext stay below excluded owner-only
.cache/private-notice-tests, never the public .cache/unit artifact tree.
"""
import importlib.util
import contextlib
import base64
import hashlib
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

        cli_cert = root / "link-notices-recipient.pem"
        s.write_private(cli_cert, cert.read_bytes())
        # Explicit v2 has exactly two fixed component roots. These inputs are
        # synthetic; no source directory can assert writer quiescence for us.
        linked_identity = s.identities(run_id, head, identity["recipient_sha256"], "links", "1", s.LINKED_LAYOUT)
        fixture_links_identity = s.identities(run_id, head, identity["recipient_sha256"], "links", "1")
        def linked_tree(name, fixture=True, empty_parent=False):
            if fixture:
                path, fixture_root = input_tree("linked-" + name)
                s.write_private(fixture_root / "fixture-note.json", s.encode({"RunID": run_id, "Notice": "PRIVATE-LINKED fixture literal"}))
            else:
                path, fixture_root = base("linked-" + name), None
                if empty_parent:
                    s.private_root(path / ".cache/fixtures-private")
            driver_root = s.private_root(path / ".cache/link-calibration-private") / run_id
            driver_root.mkdir(mode=0o700)
            s.write_private(driver_root / "PRIVATE.json", expected["PRIVATE.json"])
            s.write_private(driver_root / "driver-errors.json", s.encode({"RunID": run_id, "Errors": [{"Action": ["synthetic UpLinks"], "Cause": "UFJJVkFURS1MSU5LRUQ=", "Complete": True}]}))
            s.write_private(driver_root / "child-output.json", s.encode({"RunID": run_id, "Wait": {"Reaped": True}, "Stdout": "", "Stderr": ""}))
            return path, driver_root, fixture_root
        argv = ["seal", "--run-id", run_id, "--source-head", head, "--recipient-sha256", identity["recipient_sha256"],
                "--job", "links", "--attempt", "1", "--layout", s.LINKED_LAYOUT]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(s, "CERT_PIN", identity["recipient_sha256"]):
            with mock.patch.object(s, "reserve_operation") as reserved:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    assert s.cli() == 1
                assert reserved.call_count == 0
        passed("linked actual CLI missing writer-stop declaration before filesystem", filesystem_reservations=0)
        # Membership and bytes come from the specified input specimens, never
        # from a production snapshot, archive builder or decoder. Keep the two
        # PRIVATE occurrences explicit: they are separate required receipts.
        linked_driver_expected = {
            "driver/PRIVATE.json": b'{"Classification":"PRIVATE RAW EVIDENCE","Publication":"withhold pending explicit redaction review","RunID":"notice-test"}\n',
            "driver/driver-errors.json": b'{"Errors":[{"Action":["synthetic UpLinks"],"Cause":"UFJJVkFURS1MSU5LRUQ=","Complete":true}],"RunID":"notice-test"}\n',
            "driver/child-output.json": b'{"RunID":"notice-test","Stderr":"","Stdout":"","Wait":{"Reaped":true}}\n',
        }
        linked_both_expected = {
            "driver/PRIVATE.json": linked_driver_expected["driver/PRIVATE.json"],
            "driver/driver-errors.json": linked_driver_expected["driver/driver-errors.json"],
            "driver/child-output.json": linked_driver_expected["driver/child-output.json"],
            "driver/operation-42/network/nested/driver-notice.json": receipt,
            "fixture/PRIVATE.json": b'{"Classification":"PRIVATE RAW EVIDENCE","Publication":"withhold pending explicit redaction review","RunID":"notice-test"}\n',
            "fixture/fixture-note.json": b'{"Notice":"PRIVATE-LINKED fixture literal","RunID":"notice-test"}\n',
        }
        def assert_linked_bytes(actual, wanted):
            assert set(actual) == set(wanted), "independent linked receipt membership mismatch"
            assert actual == wanted, "independent linked receipt bytes mismatch"
        linked_archives, linked_absence_expected, linked_manifests = {}, {}, {}
        for name, present, empty_parent in [("both", True, False), ("missing-parent", False, False),
                                             ("missing-root", False, True), ("literal-notice", False, True)]:
            case_base, driver_root, fixture_root = linked_tree(name, present, empty_parent)
            if present:
                nested_driver = driver_root / "operation-42" / "network" / "nested"
                nested_driver.mkdir(mode=0o700, parents=True)
                s.write_private(nested_driver / "driver-notice.json", receipt)
                # A separate private HOME is deliberately outside both roots.
                home = s.private_root(case_base / ".cache/link-calibration-home") / run_id
                home.mkdir(mode=0o700)
                s.write_private(home / "unknown.json", s.encode({"notice": "PRIVATE-HOME excluded synthetic bytes"}))
            wanted = linked_both_expected if present else linked_driver_expected
            expected_count = 6 if present else 3
            expected_total = sum(map(len, wanted.values()))
            expected_components = {
                "driver": {"availability": "captured", "files": 4 if present else 3,
                           "total_bytes": sum(map(len, linked_driver_expected.values())) + (len(receipt) if present else 0)},
                "fixture": {"availability": "captured" if present else "absent-ENOENT", "files": 2 if present else 0,
                            "total_bytes": (len(linked_both_expected["fixture/PRIVATE.json"]) + len(linked_both_expected["fixture/fixture-note.json"])) if present else 0},
            }
            assert len(wanted) == expected_count
            expected_absence_body = None
            injected_absence = None
            if not present:
                missing_path = case_base / ".cache/fixtures-private"
                if name != "missing-parent":
                    missing_path = missing_path / "notice-test-links"
                try:
                    missing_path.lstat()  # independent actual OS observation
                except FileNotFoundError as independently_observed:
                    absence_text = str(independently_observed)
                else:
                    raise AssertionError("expected absent input root unexpectedly exists")
                if name == "literal-notice":
                    injected_absence = FileNotFoundError(errno.ENOENT, "PRIVATE-ABSENCE exact original Ω\nsecond line with  two spaces", str(missing_path))
                    absence_text = str(injected_absence)
                # Independent standard serialization of known fields and the
                # independently observed/provided original notice, never pack,
                # snapshot, decode_fixture_absence or production encode.
                expected_absence_body = (json.dumps({"action": "observe fixed fixture component absence", "type": "FileNotFoundError",
                        "errno": errno.ENOENT, "exact_text": absence_text}, sort_keys=True, separators=(",", ":")) + "\n").encode()
            original_lstat = Path.lstat
            def stated(path, *args, **kwargs):
                if injected_absence is not None and path == missing_path:
                    raise injected_absence
                return original_lstat(path, *args, **kwargs)
            with mock.patch.object(Path, "lstat", stated):
                result = s.seal(case_base, linked_identity, cert, notice_writers_stopped_and_reaped=True)
            envelope = (case_base / ".cache/link-quarantine" / run_id / "notice.cms").read_bytes()
            archive, hashed = artifact("linked-" + name, [("notice.cms", envelope, stat.S_IFREG | 0o600)])
            restored_base = base("linked-recovered-" + name)
            restored = u.unseal(restored_base, linked_identity, archive, hashed, key, cert)
            assert_linked_bytes(restored, wanted)
            assert result["files"] == expected_count and result["total_bytes"] == expected_total
            assert result["components"] == expected_components
            metadata = json.loads((restored_base / ".cache/unsealed-link-notices" / run_id / "MANIFEST.json").read_bytes())
            assert metadata["version"] == result["manifest_version"] == 2 and metadata["layout"] == s.LINKED_LAYOUT
            assert metadata["bundle_complete"] == result["bundle_complete"] == present
            assert metadata["count"] == expected_count and metadata["total_bytes"] == expected_total
            assert metadata["components"] == expected_components
            recovered_directory = restored_base / ".cache/unsealed-link-notices" / run_id
            if not present:
                expected_hash = hashlib.sha256(expected_absence_body).hexdigest()
                expected_record = {"scope": "fixed-fixture-root-ENOENT", "identity": dict(linked_identity),
                                   "bytes": len(expected_absence_body), "sha256": expected_hash,
                                   "body_base64": base64.b64encode(expected_absence_body).decode("ascii")}
                assert metadata["fixture_absence"] == expected_record
                assert (case_base / ".cache/link-sealing-private" / run_id / "fixture-absence.json").read_bytes() == expected_absence_body
                assert (recovered_directory / "fixture-absence.json").read_bytes() == expected_absence_body
                assert json.loads((recovered_directory / "COMPLETE.json").read_bytes())["fixture_absence_sha256"] == result["fixture_absence_sha256"] == expected_hash
                assert not (case_base / ".cache/fixtures-private" / (run_id + "-links")).exists()
                linked_absence_expected[name] = expected_absence_body
            else:
                assert metadata["fixture_absence"] is None and result["fixture_absence_sha256"] is None
                assert not (recovered_directory / "fixture-absence.json").exists()
            linked_manifests[name] = metadata
            assert not any("PRIVATE-HOME" in body.decode() for body in restored.values())
            linked_archives[name] = (archive, hashed, wanted)
            passed("linked v2 real-stock exact recovery " + name, files=expected_count, total_bytes=expected_total,
                   independent_literal_members=True, bundle_complete=present,
                   fixture_availability=result["components"]["fixture"]["availability"], release_qualified=False,
                   exact_absence_preserved=not present, absence_bytes=len(expected_absence_body) if expected_absence_body is not None else 0)
            if present:
                for omitted in ("driver/driver-errors.json", "fixture/fixture-note.json"):
                    incomplete = dict(restored)
                    del incomplete[omitted]
                    try:
                        assert_linked_bytes(incomplete, linked_both_expected)
                    except AssertionError:
                        pass
                    else:
                        raise AssertionError("independent oracle accepted omitted supplied receipt")
                    passed("linked independent oracle detects omitted " + omitted, expected_files=6,
                           supplied_files=len(incomplete), actual_network=False)
        # Independent malformed encrypted archives exercise actual consumer
        # admission. The supplied driver map stays literal; pack is not used.
        bad_absence_archives = {}
        for name in ("missing", "tampered-body", "wrong-hash", "wrong-bytes", "cross-run", "unknown-scope", "not-ENOENT", "oversize"):
            manifest = copy.deepcopy(linked_manifests["missing-root"])
            record = manifest["fixture_absence"]
            if name == "missing":
                del manifest["fixture_absence"]
            elif name == "tampered-body":
                changed = linked_absence_expected["missing-root"].replace(b"notice-test-links", b"notice-test-linkX")
                assert changed != linked_absence_expected["missing-root"]
                record["body_base64"] = base64.b64encode(changed).decode("ascii")
            elif name == "wrong-hash":
                record["sha256"] = "0" * 64
            elif name == "wrong-bytes":
                record["bytes"] += 1
            elif name == "cross-run":
                record["identity"]["run_id"] = "another-run"
            elif name == "unknown-scope":
                record["scope"] = "arbitrary-root"
            else:
                if name == "oversize":
                    changed = b"x" * (16384 + 1)
                else:
                    notice = json.loads(linked_absence_expected["missing-root"])
                    notice["errno"] = errno.EACCES
                    changed = (json.dumps(notice, sort_keys=True, separators=(",", ":")) + "\n").encode()
                record.update(body_base64=base64.b64encode(changed).decode("ascii"), bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest())
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive_:
                for member, body in [("MANIFEST.json", s.encode(manifest)), *sorted(linked_driver_expected.items())]:
                    entry = tarfile.TarInfo("link-notices/notice-test/" + member)
                    entry.size, entry.mode, entry.mtime = len(body), 0o600, 0
                    archive_.addfile(entry, io.BytesIO(body))
            encrypted = s.openssl(["cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", "-recip", str(cert),
                       "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"],
                       buffer.getvalue(), root, "absence-bad-envelope-" + name, s.MAX_CMS)
            archive_path, archive_hash = artifact("absence-bad-" + name, [("notice.cms", encrypted, stat.S_IFREG | 0o600)])
            bad_absence_archives[name] = (archive_path, archive_hash, linked_driver_expected)
            recovery = base("absence-bad-recovery-" + name)
            reject("encrypted absence observation rejection " + name,
                   lambda path=recovery, archive=archive_path, hashed=archive_hash: u.unseal(path, linked_identity, archive, hashed, key, cert), calls=1)
            destination = recovery / ".cache/unsealed-link-notices" / run_id
            assert not (destination / "COMPLETE.json").exists() and not (destination / "fixture-absence.json").exists()
        # Newly recovered observation persistence is mandatory, with the same
        # reserved private boundary and no later path open after a write fault.
        recovered_failure_base = base("absence-recovered-write-failure")
        failure = OSError(errno.EIO, "PRIVATE-ABSENCE exact recovered observation write failure")
        original_write, original_open = s.write_private, s.os.open
        failed_write = False
        def observation_written(path, body):
            nonlocal failed_write
            if path.name == "fixture-absence.json":
                failed_write = True
                raise failure
            return original_write(path, body)
        def observation_opened(*args, **kwargs):
            if failed_write:
                raise AssertionError("new path after recovered absence write failure")
            return original_open(*args, **kwargs)
        valid_archive, valid_hash, _ = linked_archives["missing-root"]
        with mock.patch.object(s, "write_private", side_effect=observation_written):
            with mock.patch.object(s.os, "open", side_effect=observation_opened):
                reject("recovered exact absence write failure stops completion",
                       lambda: u.unseal(recovered_failure_base, linked_identity, valid_archive, valid_hash, key, cert), calls=1)
        failed_destination = recovered_failure_base / ".cache/unsealed-link-notices" / run_id
        notice = json.loads((failed_destination / "OS-ERROR.json").read_bytes())
        assert failed_write and notice["complete"] and notice["exceptions"][0]["exact_text"] == str(failure)
        assert not (failed_destination / "COMPLETE.json").exists() and not (failed_destination / "fixture-absence.json").exists()
        oversized_base, _, _ = linked_tree("oversize-original-absence", False, True)
        missing_path = oversized_base / ".cache/fixtures-private/notice-test-links"
        original_lstat = Path.lstat
        original_notice = FileNotFoundError(errno.ENOENT, "PRIVATE-ABSENCE original " + "x" * 16384, str(missing_path))
        def oversized_lstat(path, *args, **kwargs):
            if path == missing_path:
                raise original_notice
            return original_lstat(path, *args, **kwargs)
        with mock.patch.object(Path, "lstat", oversized_lstat):
            reject("oversized original fixture absence before encryption",
                   lambda: s.seal(oversized_base, linked_identity, cert, notice_writers_stopped_and_reaped=True))
        assert not (oversized_base / ".cache/link-quarantine" / run_id / "COMPLETE.json").exists()
        linked_expected = linked_archives["both"][2]
        linked_clear, linked_manifest = s.pack(linked_expected, linked_identity)
        fixture_clear, _ = s.pack(expected, fixture_links_identity)
        reject("linked v2 consumer requires explicit layout", lambda: u.unpack(linked_clear, fixture_links_identity))
        reject("fixture v1 cannot be reinterpreted as linked v2", lambda: u.unpack(fixture_clear, linked_identity))
        reject("linked v2 caller source head mismatch", lambda: u.unpack(linked_clear, dict(linked_identity, source_head="b" * 40)))
        for name, change in [("version", lambda m: m.update(version=1)),
                             ("layout", lambda m: m.update(layout="fixture-v1")),
                             ("availability", lambda m: m["components"]["fixture"].update(availability="absent-ENOENT")),
                             ("bundle-complete", lambda m: m.update(bundle_complete=False))]:
            manifest = copy.deepcopy(linked_manifest)
            change(manifest)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for member, body in [("MANIFEST.json", s.encode(manifest)), *sorted(linked_expected.items())]:
                    entry = tarfile.TarInfo("link-notices/" + run_id + "/" + member)
                    entry.size, entry.mode, entry.mtime = len(body), 0o600, 0
                    archive.addfile(entry, io.BytesIO(body))
            reject("linked manifest confusion " + name, lambda body=buffer.getvalue(): u.unpack(body, linked_identity))
        for name, present in [("driver-crossrun", True), ("fixture-crossrun", True), ("driver-symlink", True),
                              ("fixture-symlink", True), ("partial-fixture", True), ("malformed-driver", True),
                              ("unexpected-driver-home", True), ("oversize-driver", True), ("missing-driver", False)]:
            case_base, driver_root, fixture_root = linked_tree(name, present)
            if name.endswith("crossrun"):
                target = driver_root / "driver-errors.json" if name.startswith("driver") else fixture_root / "fixture-note.json"
                target.write_bytes(s.encode({"RunID": "another-run", "Notice": "PRIVATE-LINKED wrong run"}))
            elif name.endswith("symlink"):
                target = driver_root / "driver-errors.json" if name.startswith("driver") else fixture_root / "fixture-note.json"
                target.unlink()
                target.symlink_to(cert)
            elif name == "partial-fixture":
                (fixture_root / "PRIVATE.json").unlink()
            elif name == "malformed-driver":
                (driver_root / "driver-errors.json").write_bytes(b'{"RunID":')
            elif name == "unexpected-driver-home":
                (driver_root / ".docker").mkdir(mode=0o700)
            elif name == "oversize-driver":
                (driver_root / "driver-errors.json").write_bytes(b"x" * (s.MAX_FILE + 1))
            else:
                for item in driver_root.iterdir():
                    item.unlink()
                driver_root.rmdir()
            reject("linked input fail-closed " + name, lambda path=case_base: s.seal(path, linked_identity, cert, notice_writers_stopped_and_reaped=True))
        # The two components share limits; neither receives its own allowance.
        count_base, count_driver, count_fixture = linked_tree("shared-count")
        for directory_, count in [(count_driver, 509), (count_fixture, 510)]:
            for number in range(count):
                s.write_private(directory_ / ("count-" + str(number) + ".json"), b"{}\n")
        count_payloads, _ = s.linked_snapshot(count_base, linked_identity)
        assert len(count_payloads) == s.MAX_FILES
        count_clear, _ = s.pack(count_payloads, linked_identity)
        assert u.unpack(count_clear, linked_identity)[0] == count_payloads
        passed("linked shared exact1024 file producer/consumer boundary", files=len(count_payloads))
        s.write_private(count_fixture / "one-extra.json", b"{}\n")
        reject("linked shared1025 files before encryption", lambda: s.seal(count_base, linked_identity, cert, notice_writers_stopped_and_reaped=True))
        total_base, total_driver, total_fixture = linked_tree("shared-bytes")
        initial = sum(path.stat().st_size for directory_ in (total_driver, total_fixture) for path in directory_.iterdir())
        remaining = s.MAX_PAYLOAD - initial
        number = 0
        while remaining:
            size = min(s.MAX_FILE, remaining)
            body = s.encode({"notice": "x" * (size - len(s.encode({"notice": ""})))})
            assert len(body) == size
            directory_ = total_driver if number % 2 == 0 else total_fixture
            s.write_private(directory_ / ("bytes-" + str(number) + ".json"), body)
            remaining -= size
            number += 1
        total_payloads, _ = s.linked_snapshot(total_base, linked_identity)
        assert sum(map(len, total_payloads.values())) == s.MAX_PAYLOAD
        total_clear, _ = s.pack(total_payloads, linked_identity)
        assert u.unpack(total_clear, linked_identity)[0] == total_payloads
        passed("linked shared exact8MiB producer/consumer boundary", total_bytes=len(b"".join(total_payloads.values())))
        s.write_private(total_fixture / "one-extra.json", b"{}\n")
        reject("linked shared8MiB plus3 bytes before encryption", lambda: s.seal(total_base, linked_identity, cert, notice_writers_stopped_and_reaped=True))
        for name in ("late-driver-replacement", "late-fixture-appearance"):
            present = name == "late-driver-replacement"
            case_base, driver_root, fixture_root = linked_tree(name, present)
            original_snapshot = s.snapshot
            calls = 0
            def changed_snapshot(path, *args, **kwargs):
                nonlocal calls
                result = original_snapshot(path, *args, **kwargs)
                calls += 1
                if calls == 2:
                    if present:
                        target = driver_root / "driver-errors.json"
                        replacement = driver_root / "replacement.json"
                        s.write_private(replacement, target.read_bytes())
                        replacement.replace(target)
                    else:
                        parent = s.private_root(case_base / ".cache/fixtures-private")
                        new_root = parent / (run_id + "-links")
                        new_root.mkdir(mode=0o700)
                        s.write_private(new_root / "PRIVATE.json", expected["PRIVATE.json"])
                return result
            with mock.patch.object(s, "snapshot", side_effect=changed_snapshot):
                reject("linked cross-component consistency " + name, lambda: s.seal(case_base, linked_identity, cert, notice_writers_stopped_and_reaped=True))
        for name, component, point, number in [("driver-read-denial", "driver", "read", errno.EACCES),
                                                 ("fixture-read-denial", "fixture", "read", errno.EACCES),
                                                 ("fixture-probe-denial", "fixture", "probe", errno.EPERM),
                                                 ("fixture-probe-unknown", "fixture", "probe", errno.EIO),
                                                 ("fixture-descendant-ENOENT", "fixture", "read", errno.ENOENT),
                                                 ("absence-receipt-write", "fixture", "receipt", errno.EIO)]:
            case_base, _, fixture_root = linked_tree(name, point != "receipt")
            target = "driver-errors.json" if component == "driver" else "fixture-note.json"
            error = OSError(number, "PRIVATE-LINKED exact " + name, "/private/PRIVATE-LINKED/" + target)
            original_open, original_lstat, original_write = s.os.open, Path.lstat, s.write_private
            fault_reached = False
            def fail():
                nonlocal fault_reached
                fault_reached = True
                raise error
            def opened(path, *args, **kwargs):
                if fault_reached:
                    raise AssertionError("new path after linked input failure")
                if point == "read" and str(path) == target:
                    fail()
                return original_open(path, *args, **kwargs)
            def stated(path, *args, **kwargs):
                if point == "probe" and path == fixture_root:
                    fail()
                return original_lstat(path, *args, **kwargs)
            def written(path, body):
                if point == "receipt" and path.name == "fixture-absence.json":
                    fail()
                return original_write(path, body)
            argv = ["seal", "--run-id", run_id, "--source-head", head, "--recipient-sha256", identity["recipient_sha256"],
                    "--job", "links", "--attempt", "1", "--layout", s.LINKED_LAYOUT, "--notice-writers-stopped-and-reaped"]
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                for module, name_, value in [(s, "CERT_PIN", identity["recipient_sha256"]), (s, "__file__", str(root / "seal-link-notices.py")), (Path, "cwd", lambda: case_base), (sys, "argv", argv)]:
                    stack.enter_context(mock.patch.object(module, name_, value))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                stack.enter_context(mock.patch.object(s.os, "open", side_effect=opened))
                stack.enter_context(mock.patch.object(Path, "lstat", stated))
                stack.enter_context(mock.patch.object(s, "write_private", side_effect=written))
                commands = stack.enter_context(mock.patch.object(s, "openssl", wraps=s.openssl))
                assert s.cli() == 1 and commands.call_count == 0
            assert fault_reached and "PRIVATE-LINKED" not in stdout.getvalue() + stderr.getvalue()
            notice = json.loads((case_base / ".cache/link-sealing-private" / run_id / "OS-ERROR.json").read_bytes())
            assert notice["complete"] and notice["exceptions"][0]["exact_text"] == str(error)
            assert not (case_base / ".cache/link-quarantine" / run_id / "COMPLETE.json").exists()
            passed("linked actual CLI private exact failure " + name, stock_commands=0, no_new_path_after_failure=True)

        # Injected literal OS failures on the actual CLI entrypoints. The flag
        # rejects EVERY later os.open, proving retention uses the reserved FD.
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
                self.wait_stdin_open = []
                os.set_blocking(self.reader, False)
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
                self.wait_stdin_open.append(not self.stdin.closed)
                if self.mode == "full":
                    deadline = time.monotonic() + timeout
                    with original_selector() as selector:
                        selector.register(self.reader, s.selectors.EVENT_READ)
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise s.subprocess.TimeoutExpired("PRIVATE-WAIT synthetic stdin EOF", timeout)
                            if not selector.select(min(remaining, 0.05)):
                                continue
                            try:
                                chunk = os.read(self.reader, 65536)
                            except BlockingIOError:
                                continue
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
        # Setup can fail before production closes stdin. Its cleanup must still
        # observe a bounded fake wait, then close streams and retain the failure.
        def open_stdin_cleanup_cli(consumer):
            case_base, _ = input_tree("open-stdin-" + ("consumer" if consumer else "producer"))
            child = StdinChild("full", b"")
            original_blocking, original_open = s.os.set_blocking, s.os.open
            setup_failure = KeyboardInterrupt("PRIVATE-WAIT original stdin setup interrupt") if consumer else OSError(errno.EIO, "PRIVATE-WAIT original stdin setup failure")
            injected = False
            def blocking(fd, enabled):
                nonlocal injected
                if fd == child.stdin_fd:
                    assert not injected
                    injected = True
                    raise setup_failure
                return original_blocking(fd, enabled)
            def opened(*args, **kwargs):
                if injected:
                    raise AssertionError("new path opened after stdin setup failure")
                return original_open(*args, **kwargs)
            argv = ["unseal" if consumer else "seal", "--run-id", run_id, "--source-head", head,
                    "--recipient-sha256", identity["recipient_sha256"], "--job", identity["job"], "--attempt", identity["attempt"]]
            if consumer:
                argv += ["--artifact-zip", str(zip_path), "--trusted-artifact-zip-sha256", trusted, "--private-key", str(key)]
            stdout, stderr = io.StringIO(), io.StringIO()
            try:
                started = time.monotonic()
                with contextlib.ExitStack() as stack:
                    for module, name_, value in [(s, "CERT_PIN", identity["recipient_sha256"]), (s, "__file__", str(root / "seal-link-notices.py")), (u, "__file__", str(root / "unseal-link-notices.py")), (Path, "cwd", lambda: case_base), (sys, "argv", argv)]:
                        stack.enter_context(mock.patch.object(module, name_, value))
                    stack.enter_context(contextlib.redirect_stdout(stdout))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    stack.enter_context(mock.patch.object(s.os, "set_blocking", side_effect=blocking))
                    stack.enter_context(mock.patch.object(s.os, "open", side_effect=opened))
                    popen = stack.enter_context(mock.patch.object(s.subprocess, "Popen", return_value=child))
                    commands = stack.enter_context(mock.patch.object(s, "openssl", wraps=s.openssl))
                    assert (u.cli() if consumer else s.cli()) == 1
                    assert popen.call_count == commands.call_count == 1
                elapsed = time.monotonic() - started
                assert injected and 1.8 <= elapsed < 5, elapsed
                assert child.wait_stdin_open == [True] and child.polls == child.waits == 1 and child.kills == 0
                assert all(stream.closed and stream.closes == 1 for stream in (child.stdin, child.stdout, child.stderr))
                public = stdout.getvalue() + stderr.getvalue()
                assert "private evidence incomplete" in public and "PRIVATE-WAIT" not in public and str(case_base) not in public
                directory = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-sealing-private") / run_id
                record = json.loads((directory / ("unseal-command.json" if consumer else "seal-command.json")).read_bytes())
                assert record["failure"] == {"type": type(setup_failure).__name__, "errno": getattr(setup_failure, "errno", None), "exact_text": str(setup_failure)}
                assert not record["child_reaped"] and not record["streams_complete"] and not record["input_complete"]
                assert record["input_accepted_bytes"] == 0 and record["interrupted"] == consumer
                timeout = s.subprocess.TimeoutExpired("PRIVATE-WAIT synthetic stdin EOF", 2)
                assert record["cleanup_failures"] == [{"action": "wait owned child", "type": "TimeoutExpired", "errno": None, "exact_text": str(timeout)}]
                notice = json.loads((directory / "OS-ERROR.json").read_bytes())
                assert notice["complete"] and any(node["exact_text"] == str(setup_failure) for node in notice["exceptions"])
                marker = case_base / (".cache/unsealed-link-notices" if consumer else ".cache/link-quarantine") / run_id / "COMPLETE.json"
                assert not marker.exists()
            finally:
                child.release_fixture()
            assert child.reader is None and child.writer_result["joined"] and child.writer_result["closed"]
            passed("actual CLI open stdin bounded cleanup " + ("consumer-interrupt" if consumer else "producer-setup-error"),
                   elapsed_seconds=elapsed, wait_timeout_seconds=2, child_reaped=False, waits=child.waits, kills=child.kills,
                   all_streams_closed=True, writer_joined=True, no_new_path_after_failure=True, synthetic_child=True)
        open_stdin_cleanup_cli(False)
        open_stdin_cleanup_cli(True)
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
        # The same literal API tuple now selects job links, but the encrypted
        # manifest must independently match the caller's explicit v2 layout.
        for label in ("both", "missing-root", "literal-notice", "wrong-layout", "missing-absence", "tampered-absence"):
            rejected = label in ("wrong-layout", "missing-absence", "tampered-absence")
            if label.endswith("-absence"):
                archive_path, archive_hash, wanted = bad_absence_archives["missing" if label == "missing-absence" else "tampered-body"]
            else:
                archive_path, archive_hash, wanted = linked_archives["both" if label == "wrong-layout" else label]
            data = copy.deepcopy(fixtures)
            data["jobs"]["jobs"][0]["name"] = "links"
            canonical_name = "encrypted-link-notices-links-" + head + "-" + str(github_run) + "-1"
            for artifact_ in (data["artifacts"]["artifacts"][0], data["artifact"]):
                artifact_.update(name=canonical_name, size_in_bytes=archive_path.stat().st_size, digest="sha256:" + archive_hash)
            case_base = base("linked-api-" + label)
            requested = fixture_links_identity if label == "wrong-layout" else linked_identity
            download_calls = 0
            def linked_transport(url, token, maximum, deadline, download=False):
                nonlocal download_calls
                assert token == synthetic_token
                if download:
                    download_calls += 1
                    assert url == artifact_info["archive_download_url"]
                    return 200, None, archive_path.read_bytes()
                assert url in routes
                return 200, None, s.encode(data[routes[url]])
            with mock.patch.object(r, "https_get", side_effect=linked_transport):
                with mock.patch.object(r.http.client, "HTTPSConnection", side_effect=AssertionError("real network forbidden")):
                    with mock.patch.object(r.u, "unseal", wraps=r.u.unseal) as consumer:
                        with mock.patch.object(r.u, "verified_member", wraps=r.u.verified_member) as admission:
                            try:
                                result = r.retrieve(case_base, requested, str(github_run), key, cert, synthetic_token)
                            except r.s.Rejected:
                                assert rejected
                            else:
                                assert not rejected
                                assert_linked_bytes(result, wanted)
                            assert consumer.call_count == admission.call_count == 1 and download_calls == 1
            marker = case_base / ".cache/retrieved-link-notices" / run_id / "COMPLETE.json"
            assert marker.exists() == (not rejected)
            if not rejected:
                complete = json.loads(marker.read_bytes())
                assert complete["layout"] == s.LINKED_LAYOUT and complete["bundle_complete"] == (label == "both")
                assert complete["api_zip_sha256"] == archive_hash
                assert complete["fixture_absence_verified_by_consumer"] == (label != "both")
                if label != "both":
                    assert (case_base / ".cache/unsealed-link-notices" / run_id / "fixture-absence.json").read_bytes() == linked_absence_expected[label]
                assert complete["components"]["driver"]["files"] == (4 if label == "both" else 3)
                assert complete["components"]["fixture"]["files"] == (2 if label == "both" else 0)
                assert sum(item["total_bytes"] for item in complete["components"].values()) == sum(map(len, wanted.values()))
            passed("linked synthetic authenticated retrieval " + label, actual_network=False,
                   consumer_calls=1, digest_admissions=1, downloads=download_calls)
        for module, operation in [(s, "seal"), (u, "unseal"), (r, "retrieve")]:
            source_module = s if module is s else module.s
            invalid = dict(linked_identity, job="unit")
            with mock.patch.object(source_module, "reserve_operation") as reserved:
                try:
                    if operation == "seal":
                        s.seal(root / "must-not-exist", invalid, cert)
                    elif operation == "unseal":
                        u.unseal(root / "must-not-exist", invalid, zip_path, trusted, key, cert)
                    else:
                        r.retrieve(root / "must-not-exist", invalid, str(github_run), key, cert, synthetic_token)
                except source_module.Rejected:
                    pass
                else:
                    raise AssertionError("linked wrong job admitted")
                assert reserved.call_count == 0
            passed("linked pure layout/job admission " + operation, filesystem_reservations=0)
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
