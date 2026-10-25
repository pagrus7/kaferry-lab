#!/usr/bin/env python3
"""Bounded SYNTHETIC controls. No Go, Docker, real HTTPS or upload.

Keys and all synthetic plaintext stay below excluded owner-only
.cache/private-notice-tests, never the public .cache/unit artifact tree.
"""
import importlib.util
import contextlib
import copy
import errno
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
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
            original_notice = "PRIVATE-SENTINEL original literal OS notice " + name
            private_path = "/private/PRIVATE-SENTINEL/" + name
            error = OSError(number, original_notice, private_path)
            error.__cause__ = OSError(errno.EIO, "PRIVATE-SENTINEL original cause", private_path + "-cause")
            error.__context__ = ValueError("PRIVATE-SENTINEL original context")
            original_read, original_write = s.read_regular, s.write_private
            original_open, original_persist = s.os.open, s.persist_receipt
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
                return original_open(path, *args, **kwargs)
            def read(path, *args, **kwargs):
                if point == "read" or (point == "key" and Path(path) == key):
                    fail()
                return original_read(path, *args, **kwargs)
            def write(path, body):
                if ((point == "write" and Path(path).name == "notice.cms")
                        or (point == "recovered" and "receipts" in Path(path).parts)):
                    fail()
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
            ("producer-complete-rename-EPERM", False, "rename", errno.EPERM, 1, False),
            ("initial-reservation-EACCES", False, "reservation", errno.EACCES, 0, True),
            ("initial-receipt-persistence-EPERM", True, "receipt-initial", errno.EPERM, 0, True),
            ("original-notice-receipt-failure", False, "receipt-failed", errno.EACCES, 0, True),
            ("stock-command-receipt-write-EACCES", False, "receipt-write", errno.EACCES, 1, False),
        ]:
            cli_os_failure(name, consumer, point, number, commands, sink)
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
        def retrieved_case(name, changed=None, *, success=False, downloads=0, corrupt=False, reflected_error=False, http_failure=False, malformed=False):
            data = copy.deepcopy(fixtures)
            if changed is not None:
                changed(data)
            case_base = base("api-" + name)
            download_calls, request_calls = 0, 0
            def transport(url, token, maximum, deadline, download=False):
                nonlocal download_calls, request_calls
                request_calls += 1
                assert token == synthetic_token
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
            with mock.patch.object(r, "https_get", side_effect=transport):
                with mock.patch.object(r.http.client, "HTTPSConnection", side_effect=AssertionError("real network forbidden")):
                    with mock.patch.object(r.u, "unseal", wraps=r.u.unseal) as consumer:
                        try:
                            result = r.retrieve(case_base, identity, str(github_run), key, cert, synthetic_token)
                        except r.s.Rejected as error:
                            assert not success, name
                            assert "PRIVATE HTTP" not in str(error) and "HTTP-SENTINEL" not in str(error) and synthetic_token not in str(error)
                        else:
                            assert success and result == expected, name
                        assert consumer.call_count == (1 if success else 0), name
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
                   requests=request_calls, consumer_calls=1 if success else 0, actual_network=False)
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
        report["source_sha256"] = {p.name: s.digest(p.read_bytes()) for p in [Path(__file__), Path(__file__).with_name("seal-link-notices.py"), Path(__file__).with_name("unseal-link-notices.py"), Path(__file__).with_name("link-notices-recipient.pem"), Path(__file__).with_name("retrieve-link-notices.py")]}
        report["limits"] = ["Synthetic digest generated locally; external GitHub trust not established", "This self-report does not authenticate the runner; native identity requires collected CI bindings", "Recipient custody/backup not established by certificate or this test", "CBC is not AEAD; digest trust cannot be supplied by adjacent manifest", "No actual platform denial or stock-command timeout/output-overflow injection; deadline transport is synthetic", "Caller must stop notice writers before sealing; consistency checks detect observed changes, not hostile concurrent writers", "No publication exception or workflow enabled"]
        s.write_private(root / "report.json", s.encode(report))
        out = s.private_root(Path.cwd() / ".cache/m2/notice-sealing-implementation")
        s.write_private(out / (root.name + "-report.json"), s.encode(report))
    print(json.dumps({"status": report["status"], "controls": len(report["controls"]), "report": str(root / "report.json")}))


if __name__ == "__main__":
    run()
