#!/usr/bin/env python3
"""SYNTHETIC data-only controls of standalone linked-caller admission.

No driver, Go, Docker, crypto, network or uploaded notice is executed/read.
Literal receipts model driver facts; they cannot establish real writer closure.
"""
import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from unittest import mock

RUN = "links-123456-2"
HEAD = "a" * 40
TEST_IMAGE = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x02\x00\xb7\x00" + bytes(44)
DRIVER_IMAGE = TEST_IMAGE + b"literal synthetic driver image"
TEST_SHA = hashlib.sha256(TEST_IMAGE).hexdigest()
DRIVER_SHA = hashlib.sha256(DRIVER_IMAGE).hexdigest()
SENTINEL = "PRIVATE_SYNTHETIC_CALLER_FIELD=must-never-be-public"
SCOPE = "Reviewed driver final marker after actual wait/tree closure and primary sink sync/close; no ACK or Kaferry qualification."


def digest(body):
    return hashlib.sha256(body).hexdigest()


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


def literal_fixture(repository):
    # Given independently literal public driver/build facts, including real
    # struct field names, paths and terminal wait encodings, not production
    # constructors or values computed by the proof under test.
    marker = {
        "Version": "1", "RunID": RUN, "ReviewedHead": HEAD,
        "TestSHA256": TEST_SHA, "Synthetic": True, "ReleaseQualified": False,
        "Status": "CALIBRATION_PASSED_NOT_QUALIFICATION",
        "PrivateReference": str(repository / ".cache/link-calibration-private" / RUN / "driver-errors.json"),
        "DriverPrivate": str(repository / ".cache/link-calibration-private" / RUN),
        "FixturePrivate": str(repository / ".cache/fixtures-private" / (RUN + "-links")),
        "Wait": {
            "Started": True, "WaitReturned": True, "Reaped": True,
            "StreamCopiesJoined": True, "PID": 41001, "StartTicks": "123456789",
            "ExitCode": 0, "SignalNumber": 0,
            "LaunchAt": "2026-10-25T12:00:00Z", "WaitObservedAt": "2026-10-25T12:00:01Z",
            "WaitElapsedNS": 1000000000, "StdoutBytes": 10, "StderrBytes": 0,
            "CapturedStdoutBytes": 10, "CapturedStderrBytes": 0,
            "DroppedObservedStdoutBytes": 0, "DroppedObservedStderrBytes": 0,
            "OutputComplete": True, "TestsPassed": True,
        },
        "Tree": {
            "SubreaperEnabled": True, "AnchorStarted": True,
            "AnchorWaitReturned": True, "AnchorReaped": True,
            "AnchorPID": 41000, "AnchorStatus": 9, "AnchorStartTicks": "123456788",
            "ControlFailed": False, "SignalsClosed": True, "NoChildren": True, "Closed": True,
            "Signals": [{"SignalNumber": 9, "Errno": 0, "Succeeded": True, "Absent": False}],
            "Adopted": [{"PID": 41002, "Status": 0, "Terminal": True}],
        },
        "LatencyCleanup": {
            "PlannedName": "", "ContainerID": "", "PlanFound": False,
            "Attempted": False, "Resolved": True, "Removed": False,
            "Absent": False, "JournalComplete": True,
        },
        "SetupReturned": True, "CleanupReturned": True, "CleanupAttempted": True,
        "ResourcesCleaned": True, "FixtureCleanupSucceeded": True,
        "WritersQuiescent": True, "PrivateCaptureComplete": True,
        "SealingReady": False, "PublicationAuthorized": False,
    }
    build = {
        "namespace": "calibration/linked-build", "run_id": RUN, "job": "links",
        "attempt": "2", "source_head": HEAD, "built_after_utc": "2026-10-25T11:59:00Z",
        "executables": {
            "campaign.test": {"sha256": TEST_SHA, "bytes": len(TEST_IMAGE), "mode": "0555",
                              "package": "github.com/pagrus7/kaferry-lab/internal/campaign.test",
                              "source_head": HEAD, "source_clean": True, "goos": "linux", "goarch": "arm64"},
            "link-calibration": {"sha256": DRIVER_SHA, "bytes": len(DRIVER_IMAGE), "mode": "0555",
                                 "package": "github.com/pagrus7/kaferry-lab/cmd/link-calibration",
                                 "source_head": HEAD, "source_clean": True, "goos": "linux", "goarch": "arm64"},
        },
        "release_qualified": False, "runtime_requested": True,
        "kernel_system": "Linux", "kernel_machine": "aarch64",
    }
    return {"marker": marker, "build": build, "foreground": "0\n", "cancelled": "false", "extra": [],
            "kernel": ("Linux", "guest", "test", "test", "aarch64"), "test_image": TEST_IMAGE,
            "driver_image": DRIVER_IMAGE, "metadata_arch": "arm64", "metadata_extra": "", "fault": None, "partial_proof": False, "built_after_file": "2026-10-25T11:59:00Z\n"}


def expected_public():
    # Literal complete public projection: extra input fields must never appear.
    return {
        "namespace": "calibration/linked-caller", "run_id": RUN, "source_head": HEAD,
        "job": "links", "attempt": "2", "identity_source": "explicit-caller",
        "kernel_system": "Linux", "kernel_machine": "aarch64", "goos": "linux", "goarch": "arm64",
        "driver_sha256": DRIVER_SHA, "test_sha256": TEST_SHA, "foreground_return_observed": True,
        "foreground_exit_code": 0, "caller_cancelled_at_admission": False,
        "writers_quiescent": True, "private_capture_complete": True, "setup_returned": True,
        "cleanup_attempted": True, "cleanup_returned": True, "resources_cleaned": True,
        "fixture_cleanup_succeeded": True, "child_started": True, "child_wait_returned": True,
        "child_reaped": True, "stream_copies_joined": True, "anchor_started": True,
        "anchor_wait_returned": True, "anchor_reaped": True, "subreaper_enabled": True,
        "terminal_adopted_waits": 1, "actual_ECHILD_observed_by_driver": True,
        "calibration_passed": True, "release_qualified": False, "scope": SCOPE,
    }


def failed_but_quiescent(fixture):
    fixture["foreground"] = "1\n"
    fixture["marker"].update(Status="INCOMPLETE", ResourcesCleaned=False, FixtureCleanupSucceeded=False)
    fixture["marker"]["Wait"].update(TestsPassed=False, ExitCode=1)


def failed_setup(fixture):
    failed_but_quiescent(fixture)
    fixture["marker"].update(CleanupAttempted=False, CleanupReturned=False)
    fixture["marker"]["Wait"].update(Started=False, WaitReturned=False, Reaped=False,
                                    StreamCopiesJoined=False, PID=0, StartTicks="", OutputComplete=False)
    fixture["marker"]["Tree"].update(AnchorStarted=False, AnchorWaitReturned=False,
                                    AnchorReaped=False, AnchorPID=0, AnchorStartTicks="", Adopted=None)


def unknown_fields(fixture):
    fixture["marker"]["UnreviewedDiagnostic"] = SENTINEL
    fixture["marker"]["Wait"]["RawChildOutput"] = SENTINEL
    fixture["marker"]["Tree"]["UnknownFutureField"] = {"nested": SENTINEL}
    fixture["marker"]["LatencyCleanup"]["PlannedName"] = SENTINEL
    fixture["build"]["UnreviewedDiagnostic"] = SENTINEL


def run():
    os.umask(0o077)
    repository = Path(__file__).resolve().parent.parent
    implementation = repository / "scripts/admit-linked-caller.py"
    spec = importlib.util.spec_from_file_location("linked_caller", implementation)
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    parent = repository / ".cache/m2/native-return-20261028/caller-slice"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="controls-", dir=parent))
    source_paths = [Path(__file__).resolve(), implementation]
    source_hashes = {str(path.relative_to(repository)): digest(path.read_bytes()) for path in source_paths}
    report = {"scope": "SYNTHETIC data-only caller sensitivity; no actual process/tree/writer proof",
              "status": "INCOMPLETE", "source_sha256": source_hashes, "controls": [],
              "limits": ["Actual standalone main reads literal synthetic files; only uname is mocked.",
                         "No real driver, native platform, wait, ECHILD, cancellation or resource cleanup occurs.",
                         "ELF specimens and retained Go metadata are literal synthetic data, never executed.",
                         "No Docker/Go/network/crypto/upload/publication authorization."]}
    cases = [("valid-complete-terminal-proof", lambda f: None, expected_public()),
             ("unknown-raw-fields-stay-out-of-public-projection", unknown_fields, expected_public())]
    failed_expected = expected_public()
    failed_expected.update(foreground_exit_code=1, resources_cleaned=False,
                           fixture_cleanup_succeeded=False, calibration_passed=False)
    cases.append(("failed-calibration-still-retains-writer-proof", failed_but_quiescent, failed_expected))
    setup_expected = copy.deepcopy(failed_expected)
    setup_expected.update(cleanup_attempted=False, cleanup_returned=False, child_started=False,
                          child_wait_returned=False, child_reaped=False, stream_copies_joined=False,
                          anchor_started=False, anchor_wait_returned=False, anchor_reaped=False,
                          terminal_adopted_waits=0)
    cases.append(("failed-setup-no-child-no-invented-cleanup-return", failed_setup, setup_expected))
    cases += [(name, mutate, None) for name, mutate in [
        ("cancelled-caller", lambda f: f.update(cancelled="true")),
        ("absent-foreground-return", lambda f: f.update(foreground=None)),
        ("malformed-foreground-return", lambda f: f.update(foreground="0")),
        ("foreground-failure-cannot-claim-calibration-pass", lambda f: f.update(foreground="1\n")),
        ("incomplete-final-marker-present", lambda f: f["extra"].append("INCOMPLETE.json")),
        ("pending-result-present", lambda f: f["extra"].append("result.pending.json")),
        ("writer-proof-false", lambda f: f["marker"].update(WritersQuiescent=False)),
        ("capture-incomplete", lambda f: f["marker"].update(PrivateCaptureComplete=False)),
        ("setup-unreturned", lambda f: f["marker"].update(SetupReturned=False)),
        ("passed-nonzero-child-exit", lambda f: f["marker"]["Wait"].update(ExitCode=23)),
        ("passed-signalled-child", lambda f: f["marker"]["Wait"].update(ExitCode=-1, SignalNumber=15)),
        ("passed-no-child", lambda f: f["marker"]["Wait"].update(Started=False, WaitReturned=False, Reaped=False, StreamCopiesJoined=False, PID=0, StartTicks="", WaitElapsedNS=0, StdoutBytes=0, CapturedStdoutBytes=0)),
        ("passed-no-anchor", lambda f: f["marker"]["Tree"].update(AnchorStarted=False, AnchorWaitReturned=False, AnchorReaped=False, AnchorPID=0, AnchorStartTicks="", AnchorStatus=0)),
        ("test-wait-unreturned", lambda f: f["marker"]["Wait"].update(WaitReturned=False)),
        ("test-unreaped", lambda f: f["marker"]["Wait"].update(Reaped=False)),
        ("copier-unjoined", lambda f: f["marker"]["Wait"].update(StreamCopiesJoined=False)),
        ("cleanup-attempt-unreturned", lambda f: f["marker"].update(CleanupReturned=False)),
        ("cleanup-return-without-call", lambda f: f["marker"].update(CleanupAttempted=False)),
        ("live-anchor", lambda f: f["marker"]["Tree"].update(AnchorWaitReturned=False, AnchorReaped=False)),
        ("anchor-signal-phase-open", lambda f: f["marker"]["Tree"].update(SignalsClosed=False)),
        ("missing-ECHILD-nochildren", lambda f: f["marker"]["Tree"].update(NoChildren=False)),
        ("missing-ECHILD-closure", lambda f: f["marker"]["Tree"].update(Closed=False)),
        ("control-denial", lambda f: f["marker"]["Tree"].update(ControlFailed=True)),
        ("subreaper-not-proven", lambda f: f["marker"]["Tree"].update(SubreaperEnabled=False)),
        ("adopted-wait-nonterminal", lambda f: f["marker"]["Tree"]["Adopted"][0].update(Terminal=False)),
        ("adopted-stopped-status", lambda f: f["marker"]["Tree"]["Adopted"][0].update(Status=0x137f)),
        ("anchor-stopped-status", lambda f: f["marker"]["Tree"].update(AnchorStatus=0x137f)),
        ("adopted-status-not-integer", lambda f: f["marker"]["Tree"]["Adopted"][0].update(Status="0")),
        ("adopted-status-bool", lambda f: f["marker"]["Tree"]["Adopted"][0].update(Status=True)),
        ("anchor-status-negative", lambda f: f["marker"]["Tree"].update(AnchorStatus=-1)),
        ("test-signal-exit-contradiction", lambda f: f["marker"]["Wait"].update(SignalNumber=9, ExitCode=0)),
        ("output-prefix-incomplete", lambda f: f["marker"]["Wait"].update(OutputComplete=False)),
        ("observed-output-dropped", lambda f: f["marker"]["Wait"].update(DroppedObservedStdoutBytes=1)),
        ("captured-output-count-mismatch", lambda f: f["marker"]["Wait"].update(CapturedStdoutBytes=9)),
        ("wrong-marker-run", lambda f: f["marker"].update(RunID="links-654321-2")),
        ("wrong-reviewed-head", lambda f: f["marker"].update(ReviewedHead="d" * 40)),
        ("wrong-test-image", lambda f: f["marker"].update(TestSHA256="e" * 64)),
        ("wrong-build-run", lambda f: f["build"].update(run_id="links-654321-2")),
        ("wrong-build-attempt", lambda f: f["build"].update(attempt="3")),
        ("wrong-build-job", lambda f: f["build"].update(job="unit")),
        ("wrong-driver-private-root", lambda f: f["marker"].update(DriverPrivate="/CALIBRATION-ONLY/wrong")),
        ("wrong-primary-sink", lambda f: f["marker"].update(PrivateReference="/CALIBRATION-ONLY/wrong")),
        ("wrong-fixture-private-root", lambda f: f["marker"].update(FixturePrivate="/CALIBRATION-ONLY/wrong")),
        ("raw-status-cannot-be-public", lambda f: f["marker"].update(Status=SENTINEL)),
        ("raw-identity-cannot-be-public", lambda f: f["marker"].update(ReviewedHead=SENTINEL)),
        ("false-release-qualification", lambda f: f["marker"].update(ReleaseQualified=True)),
    ]]
    cases += [(name, mutate, None) for name, mutate in [
        ("mac-kernel-refused", lambda f: f.update(kernel=("Darwin", "guest", "test", "test", "arm64"))),
        ("amd64-kernel-refused", lambda f: f.update(kernel=("Linux", "guest", "test", "test", "x86_64"))),
        ("build-kernel-mismatch", lambda f: f["build"].update(kernel_machine="x86_64")),
        ("amd64-test-build-refused", lambda f: f["build"]["executables"]["campaign.test"].update(goarch="amd64")),
        ("amd64-driver-build-refused", lambda f: f["build"]["executables"]["link-calibration"].update(goarch="amd64")),
        ("wrong-driver-source", lambda f: f["build"]["executables"]["link-calibration"].update(source_head="f" * 40)),
        ("dirty-driver-source", lambda f: f["build"]["executables"]["link-calibration"].update(source_clean=False)),
        ("wrong-driver-image", lambda f: f.update(driver_image=DRIVER_IMAGE + b"altered")),
        ("wrong-test-bytes", lambda f: f.update(test_image=TEST_IMAGE + b"altered")),
        ("wrong-retained-Go-target", lambda f: f.update(metadata_arch="amd64")),
        ("conflicting-retained-Go-target", lambda f: f.update(metadata_extra="\tbuild\tGOARCH=amd64\n")),
        ("wrong-build-timestamp-binding", lambda f: f.update(built_after_file="2026-10-25T11:58:00Z\n")),
        ("exact-private-read-error", lambda f: f.update(fault="read")),
        ("read-and-close-originals-both-retained", lambda f: f.update(fault="read-close")),
        ("proof-sync-error-cannot-admit", lambda f: f.update(fault="sync", partial_proof=True)),
        ("negative-guest-foreground", lambda f: f.update(foreground="-1\n")),
        ("boolean-guest-foreground", lambda f: f.update(foreground="true\n")),
    ]]
    assert len(cases) <= 80
    assert len({case_name for case_name, _, _ in cases}) == len(cases), "control identities must be unique"
    started = time.monotonic()
    try:
        for index, (name, mutate, expected) in enumerate(cases):
            case = root / ("case-%02d" % index)
            case.mkdir(mode=0o700)
            fixture = literal_fixture(case)
            mutate(fixture)
            cache = case / ".cache"
            cache.mkdir(mode=0o700)
            (cache / "links").mkdir(mode=0o700)
            (cache / "link-calibration").mkdir(mode=0o700)
            public = cache / "link-calibration" / RUN
            public.mkdir(mode=0o700)
            write_json(public / "WRITERS_QUIESCENT.json", fixture["marker"])
            write_json(cache / "links/build.json", fixture["build"])
            if fixture["foreground"] is not None:
                (cache / "links/foreground.exit").write_text(fixture["foreground"])
            for extra in fixture["extra"]:
                write_json(public / extra, {})
            build_dir = cache / "link-calibration-build" / RUN
            build_dir.mkdir(mode=0o700, parents=True)
            build_dir.parent.chmod(0o700)
            (build_dir / "BuiltAfterUTC").write_text(fixture["built_after_file"])
            for executable_name, body, package, metadata in [
                    ("campaign.test", fixture["test_image"], "github.com/pagrus7/kaferry-lab/internal/campaign.test", "test-buildinfo.txt"),
                    ("link-calibration", fixture["driver_image"], "github.com/pagrus7/kaferry-lab/cmd/link-calibration", "driver-buildinfo.txt")]:
                (build_dir / executable_name).write_bytes(body)
                (build_dir / executable_name).chmod(0o555)
                (build_dir / metadata).write_text("\tpath\t" + package + "\n" + "".join(
                    "\tbuild\t" + setting + "\n" for setting in (
                        "GOOS=linux", "GOARCH=" + fixture["metadata_arch"], "vcs.revision=" + HEAD, "vcs.modified=false")) + fixture["metadata_extra"])
            error_path = case / "caller-errors.json"
            error_fd = os.open(error_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            stdout, stderr = io.StringIO(), io.StringIO()
            argv = ["--repository", str(case), "--run-id", RUN, "--source-head", HEAD,
                    "--attempt", "2", "--caller-cancelled", fixture["cancelled"], "--error-fd", str(error_fd)]
            # When: execute the actual standalone CLI body with literal files.
            # Mock uname is explicitly synthetic and never establishes native evidence.
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(c.os, "uname", return_value=os.uname_result(fixture["kernel"])))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                if fixture["fault"] == "read":
                    stack.enter_context(mock.patch.object(c, "read", side_effect=PermissionError(13, SENTINEL, "/synthetic/private")))
                if fixture["fault"] == "read-close":
                    original_fdopen = c.os.fdopen
                    class ReadCloseFailure:
                        def __init__(self, fd, mode):
                            self.stream = original_fdopen(fd, mode)
                        def fileno(self):
                            return self.stream.fileno()
                        def read(self, maximum):
                            raise OSError(5, SENTINEL + " read")
                        def close(self):
                            self.stream.close()
                            raise OSError(9, SENTINEL + " close")
                    stack.enter_context(mock.patch.object(c.os, "fdopen", side_effect=ReadCloseFailure))
                if fixture["fault"] == "sync":
                    stack.enter_context(mock.patch.object(c.os, "fsync", side_effect=[OSError(5, SENTINEL), None]))
                returned = c.main(argv)

            proof = cache / "links/caller-proof.json"
            stdout_body, stderr_body = stdout.getvalue(), stderr.getvalue()
            published = proof.read_bytes() if proof.exists() else b""
            errors = error_path.read_bytes()
            # Then: independent exact public map or rejection without any flag.
            safe = SENTINEL not in stdout_body + stderr_body + published.decode()
            if expected is None:
                passed = returned == 1 and proof.exists() == fixture["partial_proof"] and bool(errors) and safe
            else:
                desired_exit = 0 if expected["calibration_passed"] else 2
                passed = returned == desired_exit and json.loads(published) == expected and errors == b"" and safe
            if name == "absent-foreground-return":
                raw_error = json.loads(errors)
                passed = passed and raw_error == {
                    "action": "linked caller admission", "type": "FileNotFoundError", "errno": 2,
                    "exact_text": str(FileNotFoundError(2, "No such file or directory", str(cache / "links/foreground.exit"))),
                    "filename": str(cache / "links/foreground.exit"), "filename2": None}
            if fixture["fault"] == "read":
                passed = passed and json.loads(errors) == {
                    "action": "linked caller admission", "type": "PermissionError", "errno": 13,
                    "exact_text": str(PermissionError(13, SENTINEL, "/synthetic/private")),
                    "filename": "/synthetic/private", "filename2": None}
            if fixture["fault"] == "read-close":
                passed = passed and json.loads(errors) == {"complete": True, "failures": [
                    {"action": "read/validate build.json", "type": "OSError", "errno": 5,
                     "exact_text": str(OSError(5, SENTINEL + " read")), "filename": None, "filename2": None},
                    {"action": "close build.json", "type": "OSError", "errno": 9,
                     "exact_text": str(OSError(9, SENTINEL + " close")), "filename": None, "filename2": None}]}
            if fixture["fault"] == "sync":
                passed = passed and json.loads(errors) == {"complete": True, "failures": [{
                    "action": "write/sync caller-proof.json", "type": "OSError", "errno": 5,
                    "exact_text": str(OSError(5, SENTINEL)), "filename": None, "filename2": None}]}
            assert len(stdout_body) + len(stderr_body) <= 16384
            report["controls"].append({"case": name, "passed": passed, "expected_admission": expected is not None,
                                       "actual_exit": returned, "public_projection_created": proof.exists(),
                                       "no_synthetic_private_leak": safe, "private_error_retained": bool(errors),
                                       "stdout_bytes": len(stdout_body.encode()), "stderr_bytes": len(stderr_body.encode())})
            assert time.monotonic() - started <= 20, "bounded caller control budget exceeded"
        assert source_hashes == {str(path.relative_to(repository)): digest(path.read_bytes()) for path in source_paths}, "source changed during controls"
        assert [row["case"] for row in report["controls"]] == [case_name for case_name, _, _ in cases], "reported control identities changed"
        report["status"] = "PASS" if all(row["passed"] for row in report["controls"]) else "FAIL"
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        write_json(root / "report.json", report)
    print("linked caller synthetic controls: %d/%d passed; %s" % (sum(row["passed"] for row in report["controls"]), len(report["controls"]), root / "report.json"))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(run())
