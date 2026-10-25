#!/usr/bin/env python3
"""SYNTHETIC data-only controls of the exact workflow PYPROOF controller.

No driver, Go, Docker, crypto, network or uploaded notice is executed/read.
Literal receipts model driver facts; they cannot establish real writer closure.
"""
import ast
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
TEST_SHA = "b" * 64
SENTINEL = "PRIVATE_SYNTHETIC_CALLER_FIELD=must-never-be-public"
SCOPE = "Reviewed driver final marker after actual wait/tree closure and primary sink sync/close; no ACK or Kaferry qualification."


def digest(body):
    return hashlib.sha256(body).hexdigest()


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


def extract_proof(workflow):
    # Exact unique workflow heredoc, without a YAML dependency or logic copy.
    lines = workflow.decode().splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line == "          python3 - <<'PYPROOF'\n"]
    assert len(starts) == 1, "workflow must contain one exact PYPROOF"
    start = starts[0] + 1
    end = lines.index("          PYPROOF\n", start)
    assert all(line.startswith("          ") for line in lines[start:end])
    body = "".join(line[10:] for line in lines[start:end])
    ast.parse(body)
    return body


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
            "campaign.test": {"sha256": TEST_SHA, "bytes": 100, "mode": "0555",
                              "package": "github.com/pagrus7/kaferry-lab/internal/campaign.test",
                              "source_head": HEAD, "source_clean": True, "goos": "linux", "goarch": "amd64"},
            "link-calibration": {"sha256": "c" * 64, "bytes": 100, "mode": "0555",
                                 "package": "github.com/pagrus7/kaferry-lab/cmd/link-calibration",
                                 "source_head": HEAD, "source_clean": True, "goos": "linux", "goarch": "amd64"},
        },
        "release_qualified": False, "runtime_requested": True,
    }
    return {"marker": marker, "build": build, "foreground": "0\n", "cancelled": "false", "extra": []}


def expected_public():
    # Literal complete public projection: extra input fields must never appear.
    return {
        "namespace": "calibration/linked-caller", "run_id": RUN, "source_head": HEAD,
        "job": "links", "attempt": "2", "foreground_return_observed": True,
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
    workflow_path = repository / ".github/workflows/ci.yml"
    workflow = workflow_path.read_bytes()
    body = extract_proof(workflow)
    code = compile(body, str(workflow_path) + ":PYPROOF", "exec")
    parent = repository / ".cache/m2/linked-caller-controls"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
    root = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    source_paths = [Path(__file__).resolve(), workflow_path,
                    repository / "internal/campaign/link_calibration_driver.go",
                    repository / "internal/campaign/link_calibration_tree_linux.go",
                    repository / "cmd/link-calibration/main.go"]
    source_hashes = {str(path.relative_to(repository)): digest(path.read_bytes()) for path in source_paths}
    report = {"scope": "SYNTHETIC data-only caller sensitivity; no actual process/tree/writer proof",
              "status": "INCOMPLETE", "source_sha256": source_hashes,
              "exact_workflow_PYPROOF_sha256": digest(body.encode()), "controls": [],
              "limits": ["Exact extracted workflow code executes on independently literal synthetic files only.",
                         "No real driver, wait, ECHILD, cancellation, sink close or resource cleanup occurs.",
                         "No Docker/Go/network/crypto/raw notice/upload/publication authorization.",
                         "Unknown runtime/publication remain disabled; native source/evidence reviews remain separate."]}
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
    assert len(cases) <= 64
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
            output = case / "github-output"
            environment = {"CALLER_CANCELLED": fixture["cancelled"], "LAB_RUN_ID": RUN,
                           "GITHUB_SHA": HEAD, "GITHUB_JOB": "links", "GITHUB_RUN_ID": "123456",
                           "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKSPACE": str(case), "GITHUB_OUTPUT": str(output)}
            stdout, stderr = io.StringIO(), io.StringIO()
            previous = Path.cwd()
            returned = 0
            try:
                os.chdir(case)
                # When: run the exact compiled workflow body on actual bounded
                # files; only environment/cwd/output capture are test-local.
                with mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        exec(code, {"__name__": "__main__"})
                    except SystemExit as error:
                        returned = error.code
            finally:
                os.chdir(previous)
            proof = cache / "links/caller-proof.json"
            stdout_body, stderr_body = stdout.getvalue(), stderr.getvalue()
            published = proof.read_bytes() if proof.exists() else b""
            outputs = output.read_text() if output.exists() else ""
            # Then: independent exact public map or rejection without any flag.
            safe = SENTINEL not in stdout_body + stderr_body + published.decode() + outputs
            if expected is None:
                passed = returned == 1 and not proof.exists() and outputs == "" and safe
            else:
                desired_flags = "writers_stopped=true\ncalibration_passed=" + str(expected["calibration_passed"]).lower() + "\n"
                passed = returned == 0 and json.loads(published) == expected and outputs == desired_flags and safe
            assert len(stdout_body) + len(stderr_body) <= 16384
            report["controls"].append({"case": name, "passed": passed, "expected_admission": expected is not None,
                                       "actual_exit": returned, "public_projection_created": proof.exists(),
                                       "no_synthetic_private_leak": safe, "step_flags_exact": outputs == ("" if expected is None else desired_flags),
                                       "stdout_bytes": len(stdout_body.encode()), "stderr_bytes": len(stderr_body.encode())})
            assert time.monotonic() - started <= 20, "bounded caller control budget exceeded"
        assert source_hashes == {str(path.relative_to(repository)): digest(path.read_bytes()) for path in source_paths}, "source changed during controls"
        report["status"] = "PASS" if all(row["passed"] for row in report["controls"]) else "FAIL"
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        write_json(root / "report.json", report)
    print("linked caller synthetic controls: %d/%d passed; %s" % (sum(row["passed"] for row in report["controls"]), len(report["controls"]), root / "report.json"))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(run())
