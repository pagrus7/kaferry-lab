#!/usr/bin/env python3
"""Admit a closed one-shot diagnostic snapshot; no request or qualification.

The workflow separately observes the caller and sealer foreground returns.
Receipt contents cannot prove their own writer's successful terminal close.
"""
import argparse
import base64
import importlib.util
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("metadata_caller", Path(__file__).with_name("capture-metadata.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
s = c.s


def exact(actual, expected):
    c.require(type(actual) is type(expected))
    if type(expected) is dict:
        c.require(set(actual) == set(expected))
        for key in expected:
            exact(actual[key], expected[key])
    elif type(expected) is list:
        c.require(len(actual) == len(expected))
        for a, e in zip(actual, expected):
            exact(a, e)
    else:
        c.require(actual == expected)


def validate(base, value, binary_sha, foreground_exit, sealed=False, calibration=False):
    """Data-only admission, after the workflow's actual foreground command."""
    c.require(type(foreground_exit) is int and foreground_exit in (0, 2))
    c.binary(base, value, binary_sha)
    foreground = base / ".cache/metadata-foreground-private" / value["run_id"]
    s.check_chain(foreground)
    s.check_private(foreground.lstat(), True)
    exact(s.read_regular(foreground / "foreground.exit", 4, private=True), (str(foreground_exit) + "\n").encode())
    exact(s.read_regular(foreground / "stderr.bin", 65536, private=True), b"")
    public = s.parse_json(s.read_regular(foreground / "stdout.json", 4096, private=True))
    expected = dict(namespace=c.NAMESPACE, release_qualified=False, status="capture-closed",
                    finite_snapshot_closed=True, snapshot_admissible=True,
                    capture_complete=foreground_exit == 0)
    exact(public, expected)
    root = base / ".cache/fixtures-private" / (value["run_id"] + "-links")
    payloads = s.snapshot(root, value["run_id"])
    c.require(set(payloads) == {"PRIVATE.json", "metadata.json", "capture-closure.json"})
    proof = s.parse_json(payloads["capture-closure.json"])
    for key, expected_value in dict(value, RunID=value["run_id"], namespace=c.NAMESPACE,
            release_qualified=False, binary_sha256=binary_sha, child_started=True,
            private_sinks_synced_closed=True, error_sink_synced_closed=True,
            finite_snapshot_closed=True, snapshot_admissible=True, errors_complete=True,
            producer_receipt_valid=True, capture_complete=foreground_exit == 0).items():
        exact(proof[key], expected_value)
    for key in ("child_pid", "child_start_ticks"):
        c.require(type(proof[key]) is int and proof[key] > 0)
    exact(proof["errors"], [])
    wait = proof["child_wait"]
    for key, expected_value in {"wait_returned": True, "returncode": foreground_exit,
            "selector_closed": True, "terminate_requested": False, "kill_requested": False,
            "deadline_reached": False, "cancelled": False, "cleanup_exhausted": False}.items():
        exact(wait[key], expected_value)
    exact(set(proof["streams"]), {"stdout", "stderr"})
    for stream in proof["streams"].values():
        for key, expected_value in {"eof": True, "pipe_closed": True,
                "private_write_complete": True, "overflow": False, "read_failed": False,
                "representation": "base64 observed bytes"}.items():
            exact(stream[key], expected_value)
    exact(proof["streams"]["stdout"]["prefix"], "bWV0YWRhdGEgZGlhZ25vc3RpYyBvYnNlcnZhdGlvbiBjbG9zZWQK")
    exact(proof["streams"]["stderr"]["prefix"], "")
    metadata = c.producer_receipt(payloads["metadata.json"], value, wait)
    exact(metadata["capture_complete"], foreground_exit == 0)
    if calibration:
        # The actual Go executable traverses the same foreground/admission/seal
        # path using a deliberately absent synthetic trust file. Ordinary trust
        # setup must fail before client.Do; no provider request is a control.
        exact(foreground_exit, 2)
        exact(metadata["attempt_count"], 0)
        exact(metadata["response_available"], False)
        exact(metadata["errors"]["complete"], True)
        missing = str(base / ".cache/metadata-build" / value["run_id"] /
                      "calibration-trust-file-must-be-absent.pem").encode()
        fields = c.decode_frames(base64.b64decode(metadata["errors"]["prefix_base64"], validate=True))
        exact(fields, [b"0", b"*fs.PathError", b"open " + missing + b": no such file or directory",
                       b"0/0", b"syscall.Errno", b"no such file or directory"])
    if sealed:
        quarantine = base / ".cache/link-quarantine" / value["run_id"]
        s.check_chain(quarantine)
        s.check_private(quarantine.lstat(), True)
        exact(set(p.name for p in quarantine.iterdir()), {"notice.cms", "COMPLETE.json"})
        cms = s.read_regular(quarantine / "notice.cms", s.MAX_CMS, private=True)
        c.require(0 < len(cms) <= s.MAX_CMS)
        complete = s.parse_json(s.read_regular(quarantine / "COMPLETE.json", s.MAX_FILE, private=True))
        expected = dict(value, complete=True, cms_bytes=len(cms), cms_sha256=s.digest(cms),
                        files=len(payloads), total_bytes=sum(map(len, payloads.values())),
                        publication="DISABLED; explicit encrypted-public-quarantine exception required",
                        cipher="AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD")
        exact(complete, expected)
    return metadata["capture_complete"]


def main():
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise s.Rejected("metadata admission arguments rejected")
    p = Parser(description=__doc__)
    for name in ("run-id", "source-head", "attempt", "binary-sha256", "foreground-exit"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--sealed", action="store_true")
    p.add_argument("--calibration", action="store_true")
    args = p.parse_args()
    value = c.identity(args.run_id, args.source_head, "metadata", args.attempt, os.environ)
    # The one primary private admission sink precedes reads of unknown receipts.
    _, fd = s.reserve_operation(Path(".cache/metadata-admission-private"),
                                args.run_id + ("-sealed" if args.sealed else "-open"))
    try:
        c.require(args.foreground_exit in ("0", "2"))
        c.require(os.environ.get("METADATA_MODE") in ("metadata-calibration", "metadata-diagnostic"))
        exact(args.calibration, os.environ["METADATA_MODE"] == "metadata-calibration")
        complete = validate(Path.cwd(), value, args.binary_sha256, int(args.foreground_exit), args.sealed, args.calibration)
        owned, fd = fd, None
        s.close_operation(owned)
        # Outcome=success is separately mandatory: a partial GITHUB_OUTPUT write
        # followed by a failed close never authorizes the upload.
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write("complete=true\nsnapshot_admissible=true\ncapture_complete=" + str(complete).lower() + "\n")
        return 0
    except BaseException as error:
        if fd is not None:
            try:
                s.retain_os_error(fd, "admit closed metadata snapshot" + (" and sealed capsule" if args.sealed else ""), error)
            finally:
                owned, fd = fd, None
                s.close_operation(owned, error)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit as error:
        if error.code != 0:
            print("metadata admission rejected; upload disabled", file=sys.stderr)
        raise
    except BaseException:
        print("metadata admission rejected; upload disabled", file=sys.stderr)
        raise SystemExit(1) from None
