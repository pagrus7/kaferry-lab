#!/usr/bin/env python3
"""Data-only controls: fake handles and pipes are NOT actual wait/PID evidence."""
import base64
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch, Mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("metadata_caller_proposal", Path(__file__).with_name("capture-metadata.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class Pipe:
    def __init__(self, fd):
        self.fd, self.closed = fd, False

    def fileno(self):
        return self.fd

    def close(self):
        self.closed = True


class FakeChild:
    """Synthetic integers only: no operating-system PID or wait is consulted."""
    pid = 123

    def __init__(self, exit_code=0, live=False, resist_term=False, wait_error=False):
        self.stdout, self.stderr = Pipe(11), Pipe(12)
        self.code = None if live else exit_code
        self.resist_term, self.wait_error = resist_term, wait_error
        self.calls = []

    def poll(self):
        return self.code

    def terminate(self):
        self.calls.append("TERM exact fake handle")
        if not self.resist_term:
            self.code = -15

    def kill(self):
        self.calls.append("KILL exact fake handle")
        self.code = -9

    def wait(self, timeout):
        self.calls.append(("WAIT exact fake handle", timeout))
        if self.wait_error:
            raise OSError(10, "synthetic unavailable child wait")
        if self.code is None:
            raise subprocess.TimeoutExpired("fixed fake producer", timeout)
        return self.code


class FakeSelector:
    def __init__(self, data, child, close_error=False, missing_eof=False):
        self.keys = {}
        self.data = {key: list(value) for key, value in data.items()}
        self.child, self.close_error, self.missing_eof = child, close_error, missing_eof

    def register(self, pipe, _events, name):
        self.keys[pipe.fd] = type("Key", (), {"fileobj": pipe, "data": name})()

    def unregister(self, pipe):
        self.keys.pop(pipe.fd)

    def get_map(self):
        return self.keys

    def select(self, _timeout):
        return [(key, 1) for fd, key in self.keys.items()
                if self.data.get(fd) or (self.child.code is not None and not self.missing_eof)]

    def read(self, fd, _size):
        return self.data[fd].pop(0) if self.data.get(fd) else b""

    def close(self):
        if self.close_error:
            raise OSError(5, "synthetic selector close failed")


def run_fake(child=None, data=None, selector_options=None, write=None):
    child = child or FakeChild()
    selector = FakeSelector(data or {11: [b"\x00\xffopaque"], 12: [b"synthetic private error"]},
                            child, **(selector_options or {}))
    ticks, errors, persisted = [0], [], {21: bytearray(), 22: bytearray()}

    def clock():
        ticks[0] += 0.25
        return ticks[0]

    def persist(fd, body):
        persisted[fd].extend(body)
        return len(body)

    wait, streams = c.drive(child, {"stdout": 21, "stderr": 22},
                            lambda action, error: errors.append(c.exception_record(action, error)),
                            selector_factory=lambda: selector, read=selector.read,
                            monotonic=clock, persist=write or persist)
    return wait, streams, errors, persisted, child


VALUE = {"run_id": "metadata-123-1", "source_head": "a" * 40, "job": "metadata", "attempt": "1",
         "recipient_sha256": c.s.CERT_PIN}


def framed(*values):
    # Independent contract fixture encoder, not the producer/caller codec.
    return b"".join(len(value).to_bytes(8, "big") + value for value in values)


def literal_receipt(complete=True, status=403):
    # Literal contract fixture; does not derive fields from the producer/source.
    stream = {"prefix_base64": "", "observed_bytes_lower_bound": 0, "complete": True,
              "overflow": False, "traversal_guard_reached": False}
    def observed(raw, done=True):
        return dict(stream, prefix_base64=base64.b64encode(raw).decode(),
                    observed_bytes_lower_bound=len(raw), complete=done)
    headers = framed(str(status).encode() + (b" Forbidden" if status == 403 else b" OK"),
                     b"HTTP/2.0", b"headers", b"X-Synthetic", b"1", b"binary:\x00\xff")
    return dict(RunID="metadata-123-1", source_head="a" * 40, github_run_id="123", job="metadata", attempt="1",
                namespace="calibration/metadata-diagnostic", release_qualified=False, platform="linux/amd64",
                method="GET", url="https://api.github.com/repos/pagrus7/kaferry/git/ref/tags/v0.6.0",
                accept="application/vnd.github+json", user_agent="kaferry-lab-artifact", attempt_count=1,
                started_utc="2026-10-26T00:00:00Z", elapsed_ns_monotonic=123,
                response_available=complete, status_code=status if complete else 0,
                headers_representation="CLIENT-DECODED net/http fields; uint64be-length frames: status,protocol, then section,name,value-count,values; sections=headers,trailers; sorted names; not wire octets", headers=observed(headers if complete else b"", complete),
                body_representation="net/http exposed response-body bytes; may be transparently decompressed; not wire octets", body=observed(b"synthetic provider explanation:\x00\xff" if complete else b"", complete),
                errors_representation="uint64be-length frames: node-path,Go-type,Error()-bytes; root 0=setup/transport,1=body-read,2=body-close,3=context; bounded unwrap graph", errors=observed(b"" if complete else framed(b"0", b"*url.Error", b"synthetic transport failure")),
                body_close_attempted=complete, body_close_succeeded=complete, net_http_uncompressed=False,
                capture_complete=complete)


def run_caller_fake(*, code=0, raw=None, final_close_error=False, final_write_error=False,
                    error_close_error=False, read_error=None, error_write_error=False):
    wait, streams, errors, _, child = run_fake(FakeChild(exit_code=code),
                                               data={11: [b"metadata diagnostic observation closed\n"], 12: []})
    fds, close_calls, persisted = iter((100, 101, 102)), [], []

    def close(fd):
        close_calls.append(fd)
        if (fd == 100 and final_close_error) or (fd == 90 and error_close_error):
            raise OSError(5, "synthetic terminal sink failure")

    def persist(fd, body):
        persisted.append((fd, body))
        if fd == 100 and final_write_error:
            raise OSError(5, "synthetic final receipt failure")
        if fd == 90 and error_write_error:
            raise OSError(5, "synthetic primary error receipt failure")

    def launch(argv, **options):
        # Literal cross-language CLI contract: absolute output used to fail it.
        expected = ["/SYNTHETIC/fixed", "--run-id", "metadata-123-1", "--source-head", "a" * 40,
                    "--job", "metadata", "--attempt", "1", "--output",
                    ".cache/fixtures-private/metadata-123-1-links/metadata.json"]
        if argv != expected or options.get("cwd") != Path("/SYNTHETIC"):
            raise AssertionError("producer launch interface mismatch")
        if options != dict(cwd=Path("/SYNTHETIC"), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, shell=False):
            raise AssertionError("producer launch transport drift")
        return child

    with ExitStack() as stack:
        for owner, attribute, replacement in (
                (c.s, "reserve_operation", Mock(return_value=(Path("/SYNTHETIC/private"), 90))),
                (c.s, "reserve", Mock(return_value=Path("/SYNTHETIC/fixture"))),
                (c.s, "write_private", Mock()), (c.s, "signature", Mock(return_value="synthetic signature")),
                (c.s, "read_regular", Mock(side_effect=read_error, return_value=raw if raw is not None else c.s.encode(literal_receipt(code == 0)))),
                (c.s, "persist_receipt", persist), (c, "binary", Mock(return_value=(Path("/SYNTHETIC/fixed"), "synthetic signature"))),
                (c, "start_ticks", Mock(return_value=456)), (c, "drive", Mock(return_value=(wait, streams))),
                (Path, "lstat", Mock()), (c.os, "open", Mock(side_effect=lambda *_args: next(fds))),
                (c.os, "fsync", Mock()), (c.os, "close", close), (c.subprocess, "Popen", Mock(side_effect=launch))):
            stack.enter_context(patch.object(owner, attribute, replacement))
        result = c.run_capture(Path("/SYNTHETIC"), VALUE, "b" * 64)
    return result, close_calls, persisted


class Controls(unittest.TestCase):
    def test_foreground_return_codes_keep_closed_failure_distinct(self):
        argv = ["capture-metadata.py", "--run-id", "metadata-123-1", "--source-head", "a" * 40,
                "--job", "metadata", "--attempt", "1", "--binary-sha256", "b" * 64]
        for result, expected in (({"capture_complete": True, "snapshot_admissible": True}, 0),
                                 ({"capture_complete": False, "snapshot_admissible": True}, 2),
                                 ({"capture_complete": False, "snapshot_admissible": False}, 1)):
            with self.subTest(expected=expected), patch.object(sys, "argv", argv), \
                    patch.object(c, "identity", return_value=VALUE), \
                    patch.object(c, "run_capture", return_value=result), patch("builtins.print"):
                self.assertEqual(c.main(), expected)

    def test_stream_complete_cannot_hide_length_or_label_drift(self):
        for field in ("headers", "body", "errors"):
            for mutation in ("length", "label", "base64"):
                receipt = literal_receipt()
                if mutation == "length":
                    receipt[field]["observed_bytes_lower_bound"] = 1
                elif mutation == "label":
                    receipt[field + "_representation"] = "wire-exact invented label"
                else:
                    receipt[field]["prefix_base64"] = "not base64!"
                with self.subTest(field=field, mutation=mutation):
                    result, _, _ = run_caller_fake(raw=c.s.encode(receipt))
                    self.assertFalse(result.get("snapshot_admissible", False))

    def test_literal_complete_403_and_200_are_observations(self):
        for status in (403, 200):
            with self.subTest(status=status):
                result, _, _ = run_caller_fake(raw=c.s.encode(literal_receipt(status=status)))
                self.assertTrue(result["capture_complete"])
                self.assertTrue(result["snapshot_admissible"])

    def test_literal_transport_failure_closed_but_not_complete(self):
        result, _, _ = run_caller_fake(code=2)
        self.assertFalse(result["capture_complete"])
        self.assertTrue(result["finite_snapshot_closed"])
        self.assertTrue(result["snapshot_admissible"])

    def test_setup_failure_retains_zero_attempt_without_claiming_request(self):
        receipt = literal_receipt(False)
        receipt["attempt_count"] = 0
        receipt["errors"]["prefix_base64"] = base64.b64encode(framed(b"0", b"*fs.PathError", b"synthetic trust setup failure")).decode()
        receipt["errors"]["observed_bytes_lower_bound"] = len(base64.b64decode(receipt["errors"]["prefix_base64"]))
        result, _, _ = run_caller_fake(code=2, raw=c.s.encode(receipt))
        self.assertTrue(result["snapshot_admissible"])
        self.assertFalse(result["capture_complete"])
        for mutation in ("complete", "response", "close", "empty-error"):
            wrong = c.s.parse_json(c.s.encode(receipt))
            if mutation == "complete":
                wrong["capture_complete"] = True
            elif mutation == "response":
                wrong["response_available"], wrong["status_code"] = True, 403
            elif mutation == "close":
                wrong["body_close_attempted"] = True
            else:
                wrong["errors"] = dict(wrong["errors"], prefix_base64="", observed_bytes_lower_bound=0)
            with self.subTest(mutation=mutation):
                rejected, _, _ = run_caller_fake(code=2, raw=c.s.encode(wrong))
                self.assertFalse(rejected.get("snapshot_admissible", False))

    def test_post_capture_read_error_is_retained_before_terminal_sink_close(self):
        original = PermissionError(13, "synthetic metadata read denial", "/SYNTHETIC/metadata.json")
        result, closes, receipts = run_caller_fake(read_error=original)
        self.assertFalse(result.get("snapshot_admissible", False))
        diagnostic = [c.s.parse_json(body) for fd, body in receipts if fd == 90]
        self.assertEqual(len(diagnostic), 1)
        node = diagnostic[0]["errors"][0]["exceptions"][0]
        self.assertEqual(node["exact_text"], str(original))
        self.assertEqual(node["errno"], 13)
        closure = [c.s.parse_json(body) for fd, body in receipts if fd == 100][0]
        self.assertFalse(closure["producer_receipt_valid"])
        self.assertEqual(closure["errors"][0]["exceptions"][0], node)
        self.assertEqual(closes.count(90), 1)

    def test_primary_notice_write_failure_has_no_retry_or_new_sink(self):
        result, closes, receipts = run_caller_fake(read_error=OSError(5, "synthetic metadata read failure"),
                                                  error_write_error=True)
        self.assertFalse(result.get("snapshot_admissible", False))
        self.assertEqual(sum(fd == 90 for fd, _ in receipts), 1)
        self.assertEqual(closes.count(90), 1)

    def test_complete_headers_and_errors_must_have_valid_frames(self):
        for field, raw in (("headers", b""), ("headers", b"short"),
                           ("errors", framed(b"0", b"missing-error-text"))):
            receipt = literal_receipt()
            receipt[field] = dict(receipt[field], prefix_base64=base64.b64encode(raw).decode(),
                                  observed_bytes_lower_bound=len(raw))
            with self.subTest(field=field, raw=raw):
                result, _, _ = run_caller_fake(raw=c.s.encode(receipt))
                self.assertFalse(result.get("snapshot_admissible", False))

    def test_producer_exit1_never_admitted_even_with_valid_json(self):
        result, _, _ = run_caller_fake(code=1, raw=c.s.encode(literal_receipt(False)))
        self.assertFalse(result.get("snapshot_admissible", False))

    def test_producer_complete_flag_must_agree_with_wait(self):
        result, _, _ = run_caller_fake(code=2, raw=c.s.encode(literal_receipt(True)))
        self.assertFalse(result.get("snapshot_admissible", False))

    def test_missing_wrong_duplicate_identity_or_malformed_metadata_not_admitted(self):
        for raw in (b"{", b'{"RunID":"metadata-123-1"}',
                    c.s.encode(dict(literal_receipt(), source_head="b" * 40)),
                    b'{"RunID":"metadata-123-1","RunID":"metadata-123-1"}'):
            with self.subTest(raw=raw[:50]):
                result, _, _ = run_caller_fake(raw=raw)
                self.assertFalse(result.get("snapshot_admissible", False))

    def test_final_receipt_close_failure_cannot_admit_written_success(self):
        result, closes, persisted = run_caller_fake(final_close_error=True)
        self.assertTrue(any(fd == 100 for fd, _ in persisted))
        self.assertEqual(closes.count(100), 1)
        self.assertFalse(result.get("snapshot_admissible", False))
        self.assertFalse(result["capture_complete"])

    def test_final_receipt_write_failure_has_no_retry_or_alternate(self):
        result, closes, persisted = run_caller_fake(final_write_error=True)
        self.assertEqual(sum(fd == 100 for fd, _ in persisted), 1)
        self.assertEqual(closes.count(100), 1)
        self.assertFalse(result.get("snapshot_admissible", False))

    def test_terminal_error_sink_failure_cannot_admit_snapshot(self):
        result, closes, _ = run_caller_fake(error_close_error=True)
        self.assertEqual(closes.count(90), 1)
        self.assertFalse(result.get("snapshot_admissible", False))

    def test_public_output_failure_is_once_only_and_returns1(self):
        argv = ["capture-metadata.py", "--run-id", "metadata-123-1", "--source-head", "a" * 40,
                "--job", "metadata", "--attempt", "1", "--binary-sha256", "b" * 64]
        with patch.object(sys, "argv", argv), patch.object(c, "identity", return_value=VALUE), \
                patch.object(c, "run_capture", return_value={"capture_complete": True}), \
                patch("builtins.print", side_effect=BrokenPipeError("synthetic public output failure")) as public:
            self.assertEqual(c.main(), 1)
        self.assertEqual(public.call_count, 1)

    def test_complete_opaque_streams_require_eof_and_wait(self):
        wait, streams, errors, persisted, child = run_fake()
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (True, True))
        self.assertEqual(persisted[21], b"\x00\xffopaque")
        self.assertEqual(streams["stdout"]["prefix"], persisted[21])
        self.assertTrue(any(isinstance(call, tuple) and call[0].startswith("WAIT") for call in child.calls))

    def test_nonzero_valid_finite_failure_is_never_capture_success(self):
        wait, streams, errors, _, _ = run_fake(FakeChild(exit_code=2))
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (True, False))

    def test_overflow_is_detected_not_quietly_complete(self):
        wait, streams, errors, persisted, _ = run_fake(data={11: [b"x" * (c.MAX_STREAM + 1)], 12: []})
        self.assertEqual(len(persisted[21]), c.MAX_STREAM)
        self.assertTrue(streams["stdout"]["overflow"])
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (True, False))

    def test_live_timeout_escalates_only_exact_handle_and_reaps(self):
        wait, streams, errors, _, child = run_fake(FakeChild(live=True, resist_term=True), data={11: [], 12: []})
        self.assertTrue(wait["deadline_reached"])
        self.assertTrue(wait["wait_returned"])
        self.assertIn("TERM exact fake handle", child.calls)
        self.assertIn("KILL exact fake handle", child.calls)
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (True, False))

    def test_terminal_wait_without_eof_cannot_close_snapshot(self):
        wait, streams, errors, _, _ = run_fake(selector_options={"missing_eof": True})
        self.assertTrue(wait["wait_returned"])
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (False, False))

    def test_private_stream_failure_still_reaps_and_never_closes_snapshot(self):
        def denied(_fd, _body):
            raise PermissionError(13, "synthetic denied private stream")
        wait, streams, errors, _, child = run_fake(write=denied)
        self.assertTrue(wait["wait_returned"])
        self.assertTrue(errors)
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (False, False))
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_terminal_wait_failure_is_unavailable(self):
        wait, streams, errors, _, _ = run_fake(FakeChild(wait_error=True))
        self.assertFalse(wait["wait_returned"])
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (False, False))

    def test_selector_final_close_failure_is_unavailable(self):
        wait, streams, errors, _, _ = run_fake(selector_options={"close_error": True})
        self.assertEqual(c.closed_capture(wait, streams, True, errors), (False, False))

    def test_sink_closure_is_required_despite_complete_pipes(self):
        wait, streams, errors, _, _ = run_fake()
        self.assertEqual(c.closed_capture(wait, streams, False, errors), (False, False))

    def test_error_graph_bound_explicitly_incomplete(self):
        record = c.exception_record("synthetic", OSError(5, "x" * (c.MAX_ERROR + 1)))
        self.assertFalse(record["complete"])
        self.assertTrue(record["overflow"])
        self.assertLessEqual(len(c.s.encode(record)), c.MAX_ERROR)

    def test_identity_uses_supplied_data_only_not_actual_ci_claim(self):
        head = "a" * 40
        env = {"GITHUB_REPOSITORY": "pagrus7/kaferry-lab", "GITHUB_REPOSITORY_ID": "1432555755",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/codex/resilience-release-lab",
               "GITHUB_JOB": "metadata", "GITHUB_SHA": head, "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_RUN_ID": "123", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
        self.assertEqual(c.identity("metadata-123-1", head, "metadata", "1", env)["job"], "metadata")
        for key in env:
            wrong = dict(env, **{key: "wrong"})
            with self.subTest(field=key), self.assertRaises(c.s.Rejected):
                c.identity("metadata-123-1", head, "metadata", "1", wrong)

    def test_first_sink_failure_never_launches_or_tries_alternate(self):
        with patch.object(c.s, "reserve_operation", side_effect=c.s.EvidenceIncomplete("synthetic first sink")), \
                patch.object(c.subprocess, "Popen") as popen, patch.object(c.os, "open") as opened:
            with self.assertRaises(c.s.EvidenceIncomplete):
                c.run_capture(Path("/SYNTHETIC"), {"run_id": "metadata-123-1"}, "b" * 64)
        popen.assert_not_called()
        opened.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
