#!/usr/bin/env python3
"""Synthetic data-only controls; no process, request, crypto or upload."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("metadata_admission", Path(__file__).with_name("admit-metadata.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
spec = importlib.util.spec_from_file_location("metadata_fixtures", Path(__file__).with_name("test-capture-metadata.py"))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


def fixture(code=0):
    value = dict(f.VALUE)
    wait = dict(wait_returned=True, returncode=code, selector_closed=True, terminate_requested=False,
                kill_requested=False, deadline_reached=False, cancelled=False, cleanup_exhausted=False)
    stream = dict(eof=True, pipe_closed=True, private_write_complete=True, overflow=False,
                  read_failed=False, representation="base64 observed bytes", prefix="")
    proof = dict(value, RunID=value["run_id"], namespace=a.c.NAMESPACE, release_qualified=False,
                 binary_sha256="b" * 64, child_started=True, child_pid=123, child_start_ticks=456,
                 private_sinks_synced_closed=True, error_sink_synced_closed=True,
                 finite_snapshot_closed=True, snapshot_admissible=True, errors_complete=True,
                 producer_receipt_valid=True, capture_complete=code == 0, errors=[], child_wait=wait,
                 streams={"stdout": dict(stream, prefix="bWV0YWRhdGEgZGlhZ25vc3RpYyBvYnNlcnZhdGlvbiBjbG9zZWQK"),
                          "stderr": dict(stream)})
    payloads = {"PRIVATE.json": a.s.encode({"RunID": value["run_id"], "Classification": "PRIVATE RAW EVIDENCE",
                                          "Publication": "withhold pending explicit redaction review"}),
                "metadata.json": a.s.encode(f.literal_receipt(code == 0)),
                "capture-closure.json": a.s.encode(proof)}
    public = dict(namespace=a.c.NAMESPACE, release_qualified=False, status="capture-closed",
                  finite_snapshot_closed=True, snapshot_admissible=True, capture_complete=code == 0)
    return value, proof, payloads, public


def run(value, payloads, public, code=0, exit_body=None, stderr=b"", sealed=False, complete_change=None):
    cms = b"SYNTHETIC CMS BYTES; NO CRYPTO"
    complete = dict(value, complete=True, cms_bytes=len(cms), cms_sha256=a.s.digest(cms),
                    files=len(payloads), total_bytes=sum(map(len, payloads.values())),
                    publication="DISABLED; explicit encrypted-public-quarantine exception required",
                    cipher="AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD")
    if complete_change:
        complete_change(complete)
    contents = {"foreground.exit": exit_body if exit_body is not None else (str(code) + "\n").encode(),
                "stderr.bin": stderr, "stdout.json": a.s.encode(public), "notice.cms": cms,
                "COMPLETE.json": a.s.encode(complete)}
    with patch.object(a.c, "binary"), patch.object(a.s, "snapshot", return_value=payloads), \
            patch.object(a.s, "check_chain"), patch.object(a.s, "check_private"), \
            patch.object(Path, "lstat"), \
            patch.object(Path, "iterdir", return_value=iter([Path("notice.cms"), Path("COMPLETE.json")])), \
            patch.object(a.s, "read_regular", side_effect=lambda path, *_args, **_kw: contents[path.name]):
        return a.validate(Path("/SYNTHETIC"), value, "b" * 64, code, sealed)


def publication_policy(workflow):
    # Inspect the actual new upload boundary, then deliberately mutate it. This
    # supplements data admission controls; it is not GitHub runtime evidence.
    job = workflow.split("  metadata:\n", 1)[1].split("  m1:\n", 1)[0]
    upload = job.split("      - name: Upload only the sole admitted metadata ciphertext\n", 1)[1].split("      - name:", 1)[0]
    for required in ["steps.metadata-controls.outcome == 'success'", "steps.metadata-sample.outcome == 'success'",
                     "steps.metadata-foreground.outcome == 'success'", "steps.metadata-proof.outcome == 'success'",
                     "steps.metadata-seal.outcome == 'success'", "steps.metadata-seal.outputs.complete == 'true'",
                     "steps.metadata-proof.outputs.snapshot_admissible == 'true'",
                     "path: .cache/link-quarantine/${{ env.LAB_RUN_ID }}/notice.cms\n",
                     "retention-days: 7\n", "overwrite: false\n",
                     "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"]:
        if required not in upload:
            raise AssertionError("synthetic metadata publication policy mutation detected")
    for name in ("unit", "observer"):
        prefix = workflow.split("  " + name + ":\n", 1)[1].split("    runs-on:", 1)[0]
        if "github.event_name != 'workflow_dispatch' || inputs.mode == 'normal'" not in prefix:
            raise AssertionError("synthetic duplicate-ciphertext isolation mutation detected")
    if "github.event_name == 'workflow_dispatch'" not in job.split("    runs-on:", 1)[0]:
        raise AssertionError("synthetic diagnostic event mutation detected")


class Controls(unittest.TestCase):
    def test_workflow_publication_guard_mutations_are_detected(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
        publication_policy(workflow)
        for original, changed in [("/notice.cms\n", "/metadata.json\n"),
                ("steps.metadata-proof.outcome == 'success'", "steps.metadata-proof.outcome == 'skipped'"),
                ("steps.metadata-seal.outcome == 'success'", "steps.metadata-seal.outcome == 'failure'"),
                ("retention-days: 7", "retention-days: 8"),
                ("github.event_name != 'workflow_dispatch' || inputs.mode == 'normal'", "true")]:
            with self.subTest(mutation=original), self.assertRaises(Exception):
                publication_policy(workflow.replace(original, changed))

    def test_complete_and_closed_incomplete_are_distinct(self):
        for code in (0, 2):
            value, _, payloads, public = fixture(code)
            self.assertIs(run(value, payloads, public, code), code == 0)

    def test_no_terminal_foreground_return(self):
        value, _, payloads, public = fixture()
        for code in (1, 143, True):
            with self.subTest(code=code), self.assertRaises(Exception):
                run(value, payloads, public, code)
        with self.assertRaises(Exception):
            run(value, payloads, public, exit_body=b"2\n")

    def test_private_stderr_is_not_publicly_interpolated_or_admitted(self):
        value, _, payloads, public = fixture()
        with self.assertRaises(Exception):
            run(value, payloads, public, stderr=b"SYNTHETIC unknown private cause\x00\xff")

    def test_actual_closure_and_identity_are_required(self):
        value, proof, payloads, public = fixture()
        for key, replacement in [("source_head", "c" * 40), ("binary_sha256", "d" * 64),
                ("child_started", False), ("child_pid", 0), ("child_start_ticks", 0),
                ("private_sinks_synced_closed", False), ("error_sink_synced_closed", False),
                ("finite_snapshot_closed", False), ("snapshot_admissible", False),
                ("producer_receipt_valid", False), ("errors_complete", False),
                ("errors", [{"exact_text": "SYNTHETIC failure"}])]:
            bad = copy.deepcopy(proof);bad[key] = replacement
            with self.subTest(key=key), self.assertRaises(Exception):
                run(value, dict(payloads, **{"capture-closure.json": a.s.encode(bad)}), public)

    def test_each_wait_and_stream_failure_rejects(self):
        value, proof, payloads, public = fixture()
        for group, keys in [("child_wait", ["wait_returned", "selector_closed", "deadline_reached", "cancelled", "cleanup_exhausted"]),
                            ("stdout", ["eof", "pipe_closed", "private_write_complete", "overflow", "read_failed"]),
                            ("stderr", ["eof", "pipe_closed", "private_write_complete", "overflow", "read_failed"])]:
            for key in keys:
                bad = copy.deepcopy(proof)
                target = bad["child_wait"] if group == "child_wait" else bad["streams"][group]
                target[key] = not target[key]
                with self.subTest(group=group, key=key), self.assertRaises(Exception):
                    run(value, dict(payloads, **{"capture-closure.json": a.s.encode(bad)}), public)

    def test_unknown_payload_or_nonboolean_receipt_rejects(self):
        value, _, payloads, public = fixture()
        with self.assertRaises(Exception):
            run(value, dict(payloads, **{"unexpected.json": b"{}"}), public)
        with self.assertRaises(Exception):
            run(value, payloads, dict(public, capture_complete=1))

    def test_sealed_size_digest_and_identity_required(self):
        value, _, payloads, public = fixture()
        self.assertTrue(run(value, payloads, public, sealed=True))
        for key, replacement in [("cms_bytes", 0), ("cms_sha256", "0" * 64), ("files", 0),
                                 ("source_head", "c" * 40), ("complete", 1)]:
            with self.subTest(key=key), self.assertRaises(Exception):
                run(value, payloads, public, sealed=True, complete_change=lambda d: d.update({key: replacement}))


if __name__ == "__main__":
    unittest.main()
