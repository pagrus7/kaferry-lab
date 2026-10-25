#!/usr/bin/env python3
"""Create and seal ONLY the reviewed fixed synthetic notice transport sample.

This is calibration/private-notice-transport, never a Kaferry qualification or
an unknown-raw-notice publication exception. No upload, network or key read.
The trusted caller must independently bind the reviewed source head/event.
"""
import argparse
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("transport_sample_seal", Path(__file__).with_name("seal-link-notices.py"))
s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s)
NAMESPACE = "calibration/private-notice-transport"
NOTICE = "Reviewed fixed synthetic notice transport sample."


def sample_identity(run, head, job, attempt, reviewed_synthetic_transport):
    identity = s.identities(run, head, s.CERT_PIN, job, attempt)
    if reviewed_synthetic_transport is not True or job != "unit":
        raise s.Rejected("explicit reviewed synthetic unit transport control required")
    return identity


def sample_payloads(identity):
    # These are the only two plaintext members ever created. The only varying
    # fields are validated caller run/head/job/attempt; no host/environment data.
    return {
        "PRIVATE.json": s.encode({"RunID": identity["run_id"], "Classification": "PRIVATE RAW EVIDENCE",
                                  "Publication": "withhold pending explicit redaction review"}),
        "transport-sample.json": s.encode({"RunID": identity["run_id"], "SourceHead": identity["source_head"],
                "Job": identity["job"], "Attempt": identity["attempt"], "namespace": NAMESPACE,
                "synthetic": True, "release_qualified": False, "notice": NOTICE}),
    }


def create_sample(base, run, head, job, attempt, reviewed_synthetic_transport=False):
    identity = sample_identity(run, head, job, attempt, reviewed_synthetic_transport)
    expected = sample_payloads(identity)
    base = Path(base)
    _, error_fd = s.reserve_operation(base / ".cache/notice-transport-samples", run)
    action = "reserve fresh fixed synthetic receipt tree"
    try:
        # A preexisting run tree is refused, even when its bytes look identical.
        # No adoption, append, recursive cache selection or unknown input exists.
        directory = s.reserve(base / ".cache/fixtures-private", run + "-links")
        action = "write reviewed fixed synthetic receipt bytes"
        for name, body in expected.items():
            s.write_private(directory / name, body)
        action = "verify exact reviewed synthetic receipt selection"
        if s.snapshot(directory, run) != expected:
            raise s.Rejected("synthetic receipt selection differs from reviewed two-file sample")
        owned_fd, error_fd = error_fd, None
        s.close_operation(owned_fd)
    except (OSError, KeyboardInterrupt, SystemExit) as error:
        if error_fd is None:
            raise s.EvidenceIncomplete("sample terminal sink unavailable; exact notice unavailable; evidence incomplete; stopped") from None
        s.retain_os_error(error_fd, action, error)
    finally:
        if error_fd is not None:
            owned_fd, error_fd = error_fd, None
            s.close_operation(owned_fd, sys.exc_info()[1])
    # The production sealer owns its own pre-reserved error sink and completion.
    # Creator performs no later filesystem action that could invalidate it.
    sealed = s.seal(base, identity, Path(__file__).with_name("link-notices-recipient.pem"), expected_payloads=expected)
    return dict(identity, namespace=NAMESPACE, synthetic=True, release_qualified=False,
                sample_files=sorted(expected), complete=sealed["complete"], cms_sha256=sealed["cms_sha256"],
                publication_class="reviewed fixed synthetic transport control only; unknown raw publication remains disabled")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--reviewed-synthetic-transport-only", action="store_true", required=True)
    args = parser.parse_args()
    result = create_sample(Path.cwd(), args.run_id, args.source_head, args.job, args.attempt,
                           args.reviewed_synthetic_transport_only)
    print(s.encode(result).decode(), end="")


def cli():
    previous_term = s.signal.signal(s.signal.SIGTERM, s.terminal_signal)
    try:
        main()
        return 0
    except (s.EvidenceIncomplete, KeyboardInterrupt):
        print("synthetic transport sample rejected; private evidence incomplete; stopped", file=sys.stderr)
        return 1
    except (s.Rejected, OSError):
        print("synthetic transport sample rejected; no sealed completion accepted; stopped", file=sys.stderr)
        return 1
    finally:
        s.signal.signal(s.signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(cli())
