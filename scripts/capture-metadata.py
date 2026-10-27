#!/usr/bin/env python3
"""Foreground closure for the fixed metadata diagnostic producer.

This file is not an admitted workflow capability. No encryption or upload is
performed here. Caller return is required in addition to the closure receipt.
"""
import argparse
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
try:
    _spec = importlib.util.spec_from_file_location("metadata_seal", Path.cwd() / "scripts/seal-link-notices.py")
    s = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(s)
except (Exception, KeyboardInterrupt, SystemExit):
    # Before the first private sink exists, exact causes may be unavailable.
    try:
        print('{"namespace":"calibration/metadata-caller","status":"capture-unavailable","finite_snapshot_closed":false,"capture_complete":false,"release_qualified":false}', flush=True)
    except (Exception, KeyboardInterrupt, SystemExit):
        pass
    raise SystemExit(1) from None
MAX_STREAM = 64 << 10
MAX_ERROR = 32 << 10
NAMESPACE = "calibration/metadata-caller"
REPRESENTATIONS = {
    "headers": "CLIENT-DECODED net/http fields; uint64be-length frames: status,protocol, then section,name,value-count,values; sections=headers,trailers; sorted names; not wire octets",
    "body": "net/http exposed response-body bytes; may be transparently decompressed; not wire octets",
    "errors": "uint64be-length frames: node-path,Go-type,Error()-bytes; root 0=setup/transport,1=body-read,2=body-close,3=context; bounded unwrap graph",
}


def require(value):
    if not value:
        raise s.Rejected("metadata caller admission rejected")


def identity(run, head, job, attempt, environment):
    value = s.identities(run, head, s.CERT_PIN, job, str(attempt))
    require(job == "metadata")
    expected = {"GITHUB_REPOSITORY": "pagrus7/kaferry-lab", "GITHUB_REPOSITORY_ID": "1432555755",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/codex/resilience-release-lab",
                "GITHUB_JOB": "metadata", "GITHUB_SHA": head, "GITHUB_RUN_ATTEMPT": str(attempt),
                "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    require(all(environment.get(k) == v for k, v in expected.items()))
    number = environment.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", number) is not None)
    require(run == "metadata-" + number + "-" + str(attempt))
    return value


def binary(base, value, expected_sha):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None)
    directory = base / ".cache/metadata-build" / value["run_id"]
    s.check_chain(directory)
    s.check_private(directory.lstat(), True)
    path = directory / "metadata-capture"
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700
            and before.st_uid == os.getuid() and before.st_nlink == 1 and before.st_size <= 32 << 20)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(s.signature(os.fstat(fd)) == s.signature(before))
        digest = hashlib.sha256()
        remaining = (32 << 20) + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            digest.update(chunk)
        require(remaining > 0 and digest.hexdigest() == expected_sha)
        require(s.signature(os.fstat(fd)) == s.signature(before) == s.signature(path.lstat()))
    finally:
        os.close(fd)
    # The reviewed workflow supplies the digest from this run's fresh build and
    # source checkout. This check cannot independently establish build provenance.
    return path, s.signature(before)


def exception_record(action, error):
    pending, seen, nodes = [("original", error)], set(), []
    while pending and len(nodes) < 8:
        relation, current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        nodes.append({"relation": relation, "type": type(current).__name__,
                      "errno": getattr(current, "errno", None), "exact_text": str(current),
                      "filename": getattr(current, "filename", None),
                      "filename2": getattr(current, "filename2", None)})
        for relation, following in (("cause", current.__cause__), ("context", current.__context__)):
            if following is not None and id(following) not in seen:
                pending.append((relation, following))
    body = s.encode({"action": action, "complete": not pending, "exceptions": nodes})
    if len(body) > MAX_ERROR:
        return {"action": action, "complete": False, "representation": "JSON byte prefix",
                "prefix_base64": base64.b64encode(body[:16384]).decode(), "overflow": True}
    return s.parse_json(body)


def start_ticks(pid):
    # Only the exact launched handle's /proc identity; no process inventory.
    raw = s.read_regular(Path("/proc") / str(pid) / "stat", 8192)
    prefix, separator, tail = raw.rpartition(b") ")
    require(separator and prefix.startswith(str(pid).encode() + b" ("))
    fields = tail.split()
    require(len(fields) > 19 and fields[19].isdigit())
    return int(fields[19])


def drive(child, sinks, record_error, *, selector_factory=selectors.DefaultSelector,
          read=os.read, monotonic=time.monotonic, persist=os.write):
    """Own this sole no-fork producer; bounded pipes, exact handle cleanup/wait.

    Injectable primitives support data-only controls and explicitly labelled
    hosted calibration. Production uses actual OS reads, signals and waits.
    """
    streams = {name: {"prefix": bytearray(), "eof": False, "overflow": False,
                      "read_failed": False, "private_write_complete": True, "pipe_closed": False}
               for name in ("stdout", "stderr")}
    state = {"wait_returned": False, "returncode": None, "terminate_requested": False,
             "kill_requested": False, "deadline_reached": False, "cancelled": False,
             "selector_closed": False, "cleanup_exhausted": False}
    selector = None
    deadline = monotonic() + 45.0
    cleanup_deadline = None
    termination_at = None
    failed = False
    try:
        selector = selector_factory()
        for name in streams:
            selector.register(getattr(child, name), selectors.EVENT_READ, name)
        while True:
            now = monotonic()
            if now >= deadline and cleanup_deadline is None:
                state["deadline_reached"] = failed = True
            if failed and cleanup_deadline is None:
                cleanup_deadline = now + 10.0
                if child.poll() is None:
                    state["terminate_requested"] = True
                    termination_at = now
                    child.terminate()
            if termination_at is not None and now - termination_at >= 2.0 and child.poll() is None and not state["kill_requested"]:
                state["kill_requested"] = True
                child.kill()
            if cleanup_deadline is not None and now >= cleanup_deadline:
                state["cleanup_exhausted"] = True
                break
            if child.poll() is not None and not selector.get_map():
                break
            for key, _mask in selector.select(0.1):
                stream = streams[key.data]
                try:
                    chunk = read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        stream["eof"] = True
                        selector.unregister(key.fileobj)
                        continue
                    available = MAX_STREAM - len(stream["prefix"])
                    kept = chunk[:available]
                    if kept:
                        stream["prefix"].extend(kept)
                        if persist(sinks[key.data], kept) != len(kept):
                            raise OSError(5, "private stream short write")
                    if len(chunk) > available:
                        stream["overflow"] = failed = True
                except (OSError, ValueError) as error:
                    stream["read_failed"] = failed = True
                    stream["private_write_complete"] = False
                    record_error("capture private " + key.data, error)
                    selector.unregister(key.fileobj)
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        state["cancelled"] = isinstance(error, (KeyboardInterrupt, SystemExit))
        record_error("drive producer", error)
        failed = True
    finally:
        # Any exception during the pump still goes through exact-handle cleanup.
        try:
            if child.poll() is None:
                state["terminate_requested"] = True
                try:
                    child.terminate()
                except (Exception, KeyboardInterrupt, SystemExit) as error:
                    record_error("terminate exact producer handle", error)
                try:
                    child.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    state["kill_requested"] = True
                    try:
                        child.kill()
                    except (Exception, KeyboardInterrupt, SystemExit) as error:
                        record_error("kill exact producer handle", error)
            state["returncode"] = child.wait(timeout=3.0)
            state["wait_returned"] = True
        except (Exception, KeyboardInterrupt, SystemExit) as error:
            record_error("terminal producer wait", error)
        if selector is not None:
            try:
                selector.close()
                state["selector_closed"] = True
            except (Exception, KeyboardInterrupt, SystemExit) as error:
                record_error("close selector", error)
        for name, stream in streams.items():
            try:
                getattr(child, name).close()
                stream["pipe_closed"] = True
            except (Exception, KeyboardInterrupt, SystemExit) as error:
                record_error("close producer " + name, error)
    return state, streams


def closed_capture(wait, streams, sinks_closed, errors):
    closed = (wait["wait_returned"] and wait["selector_closed"] and sinks_closed
              and all(value["eof"] and value["pipe_closed"] for value in streams.values()))
    complete = (closed and wait["returncode"] == 0 and not errors
                and not any(wait[k] for k in ("deadline_reached", "cancelled", "terminate_requested", "kill_requested"))
                and all(not value["overflow"] and not value["read_failed"]
                        and value["private_write_complete"] for value in streams.values()))
    return closed, complete


def decode_frames(raw):
    fields = []
    while raw:
        require(len(raw) >= 8)
        size = int.from_bytes(raw[:8], "big")
        require(size <= len(raw) - 8)
        fields.append(raw[8:8 + size])
        raw = raw[8 + size:]
    return fields


def producer_receipt(raw, value, wait):
    metadata = s.parse_json(raw)
    keys = {"RunID", "source_head", "github_run_id", "job", "attempt", "namespace", "release_qualified",
            "platform", "method", "url", "accept", "user_agent", "attempt_count", "started_utc",
            "elapsed_ns_monotonic", "response_available", "status_code", "headers_representation", "headers",
            "body_representation", "body", "body_close_attempted", "body_close_succeeded", "net_http_uncompressed",
            "errors_representation", "errors", "capture_complete"}
    require(type(metadata) is dict and set(metadata) == keys)
    fixed = {"RunID": value["run_id"], "source_head": value["source_head"], "job": "metadata",
             "attempt": value["attempt"], "github_run_id": value["run_id"].split("-")[1],
             "namespace": "calibration/metadata-diagnostic", "platform": "linux/amd64", "method": "GET",
             "url": "https://api.github.com/repos/pagrus7/kaferry/git/ref/tags/v0.6.0",
             "accept": "application/vnd.github+json", "user_agent": "kaferry-lab-artifact"}
    require(all(metadata[k] == v for k, v in fixed.items()))
    require(metadata["release_qualified"] is False and type(metadata["attempt_count"]) is int
            and metadata["attempt_count"] in (0, 1))
    for key in ("response_available", "body_close_attempted", "body_close_succeeded", "net_http_uncompressed", "capture_complete"):
        require(type(metadata[key]) is bool)
    require(type(metadata["status_code"]) is int and
            (100 <= metadata["status_code"] <= 599 if metadata["response_available"] else metadata["status_code"] == 0))
    require(type(metadata["elapsed_ns_monotonic"]) is int and 0 <= metadata["elapsed_ns_monotonic"] <= 60_000_000_000)
    require(type(metadata["started_utc"]) is str and len(metadata["started_utc"]) <= 128)
    prefixes = {}
    for name, maximum in (("headers", 16 << 10), ("body", 64 << 10), ("errors", 32 << 10)):
        stream = metadata[name]
        require(type(stream) is dict and set(stream) == {"prefix_base64", "observed_bytes_lower_bound", "complete", "overflow", "traversal_guard_reached"})
        require(type(stream["prefix_base64"]) is str)
        try:
            prefix = base64.b64decode(stream["prefix_base64"], validate=True)
        except (ValueError, TypeError):
            raise s.Rejected("metadata producer stream rejected") from None
        require(len(prefix) <= maximum and base64.b64encode(prefix).decode() == stream["prefix_base64"])
        require(type(stream["observed_bytes_lower_bound"]) is int and len(prefix) <= stream["observed_bytes_lower_bound"] <= (1 << 63) - 1)
        require(all(type(stream[k]) is bool for k in ("complete", "overflow", "traversal_guard_reached")))
        require(not stream["complete"] or (not stream["overflow"] and not stream["traversal_guard_reached"]
                                           and stream["observed_bytes_lower_bound"] == len(prefix)))
        require(metadata[name + "_representation"] == REPRESENTATIONS[name])
        prefixes[name] = prefix
    require(wait["returncode"] in (0, 2) and metadata["capture_complete"] == (wait["returncode"] == 0))
    if metadata["attempt_count"] == 0:
        # Setup failed before client.Do. Never invent an attempted request or
        # discard its useful, closed error evidence merely because it was unreached.
        require(not metadata["capture_complete"] and not metadata["response_available"]
                and not metadata["body_close_attempted"] and not metadata["body_close_succeeded"]
                and not metadata["net_http_uncompressed"] and not prefixes["headers"]
                and not prefixes["body"] and bool(prefixes["errors"]))
    if metadata["headers"]["complete"]:
        require(metadata["response_available"])
        fields = decode_frames(prefixes["headers"])
        require(len(fields) >= 2 and bool(fields[0]) and bool(fields[1]))
        position = 2
        while position < len(fields):
            require(position + 3 <= len(fields) and fields[position] in (b"headers", b"trailers")
                    and bool(fields[position + 1]) and re.fullmatch(rb"0|[1-9][0-9]{0,4}", fields[position + 2]))
            position += 3 + int(fields[position + 2])
            require(position <= len(fields))
    if metadata["errors"]["complete"]:
        fields = decode_frames(prefixes["errors"])
        require(len(fields) % 3 == 0 and all(fields[i] and fields[i + 1] for i in range(0, len(fields), 3)))
    if metadata["capture_complete"]:
        require(metadata["attempt_count"] == 1 and not prefixes["errors"])
        require(metadata["response_available"] and metadata["body_close_attempted"] and metadata["body_close_succeeded"]
                and all(metadata[name]["complete"] for name in ("headers", "body", "errors")))
    return metadata


def run_capture(base, value, expected_sha):
    operation, error_fd = s.reserve_operation(base / ".cache/metadata-capture-private", value["run_id"])
    errors, sinks, closure_fd = [], {}, None
    error_sink_ok = True
    fixture = None
    child = None
    wait = None
    streams = None
    ticks = None
    metadata = None
    metadata_valid = False

    def record(action, error):
        nonlocal error_sink_ok
        errors.append(exception_record(action, error))
        # Bounded list: retain observed prefix and explicit incompleteness.
        body = s.encode({"complete": len(errors) <= 8 and all(e["complete"] for e in errors),
                         "errors": errors[:8]})
        if len(body) > MAX_ERROR:
            body = s.encode({"complete": False, "overflow": True,
                             "prefix_base64": base64.b64encode(body[:16384]).decode()})
        if error_sink_ok:
            try:
                s.persist_receipt(error_fd, body)
            except (OSError, KeyboardInterrupt, SystemExit):
                # No alternate sink, path or retry after the terminal sink fails.
                error_sink_ok = False

    try:
        path, signature = binary(base, value, expected_sha)
        fixture = s.reserve(base / ".cache/fixtures-private", value["run_id"] + "-links")
        s.write_private(fixture / "PRIVATE.json", s.encode({"RunID": value["run_id"],
                        "Classification": "PRIVATE RAW EVIDENCE",
                        "Publication": "withhold pending explicit redaction review"}))
        closure_fd = os.open(fixture / "capture-closure.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        for name in ("stdout", "stderr"):
            sinks[name] = os.open(operation / (name + ".bin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        require(s.signature(path.lstat()) == signature)
        child = subprocess.Popen([str(path), "--run-id", value["run_id"], "--source-head", value["source_head"],
                                  "--job", "metadata", "--attempt", value["attempt"],
                                  "--output", str(Path(".cache/fixtures-private") / (value["run_id"] + "-links") / "metadata.json")],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, shell=False, cwd=base)
        try:
            try:
                ticks = start_ticks(child.pid)
            except (Exception, KeyboardInterrupt, SystemExit) as error:
                record("read exact launched start identity", error)
                # Identity loss prevents admission; the exact handle still needs
                # its terminal wait even if retaining this notice itself fails.
        finally:
            wait, streams = drive(child, sinks, record)
        # These ordinary evidence reads/checks still have the primary private
        # error sink available. A failure is retained before any terminal close.
        try:
            raw = s.read_regular(fixture / "metadata.json", s.MAX_FILE, private=True)
            metadata = producer_receipt(raw, value, wait)
            require(bytes(streams["stdout"]["prefix"]) == b"metadata diagnostic observation closed\n"
                    and streams["stdout"]["eof"])
            metadata_valid = True
        except (Exception, KeyboardInterrupt, SystemExit) as error:
            record("read or validate producer metadata", error)
    except (Exception, KeyboardInterrupt, SystemExit) as error:
        record("prepare or launch metadata producer", error)
    finally:
        sinks_closed = True
        for name, fd in sinks.items():
            try:
                os.fsync(fd)
            except (OSError, KeyboardInterrupt, SystemExit) as error:
                sinks_closed = False
                record("sync private " + name, error)
            try:
                os.close(fd)
            except (OSError, KeyboardInterrupt, SystemExit) as error:
                sinks_closed = False
                record("close private " + name, error)
        try:
            os.fsync(error_fd)
        except (OSError, KeyboardInterrupt, SystemExit):
            error_sink_ok = False
        owned_fd, error_fd = error_fd, None
        try:
            os.close(owned_fd)
        except (OSError, KeyboardInterrupt, SystemExit):
            error_sink_ok = False
    # No private diagnostic writer remains. The final closure receipt's own
    # successful sync/close is established only by foreground caller return.
    if closure_fd is None:
        return {"status": "capture-unavailable", "finite_snapshot_closed": False, "capture_complete": False}
    final_closed = False
    result = {"status": "capture-unavailable", "finite_snapshot_closed": False, "capture_complete": False, "snapshot_admissible": False}
    try:
        closed, complete = (False, False) if wait is None else closed_capture(wait, streams, sinks_closed and error_sink_ok, errors)
        complete = complete and ticks is not None
        # Invalid/missing metadata keeps its original diagnostic notice above;
        # it can never be adopted as an admissible producer receipt.
        complete = complete and metadata_valid and metadata["capture_complete"]
        notices_complete = len(errors) <= 8 and all(e["complete"] for e in errors)
        denied = any(node.get("errno") in (1, 13) for error in errors for node in error.get("exceptions", []))
        admissible = closed and ticks is not None and metadata_valid and notices_complete and not denied
        receipt = dict(value, RunID=value["run_id"], namespace=NAMESPACE, release_qualified=False,
                       binary_sha256=expected_sha, producer_receipt_valid=metadata_valid,
                       child_started=child is not None, child_pid=child.pid if child is not None else None,
                       child_start_ticks=ticks, child_wait=wait,
                       private_sinks_synced_closed=sinks_closed, error_sink_synced_closed=error_sink_ok,
                       finite_snapshot_closed=closed, capture_complete=complete, snapshot_admissible=admissible,
                       errors_complete=notices_complete,
                       errors=errors[:8], streams={})
        for name, stream in (streams or {}).items():
            receipt["streams"][name] = dict(stream, prefix=base64.b64encode(stream["prefix"]).decode(),
                                           representation="base64 observed bytes")
        body = s.encode(receipt)
        require(len(body) <= s.MAX_FILE)
        s.persist_receipt(closure_fd, body)
        result = {"status": "capture-closed" if closed else "capture-incomplete",
                  "finite_snapshot_closed": closed, "capture_complete": complete, "snapshot_admissible": admissible}
    except (Exception, KeyboardInterrupt, SystemExit):
        # Final-sink failure has no alternate sink or serializable success claim.
        result = {"status": "capture-unavailable", "finite_snapshot_closed": False, "capture_complete": False}
    finally:
        owned_fd, closure_fd = closure_fd, None
        try:
            os.close(owned_fd)
            final_closed = True
        except (OSError, KeyboardInterrupt, SystemExit):
            pass
    if not final_closed:
        return {"status": "capture-unavailable", "finite_snapshot_closed": False, "capture_complete": False}
    return result


def main():
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise s.Rejected("metadata caller arguments rejected")
    parser = Parser(description=__doc__)
    for name in ("run-id", "source-head", "job", "attempt", "binary-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    value = identity(args.run_id, args.source_head, args.job, args.attempt, os.environ)
    result = run_capture(Path.cwd(), value, args.binary_sha256)
    try:
        print(s.encode(dict(result, namespace=NAMESPACE, release_qualified=False)).decode(), end="", flush=True)
    except (Exception, KeyboardInterrupt, SystemExit):
        # A public output failure is terminal; no alternate/second print attempt.
        return 1
    # A closed failure can be admitted by a separate, reviewed evidence gate,
    # but must never pass capture or product acceptance.
    return 0 if result["capture_complete"] else (2 if result.get("snapshot_admissible", False) else 1)


def cli():
    prior = signal.signal(signal.SIGTERM, s.terminal_signal)
    try:
        return main()
    except (Exception, KeyboardInterrupt, SystemExit):
        try:
            print('{"namespace":"calibration/metadata-caller","status":"capture-unavailable","finite_snapshot_closed":false,"capture_complete":false,"release_qualified":false}', flush=True)
        except (Exception, KeyboardInterrupt, SystemExit):
            pass
        return 1
    finally:
        signal.signal(signal.SIGTERM, prior)


if __name__ == "__main__":
    raise SystemExit(cli())
