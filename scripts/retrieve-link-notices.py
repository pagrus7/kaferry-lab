#!/usr/bin/env python3
"""Read-only GitHub retrieval and PRIVATE recovery of one notice artifact.

The caller supplies an independently reviewed exact source head. HTTPS API
metadata establishes transport provenance; ciphertext/self-hashes do not.
Token input is bounded stdin, never an argument, file, log or header dump.
"""
import argparse
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import ssl
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("notice_unseal", Path(__file__).with_name("unseal-link-notices.py"))
u = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(u)
s = u.s
REPOSITORY = "pagrus7/kaferry-lab"
REPOSITORY_ID = 1432555755
BRANCH = "codex/resilience-release-lab"
WORKFLOW = ".github/workflows/ci.yml"
API = "https://api.github.com"
ROOT = API + "/repos/" + REPOSITORY + "/actions"
MAX_JSON = 1 << 20
MAX_REQUESTS = 8
HTTP_SECONDS = 60


def numeric(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 10 ** 20


def run_number(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
        raise s.Rejected("GitHub run identity rejected")
    return int(value)


def token_from_stdin():
    # No terminal prompt or environment/credential-store fallback.
    if sys.stdin.isatty():
        raise s.Rejected("token must arrive through bounded stdin")
    body = bytearray()
    deadline = time.monotonic() + 5
    with selectors.DefaultSelector() as selector:
        selector.register(sys.stdin.buffer, selectors.EVENT_READ)
        while b"\n" not in body:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise s.Rejected("token stdin deadline exceeded")
            chunk = os.read(sys.stdin.fileno(), 513 - len(body))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) >= 513:
                raise s.Rejected("token stdin byte bound exceeded")
    try:
        token = bytes(body).decode("ascii").strip()
    except UnicodeError:
        raise s.Rejected("token input rejected") from None
    validate_token(token)
    return token


def validate_token(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{20,512}", token):
        raise s.Rejected("token input rejected")


def http_deadline(_signum, _frame):
    raise TimeoutError("bounded HTTPS operation deadline reached")


def https_get(url, token, maximum, deadline, *, download=False):
    """One TLS GET, no automatic redirects/retries, no persisted headers."""
    if os.environ.get("SSLKEYLOGFILE"):
        raise s.Rejected("TLS key logging configuration refused")
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.fragment or len(url) > 8192
            or any(ord(c) < 33 or ord(c) > 126 for c in url)):
        raise s.Rejected("HTTPS destination rejected")
    is_api = parsed.netloc == "api.github.com"
    if not is_api and (not download or not parsed.hostname.endswith((".blob.core.windows.net", ".githubusercontent.com"))):
        raise s.Rejected("artifact redirect destination rejected")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise s.Rejected("HTTP operation deadline exceeded")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "kaferry-lab-private-notice-retrieval"}
    if is_api:
        headers["Authorization"] = "Bearer " + token
    # Socket timeouts alone do not bound slow-trickle HTTP header/body reads.
    # This CLI owns a process-local absolute deadline, never the host clock.
    if signal.getitimer(signal.ITIMER_REAL)[0] != 0:
        raise s.Rejected("existing process deadline timer refused")
    previous_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, http_deadline)
    except ValueError:
        raise s.Rejected("HTTPS retrieval requires the main process thread") from None
    connection = None
    try:
        signal.setitimer(signal.ITIMER_REAL, min(15, remaining))
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=min(10, remaining), context=ssl.create_default_context())
        connection.request("GET", parsed.path + ("?" + parsed.query if parsed.query else ""), headers=headers)
        response = connection.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            return response.status, response.getheader("Location"), b""
        if response.status != 200:
            # Original HTTP status/reason only; no body, URL query or headers.
            raise OSError("GitHub HTTPS status " + str(response.status) + ": " + response.reason)
        length = response.getheader("Content-Length")
        if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > maximum):
            raise s.Rejected("HTTP response byte bound exceeded")
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise s.Rejected("HTTP operation deadline exceeded")
            if connection.sock is not None:
                connection.sock.settimeout(min(5, remaining))
            chunk = response.read(min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum:
                raise s.Rejected("HTTP response byte bound exceeded")
        if length is not None and len(body) != int(length):
            raise s.Rejected("HTTP response length mismatch")
        return response.status, None, bytes(body)
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)


def bound_run(info, github_run, identity):
    if (not isinstance(info, dict) or info.get("id") != github_run
            or not numeric(info.get("id")) or not numeric(info.get("run_attempt"))
            or info.get("run_attempt") != int(identity["attempt"])
            or info.get("head_sha") != identity["source_head"] or info.get("head_branch") != BRANCH
            or info.get("path") != WORKFLOW or info.get("event") not in ("push", "workflow_dispatch")
            or info.get("pull_requests") != [] or info.get("status") != "completed"
            or not numeric(info.get("workflow_id"))):
        raise s.Rejected("trusted run/attempt/workflow tuple rejected")
    for key in ("repository", "head_repository"):
        repo = info.get(key)
        if (not isinstance(repo, dict) or repo.get("id") != REPOSITORY_ID
                or not numeric(repo.get("id")) or repo.get("full_name") != REPOSITORY or repo.get("fork") is not False):
            raise s.Rejected("trusted repository tuple rejected")


def bound_job(listing, github_run, identity):
    if not isinstance(listing, dict) or not isinstance(listing.get("jobs"), list):
        raise s.Rejected("attempt job listing rejected")
    jobs = listing["jobs"]
    if not 1 <= len(jobs) <= 100 or not numeric(listing.get("total_count")) or listing.get("total_count") != len(jobs):
        raise s.Rejected("attempt job listing bound rejected")
    ids = [job.get("id") for job in jobs if isinstance(job, dict)]
    if len(ids) != len(jobs) or not all(numeric(i) for i in ids) or len(set(ids)) != len(ids):
        raise s.Rejected("attempt job IDs rejected")
    matches = [job for job in jobs if job.get("name") == identity["job"]]
    if len(matches) != 1:
        raise s.Rejected("expected unique attempt job missing")
    job = matches[0]
    if (job.get("run_id") != github_run or not numeric(job.get("run_id"))
            or not numeric(job.get("run_attempt")) or job.get("run_attempt") != int(identity["attempt"])
            or job.get("head_sha") != identity["source_head"] or job.get("status") != "completed"
            or job.get("conclusion") not in ("success", "failure", "cancelled", "timed_out")
            or job.get("url") != ROOT + "/jobs/" + str(job["id"])):
        raise s.Rejected("expected attempt job tuple rejected")
    return job


def bound_artifact(artifact, github_run, identity):
    name = "encrypted-link-notices-" + identity["job"] + "-" + identity["source_head"] + "-" + str(github_run) + "-" + identity["attempt"]
    if (not isinstance(artifact, dict) or artifact.get("name") != name or not numeric(artifact.get("id"))
            or artifact.get("expired") is not False or not numeric(artifact.get("size_in_bytes"))
            or artifact["size_in_bytes"] > s.MAX_ZIP or not isinstance(artifact.get("digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])
            or artifact.get("archive_download_url") != ROOT + "/artifacts/" + str(artifact["id"]) + "/zip"):
        raise s.Rejected("artifact identity, size, expiry or API digest rejected")
    workflow = artifact.get("workflow_run")
    if (not isinstance(workflow, dict) or workflow.get("id") != github_run
            or not all(numeric(workflow.get(k)) for k in ("id", "repository_id", "head_repository_id"))
            or workflow.get("repository_id") != REPOSITORY_ID or workflow.get("head_repository_id") != REPOSITORY_ID
            or workflow.get("head_branch") != BRANCH or workflow.get("head_sha") != identity["source_head"]):
        raise s.Rejected("artifact workflow tuple rejected")
    return artifact


def select_artifact(listing, github_run, identity):
    if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
        raise s.Rejected("artifact listing rejected")
    artifacts = listing["artifacts"]
    if not 1 <= len(artifacts) <= 100 or not numeric(listing.get("total_count")) or listing.get("total_count") != len(artifacts):
        raise s.Rejected("artifact listing bound rejected")
    ids = [a.get("id") for a in artifacts if isinstance(a, dict)]
    if len(ids) != len(artifacts) or not all(numeric(i) for i in ids) or len(set(ids)) != len(ids):
        raise s.Rejected("artifact listing IDs rejected")
    encrypted = [a for a in artifacts if isinstance(a.get("name"), str) and a["name"].startswith("encrypted-link-notices-")]
    if len(encrypted) != 1:
        raise s.Rejected("exactly one canonical encrypted notice artifact required")
    return bound_artifact(encrypted[0], github_run, identity)


def retrieve(base, identity, github_run, key, cert, token=None):
    identity = s.identities(identity["run_id"], identity["source_head"], identity["recipient_sha256"], identity["job"], identity["attempt"])
    github_run = run_number(github_run)
    directory, error_fd = s.reserve_operation(Path(base) / ".cache/retrieved-link-notices", identity["run_id"])
    action = "read bounded token stdin"
    try:
        token = token_from_stdin() if token is None else token
        validate_token(token)
        deadline, requests = time.monotonic() + HTTP_SECONDS, 0
        def get(url, maximum, download=False):
            nonlocal requests
            if requests >= MAX_REQUESTS:
                raise s.Rejected("HTTPS request bound exceeded")
            if token in url:
                raise s.EvidenceIncomplete("credential-bearing URL refused; private evidence incomplete; stopped")
            requests += 1
            status, location, body = https_get(url, token, maximum, deadline, download=download)
            if len(body) > maximum:
                raise s.Rejected("HTTP response byte bound exceeded")
            # Authentication material must never be persisted even if reflected.
            if token.encode() in body:
                raise s.EvidenceIncomplete("credential-bearing response withheld; private evidence incomplete; stopped")
            return status, location, body
        def metadata(url, filename):
            status, _, body = get(url, MAX_JSON)
            if status != 200:
                raise s.Rejected("API metadata redirect refused")
            # Keep bounded credential-checked original response even if JSON is
            # malformed; it remains private and cannot become accepted metadata.
            s.write_private(directory / filename, body)
            return s.parse_json(body)
        root = ROOT + "/runs/" + str(github_run)
        action = "authenticate exact GitHub run metadata"
        info = metadata(root, "run.json")
        bound_run(info, github_run, identity)
        action = "authenticate exact GitHub attempt metadata"
        attempt = metadata(root + "/attempts/" + identity["attempt"], "attempt.json")
        bound_run(attempt, github_run, identity)
        if attempt["workflow_id"] != info["workflow_id"]:
            raise s.Rejected("run/attempt workflow IDs differ")
        action = "authenticate exact attempt job listing"
        job = bound_job(metadata(root + "/attempts/" + identity["attempt"] + "/jobs?per_page=100", "jobs.json"), github_run, identity)
        action = "authenticate canonical artifact listing and detail"
        artifact = select_artifact(metadata(root + "/artifacts?per_page=100", "artifacts.json"), github_run, identity)
        detail = bound_artifact(metadata(ROOT + "/artifacts/" + str(artifact["id"]), "artifact.json"), github_run, identity)
        if any(detail[k] != artifact[k] for k in ("id", "name", "digest", "size_in_bytes", "archive_download_url", "workflow_run")):
            raise s.Rejected("artifact listing/detail mismatch")
        action = "download exact artifact ZIP through bounded HTTPS redirects"
        url = artifact["archive_download_url"]
        for redirect in range(3):
            status, location, body = get(url, s.MAX_ZIP, True)
            if status == 200:
                break
            if status not in (301, 302, 303, 307, 308) or redirect == 2 or not isinstance(location, str):
                raise s.Rejected("artifact download redirect bound rejected")
            if urlsplit(location).netloc == "api.github.com":
                raise s.Rejected("artifact redirect back to authenticated API refused")
            url = location
        trusted = artifact["digest"][7:]
        if len(body) != artifact["size_in_bytes"] or s.digest(body) != trusted:
            raise s.Rejected("API artifact ZIP size/digest mismatch before parse or decrypt")
        action = "persist API-verified ZIP snapshot"
        archive = directory / "artifact.zip"
        s.write_private(archive, body)
        action = "privately unseal API-verified artifact"
        payloads = u.unseal(base, identity, archive, trusted, key, cert)
        action = "persist authenticated retrieval metadata"
        s.write_complete(directory, s.encode(dict(identity, repository=REPOSITORY, github_run_id=github_run,
                workflow=WORKFLOW, artifact_id=artifact["id"], artifact_name=artifact["name"],
                api_zip_sha256=trusted, job_id=job["id"], requests=requests, complete=True)))
        return payloads
    except (OSError, http.client.HTTPException) as error:
        # The token was never placed in URLs or exception construction. Withhold
        # even an unexpected reflected credential rather than persist it.
        pending, seen = [error], set()
        while pending and len(seen) < 8:
            current = pending.pop(0)
            if id(current) in seen:
                continue
            seen.add(id(current))
            if token and token in str(current):
                raise s.EvidenceIncomplete("credential-bearing notice withheld; private evidence incomplete; stopped") from None
            pending.extend(next_error for next_error in (current.__cause__, current.__context__) if next_error is not None)
        if not isinstance(error, OSError):
            try:
                raise OSError("original HTTPS protocol failure") from error
            except OSError as wrapped:
                s.retain_os_error(error_fd, action, wrapped)
        s.retain_os_error(error_fd, action, error)
    finally:
        token = None
        os.close(error_fd)


def main():
    parser = s.arguments(__doc__)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--token-stdin", action="store_true", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()
    identity = s.identities(args.run_id, args.source_head, args.recipient_sha256, args.job, args.attempt)
    if args.recipient_sha256 != s.CERT_PIN:
        raise s.Rejected("reviewed recipient pin required")
    retrieve(Path.cwd(), identity, args.github_run_id, args.private_key,
             Path(__file__).with_name("link-notices-recipient.pem"))
    print("retrieved and unsealed: authenticated tuple and receipts retained privately")


def cli():
    try:
        main()
        return 0
    except s.EvidenceIncomplete:
        print("retrieval rejected; private evidence incomplete; stopped", file=sys.stderr)
        return 1
    except (s.Rejected, OSError, ValueError, http.client.HTTPException):
        print("retrieval rejected; no complete retrieval accepted; stopped", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
