#!/usr/bin/env python3
"""Synthetic data-only controls of the exact private-store workflow projections.

No store helper, crypto, Go, Docker, network or original diagnostic is executed.
"""
import ast
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import time
from unittest import mock

ROOT = None
RUN = 'links-123456-2'
HEAD = 'a' * 40
PIN = 'ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57'
_private_error_fd = None
_private_error_records = 0
_private_error_broken = False


def close_private_error():
    global _private_error_fd
    owned, _private_error_fd = _private_error_fd, None
    if owned is not None:
        os.close(owned)  # one terminal close; uncertainty never opens another sink


def retain_private_error(error):
    global _private_error_records, _private_error_broken
    if _private_error_broken or _private_error_fd is None or _private_error_records >= 2:
        return False
    raw = str(error).encode('utf-8', errors='backslashreplace')
    prefix = raw[:64 << 10]
    record = {'type': type(error).__name__, 'original_bytes': len(raw),
              'complete': len(prefix) == len(raw), 'cause_base64': base64.b64encode(prefix).decode()}
    body = encoded(record)
    try:
        if os.write(_private_error_fd, body) != len(body):
            raise OSError('private reporter error record incomplete')
        os.fsync(_private_error_fd)
    except BaseException:
        _private_error_broken = True  # no further records after sink failure
        raise
    _private_error_records += 1
    return len(prefix) == len(raw)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def extract(workflow, marker):
    lines = workflow.splitlines(keepends=True)
    begin = "          python3 - <<'" + marker + "'\n"
    assert lines.count(begin) == 1
    start = lines.index(begin) + 1
    end = lines.index('          ' + marker + '\n', start)
    assert all(line.startswith('          ') for line in lines[start:end])
    body = ''.join(line[10:] for line in lines[start:end])
    ast.parse(body)
    return body


def literal():
    common = {'namespace': 'calibration/private-notice-store', 'run_id': RUN,
              'source_head': HEAD, 'job': 'links', 'attempt': '2',
              'recipient_sha256': PIN, 'layout': 'linked-calibration-v2',
              'repository': 'pagrus7/kaferry-lab', 'repository_id': '1432555755',
              'storage_binding_sha256': 'b' * 64, 'release_qualified': False}
    before = dict(common, status='preflight-ready', complete=False,
                  retention_limit_attempts=64, retention_limit_bytes_per_attempt=13631488)
    cms = b'SYNTHETIC CMS-COPY BYTES; NO CRYPTO OR REAL NOTICES\n'
    seal = encoded({'cms_sha256': sha(cms), 'cms_bytes': len(cms)})
    caller = encoded({'source_head': HEAD, 'run_id': RUN, 'synthetic': True})
    stored = dict(common, status='stored', complete=True, cms_sha256=sha(cms),
                  cms_bytes=len(cms), seal_complete_sha256=sha(seal),
                  caller_proof_sha256=sha(caller), storage_receipt_sha256='c' * 64,
                  stored_payload_bytes=len(cms) + len(seal) + len(caller), stored_payload_files=3)
    return before, stored, seal, caller


def run_case(case_dir, body, phase, candidate, before, seal, caller, accept):
    links = case_dir / '.cache/links'
    links.mkdir(parents=True, mode=0o700)
    sealed = case_dir / '.cache/link-quarantine' / RUN
    sealed.mkdir(parents=True, mode=0o700)
    (sealed / 'COMPLETE.json').write_bytes(seal)
    (links / 'caller-proof.json').write_bytes(caller)
    (links / 'private-preflight.json').write_bytes(encoded(before))
    pending = links / ('private-' + phase + '.pending.json')
    pending.write_bytes(encoded(candidate))
    public = links / ('private-' + phase + '.json')
    if public.exists():
        public.unlink()  # remove only this synthetic preflight input before its projection
    output = case_dir / 'github-output'
    env = {'LAB_RUN_ID': RUN, 'GITHUB_SHA': HEAD, 'GITHUB_RUN_ATTEMPT': '2',
           'GITHUB_OUTPUT': str(output)}
    old = Path.cwd()
    rejected = False
    captured_out, captured_err = io.StringIO(), io.StringIO()
    try:
        os.chdir(case_dir)
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            try:
                exec(compile(body, '<reviewed-workflow-private-' + phase + '>', 'exec'), {})
            except (AssertionError, ValueError, KeyError, TypeError):
                rejected = True
    finally:
        os.chdir(old)
    assert captured_out.getvalue() == '' and captured_err.getvalue() == ''
    if accept:
        assert not rejected and public.is_file()
        assert json.loads(public.read_bytes()) == candidate
        assert output.read_text() == ('ready=true\n' if phase == 'preflight' else 'complete=true\n')
    else:
        assert rejected and not public.exists() and not output.exists()


def main():
    global ROOT, _private_error_fd, _private_error_records, _private_error_broken
    ROOT = Path(__file__).resolve().parents[1]
    output_root = ROOT / '.cache/m2/private-store-caller-controls'
    output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    attempt = output_root / ('run-' + str(time.time_ns()))
    attempt.mkdir(mode=0o700)
    _private_error_fd = os.open(attempt / 'PRIVATE-ERROR.jsonl', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    _private_error_records = 0
    _private_error_broken = False
    workflow_raw = (ROOT / '.github/workflows/ci.yml').read_bytes()
    workflow = workflow_raw.decode()
    bodies = {'preflight': extract(workflow, 'PYSTORECHECK'),
              'store': extract(workflow, 'PYSTORERESULT')}
    # Independent literal field corruptions, not values constructed by the helper.
    mutations = {
        'preflight': [('valid-preflight', None, None),
                      ('wrong-head', 'source_head', 'd' * 40),
                      ('bool-count', 'retention_limit_attempts', True),
                      ('premature-complete', 'complete', True),
                      ('extra-private-field', 'unreviewed_body', 'PRIVATE_LITERAL_MARKER'),
                      ('invalid-storage-binding', 'storage_binding_sha256', 'wrong'),
                      ('wrong-namespace', 'namespace', 'release')],
        'store': [('valid-store', None, None),
                  ('wrong-head', 'source_head', 'd' * 40),
                  ('incomplete-store', 'complete', False),
                  ('bool-byte-count', 'cms_bytes', True),
                  ('oversized-capsule', 'cms_bytes', (12 << 20) + 1),
                  ('extra-private-field', 'unreviewed_body', 'PRIVATE_LITERAL_MARKER'),
                  ('wrong-caller-binding', 'caller_proof_sha256', 'd' * 64),
                  ('wrong-seal-binding', 'seal_complete_sha256', 'd' * 64),
                  ('wrong-capsule-hash', 'cms_sha256', 'd' * 64),
                  ('wrong-capsule-length', 'cms_bytes', 1),
                  ('changed-storage-root', 'storage_binding_sha256', 'd' * 64),
                  ('bool-file-count', 'stored_payload_files', True),
                  ('noncanonical-attempt', 'attempt', 2),
                  ('wrong-recipient', 'recipient_sha256', 'd' * 64)]}
    rows, private_failure = [], None
    for phase, cases in mutations.items():
        for name, key, value in cases:
            before, stored, seal, caller = literal()
            candidate = copy.deepcopy(before if phase == 'preflight' else stored)
            if key is not None:
                candidate[key] = value
            case = attempt / (phase + '-' + name)
            case.mkdir(mode=0o700)
            try:
                run_case(case, bodies[phase], phase, candidate, before, seal, caller, key is None)
            except Exception as error:
                rows.append({'case': phase + '-' + name, 'passed': False})
                private_failure = {'case': phase + '-' + name}
                retain_private_error(error)
                break  # no more filesystem work after an unexpected platform failure
            rows.append({'case': phase + '-' + name, 'passed': True})
        if private_failure:
            break
    if private_failure is None:
        links_job = workflow.split('\n  links:\n', 1)[1]
        upload_paths = []
        for block in links_job.split('uses: actions/upload-artifact@')[1:]:
            body = block.split('\n      - ', 1)[0]
            start = body.index('          path: |\n') + len('          path: |\n')
            for line in body[start:].splitlines():
                if not line.startswith('            '):
                    break
                upload_paths.append(line.strip())
        safe = upload_paths == ['.cache/links/build.json', '.cache/links/caller-proof.json', '.cache/links/private-store.json']
        safe = safe and 'encrypted-link-notices-links-' not in links_job
        safe = safe and "LAB_LINK_RUNTIME: 'disabled'" in workflow
        safe = safe and 'steps.private_preflight.outputs.ready' in links_job and 'test "$PRIVATE_STORED" = true' in links_job
        rows.append({'case': 'public-upload-allowlist-and-disabled-runtime', 'passed': safe})
        for stage in ('entry-before-sink', 'root-resolution-before-sink', 'report-write-with-sink', 'private-sink-write-failure'):
            marker = 'PRIVATE_LITERAL_REPORTER_ERROR_' + stage
            failure = OSError(5, marker)
            case = attempt / ('reporter-' + stage)
            case.mkdir(mode=0o700)
            private = case / 'original.jsonl'
            fd = None if stage in ('entry-before-sink', 'root-resolution-before-sink') else os.open(private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            def fail_entry():
                raise failure
            def fail_report_write():
                return (case / 'public-report.json').write_bytes(b'{}')
            def fail_private_sink():
                retain_private_error(failure)
            fake = main if stage == 'root-resolution-before-sink' else fail_entry if fd is None else fail_private_sink if stage == 'private-sink-write-failure' else fail_report_write
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.dict(globals(), {'main': fake, '_private_error_fd': fd, '_private_error_records': 0, '_private_error_broken': False}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    if stage == 'root-resolution-before-sink':
                        with mock.patch.object(Path, 'resolve', side_effect=failure) as resolves:
                            status = cli()
                        assert resolves.call_count == 1
                    elif fd is None:
                        status = cli()
                    elif stage == 'private-sink-write-failure':
                        with mock.patch.object(os, 'write', side_effect=failure) as writes:
                            status = cli()
                        assert writes.call_count == 1
                    else:
                        with mock.patch.object(Path, 'write_bytes', side_effect=failure):
                            status = cli()
                assert _private_error_fd is None
            assert status == 1 and err.getvalue() == '' and marker not in out.getvalue()
            selected = json.loads(out.getvalue())
            assert selected == {'namespace': 'calibration/private-store-caller-controls', 'all_passed': False, 'report_complete': False, 'release_qualified': False}
            if fd is None:
                assert not private.exists()
            elif stage == 'private-sink-write-failure':
                assert private.read_bytes() == b''
            else:
                original = [json.loads(line) for line in private.read_bytes().splitlines()]
                assert len(original) == 1 and original[0]['complete'] is True
                assert base64.b64decode(original[0]['cause_base64']) == str(failure).encode()
                assert not (case / 'public-report.json').exists()
            rows.append({'case': 'fixed-safe-reporter-' + stage, 'passed': True})
    report = {'namespace': 'calibration/private-store-caller-controls', 'release_qualified': False,
              'controls': rows, 'all_passed': private_failure is None and all(row['passed'] for row in rows),
              'workflow_sha256': sha(workflow_raw), 'controller_sha256': {k: sha(v.encode()) for k, v in bodies.items()},
              'test_source_sha256': sha(Path(__file__).read_bytes()),
              'scope': 'Synthetic data-only exact workflow projections; no actual storage persistence or native custody.'}
    public = attempt / 'public-report.json'
    public.write_bytes(encoded(report))
    return report


def cli():
    try:
        report = main()
        close_private_error()
        summary = {'controls': len(report['controls']), 'all_passed': report['all_passed'],
                   'report_complete': True, 'release_qualified': False}
        status = 0 if report['all_passed'] else 1
    except (Exception, KeyboardInterrupt) as error:
        # A first-sink or terminal sink failure may leave no exact original.
        # Preserve an available existing sink; never reopen or print the cause.
        try:
            retain_private_error(error)
        except Exception:
            pass
        try:
            close_private_error()
        except Exception:
            pass
        summary = {'namespace': 'calibration/private-store-caller-controls',
                   'all_passed': False, 'report_complete': False, 'release_qualified': False}
        status = 1
    try:
        print(json.dumps(summary), flush=True)
    except (Exception, KeyboardInterrupt):
        return 1  # failed public stream: no second write, route or traceback
    return status


if __name__ == '__main__':
    raise SystemExit(cli())
