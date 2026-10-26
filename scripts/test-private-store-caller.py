#!/usr/bin/env python3
"""Synthetic data-only controls of the exact private-store workflow projections.

No store helper, crypto, Go, Docker, network or original diagnostic is executed.
"""
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import time
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUN = 'links-123456-2'
HEAD = 'a' * 40
PIN = 'ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57'


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
    output_root = ROOT / '.cache/m2/private-store-caller-controls'
    output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    attempt = output_root / ('run-' + str(time.time_ns()))
    attempt.mkdir(mode=0o700)
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
                private_failure = {'case': phase + '-' + name, 'type': type(error).__name__, 'exact_text': str(error)}
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
    report = {'namespace': 'calibration/private-store-caller-controls', 'release_qualified': False,
              'controls': rows, 'all_passed': private_failure is None and all(row['passed'] for row in rows),
              'workflow_sha256': sha(workflow_raw), 'controller_sha256': {k: sha(v.encode()) for k, v in bodies.items()},
              'test_source_sha256': sha(Path(__file__).read_bytes()),
              'scope': 'Synthetic data-only exact workflow projections; no actual storage persistence or native custody.'}
    if private_failure:
        (attempt / 'private-failure.json').write_bytes(encoded(private_failure))
    public = attempt / 'public-report.json'
    public.write_bytes(encoded(report))
    print(json.dumps({'controls': len(rows), 'all_passed': report['all_passed'], 'release_qualified': False}))
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
