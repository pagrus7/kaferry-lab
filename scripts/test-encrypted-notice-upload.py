#!/usr/bin/env python3
"""Synthetic data-only sensitivity controls of exact workflow seal admission.

No upload, crypto, Go, Docker, release executable or network is invoked.
The literal closure fixtures establish test inputs, never actual native proof.
"""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from unittest import mock

sys.dont_write_bytecode = True
REPOSITORY = Path(__file__).resolve().parents[1]
RUN = 'links-123456-2'
HEAD = 'a' * 40
PIN = 'ce023413c3cb69ca45f71d23a4fb6e6a5cabcea1b2feb4ae54f1e5452c74af57'
SECRET = 'PRIVATE_SYNTHETIC_DIAGNOSTIC_MUST_NOT_APPEAR_PUBLICLY'


def digest(body):
    return hashlib.sha256(body).hexdigest()


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


def step(workflow, name):
    begin = '      - name: ' + name + '\n'
    assert workflow.count(begin) == 1
    return workflow.split(begin, 1)[1].split('      - name: ', 1)[0]


def job_before_steps(workflow, name):
    return workflow.split('  ' + name + ':\n', 1)[1].split('    steps:', 1)[0]


def release_conditions(workflow, job):
    # Only the four literal equality conjuncts used by these two trusted jobs
    # are accepted. This is not a general GitHub expression evaluator.
    body = job_before_steps(workflow, job)
    guards = re.findall(r'^    if: \$\{\{ (.*?) \}\}$', body, re.M)
    assert len(guards) == 1
    clauses = guards[0].split(' && ')
    assert len(clauses) == 4
    conditions = {}
    for clause in clauses:
        match = re.fullmatch(r"(github\.[a-z_]+) == '([^']+)'", clause)
        assert match and match[1] not in conditions
        conditions[match[1]] = match[2]
    return conditions


def activation_policy(workflow):
    assert workflow.count("  LAB_LINK_RUNTIME: 'enabled'\n") == 1
    assert "  LAB_LINK_RUNTIME: 'disabled'\n" not in workflow
    expected = {'github.repository': 'pagrus7/kaferry-lab', 'github.repository_id': '1432555755',
                'github.event_name': 'push', 'github.ref': 'refs/heads/codex/resilience-release-lab'}
    for job in ('m1', 'm2-release'):
        assert release_conditions(workflow, job) == expected
        assert '\n    runs-on: ubuntu-24.04\n' in job_before_steps(workflow, job)
    # The old known sample must not create a second encrypted artifact while
    # links owns the sole normal-run ciphertext. Both creation and upload stop.
    common = "github.event_name == 'push' && github.ref == 'refs/heads/codex/resilience-release-lab' && env.LAB_LINK_RUNTIME != 'enabled'"
    expected_guards = {
        'Create reviewed fixed synthetic transport sample': common,
        'Upload only reviewed synthetic transport ciphertext': common + " && steps.reviewed-notice-sample.outputs.complete == 'true'",
    }
    for name, guard in expected_guards.items():
        selected = step(workflow, name)
        actual = re.findall(r'^        if: \$\{\{ (.*?) \}\}$', selected, re.M)
        # The following unnamed public unit artifact has a different if syntax.
        assert actual == [guard]
    normal = "    if: ${{ github.event_name != 'workflow_dispatch' || inputs.mode == 'normal' }}"
    for job in ('unit', 'observer'):
        assert job_before_steps(workflow, job).splitlines().count(normal) == 1, 'normal mode isolation missing for ' + job


def literal_metadata():
    cms = b'SYNTHETIC CIPHERTEXT PLACEHOLDER; NEVER CRYPTO OR ORIGINAL NOTICES\n'
    value = {'run_id': RUN, 'source_head': HEAD, 'recipient_sha256': PIN, 'job': 'links', 'attempt': '2',
             'layout': 'linked-calibration-v2', 'manifest_version': 2, 'complete': True, 'release_qualified': False,
             'publication': 'DISABLED; explicit encrypted-public-quarantine exception required',
             'cipher': 'AES-256-CBC; RSA-OAEP-SHA256; MGF1-SHA256; NOT AEAD',
             'completion_scope': 'captured bytes only; no writer-quiescence, cleanup or calibration qualification',
             'cms_bytes': len(cms), 'cms_sha256': digest(cms), 'files': 2, 'total_bytes': 128,
             'components': {'driver': {'availability': 'captured', 'files': 1, 'total_bytes': 64},
                            'fixture': {'availability': 'captured', 'files': 1, 'total_bytes': 64}},
             'bundle_complete': True, 'fixture_absence_sha256': None,
             'caller_declaration': {'notice_writers_stopped_and_reaped': True, 'observed_proof': False}}
    return value, cms


def execute(code, case, env):
    output, error = io.StringIO(), io.StringIO()
    old = Path.cwd()
    status = 0
    try:
        os.chdir(case)
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            try:
                exec(compile(code, '<exact-workflow-data-control>', 'exec'), {})
            except SystemExit as stopped:
                status = stopped.code
    finally:
        os.chdir(old)
    return status, output.getvalue(), error.getvalue()


def main(attempt, helper):
    workflow_raw = (REPOSITORY / '.github/workflows/ci.yml').read_bytes()
    workflow = workflow_raw.decode()
    proof_code, admission = extract(workflow, 'PYPROOF'), extract(workflow, 'PYSEALED')
    spec = importlib.util.spec_from_file_location('literal_caller_fixtures', REPOSITORY / 'scripts/test-linked-caller.py')
    literal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(literal)
    rows = []
    cases = [('valid-sealed-after-typed-proof', 'valid'), ('failed-calibration-complete-evidence-retainable', 'failed'),
             ('absent-fixture-complete-capture-retainable', 'absent')]
    cases += [(name, name) for name in ['stale-head', 'stale-run', 'stale-attempt', 'mixed-cms-hash', 'wrong-cms-size',
              'bool-cms-size', 'empty-cms', 'oversized-cms', 'oversized-metadata', 'cms-symlink', 'metadata-symlink', 'parent-symlink', 'public-cms-mode', 'hardlinked-cms',
              'missing-completion', 'unknown-metadata-field', 'unknown-component-field', 'unknown-declaration-field',
              'bool-declaration', 'duplicate-metadata-key', 'missing-closure-marker', 'closure-not-quiescent',
              'tree-not-closed', 'caller-proof-stale', 'caller-proof-unknown', 'caller-proof-missing-wait',
              'caller-cancelled', 'proof-step-failed', 'declaration-without-proof', 'foreign-repository',
              'untrusted-event', 'foreground-missing', 'incomplete-marker', 'extra-quarantine-file',
              'denied-cms-read-private-original', 'failed-public-output-private-original']]
    for index, (name, mutation) in enumerate(cases):
        case = attempt / ('case-%02d' % index)
        case.mkdir(mode=0o700)
        cache = case / '.cache'
        cache.mkdir(mode=0o700)
        for rel in ['links', 'link-calibration', 'link-calibration/' + RUN, 'link-quarantine', 'link-quarantine/' + RUN]:
            (cache / rel).mkdir(mode=0o700)
        scripts = case / 'scripts'
        scripts.mkdir(mode=0o700)
        (scripts / 'seal-link-notices.py').write_bytes((REPOSITORY / 'scripts/seal-link-notices.py').read_bytes())
        fixture = literal.literal_fixture(case)
        if mutation == 'failed':
            literal.failed_but_quiescent(fixture)
        marker = cache / 'link-calibration' / RUN / 'WRITERS_QUIESCENT.json'
        marker.write_bytes(encoded(fixture['marker']))
        (cache / 'links/build.json').write_bytes(encoded(fixture['build']))
        (cache / 'links/foreground.exit').write_text(fixture['foreground'])
        env = {'GITHUB_WORKSPACE': str(case), 'LAB_RUN_ID': RUN, 'GITHUB_SHA': HEAD, 'GITHUB_RUN_ID': '123456',
               'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_JOB': 'links', 'GITHUB_REPOSITORY': 'pagrus7/kaferry-lab',
               'GITHUB_REPOSITORY_ID': '1432555755', 'GITHUB_REF': 'refs/heads/codex/resilience-release-lab',
               'GITHUB_EVENT_NAME': 'push', 'CALLER_CANCELLED': 'false', 'PROOF_OUTCOME': 'success',
               'WRITERS_STOPPED': 'true', 'GITHUB_OUTPUT': str(case / 'proof-output')}
        assert execute(proof_code, case, env) == (0, '', '')
        assert 'writers_stopped=true\n' in (case / 'proof-output').read_text()
        env['GITHUB_OUTPUT'] = str(case / 'admission-output')
        metadata, cms = literal_metadata()
        sealed = cache / 'link-quarantine' / RUN
        if mutation == 'absent':
            metadata['components']['fixture'] = {'availability': 'absent-ENOENT', 'files': 0, 'total_bytes': 0}
            metadata.update(bundle_complete=False, files=1, total_bytes=64, fixture_absence_sha256='c' * 64)
        field_mutations = {'stale-head': ('source_head', 'b' * 40), 'stale-run': ('run_id', 'links-777-2'),
                           'stale-attempt': ('attempt', '3'), 'mixed-cms-hash': ('cms_sha256', 'd' * 64),
                           'wrong-cms-size': ('cms_bytes', len(cms) + 1), 'bool-cms-size': ('cms_bytes', True),
                           'unknown-metadata-field': ('raw_original', SECRET)}
        if mutation in field_mutations:
            key, value = field_mutations[mutation]
            metadata[key] = value
        if mutation == 'unknown-component-field':
            metadata['components']['driver']['original'] = SECRET
        if mutation == 'unknown-declaration-field':
            metadata['caller_declaration']['original'] = SECRET
        if mutation == 'bool-declaration':
            metadata['caller_declaration']['notice_writers_stopped_and_reaped'] = 1
        (sealed / 'notice.cms').write_bytes(cms)
        (sealed / 'COMPLETE.json').write_bytes(encoded(metadata))
        if mutation == 'empty-cms':
            (sealed / 'notice.cms').write_bytes(b'')
        if mutation == 'oversized-cms':
            with (sealed / 'notice.cms').open('wb') as stream:
                stream.truncate((12 << 20) + 1)
        if mutation == 'oversized-metadata':
            with (sealed / 'COMPLETE.json').open('wb') as stream:
                stream.truncate((256 << 10) + 1)
        if mutation == 'duplicate-metadata-key':
            (sealed / 'COMPLETE.json').write_bytes(encoded(metadata).replace(b'{', b'{"complete":false,', 1))
        if mutation in ('cms-symlink', 'metadata-symlink'):
            target = sealed / ('notice.cms' if mutation == 'cms-symlink' else 'COMPLETE.json')
            original = case / 'private-symlink-target'
            target.rename(original)
            target.symlink_to(original)
        if mutation == 'parent-symlink':
            moved = case / 'private-quarantine'
            (cache / 'link-quarantine').rename(moved)
            (cache / 'link-quarantine').symlink_to(moved, target_is_directory=True)
        if mutation == 'public-cms-mode':
            (sealed / 'notice.cms').chmod(0o644)
        if mutation == 'hardlinked-cms':
            os.link(sealed / 'notice.cms', case / 'private-hardlink')
        if mutation == 'missing-completion':
            (sealed / 'COMPLETE.json').unlink()
        if mutation == 'missing-closure-marker':
            marker.unlink()
        if mutation in ('closure-not-quiescent', 'tree-not-closed'):
            updated = copy.deepcopy(fixture['marker'])
            if mutation == 'closure-not-quiescent':
                updated['WritersQuiescent'] = False
            else:
                updated['Tree']['Closed'] = False
            marker.write_bytes(encoded(updated))
        if mutation.startswith('caller-proof-'):
            proof = json.loads((cache / 'links/caller-proof.json').read_bytes())
            if mutation == 'caller-proof-stale':
                proof['source_head'] = 'e' * 40
            elif mutation == 'caller-proof-unknown':
                proof['raw'] = SECRET
            else:
                proof['child_wait_returned'] = False
            (cache / 'links/caller-proof.json').write_bytes(encoded(proof))
        if mutation in ('caller-cancelled', 'proof-step-failed', 'declaration-without-proof', 'foreign-repository', 'untrusted-event'):
            key, value = {'caller-cancelled': ('CALLER_CANCELLED', 'true'), 'proof-step-failed': ('PROOF_OUTCOME', 'failure'),
                          'declaration-without-proof': ('WRITERS_STOPPED', ''), 'foreign-repository': ('GITHUB_REPOSITORY', 'other/repo'),
                          'untrusted-event': ('GITHUB_EVENT_NAME', 'pull_request')}[mutation]
            env[key] = value
        if mutation == 'foreground-missing':
            (cache / 'links/foreground.exit').unlink()
        if mutation == 'incomplete-marker':
            (marker.parent / 'INCOMPLETE.json').write_bytes(b'{}\n')
        if mutation == 'extra-quarantine-file':
            (sealed / 'plaintext.json').write_bytes(encoded({'raw': SECRET}))
        failure = OSError(13, SECRET, str(sealed / 'notice.cms'))
        original_open = os.open
        def denied(path, *args, **kwargs):
            if str(path) == '.cache/link-quarantine/' + RUN + '/notice.cms':
                raise failure
            return original_open(path, *args, **kwargs)
        original_builtin = open
        def failed_output(path, *args, **kwargs):
            if str(path) == env['GITHUB_OUTPUT']:
                raise failure
            return original_builtin(path, *args, **kwargs)
        with contextlib.ExitStack() as stack:
            if mutation == 'denied-cms-read-private-original':
                stack.enter_context(mock.patch.object(os, 'open', side_effect=denied))
            if mutation == 'failed-public-output-private-original':
                stack.enter_context(mock.patch('builtins.open', side_effect=failed_output))
            status, out, err = execute(admission, case, env)
        accepted = mutation in ('valid', 'failed', 'absent')
        assert status == (0 if accepted else 1)
        assert out == '' and err == ('' if accepted else 'encrypted diagnostic admission rejected; upload disabled\n')
        assert SECRET not in out + err
        projection = cache / 'links/seal-admission.json'
        output = case / 'admission-output'
        if accepted:
            assert output.read_text() == 'complete=true\n'
            selected = json.loads(projection.read_bytes())
            assert set(selected) == {'run_id', 'source_head', 'recipient_sha256', 'job', 'attempt', 'layout', 'namespace',
                                      'complete', 'cms_bytes', 'cms_sha256', 'seal_complete_sha256', 'caller_proof_sha256', 'release_qualified'}
            assert selected['cms_sha256'] == digest(cms) and selected['release_qualified'] is False
            assert selected['seal_complete_sha256'] == digest((sealed / 'COMPLETE.json').read_bytes())
            assert selected['caller_proof_sha256'] == digest((cache / 'links/caller-proof.json').read_bytes())
        else:
            assert not output.exists()
            assert not projection.exists() or mutation == 'failed-public-output-private-original'
        if mutation in ('denied-cms-read-private-original', 'failed-public-output-private-original'):
            private = json.loads((cache / 'link-upload-private' / RUN / 'OS-ERROR.json').read_bytes())
            assert private['complete'] is True and private['exceptions'][0]['exact_text'] == str(failure)
        rows.append({'case': name, 'passed': True})
    # Execute the final workflow gate verbatim; missing/skipped/failed upload must fail.
    gate = step(workflow, 'Keep incomplete or failed calibration nonpassing after retention')
    gate_body = ''.join(line[10:] for line in gate.split('        run: |\n', 1)[1].splitlines(keepends=True))
    healthy = {'CALLER_CANCELLED': 'false', 'PROOF_PASSED': 'true', 'SEALED': 'true', 'PROOF_OUTCOME': 'success',
               'SEAL_OUTCOME': 'success', 'UPLOAD_OUTCOME': 'success'}
    gate_cases = [('complete-final-gate', {}, True)]
    for key, invalid in [('CALLER_CANCELLED', 'true'), ('PROOF_PASSED', 'false'), ('SEALED', 'false'),
                         ('PROOF_OUTCOME', 'failure'), ('SEAL_OUTCOME', 'failure'), ('UPLOAD_OUTCOME', 'failure'),
                         ('UPLOAD_OUTCOME', 'skipped'), ('UPLOAD_OUTCOME', 'cancelled'), ('UPLOAD_OUTCOME', '')]:
        gate_cases.append(('final-gate-reject-' + key + '-' + (invalid or 'missing'), {key: invalid}, False))
    for name, changes, accepted in gate_cases:
        result = subprocess.run(['/bin/bash', '-c', gate_body], env=dict(healthy, **changes), capture_output=True, timeout=5)
        assert (result.returncode == 0) == accepted and result.stdout == result.stderr == b''
        rows.append({'case': name, 'passed': True})
    upload = step(workflow, 'Upload only the admitted diagnostic ciphertext')
    expected_upload = '''        id: encrypted_upload
        if: ${{ always() && !cancelled() && env.LAB_LINK_RUNTIME == 'enabled' && steps.proof.outcome == 'success' && steps.proof.outputs.writers_stopped == 'true' && steps.seal.outcome == 'success' && steps.seal.outputs.complete == 'true' }}
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
        timeout-minutes: 2
        with:
          name: encrypted-link-notices-links-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}
          path: .cache/link-quarantine/${{ env.LAB_RUN_ID }}/notice.cms
          include-hidden-files: true
          if-no-files-found: error
          compression-level: 0
          retention-days: 7
          overwrite: false
'''
    public = step(workflow, 'Upload only selected public build, caller and seal-admission facts')
    def upload_policy(candidate_upload, candidate_public):
        assert candidate_upload == expected_upload
        paths = candidate_public.split('          path: |\n', 1)[1].split('          include-hidden-files:', 1)[0]
        assert paths == '            .cache/links/build.json\n            .cache/links/caller-proof.json\n            .cache/links/seal-admission.json\n'
    upload_policy(upload, public)
    # Deliberately corrupt actual workflow text: the independent allowlist must
    # detect plaintext paths, broader directories and weakened retention gates.
    exposure_controls = [
        ('ciphertext-path-replaced-with-plaintext', upload.replace('/notice.cms', '/COMPLETE.json'), public),
        ('ciphertext-path-broadened-to-directory', upload.replace('/notice.cms', '/'), public),
        ('private-original-directory-added-publicly', upload, public.replace('            .cache/links/build.json',
             '            .cache/link-calibration-private/\n            .cache/links/build.json')),
        ('retention-exceeds-seven-days', upload.replace('retention-days: 7', 'retention-days: 8'), public),
        ('cancellation-upload-guard-removed', upload.replace('!cancelled() && ', ''), public),
    ]
    for name, candidate_upload, candidate_public in exposure_controls:
        rejected = False
        try:
            upload_policy(candidate_upload, candidate_public)
        except AssertionError:
            rejected = True
        assert rejected
        rows.append({'case': name, 'passed': True})
    assert 'private_preflight' not in workflow and 'private_store' not in workflow
    activation_policy(workflow)
    rows.append({'case': 'exact-ciphertext-paths-and-trusted-push-release-activation', 'passed': True})
    trusted = {'github.repository': 'pagrus7/kaferry-lab', 'github.repository_id': '1432555755',
               'github.event_name': 'push', 'github.ref': 'refs/heads/codex/resilience-release-lab'}
    contexts = [('trusted-push', {}, True), ('pull-request', {'github.event_name': 'pull_request'}, False),
                ('manual-dispatch', {'github.event_name': 'workflow_dispatch'}, False),
                ('wrong-repository', {'github.repository': 'foreign/kaferry-lab'}, False),
                ('wrong-repository-id', {'github.repository_id': '1'}, False),
                ('missing-branch', {'github.ref': ''}, False),
                ('different-branch', {'github.ref': 'refs/heads/unreviewed'}, False)]
    for job in ('m1', 'm2-release'):
        conditions = release_conditions(workflow, job)
        for name, changes, accepted in contexts:
            context = dict(trusted, **changes)
            admitted = all(context.get(key) == value for key, value in conditions.items())
            assert admitted == accepted
            rows.append({'case': job + '-job-context-' + name, 'passed': True})
    # Mutate the actual job/step guards, not a parallel hand-written predicate.
    for job in ('m1', 'm2-release'):
        body = job_before_steps(workflow, job)
        for name, changed in (
                ('pull-request-job-admission', body.replace("github.event_name == 'push'", "github.event_name == 'pull_request'")),
                ('wrong-repository-job-admission', body.replace("github.repository == 'pagrus7/kaferry-lab'", "github.repository == 'foreign/kaferry-lab'")),
                ('missing-branch-job-admission', body.replace(" && github.ref == 'refs/heads/codex/resilience-release-lab'", ''))):
            assert changed != body
            candidate = workflow.replace(body, changed, 1)
            try:
                activation_policy(candidate)
            except AssertionError:
                rows.append({'case': job + '-mutation-reject-' + name, 'passed': True})
            else:
                raise AssertionError('weakened release activation was accepted')
    for name in ('Create reviewed fixed synthetic transport sample', 'Upload only reviewed synthetic transport ciphertext'):
        original = step(workflow, name)
        changed = original.replace(" && env.LAB_LINK_RUNTIME != 'enabled'", '')
        assert changed != original
        try:
            activation_policy(workflow.replace(original, changed, 1))
        except AssertionError:
            rows.append({'case': 'second-unit-ciphertext-rejected-' + name, 'passed': True})
        else:
            raise AssertionError('second unit ciphertext route was accepted')
    report = {'namespace': 'calibration/encrypted-notice-upload-controls', 'controls': rows, 'all_passed': True,
              'release_qualified': False, 'workflow_sha256': digest(workflow_raw),
              'admission_sha256': digest(admission.encode()), 'caller_proof_sha256': digest(proof_code.encode()),
              'test_source_sha256': digest(Path(__file__).read_bytes()),
              'scope': 'Synthetic exact workflow data admission and final gate only; no real closure, CMS, upload or qualification.'}
    helper.write_private(attempt / 'public-report.json', encoded(report))
    return report


def cli():
    helper, error_fd = None, None
    try:
        spec = importlib.util.spec_from_file_location('notice_test_private_io', REPOSITORY / 'scripts/seal-link-notices.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        parent = REPOSITORY / '.cache/m2/encrypted-notice-upload-controls'
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        helper.check_private(parent.lstat(), True)
        attempt, error_fd = helper.reserve_operation(parent, 'run-' + str(time.time_ns()))
        old_mask = os.umask(0o077)
        try:
            report = main(attempt, helper)
        finally:
            os.umask(old_mask)
        owned, error_fd = error_fd, None
        helper.close_operation(owned)
        summary = {'controls': len(report['controls']), 'all_passed': True, 'report_complete': True, 'release_qualified': False}
        status = 0
    except BaseException as error:
        if error_fd is not None:
            try:
                helper.retain_os_error(error_fd, 'synthetic encrypted-upload controls', error)
            except BaseException:
                pass
            owned, error_fd = error_fd, None
            try:
                helper.close_operation(owned, error)
            except BaseException:
                pass
        summary = {'all_passed': False, 'report_complete': False, 'release_qualified': False}
        status = 1
    try:
        print(json.dumps(summary), flush=True)
    except BaseException:
        return 1
    return status


if __name__ == '__main__':
    raise SystemExit(cli())
