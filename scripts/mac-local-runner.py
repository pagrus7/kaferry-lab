#!/usr/bin/env python3
"""Fixed no-child Mac custody calibration. No qualification or general runner cleanup."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path('/Users/pg/services/kaferry-lab-local-evidence-20261027')
REPOSITORY = 'pagrus7/kaferry-lab'
REPOSITORY_ID = '1432555755'
REF = 'refs/heads/codex/resilience-release-lab'
JOB = 'local-retention'
DESCRIPTOR = 'PRIVATE-STORE.json'
MAX_ATTEMPTS = 16
MAX_ATTEMPT = 256 << 20
MAX_AGGREGATE = 4 << 30
FREE_GUARD = 2 << 30
MAX_FILE = 1 << 20
HEAD = re.compile(r'[0-9a-f]{40}\Z')
NUMBER = re.compile(r'[1-9][0-9]{0,19}\Z')
LEAF = re.compile(r'[1-9][0-9]{0,19}-[1-9][0-9]{0,19}-local-retention-[0-9a-f]{40}\Z')
PAYLOADS = {'sample.bin': bytes(range(256)) * 4,
            'sample.json': b'{"namespace":"calibration/mac-local-custody","synthetic":true}\n'}


class Rejected(Exception):
    pass


class IOFailures(Exception):
    def __init__(self, errors):
        self.errors = errors
        super().__init__('local custody I/O incomplete')


def require(value):
    if not value:
        raise Rejected('local custody admission rejected')


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def parse(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite JSON')))


def sha(body):
    return hashlib.sha256(body).hexdigest()


def private(info, directory=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (directory or info.st_nlink == 1))


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def chain(path):
    require(path.is_absolute() and str(path) == os.path.abspath(path))
    for item in [*reversed(path.parents), path]:
        require(stat.S_ISDIR(item.lstat().st_mode))


def read(path, maximum=MAX_FILE):
    before = path.lstat()
    private(before)
    require(0 <= before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(signature(before) == signature(os.fstat(fd)))
        body = os.read(fd, maximum + 1)
        require(len(body) == before.st_size and signature(before) == signature(os.fstat(fd))
                and signature(before) == signature(path.lstat()))
    finally:
        os.close(fd)
    return body


def write(path, body):
    require(len(body) <= MAX_FILE)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    errors = []
    try:
        try:
            if os.write(fd, body) != len(body):
                raise OSError(5, 'local custody short write')
            os.fsync(fd)
        except BaseException as error:
            errors.append(('write/sync ' + path.name, error))
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            errors.append(('close ' + path.name, error))
    if errors:
        raise IOFailures(errors)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    errors = []
    try:
        try:
            os.fsync(fd)
        except BaseException as error:
            errors.append(('sync directory', error))
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            errors.append(('close directory', error))
    if errors:
        raise IOFailures(errors)


def identity(environment):
    expected = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': REPOSITORY_ID,
                'GITHUB_REF': REF, 'GITHUB_JOB': JOB,
                'RUNNER_OS': 'macOS', 'RUNNER_ARCH': 'ARM64'}
    require(all(environment.get(k) == v for k, v in expected.items()))
    require(environment.get('GITHUB_EVENT_NAME') in ('push', 'workflow_dispatch'))
    head = environment.get('GITHUB_SHA', '')
    run, attempt = (environment.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    require(HEAD.fullmatch(head) and NUMBER.fullmatch(run) and NUMBER.fullmatch(attempt))
    return {'repository': REPOSITORY, 'repository_id': REPOSITORY_ID, 'ref': REF,
            'job': JOB, 'source_head': head, 'run_id': run, 'attempt': attempt}


def leaf(value):
    return '-'.join(value[k] for k in ('run_id', 'attempt', 'job', 'source_head'))


def inventory(directory):
    """Fixed flat calibration files only; no recursive filesystem abstraction."""
    private(directory.lstat(), True)
    names, total = [], 0
    for item in directory.iterdir():
        require(len(names) < 16 and re.fullmatch(r'[A-Za-z][A-Za-z0-9.-]{0,63}', item.name))
        info = item.lstat()
        private(info)
        require(info.st_size <= MAX_FILE)
        total += info.st_size
        names.append(item.name)
    require(total <= MAX_ATTEMPT)
    return set(names), total


def admit_root(root, value, current=None):
    chain(root)
    info = root.lstat()
    private(info, True)
    descriptor = parse(read(root / DESCRIPTOR, 8192))
    fixed = {'version': 1, 'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
             'ref': REF, 'job': JOB, 'root_device': info.st_dev,
             'root_inode': info.st_ino, 'owner_uid': os.getuid()}
    require(type(descriptor) is dict and set(descriptor) == set(fixed) | {'approved_source_heads'})
    require(all(type(descriptor[k]) is type(v) and descriptor[k] == v for k, v in fixed.items()))
    heads = descriptor['approved_source_heads']
    require(type(heads) is list and 1 <= len(heads) <= 16
            and all(type(h) is str and HEAD.fullmatch(h) for h in heads)
            and len(set(heads)) == len(heads) and value['source_head'] in heads)
    names, total = [], 0
    for item in root.iterdir():
        if item.name == DESCRIPTOR:
            continue
        if item.name == 'INFLIGHT.json':
            read(item, 4096)
            continue
        require(len(names) < MAX_ATTEMPTS and LEAF.fullmatch(item.name))
        if item.name == current:
            private(item.lstat(), True)
            size = 0  # Validate current files only after opening its reserved error sink.
        else:
            _, size = inventory(item)
        total += size
        names.append(item.name)
    require(total <= MAX_AGGREGATE)
    return (info.st_dev, info.st_ino), names, total


def error_record(fd, error):
    errors = error.errors if isinstance(error, IOFailures) else [('operation', error)]
    records = []
    for action, current in errors[:8]:
        records.append({'action': action, 'type': type(current).__name__,
                        'errno': getattr(current, 'errno', None), 'exact_text': str(current),
                        'filename': getattr(current, 'filename', None),
                        'filename2': getattr(current, 'filename2', None)})
    body = encode({'complete': len(errors) <= 8, 'failures': records})
    if len(body) > 65536:
        body = encode({'complete': False, 'bytes': len(body), 'sha256': sha(body)})
    # Exactly one attempt using the existing sink. No alternate or retry.
    if os.write(fd, body) != len(body):
        raise Rejected('original error sink incomplete')
    os.fsync(fd)


def operate(action, root, environment):
    """Inject only a synthetic root/env in tests; CLI always selects fixed ROOT."""
    value = identity(environment)
    root = Path(root)
    target = root / leaf(value)
    root_id, names, total = admit_root(root, value, target.name if action != 'start' else None)
    error_fd = None
    try:
        if action == 'start':
            require(not (root / 'INFLIGHT.json').exists())
            require(len(names) < MAX_ATTEMPTS and target.name not in names
                    and total + MAX_ATTEMPT <= MAX_AGGREGATE)
            # Unresolved directories also block reuse if the latch was lost.
            for name in names:
                previous = root / name
                require('VERIFIED.json' in inventory(previous)[0]
                        and read(previous / 'OS-ERROR.json', 65536) == b'')
            space = os.statvfs(root)
            require(space.f_bavail * space.f_frsize >= FREE_GUARD + MAX_ATTEMPT)
            target.mkdir(mode=0o700)
            error_fd = os.open(target / 'OS-ERROR.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(error_fd)
            write(target / 'INCOMPLETE.json', encode(dict(value, status='INCOMPLETE',
                  namespace='calibration/mac-local-custody', release_qualified=False)))
            write(root / 'INFLIGHT.json', encode(value))
            sync_directory(target)
            sync_directory(root)
        else:
            require(action in ('calibrate', 'finish') and target.name in names)
            require(read(target / 'OS-ERROR.json', 65536) == b'')
            error_fd = os.open(target / 'OS-ERROR.json', os.O_WRONLY | os.O_NOFOLLOW)
            _, current_bytes = inventory(target)
            require(total + current_bytes <= MAX_AGGREGATE)
            require(parse(read(root / 'INFLIGHT.json', 4096)) == value)
            require(parse(read(target / 'INCOMPLETE.json', 4096)) == dict(value, status='INCOMPLETE',
                    namespace='calibration/mac-local-custody', release_qualified=False))
            if action == 'calibrate':
                require(inventory(target)[0] == {'INCOMPLETE.json', 'OS-ERROR.json'})
                for name, body in PAYLOADS.items():
                    write(target / name, body)
                    require(read(target / name) == body)
                manifest = {name: {'bytes': len(body), 'sha256': sha(body)} for name, body in PAYLOADS.items()}
                write(target / 'MANIFEST.json', encode(dict(value, files=manifest,
                      namespace='calibration/mac-local-custody', release_qualified=False)))
                sync_directory(target)
            else:
                # A callback is observation of this callback only, never child closure.
                write(target / 'CALLBACK.json', encode(dict(value, post_job_callback_observed=True,
                      child_processes_launched_by_calibration=False, release_qualified=False)))
                require(inventory(target)[0] == {'INCOMPLETE.json', 'OS-ERROR.json',
                        'sample.bin', 'sample.json', 'MANIFEST.json', 'CALLBACK.json'})
                manifest = parse(read(target / 'MANIFEST.json'))
                expected = {name: {'bytes': len(body), 'sha256': sha(body)} for name, body in PAYLOADS.items()}
                require(manifest == dict(value, files=expected,
                        namespace='calibration/mac-local-custody', release_qualified=False))
                for name, body in PAYLOADS.items():
                    require(read(target / name) == body)
                require((root.lstat().st_dev, root.lstat().st_ino) == root_id)
                write(target / 'VERIFIED.json', encode(dict(value, fixed_calibration_bytes_verified=True,
                      post_job_callback_observed=True, release_qualified=False,
                      scope='Fixed no-child calibration only; no writer/process closure or universal retention proof.')))
                sync_directory(target)
                sync_directory(root)
        # All private writes finish before a latch can be released.
        owned, error_fd = error_fd, None
        os.close(owned)
        if action == 'finish':
            require((root.lstat().st_dev, root.lstat().st_ino) == root_id)
            # Last mutating operation; a lost removal remains conservatively locked.
            # No directory durability or actual callback-process exit is claimed.
            os.unlink(root / 'INFLIGHT.json')
        return {'status': 'local-calibration-' + action + '-observed', 'release_qualified': False}
    except BaseException as error:
        if error_fd is not None:
            try:
                error_record(error_fd, error)
            except BaseException:
                pass  # Sink failure means unavailable original, never an alternate.
            finally:
                try:
                    os.close(error_fd)
                except BaseException:
                    pass
        raise


def main(argv=None):
    try:
        arguments = sys.argv[1:] if argv is None else argv
        require(len(arguments) == 1 and arguments[0] in ('start', 'calibrate', 'finish'))
        result = operate(arguments[0], ROOT, os.environ)
    except BaseException:
        result = {'status': 'local-calibration-incomplete-stopped', 'release_qualified': False}
        try:
            sys.stdout.write(encode(result).decode())
            sys.stdout.flush()
        except BaseException:
            pass
        return 1
    try:
        sys.stdout.write(encode(result).decode())
        sys.stdout.flush()
    except BaseException:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
