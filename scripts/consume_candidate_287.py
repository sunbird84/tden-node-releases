"""One-shot read-only consumer of the exact286 candidate, on a fresh hosted runner."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile

REPO = 'sunbird84/tden-node-releases'
REPO_ID = 1335347210
BUILD = '27eef668c9cd275d1e5411b7f61346587067a7cc'
BUILD_BRANCH = 'codex/node-privacy-package-20261109-285'
CONSUMER_BRANCH = 'codex/candidate-consumer-20261109-287'
RUN = 42545032765
JOB = 128928061468
WORKFLOW = '.github/workflows/build-node-candidate.yml'
ARTIFACT = 13643805962
ZIP_BYTES = 404249450
ZIP_SHA = 'f54c1223bd234cdacb99852174c7655e90e5c4a5ce5fb78a45924265cf2448b3'
ARCHIVE = 'tden-node-linux-amd64.tar.gz'
TAR_BYTES = 404247252
TAR_SHA = '75babc3271a169b2130f28a2dc06ef88175cc1bd275b249122f1ad0994f79da2'
DESCRIPTION_SHA = '2676c79e98db1f6b616d85b368647716b1bfa87d96325478240cbb9068a88612'
VERSION = '0.12.0-test.20261109.285'
SOURCE_PINS = {
    'chain_commit': '4e5b548a97b2ddc72e8e7fa2211604be4a56a2b6',
    'gateway_commit': '30e558530a668e08b3b7b856e55206ba69cd8def',
    'deploy_commit': 'b0b009eaa64ddab2515e7634f6403debbf54de9e',
}
FILES = {ARCHIVE, ARCHIVE + '.sha256', 'candidate-build.json'}
LIMIT = 1048576


def require(value):
    if not value:
        raise ValueError('consumer-contract')


def unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj)
        obj[key] = value
    return obj


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def save(path, data):
    with path.open('x', encoding='utf-8', newline='\n') as out:
        json.dump(data, out, sort_keys=True, indent=2)
        out.write('\n')


def identity(value):
    require(stat.S_ISREG(value.st_mode))
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def bind_file(stream, path, expected=None):
    current = identity(os.fstat(stream.fileno()))
    require(current == identity(path.lstat()))
    if expected is not None:
        require(current == expected)
    return current


def cli_env():
    env = dict(os.environ)
    for name in ('GH_DEBUG', 'DEBUG', 'GH_FORCE_TTY', 'GH_HTTP_UNIX_SOCKET'):
        env.pop(name, None)
    env.update(GH_PROMPT_DISABLED='1', NO_COLOR='1', CLICOLOR='0')
    return env


def gh_json(args):
    child = subprocess.Popen(['gh', *args], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=cli_env())
    try:
        with deadline(90):
            body = bytearray()
            while chunk := child.stdout.read(min(LIMIT, 4 * LIMIT - len(body) + 1)):
                require(len(body) + len(chunk) <= 4 * LIMIT)
                body.extend(chunk)
            code = child.wait(timeout=15)
            if code != 0:
                raise subprocess.CalledProcessError(code, ['gh'])
            return decode(body)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=15)
        child.stdout.close()


def api(path, projection):
    return gh_json(['api', '--hostname', 'github.com', path, '--jq', projection])


def check_origin(run, workflow, jobs, artifact):
    for key, expected in {
        'id': RUN, 'run_attempt': 1, 'head_sha': BUILD, 'head_branch': BUILD_BRANCH,
        'workflow_id': 339139915, 'event': 'workflow_dispatch',
        'status': 'completed', 'conclusion': 'success', 'path': WORKFLOW,
    }.items():
        require(run.get(key) == expected)
    for field in ('repository', 'head_repository'):
        require(run.get(field) == {'full_name': REPO, 'id': REPO_ID})
    require(workflow.get('id') == 339139915 and workflow.get('path') == WORKFLOW)
    require(jobs.get('total_count') == 1 and len(jobs.get('jobs', [])) == 1)
    job = jobs['jobs'][0]
    require(job.get('id') == JOB and job.get('status') == 'completed'
            and job.get('conclusion') == 'success')
    steps = job.get('steps', [])
    require(steps and all(x.get('conclusion') in ('success', 'skipped') for x in steps))
    for name in ('Verify source revisions are exact and clean', 'Verify fixed release trust policy',
                 'Acquire pinned Kubo from the exact official asset', 'Run source tests',
                 'Build deterministic Linux package', 'Archive and describe candidate',
                 'Verify archived bootstrap and original metadata',
                 'Upload candidate without publishing a Release', 'Attest candidate archive',
                 'Attest candidate build description'):
        selected = [x for x in steps if x.get('name') == name]
        require(len(selected) == 1 and selected[0].get('conclusion') == 'success')
    require(artifact.get('id') == ARTIFACT
            and artifact.get('name') == f'tden-node-candidate-{RUN}'
            and artifact.get('size_in_bytes') == ZIP_BYTES
            and artifact.get('digest') == 'sha256:' + ZIP_SHA
            and artifact.get('expired') is False)
    origin = artifact.get('workflow_run', {})
    require(origin.get('id') == RUN and origin.get('head_sha') == BUILD
            and origin.get('head_branch') == BUILD_BRANCH
            and origin.get('repository_id') == REPO_ID
            and origin.get('head_repository_id') == REPO_ID)


def read_headers(stream, expected_size):
    total, lines = 0, []
    while True:
        line = stream.readline(65537)
        total += len(line)
        require(line and total <= 65536)
        if line in (b'\n', b'\r\n'):
            break
        lines.append(line.rstrip(b'\r\n'))
    require(re.fullmatch(rb'HTTP/(?:1\.[01]|2(?:\.0)?) 200(?: .*)?', lines[0]))
    selected = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b':')
        if separator and key.lower() in (b'content-length', b'content-type'):
            require(key.lower() not in selected)
            selected[key.lower()] = value.strip()
    length = selected.get(b'content-length')
    require(length is None or length == str(expected_size).encode())
    mime = selected.get(b'content-type', b'').split(b';', 1)[0].strip().lower()
    require(mime in (b'application/zip', b'application/octet-stream', b'application/x-zip-compressed'))
    return {'status': 200, 'bytes': expected_size, 'content_type': mime.decode(),
            'content_length_present': length is not None}


def copy_exact(source, dest, expected_size):
    digest, count = hashlib.sha256(), 0
    while chunk := source.read(LIMIT):
        count += len(chunk)
        require(count <= expected_size)
        dest.write(chunk)
        digest.update(chunk)
    require(count == expected_size)
    return digest.hexdigest()


@contextlib.contextmanager
def deadline(seconds):
    def expired(_signum, _frame):
        raise TimeoutError('consumer-timeout')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def download(stream, path, on_started=None):
    opened = identity(os.fstat(stream.fileno()))
    child = subprocess.Popen(
        ['gh', 'api', '--hostname', 'github.com', '--include',
         f'repos/{REPO}/actions/artifacts/{ARTIFACT}/zip'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=cli_env())
    try:
        if on_started is not None:
            on_started()
        with deadline(600):
            response = read_headers(child.stdout, ZIP_BYTES)
            digest = copy_exact(child.stdout, stream, ZIP_BYTES)
            require(child.wait(timeout=15) == 0)
        stream.flush()
        os.fsync(stream.fileno())
        current = bind_file(stream, path)
        require(current[:2] == opened[:2] and current[2] == ZIP_BYTES and digest == ZIP_SHA)
        response.update(sha256=digest, accepted=True, same_runtime_identity=True,
                        independent_redirect_chain_audit=False)
        return current, response
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=15)
        child.stdout.close()


def check_directory(entries, archive_size):
    require(len(entries) == 3 and {x.filename for x in entries} == FILES)
    for info in entries:
        require(not info.is_dir() and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                and not info.flag_bits & 1)
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
        limit = archive_size if info.filename == ARCHIVE else LIMIT
        require(0 <= info.file_size <= limit
                and (info.filename != ARCHIVE or info.file_size == archive_size))
        require(info.file_size <= max(1, info.compress_size) * 100)


def extract(stream, output, archive_size=TAR_BYTES, archive_sha=TAR_SHA,
            description_sha=DESCRIPTION_SHA):
    output.mkdir(mode=0o700)
    records, bindings = {}, {}
    stream.seek(0)
    with zipfile.ZipFile(stream) as bundle:
        entries = bundle.infolist()
        check_directory(entries, archive_size)
        for info in entries:
            path = output / info.filename
            with bundle.open(info) as source, path.open('x+b') as dest:
                digest = copy_exact(source, dest, info.file_size)
                dest.flush()
                os.fsync(dest.fileno())
                bindings[info.filename] = bind_file(dest, path)
                records[info.filename] = {'bytes': info.file_size, 'sha256': digest}
    require(records[ARCHIVE]['sha256'] == archive_sha
            and records['candidate-build.json']['sha256'] == description_sha)
    require((output / (ARCHIVE + '.sha256')).read_bytes()
            == (archive_sha + '  ' + ARCHIVE + '\n').encode('ascii'))
    return records, bindings


def check_sources(data):
    require(data.get('version') == VERSION)
    for key, value in SOURCE_PINS.items():
        require(data.get(key) == value)


def verify_attestation(path):
    return gh_json(['attestation', 'verify', str(path), '--repo', REPO,
                    '--signer-workflow', REPO + '/' + WORKFLOW,
                    '--signer-digest', BUILD, '--source-digest', BUILD,
                    '--source-ref', 'refs/heads/' + BUILD_BRANCH,
                    '--deny-self-hosted-runners', '--format', 'json'])


def load_policy(checkout):
    helper = checkout / 'scripts/candidate_metadata.py'
    policy = checkout / 'release-policy.json'
    require(hashlib.sha256(helper.read_bytes()).hexdigest()
            == '7cb700686990910c6c549300b4aeacca3fd5294076ad8bdc644a90e4a3396240')
    require(hashlib.sha256(policy.read_bytes()).hexdigest()
            == 'baaa256c79340bb27c9f40b0adbd25dc9f454fc84b4a64a793d295fbf61f97f9')
    spec = importlib.util.spec_from_file_location('fixed_candidate_metadata', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def consume(checkout, root, receipts):
    phase = 'fixed-policy'
    save(receipts / 'attempt.json', {'source_run': RUN, 'source_attempt': 1,
         'artifact_id': ARTIFACT, 'max_download_attempts': 1,
         'artifact_launches_at_entry': 0, 'retry_allowed': False})
    try:
        policy = load_policy(checkout)
        phase = 'origin'
        run = api(f'repos/{REPO}/actions/runs/{RUN}',
                  '{id,run_attempt,head_sha,head_branch,path,workflow_id,event,status,conclusion,'
                  'repository:(.repository|{full_name,id}),head_repository:(.head_repository|{full_name,id})}')
        workflow = api(f'repos/{REPO}/actions/workflows/339139915', '{id,path}')
        jobs = api(f'repos/{REPO}/actions/runs/{RUN}/attempts/1/jobs?per_page=100',
                   '{total_count,jobs:[.jobs[]|{id,status,conclusion,steps:[.steps[]|{name,status,conclusion}]}]}')
        artifact = api(f'repos/{REPO}/actions/artifacts/{ARTIFACT}',
                       '{id,name,size_in_bytes,digest,expired,workflow_run}')
        check_origin(run, workflow, jobs, artifact)
        require(policy.needs_runtime([jobs]) is True)
        for name, value in [('run', run), ('workflow', workflow), ('candidate-jobs', [jobs]), ('artifact', artifact)]:
            save(receipts / (name + '.json'), value)
        phase = 'transport'
        zip_path = root / 'candidate.zip'
        with zip_path.open('x+b') as stream:
            save(receipts / 'transport_attempt.json', {'launch_requested': True,
                 'successful_spawn_not_yet_observed': True, 'retry_allowed': False})
            binding, receipt = download(stream, zip_path, on_started=lambda: save(
                receipts / 'transport_started.json', {'spawn_returned': True, 'download_attempts': 1}))
            save(receipts / 'transport.json', receipt)
            phase = 'outer-extraction'
            bind_file(stream, zip_path, binding)
            records, bindings = extract(stream, root / 'candidate')
            bind_file(stream, zip_path, binding)
        save(receipts / 'extraction.json', records)
        candidate = root / 'candidate'
        phase = 'external-source-pins'
        check_sources(decode((candidate / 'candidate-build.json').read_bytes()))
        phase = 'archive-attestation'
        save(receipts / 'archive-verification.json', verify_attestation(candidate / ARCHIVE))
        phase = 'description-attestation'
        save(receipts / 'description-verification.json', verify_attestation(candidate / 'candidate-build.json'))
        phase = 'original-policy'
        for name, binding in bindings.items():
            with (candidate / name).open('rb') as member:
                bind_file(member, candidate / name, binding)
        with contextlib.redirect_stdout(io.StringIO()):
            policy.verify(SimpleNamespace(directory=str(candidate), policy=str(checkout / 'release-policy.json'),
                run=str(receipts / 'run.json'), jobs=str(receipts / 'candidate-jobs.json'),
                archive_receipt=str(receipts / 'archive-verification.json'),
                description_receipt=str(receipts / 'description-verification.json')),
                repository=REPO, expected_sha256=TAR_SHA)
        for name, binding in bindings.items():
            require(identity((candidate / name).lstat()) == binding)
        result = {'accepted': True, 'source_run': RUN, 'source_attempt': 1,
                  'artifact_id': ARTIFACT, 'zip_sha256': ZIP_SHA, 'archive_sha256': TAR_SHA,
                  'source_pins': SOURCE_PINS, 'crypto_provenance_verified': True,
                  'original_policy_verified': True, 'binary_executed': False,
                  'release_published': False, 'deployment_accepted': False}
        save(receipts / 'result.json', result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        kind = ('timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
                'child-exit' if isinstance(error, subprocess.CalledProcessError) else 'rejected')
        result = {'accepted': False, 'last_phase': phase, 'kind': kind, 'retry_allowed': False}
        if isinstance(error, subprocess.CalledProcessError) and type(error.returncode) is int:
            result['returncode'] = error.returncode if -255 <= error.returncode <= 255 else None
        save(receipts / 'result.json', result)
        print(json.dumps(result, sort_keys=True))
        return 1


def main():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + CONSUMER_BRANCH
            and os.environ.get('GITHUB_EVENT_NAME') == 'push'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1')
    own_run = os.environ['GITHUB_RUN_ID']
    require(re.fullmatch(r'[1-9][0-9]*', own_run))
    checkout = Path(__file__).resolve().parent.parent
    root = Path(os.environ['RUNNER_TEMP']) / ('tden-consumer-287-' + own_run + '-1')
    root.mkdir(mode=0o700)
    receipts = checkout / 'consumer-receipts'
    receipts.mkdir(mode=0o700)
    return consume(checkout, root, receipts)


if __name__ == '__main__':
    try:
        code = main()
    except Exception:
        print('Consumer stopped before acceptance; inspect exact attempt/effects.', file=sys.stderr)
        code = 1
    raise SystemExit(code)
