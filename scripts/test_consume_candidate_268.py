"""Synthetic offline boundary tests. No accepted candidate or network is accessed."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('consumer268', HERE / 'consume_candidate_268.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def zip_body(tar=b'synthetic archive', description=b'{}', sidecar=None, names=None):
    output = io.BytesIO()
    contents = {c.ARCHIVE: tar, 'candidate-build.json': description,
                c.ARCHIVE + '.sha256': sidecar if sidecar is not None else
                (digest(tar) + '  ' + c.ARCHIVE + '\n').encode()}
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED) as z:
        for name in names or contents:
            z.writestr(name, contents.get(name, b''))
    return output.getvalue()


def origin():
    run = dict(id=c.RUN, run_attempt=1, head_sha=c.BUILD, head_branch=c.BUILD_BRANCH,
               workflow_id=339139915, event='workflow_dispatch', status='completed',
               conclusion='success', path=c.WORKFLOW,
               repository={'full_name': c.REPO, 'id': c.REPO_ID},
               head_repository={'full_name': c.REPO, 'id': c.REPO_ID})
    names = ['Verify source revisions are exact and clean', 'Verify fixed release trust policy',
             'Acquire pinned Kubo from the exact official asset', 'Run source tests',
             'Build deterministic Linux package', 'Archive and describe candidate',
             'Verify archived bootstrap and original metadata',
             'Upload candidate without publishing a Release', 'Attest candidate archive',
             'Attest candidate build description']
    jobs = {'total_count': 1, 'jobs': [{'id': c.JOB, 'status': 'completed',
             'conclusion': 'success', 'steps': [{'name': n, 'conclusion': 'success'} for n in names]}]}
    artifact = dict(id=c.ARTIFACT, name=f'tden-node-candidate-{c.RUN}', size_in_bytes=c.ZIP_BYTES,
                    digest='sha256:' + c.ZIP_SHA, expired=False,
                    workflow_run=dict(id=c.RUN, head_sha=c.BUILD, head_branch=c.BUILD_BRANCH,
                                      repository_id=c.REPO_ID, head_repository_id=c.REPO_ID))
    return run, {'id': 339139915, 'path': c.WORKFLOW}, jobs, artifact


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_exact_origin(self):
        c.check_origin(*origin())

    def test_origin_mutations(self):
        cases = [('run_attempt', 2), ('head_sha', '0' * 40), ('head_branch', 'main'),
                 ('path', 'other'), ('conclusion', 'failure'), ('event', 'push')]
        for key, value in cases:
            with self.subTest(key=key):
                data = list(origin())
                data[0][key] = value
                with self.assertRaises(ValueError):
                    c.check_origin(*data)

    def test_artifact_mutations(self):
        for key, value in [('expired', True), ('size_in_bytes', 1), ('digest', 'sha256:' + '0' * 64), ('id', 1)]:
            with self.subTest(key=key):
                data = list(origin())
                data[3][key] = value
                with self.assertRaises(ValueError):
                    c.check_origin(*data)

    def test_missing_failed_duplicate_critical_step(self):
        for kind in ('missing', 'failed', 'duplicate'):
            data = list(origin())
            steps = data[2]['jobs'][0]['steps']
            if kind == 'missing':
                steps.pop()
            elif kind == 'failed':
                steps[0]['conclusion'] = 'skipped'
            else:
                steps.append(copy.deepcopy(steps[0]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                c.check_origin(*data)

    def test_source_pins_not_just_shape(self):
        data = {'version': c.VERSION, **c.SOURCE_PINS}
        c.check_sources(data)
        for key in c.SOURCE_PINS:
            changed = {**data, key: '0' * 40}
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.check_sources(changed)

    def test_headers_no_sensitive_projection(self):
        data = b'HTTP/2.0 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 3\r\nLocation: secret-canary\r\n\r\nabc'
        stream = io.BytesIO(data)
        result = c.read_headers(stream, 3)
        self.assertNotIn('secret-canary', json.dumps(result))
        self.assertEqual(stream.read(), b'abc')

    def test_header_rejections(self):
        for header in [b'HTTP/2.0 302 Found\nContent-Type: application/zip\n\n',
                       b'HTTP/1.1 200 OK\nContent-Type: text/html\n\n',
                       b'HTTP/2.0 200 OK\nContent-Type: application/zip\nContent-Length: 4\n\n',
                       b'HTTP/2.0 200 OK\nContent-Type: application/zip\nContent-Type: application/zip\n\n',
                       b'X' * 65537, b'']:
            with self.subTest(length=len(header)), self.assertRaises(ValueError):
                c.read_headers(io.BytesIO(header), 3)

    def test_exact_copy_short_and_long(self):
        self.assertEqual(c.copy_exact(io.BytesIO(b'abc'), io.BytesIO(), 3), digest(b'abc'))
        for body in (b'ab', b'abcd'):
            with self.assertRaises(ValueError):
                c.copy_exact(io.BytesIO(body), io.BytesIO(), 3)

    def test_same_runtime_identity_and_replacement(self):
        path = self.root / 'data'
        with path.open('x+b') as stream:
            stream.write(b'one')
            stream.flush()
            expected = c.bind_file(stream, path)
            c.bind_file(stream, path, expected)
            stream.write(b'two')
            stream.flush()
            with self.assertRaises(ValueError):
                c.bind_file(stream, path, expected)

    def test_symlink_identity_rejected(self):
        path, link = self.root / 'file', self.root / 'link'
        path.write_bytes(b'one')
        try:
            link.symlink_to(path)
        except OSError:
            if os.name == 'nt':
                self.skipTest('Windows symlink privilege unavailable')
            raise
        with link.open('rb') as stream, self.assertRaises(ValueError):
            c.bind_file(stream, link)

    def test_extract_exact_three(self):
        tar, desc = b'synthetic archive', b'{}'
        records, bindings = c.extract(io.BytesIO(zip_body()), self.root / 'out', len(tar), digest(tar), digest(desc))
        self.assertEqual(set(records), c.FILES)
        self.assertEqual(set(bindings), c.FILES)

    def test_bad_member_set(self):
        for names in ([c.ARCHIVE, 'candidate-build.json', '../escape'], [c.ARCHIVE] * 3):
            with self.subTest(names=names), self.assertRaises(ValueError):
                with zipfile.ZipFile(io.BytesIO(zip_body(names=names))) as z:
                    c.check_directory(z.infolist(), 17)

    def test_zip_types_encryption_ratio_and_sizes(self):
        with zipfile.ZipFile(io.BytesIO(zip_body())) as z:
            original = z.infolist()
        for field, value in [('external_attr', (stat.S_IFLNK | 0o777) << 16),
                             ('flag_bits', 1), ('compress_type', zipfile.ZIP_BZIP2),
                             ('file_size', 999999999), ('compress_size', 0)]:
            entries = copy.deepcopy(original)
            entries[0].file_size = 101 if field == 'compress_size' else entries[0].file_size
            setattr(entries[0], field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.check_directory(entries, 101 if field == 'compress_size' else 17)

    def test_extract_wrong_digest_and_sidecar(self):
        for number, (body, tar_sha, description_sha) in enumerate([
                (zip_body(), '0' * 64, digest(b'{}')),
                (zip_body(), digest(b'synthetic archive'), '0' * 64),
                (zip_body(sidecar=b'bad'), digest(b'synthetic archive'), digest(b'{}'))]):
            with self.subTest(number=number), self.assertRaises(ValueError):
                c.extract(io.BytesIO(body), self.root / str(number), 17, tar_sha, description_sha)

    def test_existing_output_not_overwritten(self):
        out = self.root / 'out'
        out.mkdir()
        (out / 'keep').write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            c.extract(io.BytesIO(zip_body()), out, 17, digest(b'synthetic archive'), digest(b'{}'))
        self.assertEqual((out / 'keep').read_bytes(), b'original')

    def test_corrupt_zip_crc_rejected(self):
        body = zip_body()
        body = body.replace(b'synthetic archive', b'synthetic archivX', 1)
        with self.assertRaises(zipfile.BadZipFile):
            c.extract(io.BytesIO(body), self.root / 'out', 17, digest(b'synthetic archive'), digest(b'{}'))

    def test_gh_flags_exact(self):
        with patch.object(c, 'gh_json', return_value=[]) as gh:
            c.verify_attestation(Path('synthetic'))
        args = gh.call_args.args[0]
        for key, value in [('--repo', c.REPO), ('--signer-digest', c.BUILD),
                           ('--source-digest', c.BUILD), ('--source-ref', 'refs/heads/' + c.BUILD_BRANCH),
                           ('--signer-workflow', c.REPO + '/' + c.WORKFLOW)]:
            self.assertEqual(args[args.index(key) + 1], value)
        self.assertIn('--deny-self-hosted-runners', args)

    def test_cli_sanitizes_debug_environment(self):
        with patch.dict(os.environ, {'GH_DEBUG': 'api', 'GH_HTTP_UNIX_SOCKET': 'bad'}):
            env = c.cli_env()
        self.assertNotIn('GH_DEBUG', env)
        self.assertNotIn('GH_HTTP_UNIX_SOCKET', env)
        self.assertEqual(env['GH_PROMPT_DISABLED'], '1')

    def test_json_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            c.decode(b'{"x":1,"x":2}')

    def test_failed_policy_redacts_error_and_never_accepts(self):
        receipts = self.root / 'receipts'
        receipts.mkdir()
        output = io.StringIO()
        with patch.object(c, 'load_policy', side_effect=ValueError('secret-canary')), context_stdout(output):
            status = c.consume(self.root, self.root, receipts)
        self.assertEqual(status, 1)
        self.assertNotIn('secret-canary', output.getvalue())
        self.assertEqual(json.loads((receipts / 'result.json').read_text())['accepted'], False)
        self.assertEqual(json.loads((receipts / 'attempt.json').read_text())['artifact_launches_at_entry'], 0)
        self.assertFalse((receipts / 'transport_attempt.json').exists())
        self.assertFalse((receipts / 'transport_started.json').exists())

    def test_json_cli_errors_not_returned_as_success(self):
        child = Mock(stdout=io.BytesIO(b'[]'))
        child.wait.return_value = 1
        child.poll.return_value = 1
        with patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.object(c.subprocess, 'Popen', return_value=child):
            with self.assertRaises(subprocess.CalledProcessError):
                c.gh_json(['api', 'synthetic'])
        self.assertTrue(child.stdout.closed)

    def test_deadline_cleanup_mock_only(self):
        with patch.object(c.signal, 'SIGALRM', 14, create=True), \
             patch.object(c.signal, 'signal', return_value='previous') as handler, \
             patch.object(c.signal, 'alarm', create=True) as alarm:
            with c.deadline(600):
                pass
        self.assertEqual(alarm.call_args_list[-1].args, (0,))
        self.assertEqual(handler.call_args_list[-1].args, (14, 'previous'))

    def test_download_exact_stream_and_identity(self):
        body = b'zip-synthetic'
        child = Mock(stdout=io.BytesIO(b'HTTP/2.0 200 OK\nContent-Type: application/zip\n\n' + body))
        child.wait.return_value = 0
        child.poll.return_value = 0
        path = self.root / 'candidate.zip'
        with patch.object(c, 'ZIP_BYTES', len(body)), patch.object(c, 'ZIP_SHA', digest(body)), \
             patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.object(c.subprocess, 'Popen', return_value=child), path.open('x+b') as stream:
            binding, result = c.download(stream, path)
            self.assertEqual(binding, c.bind_file(stream, path))
        self.assertTrue(result['accepted'])
        self.assertEqual(path.read_bytes(), body)
        child.kill.assert_not_called()
        self.assertTrue(child.stdout.closed)

    def test_download_rejects_digest_and_child_failure(self):
        for label, returncode, expected_sha in [('digest', 0, '0' * 64), ('exit', 1, digest(b'abc'))]:
            child = Mock(stdout=io.BytesIO(b'HTTP/2.0 200 OK\nContent-Type: application/zip\n\nabc'))
            child.wait.return_value = returncode
            child.poll.return_value = returncode
            with patch.object(c, 'ZIP_BYTES', 3), patch.object(c, 'ZIP_SHA', expected_sha), \
                 patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
                 patch.object(c.subprocess, 'Popen', return_value=child), \
                 (self.root / label).open('x+b') as stream, self.assertRaises(ValueError):
                c.download(stream, self.root / label)
            self.assertTrue(child.stdout.closed)

    def test_download_size_failure_kills_and_reaps_child(self):
        child = Mock(stdout=io.BytesIO(b'HTTP/2.0 200 OK\nContent-Type: application/zip\n\nlong'))
        child.poll.return_value = None
        child.wait.return_value = -9
        path = self.root / 'candidate.zip'
        with patch.object(c, 'ZIP_BYTES', 3), \
             patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.object(c.subprocess, 'Popen', return_value=child), \
             path.open('x+b') as stream, self.assertRaises(ValueError):
            c.download(stream, path)
        child.kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=15)
        self.assertTrue(child.stdout.closed)

    def test_synthetic_full_consume_requires_both_receipts_and_original_policy(self):
        receipts = self.root / 'receipts'
        receipts.mkdir()
        tar = b'synthetic archive'
        desc = json.dumps({'version': c.VERSION, **c.SOURCE_PINS}).encode()
        blob = zip_body(tar=tar, description=desc)
        fixed = Mock()
        fixed.needs_runtime.return_value = True
        def fake_download(stream, path, on_started=None):
            if on_started is not None:
                on_started()
            stream.write(blob)
            stream.flush()
            return c.bind_file(stream, path), {'accepted': True, 'synthetic': True}
        original_extract = c.extract
        def synthetic_extract(stream, path):
            return original_extract(stream, path, len(tar), digest(tar), digest(desc))
        with patch.object(c, 'load_policy', return_value=fixed), \
             patch.object(c, 'api', side_effect=origin()), \
             patch.object(c, 'download', side_effect=fake_download), \
             patch.object(c, 'extract', side_effect=synthetic_extract), \
             patch.object(c, 'verify_attestation', return_value=[{'synthetic': True}]) as attestation, \
             context_stdout(io.StringIO()):
            status = c.consume(self.root, self.root, receipts)
        self.assertEqual(status, 0)
        self.assertEqual([x.args[0].name for x in attestation.call_args_list], [c.ARCHIVE, 'candidate-build.json'])
        fixed.verify.assert_called_once()
        self.assertEqual(fixed.verify.call_args.kwargs, {'repository': c.REPO, 'expected_sha256': c.TAR_SHA})
        self.assertTrue(json.loads((receipts / 'result.json').read_text())['accepted'])
        self.assertEqual(json.loads((receipts / 'transport_started.json').read_text())['download_attempts'], 1)

    def test_json_cap_terminates_before_unbounded_read(self):
        child = Mock(stdout=io.BytesIO(b'x' * 100))
        child.poll.return_value = None
        child.wait.return_value = -9
        with patch.object(c, 'LIMIT', 4), \
             patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.object(c.subprocess, 'Popen', return_value=child), self.assertRaises(ValueError):
            c.gh_json(['api', 'synthetic'])
        child.kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=15)
        self.assertTrue(child.stdout.closed)

    def test_json_bounded_success(self):
        child = Mock(stdout=io.BytesIO(b'{"synthetic":true}'))
        child.poll.return_value = 0
        child.wait.return_value = 0
        with patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.object(c.subprocess, 'Popen', return_value=child):
            self.assertEqual(c.gh_json(['api', 'synthetic']), {'synthetic': True})
        child.kill.assert_not_called()

    def test_same_size_path_replacement_rejected(self):
        path, replacement = self.root / 'file', self.root / 'replacement'
        path.write_bytes(b'abc')
        replacement.write_bytes(b'abc')
        with path.open('rb') as stream:
            expected = c.bind_file(stream, path)
            try:
                os.replace(replacement, path)
            except PermissionError:
                if os.name == 'nt':
                    self.skipTest('Windows open-file replacement unavailable')
                raise
            with self.assertRaises(ValueError):
                c.bind_file(stream, path, expected)

    def test_late_verification_rejections_never_accept(self):
        for failure in ('archive-attestation', 'description-attestation', 'original-policy'):
            with self.subTest(failure=failure):
                root = self.root / failure
                root.mkdir()
                receipts = root / 'receipts'
                receipts.mkdir()
                tar = b'synthetic archive'
                desc = json.dumps({'version': c.VERSION, **c.SOURCE_PINS}).encode()
                blob = zip_body(tar=tar, description=desc)
                fixed = Mock()
                fixed.needs_runtime.return_value = True
                if failure == 'original-policy':
                    fixed.verify.side_effect = ValueError('secret-canary')
                def fake_download(stream, path, on_started=None):
                    on_started()
                    stream.write(blob)
                    stream.flush()
                    return c.bind_file(stream, path), {'accepted': True}
                original_extract = c.extract
                def synthetic_extract(stream, path):
                    return original_extract(stream, path, len(tar), digest(tar), digest(desc))
                effects = ([ValueError('secret-canary')] if failure == 'archive-attestation' else
                           [[], ValueError('secret-canary')] if failure == 'description-attestation' else [[], []])
                output = io.StringIO()
                with patch.object(c, 'load_policy', return_value=fixed), \
                     patch.object(c, 'api', side_effect=origin()), \
                     patch.object(c, 'download', side_effect=fake_download), \
                     patch.object(c, 'extract', side_effect=synthetic_extract), \
                     patch.object(c, 'verify_attestation', side_effect=effects), context_stdout(output):
                    status = c.consume(root, root, receipts)
                self.assertEqual(status, 1)
                self.assertNotIn('secret-canary', output.getvalue())
                result = json.loads((receipts / 'result.json').read_text())
                self.assertFalse(result['accepted'])
                self.assertEqual(result['last_phase'], failure)


from contextlib import redirect_stdout as context_stdout

if __name__ == '__main__':
    temp = Path(os.environ.get('TDEN_SYNTHETIC_TEMP', str(HERE / 'consumer-test-temp')))
    temp.mkdir(exist_ok=False)
    tempfile.tempdir = str(temp)
    with patch.object(socket, 'socket', side_effect=AssertionError('offline socket forbidden')), \
         patch.object(socket, 'getaddrinfo', side_effect=AssertionError('offline DNS forbidden')), \
         patch.object(c.subprocess, 'Popen', side_effect=AssertionError('unmocked child forbidden')):
        unittest.main(verbosity=2)
