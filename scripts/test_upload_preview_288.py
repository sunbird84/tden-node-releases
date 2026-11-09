"""Synthetic offline tests; no repository mutation or real candidate is accessed."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('uploader288', HERE / 'upload_preview_288.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
c = u.load_consumer()


def asset(name, record, identifier=123):
    return dict(id=identifier, name=name, state='uploaded', size=record['bytes'],
                digest='sha256:' + record['sha256'],
                browser_download_url=f'https://github.com/{c.REPO}/releases/download/{u.TAG}/{name}')


def release(assets=None):
    return dict(id=u.DRAFT_ID, tag_name=u.TAG, target_commitish=c.BUILD, draft=True,
                prerelease=True, published_at=None, html_url=u.DRAFT_HTML_URL,
                upload_url=f'https://uploads.github.com/repos/{c.REPO}/releases/{u.DRAFT_ID}/assets{{?name,label}}',
                assets=assets or [])


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.patches = [patch.object(u, 'DRAFT_ID', 987654),
                        patch.object(u, 'DRAFT_HTML_URL', f'https://github.com/{c.REPO}/releases/tag/untagged-synthetic')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.candidate, self.receipts = self.root / 'candidate', self.root / 'receipts'
        self.candidate.mkdir()
        self.receipts.mkdir()
        self.records = {}
        for name in c.FILES:
            data = ('synthetic:' + name).encode()
            (self.candidate / name).write_bytes(data)
            self.records[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        c.save(self.receipts / 'result.json', dict(accepted=True, source_run=c.RUN,
               crypto_provenance_verified=True, original_policy_verified=True))
        c.save(self.receipts / 'extraction.json', self.records)

    def test_unpinned_id_fails(self):
        with patch.object(u, 'DRAFT_ID', 0), self.assertRaises(ValueError):
            u.validate_release(release(), c)

    def test_draft_identity_mutations(self):
        u.validate_release(release(), c)
        for key, value in [('id', 438095756), ('tag_name', 'stable'), ('draft', False),
                           ('prerelease', False), ('target_commitish', 'main'),
                           ('published_at', 'now'), ('upload_url', 'https://evil.invalid'),
                           ('html_url', 'https://evil.invalid')]:
            data = {**release(), key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                u.validate_release(data, c)

    def test_asset_digests_sizes_states_and_url(self):
        record = self.records[c.ARCHIVE]
        good = asset(c.ARCHIVE, record)
        u.check_asset(good, c.ARCHIVE, record, c)
        for key, value in [('id', True), ('state', 'starter'), ('size', 1),
                           ('digest', 'sha256:' + '0' * 64), ('name', 'wrong'),
                           ('browser_download_url', 'https://evil.invalid/file')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                u.check_asset({**good, key: value}, c.ARCHIVE, record, c)

    def test_exact_asset_set_and_unique_ids(self):
        assets = [asset(name, record, i + 1) for i, (name, record) in enumerate(self.records.items())]
        u.validate_assets(assets, self.records, c)
        for changed in (assets[:-1], assets + assets[:1], [assets[0], assets[1], {**assets[2], 'id': assets[0]['id']}]):
            with self.assertRaises(ValueError):
                u.validate_assets(changed, self.records, c)

    def test_counted_reader_bounds(self):
        reader = u.CountedReader(io.BytesIO(b'abc'), 3)
        self.assertEqual(reader.read(2) + reader.read(2), b'abc')
        self.assertEqual(reader.digest.hexdigest(), hashlib.sha256(b'abc').hexdigest())
        with self.assertRaises(ValueError):
            u.CountedReader(io.BytesIO(b'abcd'), 3).read(4)

    def connection(self, response_body, status=201, error=None):
        conn = Mock()
        captured = {}
        def request(method, endpoint, body, headers):
            captured.update(method=method, endpoint=endpoint, headers=headers)
            if error:
                raise error
            while body.read(7):
                pass
        conn.request.side_effect = request
        response = Mock(status=status)
        response.read.side_effect = io.BytesIO(response_body).read
        conn.getresponse.return_value = response
        return conn, captured

    def run_upload(self, conn):
        with patch.object(u.http.client, 'HTTPSConnection', return_value=conn) as connect, \
             patch.object(c, 'deadline', return_value=contextlib.nullcontext()), \
             patch.dict(os.environ, {'GH_TOKEN': 'synthetic-not-a-credential'}):
            result = u.upload_one(c, self.candidate / c.ARCHIVE, self.records[c.ARCHIVE], self.receipts, 1)
        self.assertEqual(connect.call_args.args, ('uploads.github.com',))
        return result

    def test_exact_upload_no_redirect_and_no_secret_receipt(self):
        expected = asset(c.ARCHIVE, self.records[c.ARCHIVE])
        conn, captured = self.connection(json.dumps(expected).encode())
        self.assertEqual(self.run_upload(conn), expected)
        self.assertEqual(captured['method'], 'POST')
        self.assertIn(f'/releases/{u.DRAFT_ID}/assets?name=', captured['endpoint'])
        self.assertEqual(captured['headers']['Content-Length'], str(self.records[c.ARCHIVE]['bytes']))
        conn.close.assert_called_once()
        for file in self.receipts.iterdir():
            self.assertNotIn('synthetic-not-a-credential', file.read_text())

    def test_redirect_rejected_not_followed(self):
        conn, _ = self.connection(b'{}', 302)
        with self.assertRaises(ValueError):
            self.run_upload(conn)
        conn.request.assert_called_once()
        conn.close.assert_called_once()

    def test_server_failure_no_retry(self):
        conn, _ = self.connection(b'{}', 502)
        with self.assertRaises(ValueError):
            self.run_upload(conn)
        conn.request.assert_called_once()
        self.assertFalse((self.receipts / 'upload-1-accepted.json').exists())

    def test_response_size_cap(self):
        conn, _ = self.connection(b'x' * (1048576 + 1))
        with self.assertRaises(ValueError):
            self.run_upload(conn)
        conn.close.assert_called_once()

    def test_timeout_unknown_effect_no_retry(self):
        conn, _ = self.connection(b'', error=TimeoutError('secret-canary'))
        with self.assertRaises(TimeoutError):
            self.run_upload(conn)
        conn.request.assert_called_once()
        conn.close.assert_called_once()
        self.assertTrue((self.receipts / 'upload-1-request-intent.json').exists())
        self.assertFalse((self.receipts / 'upload-1-response.json').exists())

    def test_existing_asset_stops_before_upload(self):
        initial = release([asset(c.ARCHIVE, self.records[c.ARCHIVE])])
        with patch.object(u, 'get_release', return_value=initial), patch.object(u, 'upload_one') as upload, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(u.upload_transaction(c, self.candidate, self.receipts), 1)
        upload.assert_not_called()

    def test_failed_upload_stops_transaction_without_publication(self):
        with patch.object(u, 'get_release', return_value=release()), \
             patch.object(u, 'upload_one', side_effect=ValueError('secret-canary')) as upload, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(u.upload_transaction(c, self.candidate, self.receipts), 1)
        upload.assert_called_once()
        self.assertNotIn('secret-canary', output.getvalue())
        result = json.loads((self.receipts / 'upload-result.json').read_text())
        self.assertFalse(result['published'])
        self.assertTrue(result['possible_partial_upload'])

    def test_three_uploads_and_original_asset_policy_required(self):
        names = [c.ARCHIVE, c.ARCHIVE + '.sha256', 'candidate-build.json']
        assets = [asset(n, self.records[n], i + 1) for i, n in enumerate(names)]
        states = [release(), release(), release(assets[:1]), release(assets[:2]), release(assets)]
        policy = Mock()
        with patch.object(u, 'get_release', side_effect=states), \
             patch.object(u, 'upload_one', side_effect=assets) as upload, \
             patch.object(c, 'load_policy', return_value=policy), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(u.upload_transaction(c, self.candidate, self.receipts), 0)
        self.assertEqual(upload.call_count, 3)
        policy.verify_release_assets.assert_called_once_with(assets, self.candidate)
        result = json.loads((self.receipts / 'upload-result.json').read_text())
        self.assertTrue(result['draft'])
        self.assertFalse(result['published'])

    def test_unaccepted_candidate_never_uploads(self):
        (self.receipts / 'result.json').write_text('{"accepted":false}')
        with patch.object(u, 'get_release', return_value=release()), patch.object(u, 'upload_one') as upload, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(u.upload_transaction(c, self.candidate, self.receipts), 1)
        upload.assert_not_called()

    def test_server_digest_mismatch_never_accepts(self):
        data = asset(c.ARCHIVE, self.records[c.ARCHIVE])
        data['digest'] = 'sha256:' + '0' * 64
        conn, _ = self.connection(json.dumps(data).encode())
        with self.assertRaises(ValueError):
            self.run_upload(conn)
        conn.request.assert_called_once()
        self.assertTrue((self.receipts / 'upload-1-response.json').exists())
        self.assertFalse((self.receipts / 'upload-1-accepted.json').exists())

    def test_same_size_source_mutation_never_accepts_sent_bytes(self):
        path = self.candidate / c.ARCHIVE
        path.write_bytes(b'x' * self.records[c.ARCHIVE]['bytes'])
        conn, _ = self.connection(json.dumps(asset(c.ARCHIVE, self.records[c.ARCHIVE])).encode())
        with self.assertRaises(ValueError):
            self.run_upload(conn)
        conn.request.assert_called_once()
        self.assertFalse((self.receipts / 'upload-1-accepted.json').exists())

    def test_original_policy_rejection_preserves_unpublished_state(self):
        names = [c.ARCHIVE, c.ARCHIVE + '.sha256', 'candidate-build.json']
        assets = [asset(n, self.records[n], i + 1) for i, n in enumerate(names)]
        policy = Mock()
        policy.verify_release_assets.side_effect = ValueError('secret-canary')
        with patch.object(u, 'get_release', side_effect=[release(), release(), release(assets[:1]), release(assets[:2]), release(assets)]), \
             patch.object(u, 'upload_one', side_effect=assets), patch.object(c, 'load_policy', return_value=policy), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(u.upload_transaction(c, self.candidate, self.receipts), 1)
        self.assertNotIn('secret-canary', output.getvalue())
        result = json.loads((self.receipts / 'upload-result.json').read_text())
        self.assertFalse(result['uploaded_and_verified'])
        self.assertFalse(result['published'])


if __name__ == '__main__':
    temp = Path(os.environ.get('TDEN_SYNTHETIC_TEMP', str(HERE / 'upload-test-temp')))
    temp.mkdir(exist_ok=False)
    tempfile.tempdir = str(temp)
    with patch.object(socket, 'socket', side_effect=AssertionError('offline network forbidden')), \
         patch.object(socket, 'getaddrinfo', side_effect=AssertionError('offline DNS forbidden')), \
         patch.object(c.subprocess, 'Popen', side_effect=AssertionError('unmocked child forbidden')):
        unittest.main(verbosity=2)
