"""Upload verified original bytes to one pre-created TEST draft; never publish it."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import quote

DRAFT_ID = 438398767
DRAFT_HTML_URL = "https://github.com/sunbird84/tden-node-releases/releases/tag/untagged-d379c782f4f1bd847441"
TAG = 'node-0-12-0-test-20261108-265-run-42493275344-9e708c705c367ee994b8759fb0689ba7b0ce52ae424d4a59b7753c77eef459b8'
BRANCH = 'codex/preview-upload-20261109-269'
LATEST_ID = 396005201
CONSUMER_SHA = 'd8bd0cbbcf68751b34cd37738bbf1f48c4dab4f824531b50335587b592d3eaf5'


def require(value):
    if not value:
        raise ValueError('preview-contract')


def load_consumer():
    path = Path(__file__).with_name('consume_candidate_268.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == CONSUMER_SHA)
    spec = importlib.util.spec_from_file_location('fixed_consumer268', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_projection(data):
    return {key: data.get(key) for key in ('id', 'tag_name', 'target_commitish', 'draft',
            'prerelease', 'published_at', 'upload_url', 'html_url')}


def asset_projection(data):
    return {key: data.get(key) for key in ('id', 'name', 'state', 'size', 'digest', 'browser_download_url')}


def validate_release(data, c):
    require(type(DRAFT_ID) is int and DRAFT_ID > 0 and DRAFT_ID != 438095756)
    require(data.get('id') == DRAFT_ID and data.get('tag_name') == TAG
            and data.get('target_commitish') == c.BUILD and data.get('draft') is True
            and data.get('prerelease') is True and data.get('published_at') is None)
    require(data.get('upload_url') == f'https://uploads.github.com/repos/{c.REPO}/releases/{DRAFT_ID}/assets{{?name,label}}')
    require(DRAFT_HTML_URL.startswith(f'https://github.com/{c.REPO}/releases/tag/')
            and data.get('html_url') == DRAFT_HTML_URL)


def get_release(c):
    value = c.api(f'repos/{c.REPO}/releases/{DRAFT_ID}',
                  '{id,tag_name,target_commitish,draft,prerelease,published_at,upload_url,html_url,'
                  'assets:[.assets[]|{id,name,state,size,digest,browser_download_url}]}')
    validate_release(value, c)
    return value


def check_asset(asset, name, record, c):
    require(type(asset.get('id')) is int and asset['id'] > 0
            and asset.get('name') == name and asset.get('state') == 'uploaded'
            and asset.get('size') == record['bytes']
            and asset.get('digest') == 'sha256:' + record['sha256'])
    allowed_tags = {TAG, DRAFT_HTML_URL.rsplit('/', 1)[-1]}
    require(asset.get('browser_download_url') in {
        f'https://github.com/{c.REPO}/releases/download/{tag}/{name}' for tag in allowed_tags})


def validate_assets(assets, records, c):
    require(isinstance(assets, list) and len(assets) == len(records)
            and {x.get('name') for x in assets} == set(records)
            and len({x.get('id') for x in assets}) == len(assets))
    for asset in assets:
        check_asset(asset, asset['name'], records[asset['name']], c)


class CountedReader:
    def __init__(self, source, limit):
        self.source, self.limit, self.count = source, limit, 0
        self.digest = hashlib.sha256()

    def read(self, size):
        data = self.source.read(size)
        self.count += len(data)
        require(self.count <= self.limit)
        self.digest.update(data)
        return data


def upload_one(c, path, record, receipts, number):
    require(path.name in c.FILES and type(record['bytes']) is int and 0 < record['bytes'] <= c.TAR_BYTES)
    name = path.name
    endpoint = f'/repos/{c.REPO}/releases/{DRAFT_ID}/assets?name=' + quote(name, safe='')
    receipt_prefix = f'upload-{number}'
    c.save(receipts / (receipt_prefix + '-attempt.json'), {
        'release_id': DRAFT_ID, 'name': name, 'bytes': record['bytes'],
        'sha256': record['sha256'], 'method': 'POST', 'host': 'uploads.github.com',
        'request_started': False, 'retry_allowed': False})
    connection = None
    try:
        with path.open('rb') as source:
            before = c.bind_file(source, path)
            require(before[2] == record['bytes'])
            reader = CountedReader(source, record['bytes'])
            connection = http.client.HTTPSConnection('uploads.github.com', timeout=30,
                                                      context=ssl.create_default_context())
            headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'TDEN-preview-269',
                       'X-GitHub-Api-Version': '2026-03-10',
                       'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                       'Content-Type': 'application/octet-stream', 'Content-Length': str(record['bytes'])}
            c.save(receipts / (receipt_prefix + '-request-intent.json'), {
                'release_id': DRAFT_ID, 'name': name, 'effect': 'unknown-until-response', 'retry_allowed': False})
            with c.deadline(600):
                connection.request('POST', endpoint, body=reader, headers=headers)
                response = connection.getresponse()
                status = response.status
                body = bytearray()
                while chunk := response.read(min(65536, 1048576 - len(body) + 1)):
                    require(len(body) + len(chunk) <= 1048576)
                    body.extend(chunk)
            c.save(receipts / (receipt_prefix + '-response.json'), {
                'http_status': status, 'sent_bytes': reader.count,
                'sent_sha256': reader.digest.hexdigest(), 'redirect_followed': False})
            require(status == 201 and reader.count == record['bytes']
                    and reader.digest.hexdigest() == record['sha256'])
            c.bind_file(source, path, before)
            asset = asset_projection(c.decode(body))
            check_asset(asset, name, record, c)
            c.save(receipts / (receipt_prefix + '-accepted.json'), asset)
            return asset
    finally:
        if connection is not None:
            connection.close()


def upload_transaction(c, candidate, receipts):
    phase = 'release-before'
    try:
        initial = get_release(c)
        require(initial.get('assets') == [])
        c.save(receipts / 'draft-before.json', initial)
        result = c.decode((receipts / 'result.json').read_bytes())
        require(result.get('accepted') is True and result.get('source_run') == c.RUN
                and result.get('crypto_provenance_verified') is True
                and result.get('original_policy_verified') is True)
        records = c.decode((receipts / 'extraction.json').read_bytes())
        require(set(records) == c.FILES)
        for name in c.FILES:
            require((candidate / name).is_file() and not (candidate / name).is_symlink())
        uploaded = []
        for number, name in enumerate((c.ARCHIVE, c.ARCHIVE + '.sha256', 'candidate-build.json'), 1):
            phase = f'upload-{number}'
            before = get_release(c)
            validate_assets(before['assets'], {x['name']: records[x['name']] for x in uploaded}, c)
            uploaded.append(upload_one(c, candidate / name, records[name], receipts, number))
        phase = 'post-upload-assets'
        final = get_release(c)
        validate_assets(final['assets'], records, c)
        require({x['id'] for x in final['assets']} == {x['id'] for x in uploaded})
        policy = c.load_policy(Path(__file__).resolve().parent.parent)
        policy.verify_release_assets(final['assets'], candidate)
        c.save(receipts / 'draft-after.json', final)
        accepted = {'uploaded_and_verified': True, 'release_id': DRAFT_ID, 'tag': TAG,
                    'target_commit': c.BUILD, 'source_run': c.RUN, 'source_attempt': 1,
                    'draft': True, 'prerelease': True, 'published': False,
                    'assets': final['assets'], 'retry_allowed': False}
        c.save(receipts / 'upload-result.json', accepted)
        print(json.dumps(accepted, sort_keys=True))
        return 0
    except Exception:
        failure = {'uploaded_and_verified': False, 'last_phase': phase, 'release_id': DRAFT_ID,
                   'possible_partial_upload': True, 'retry_allowed': False, 'published': False}
        c.save(receipts / 'upload-result.json', failure)
        print(json.dumps(failure, sort_keys=True))
        return 1


def main():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == 'sunbird84/tden-node-releases'
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + BRANCH
            and os.environ.get('GITHUB_EVENT_NAME') == 'push'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1' and DRAFT_ID > 0)
    run = os.environ['GITHUB_RUN_ID']
    require(re.fullmatch(r'[1-9][0-9]*', run))
    c = load_consumer()
    checkout = Path(__file__).resolve().parent.parent
    root = Path(os.environ['RUNNER_TEMP']) / ('tden-preview-269-' + run + '-1')
    root.mkdir(mode=0o700)
    receipts = checkout / 'preview-receipts'
    receipts.mkdir(mode=0o700)
    initial = get_release(c)
    require(initial.get('assets') == [])
    c.save(receipts / 'pre-reception-draft.json', initial)
    if c.consume(checkout, root, receipts) != 0:
        return 1
    return upload_transaction(c, root / 'candidate', receipts)


if __name__ == '__main__':
    try:
        code = main()
    except Exception:
        print('Preview worker stopped; check exact attempt and effects. No retry or publication.', file=sys.stderr)
        code = 1
    raise SystemExit(code)
