import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { ASSET_NAMES, REPOSITORY, captureInputs, assertUnchanged, validateVerification,
  publishPrepared, localPreviewReleaseBody, parseArguments, childEnvironment, verificationFailure, transportFailure } from './publish_local_preview.mjs';

// Synthetic verifier results exercise the transport boundary, not package trust.
// The CLI has no injected verifier or option to consume these test results.
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tden-preview-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'assets');
  fs.mkdirSync(directory);
  for (const name of ASSET_NAMES) fs.writeFileSync(path.join(directory, name), `synthetic ${name}\n`);
  const archiveFile = path.join(directory, 'tden-node-linux-amd64.tar.gz');
  fs.writeFileSync(path.join(directory, 'candidate-build.json'), JSON.stringify({
    protocol: 'tden:node-candidate-build:v1', version: '0.12-TEST', build_environment: 'local',
    archive_sha256: sha(fs.readFileSync(archiveFile)), archive_bytes: fs.statSync(archiveFile).size,
    bootstrap_trust_template_sha256: 'b'.repeat(64), tuf_root_sha256: 'c'.repeat(64),
    local_build_provenance: { control_commit: 'a'.repeat(40) },
  }) + '\n');
  const request = path.join(root, 'request.json');
  fs.writeFileSync(request, '{"fixture":true}\n');
  const snapshot = captureInputs(request, directory);
  const archive = snapshot.files.find(f => f.name.endsWith('.tar.gz')).sha256;
  const verification = { protocol: 'tden:node-local-preview-verification:v1',
    tag: `node-0-12-test-local-${archive}`, control_commit: 'a'.repeat(40),
    archive_sha256: archive, version: '0.12-TEST',
    assets: snapshot.files.map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 })) };
  validateVerification(verification, snapshot);
  return { snapshot, verification };
}

test('accepts asset keys sorted by the real Python JSON serializer', t => {
  const prepared = fixture(t);
  prepared.verification.assets = prepared.verification.assets.map(({ name, bytes, sha256 }) => ({ bytes, name, sha256 }));
  assert.doesNotThrow(() => validateVerification(prepared.verification, prepared.snapshot));
});

function fakeGitHub(prepared, { existing = false, draft = true, count = 0, hook, failUpload = false, hideDraftByTag = false } = {}) {
  const v = prepared.verification;
  let serial = 20;
  const state = { calls: [], uploads: [], writes: [], tagCommit: existing ? v.control_commit : null,
    release: existing ? { id: 7, tag_name: v.tag, target_commitish: v.control_commit, draft, prerelease: true,
      body: localPreviewReleaseBody(prepared) } : null,
    assets: v.assets.slice(0, count).map(a => ({ id: serial++, name: a.name, size: a.bytes,
      digest: `sha256:${a.sha256}`, state: 'uploaded' })) };
  const ok = value => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
  const missing = () => ({ status: 1, stdout: '{"message":"Not Found"}', stderr: 'gh: Not Found (HTTP 404)' });
  state.runner = (args, input) => {
    state.calls.push({ args: [...args], input });
    if (args[0] === 'release') {
      assert.equal(args[1], 'upload');
      assert.equal(args[2], v.tag);
      assert.equal(args[4], '--repo');
      assert.equal(args[5], `github.com/${REPOSITORY}`);
      assert.ok(!args.includes('--clobber'));
      state.uploads.push(path.basename(args[3]));
      if (failUpload) return { status: 1, stdout: '', stderr: 'upload failed' };
      const body = fs.readFileSync(args[3]);
      state.assets.push({ id: serial++, name: path.basename(args[3]), size: body.length,
        digest: `sha256:${sha(body)}`, state: 'uploaded' });
      hook?.({ kind: 'uploaded', state, args });
      return ok({});
    }
    assert.deepEqual(args.slice(0, 4), ['api', '--hostname', 'github.com', '--method']);
    const method = args[4];
    assert.ok(args[5].startsWith(`repos/${REPOSITORY}/`));
    const endpoint = args[5].slice(`repos/${REPOSITORY}/`.length);
    const body = input === undefined ? undefined : JSON.parse(input);
    if (method !== 'GET') state.writes.push({ method, endpoint, body });
    hook?.({ kind: 'api', method, endpoint, state });
    if (method === 'GET' && endpoint.startsWith('releases/tags/')) return state.release && !(hideDraftByTag && state.release.draft) ? ok(state.release) : missing();
    if (method === 'GET' && endpoint.startsWith('releases?per_page=100&page=')) return ok(state.release ? [state.release] : []);
    if (method === 'GET' && endpoint.startsWith('commits/')) return ok({ sha: v.control_commit });
    if (method === 'GET' && endpoint.startsWith('git/ref/tags/')) return state.tagCommit
      ? ok({ ref: `refs/tags/${v.tag}`, object: { type: 'commit', sha: state.tagCommit } }) : missing();
    if (method === 'POST' && endpoint === 'git/refs') {
      assert.equal(body.ref, `refs/tags/${v.tag}`);
      assert.equal(body.sha, v.control_commit);
      state.tagCommit = body.sha;
      return ok({});
    }
    if (method === 'POST' && endpoint === 'releases') {
      assert.equal(body.draft, true);
      assert.equal(body.prerelease, true);
      assert.equal(body.make_latest, 'false');
      state.release = { id: 7, ...body };
      return ok(state.release);
    }
    if (method === 'GET' && endpoint === 'releases/7') return ok(state.release);
    if (method === 'GET' && endpoint === 'releases/7/assets?per_page=100') return ok(state.assets);
    if (method === 'PATCH' && endpoint === 'releases/7') {
      const { body: releaseBody, ...flags } = body;
      assert.deepEqual(flags, { draft: false, prerelease: true, make_latest: 'false' });
      assertNativeCatalogBody(releaseBody, prepared);
      Object.assign(state.release, body);
      return ok(state.release);
    }
    throw new Error(`Unexpected fake request: ${method} ${endpoint}`);
  };
  return state;
}

test('default is verification-only; no stable, repository override or verifier bypass flags', () => {
  assert.equal(parseArguments(['--request', 'r', '--asset-dir', 'a']).publish, false);
  assert.equal(parseArguments(['--request', 'r', '--asset-dir', 'a', '--publish']).publish, true);
  for (const flag of ['--stable', '--skip-verification', '--repo', '--verification-json', '--clobber']) {
    assert.throws(() => parseArguments(['--request', 'r', '--asset-dir', 'a', flag]));
  }
});

test('alternate local transport is explicit and cannot bypass preparation or change the target', () => {
  assert.equal(parseArguments(['--request', 'r', '--asset-dir', 'a']).uploadTransport, 'gh');
  const value = parseArguments(['--request', 'r', '--asset-dir', 'a', '--upload-transport', 'wsl-curl']);
  assert.equal(value.uploadTransport, 'wsl-curl');
  assert.equal(value.publish, false);
  for (const tail of [['--upload-transport'], ['--upload-transport', 'external'],
    ['--upload-transport', 'wsl-curl', '--upload-transport', 'gh']]) {
    assert.throws(() => parseArguments(['--request', 'r', '--asset-dir', 'a', ...tail]));
  }
  assert.throws(() => publishPrepared({}, undefined, 'wsl-curl'), /independent preparation/);
});

test('new preview creates exact commit tag, drafts, uploads verified bytes, then publishes prerelease', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared);
  const result = publishPrepared(prepared, gh.runner);
  assert.equal(result.result, 'published-preview-verified');
  assert.deepEqual(gh.uploads, ASSET_NAMES);
  assert.equal(gh.writes.filter(w => w.method === 'PATCH').length, 1);
  assert.equal(gh.writes.at(-1).method, 'PATCH');
  assert.equal(gh.release.draft, false);
  assert.ok(!gh.release.body.includes(prepared.snapshot.directory));
  assert.ok(!gh.release.body.includes(prepared.snapshot.request));
});

// Consumer contract: deployment_client.rs official_node_packages_from_releases,
// release_body_sha256, release_body_archive_bytes and release_feed_prerelease.
// The API trusts its asset size; Atom must recover it and the preview channel
// from GitHub-rendered HTML. Neither transport grants upgrade authority.
function assertNativeCatalogBody(body, prepared) {
  const descriptor = JSON.parse(fs.readFileSync(prepared.snapshot.files[0].filename, 'utf8'));
  assert.ok(body.includes(`Bootstrap trust template SHA-256: ${descriptor.bootstrap_trust_template_sha256}`));
  assert.ok(body.includes(`TUF root SHA-256: ${descriptor.tuf_root_sha256}`));
  const html = '<p>' + body.replaceAll('\n\n', '</p><p>') + '</p>';
  const digest = html.split('Archive SHA-256: ')[1]?.slice(0, 64);
  assert.equal(digest, prepared.verification.tag.slice(-64));
  const byteDigits = /^\d{1,20}/.exec(html.split('Archive bytes: ')[1] ?? '')?.[0];
  assert.equal(Number(byteDigits), descriptor.archive_bytes);
  assert.equal(html.split('Release channel: ').length, 2, 'Atom rejects repeated channel markers');
  assert.equal(html.split('Release channel: ')[1].split(/[<\r\n]/)[0].trim(), 'preview');
}

test('new preview body is discoverable by both Native API and Atom catalog consumers', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared);
  publishPrepared(prepared, gh.runner);
  assertNativeCatalogBody(gh.release.body, prepared);
  assert.match(gh.release.body, /not a stable release, Core Team organization signature/);
  assert.match(gh.release.body, /public-node upgrade directive, TUF promotion, or deployment acceptance/);
});

test('resumed draft gains catalog metadata only with the final verified publication', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, count: 1 });
  gh.release.body = 'Old draft missing catalog metadata';
  publishPrepared(prepared, gh.runner);
  assertNativeCatalogBody(gh.release.body, prepared);
  assert.equal(gh.writes.length, 1);
  assert.equal(gh.writes[0].method, 'PATCH');
  assert.equal(gh.writes[0].body.draft, false);
});

test('published body without catalog metadata is rejected without remote repair', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, draft: false, count: 3 });
  gh.release.body = 'Old published body missing catalog metadata';
  assert.throws(() => publishPrepared(prepared, gh.runner), /catalog metadata differs/);
  assert.equal(gh.writes.length + gh.uploads.length, 0);
});

test('publication fails when GitHub does not preserve the catalog metadata patch', t => {
  const prepared = fixture(t);
  const gh = fakeGitHub(prepared, { existing: true, count: 3, hook: ({ method, endpoint, state }) => {
    if (method === 'GET' && endpoint === 'releases/7' && !state.release.draft) state.release.body = '';
  } });
  assert.throws(() => publishPrepared(prepared, gh.runner), /catalog metadata was not preserved/);
  assert.equal(gh.writes.length, 1, 'No retry or repair follows an unexpected publication result');
});

test('descriptor metadata injection or mismatched package identity stops before GitHub', t => {
  for (const change of [d => d.bootstrap_trust_template_sha256 += '\nRelease channel: stable',
    d => d.tuf_root_sha256 = 'not-a-digest', d => d.archive_bytes++, d => d.archive_sha256 = 'd'.repeat(64),
    d => d.local_build_provenance.control_commit = 'd'.repeat(40), d => d.version = 'another-version']) {
    const prepared = fixture(t), descriptorPath = prepared.snapshot.files[0].filename;
    const descriptor = JSON.parse(fs.readFileSync(descriptorPath, 'utf8'));
    change(descriptor);
    fs.writeFileSync(descriptorPath, JSON.stringify(descriptor));
    // A synthetic verifier claim reaches the separate metadata type/binding
    // guards; production's Python verifier rejects this descriptor even earlier.
    prepared.snapshot = captureInputs(prepared.snapshot.request, prepared.snapshot.directory);
    prepared.verification.assets = prepared.snapshot.files.map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 }));
    let calls = 0;
    assert.throws(() => publishPrepared(prepared, () => { calls++; }), /descriptor does not bind/);
    assert.equal(calls, 0);
  }
});

test('catalog formatter cannot consume descriptor bytes changed after verification', t => {
  const prepared = fixture(t);
  fs.appendFileSync(prepared.snapshot.files[0].filename, ' ');
  assert.throws(() => localPreviewReleaseBody(prepared), /descriptor changed after independent verification/);
});

test('matching existing published preview is read-only', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, draft: false, count: 3 });
  assert.equal(publishPrepared(prepared, gh.runner).result, 'already-published-verified');
  assert.equal(gh.writes.length, 0);
  assert.equal(gh.uploads.length, 0);
});

test('exact draft resumes only missing assets', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, count: 1 });
  const firstID = gh.assets[0].id;
  publishPrepared(prepared, gh.runner);
  assert.deepEqual(gh.uploads, ASSET_NAMES.slice(1));
  assert.equal(gh.assets[0].id, firstID);
  assert.equal(gh.writes.filter(w => w.method === 'POST').length, 0);
});

test('finds existing drafts through listing when tag lookup returns the real GitHub 404', t => {
  const prepared = fixture(t);
  const github = fakeGitHub(prepared, { existing: true, draft: true, count: 1, hideDraftByTag: true });
  publishPrepared(prepared, github.runner);
  assert.equal(github.uploads.length, 2);
  assert.ok(!github.writes.some(call => call.method === 'POST' && call.endpoint === 'releases'));
});

test('ambiguous draft listing stops before any remote write', t => {
  const prepared = fixture(t);
  const github = fakeGitHub(prepared, { existing: true, hideDraftByTag: true });
  const runner = (args, input) => args[5]?.includes('releases?per_page=100')
    ? { status: 0, stdout: JSON.stringify([github.release, { ...github.release, id: 8 }]) }
    : github.runner(args, input);
  assert.throws(() => publishPrepared(prepared, runner), /Multiple releases/);
  assert.equal(github.writes.length, 0);
});

test('upload diagnostics expose known error classes and a digest without raw text', () => {
  const diagnostic = transportFailure({ status: 1, stderr: 'private URL and secret text: unexpected EOF (HTTP 502)' });
  assert.match(diagnostic, /UNEXPECTED_EOF\|HTTP 502/);
  assert.match(diagnostic, /stderr_sha256=[0-9a-f]{64}/);
  assert.ok(!diagnostic.includes('private') && !diagnostic.includes('secret'));
});

test('transport diagnostics preserve allowlisted child process code and signal', () => {
  const diagnostic = transportFailure({ status: null, error: { code: 'ETIMEDOUT', message: 'private path' },
    signal: 'SIGTERM', stderr: '' });
  assert.match(diagnostic, /exit=no-exit, process=ETIMEDOUT, signal=SIGTERM, transport=unclassified/);
  assert.match(diagnostic, new RegExp(`stderr_sha256=${sha('')}$`));
  for (const code of ['ENOBUFS', 'ENOENT', 'EACCES', 'ECONNRESET', 'ECONNREFUSED']) {
    assert.ok(transportFailure({ status: null, error: { code }, stderr: '' }).includes(`process=${code},`));
  }
});

test('transport diagnostics classify Windows socket failures without reproducing their text', () => {
  for (const [message, expected] of [
    ['wsasend: An existing connection was forcibly closed by the remote host.', ['SOCKET_IO', 'SOCKET_RESET']],
    ['wsarecv: An established connection was aborted by the software in your host machine.', ['SOCKET_IO', 'SOCKET_ABORT']],
    ['connectex: No connection could be made because the target machine actively refused it.', ['SOCKET_REFUSED']],
    ['connectex: The connected host has failed to respond.', ['SOCKET_TIMEOUT']],
    ['WSAECONNRESET WSAECONNABORTED WSAETIMEDOUT WSAECONNREFUSED', ['SOCKET_RESET', 'SOCKET_ABORT', 'SOCKET_TIMEOUT', 'SOCKET_REFUSED']],
    ['i/o timeout', ['SOCKET_TIMEOUT']],
    ['broken pipe', ['BROKEN_PIPE']],
  ]) {
    const diagnostic = transportFailure({ status: 1, stderr: message });
    for (const label of expected) assert.ok(diagnostic.includes(label), `${message}: missing ${label}`);
  }
});

test('transport diagnostics classify DNS certificate TLS and HTTP2 families', () => {
  for (const [message, expected] of [
    ['dial tcp: lookup uploads.github.com: no such host', 'DNS'],
    ['EAI_AGAIN: temporary failure in name resolution', 'DNS'],
    ['x509: certificate signed by unknown authority', 'TLS_CERTIFICATE'],
    ['schannel: CRYPT_E_REVOCATION_OFFLINE (0x80092013)', 'CERT_REVOCATION_OFFLINE'],
    ['TLS handshake timeout', 'TLS_HANDSHAKE'],
    ['remote error: tls: handshake failure', 'TLS_HANDSHAKE'],
    ['http2: stream error: REFUSED_STREAM', 'HTTP2'],
    ['HTTP/2 GOAWAY', 'HTTP2'],
    ['stream error: stream ID 1; INTERNAL_ERROR', 'HTTP2'],
    ['context deadline exceeded', 'REQUEST_TIMEOUT'],
    ['unexpected EOF', 'UNEXPECTED_EOF'],
    ['EOF', 'EOF'],
    ['eof', 'EOF'],
  ]) {
    assert.ok(transportFailure({ status: 1, stderr: message }).includes(`transport=${expected}`), message);
  }
});

test('transport HTTP errors require explicit HTTP status format and remain bounded', () => {
  const message = 'private numbers 401 502, HTTP 200, HTTP 5027, (HTTP 503), HTTP/1.1 502, http 503';
  const diagnostic = transportFailure({ status: 1, stderr: message });
  assert.match(diagnostic, /transport=HTTP 502\|HTTP 503,/);
  assert.ok(!diagnostic.includes('HTTP 200') && !diagnostic.includes('HTTP 401') && !diagnostic.includes('5027'));
  const many = Array.from({ length: 200 }, (_, i) => `HTTP ${400 + i}`).join('\n').repeat(100);
  const bounded = transportFailure({ status: 1, stderr: many });
  assert.ok(bounded.length < 1024);
  assert.match(bounded, /HTTP_STATUS_LIMIT/);
  assert.match(bounded, new RegExp(`stderr_sha256=${sha(many)}$`));
});

test('transport diagnostics never expose arbitrary process fields secrets paths or URLs', () => {
  const privateText = 'SECRET_SENTINEL https://private.invalid/?token=abc C:\\private\\key /home/private/key Authorization: Bearer abc';
  const diagnostic = transportFailure({ status: privateText, error: { code: privateText, message: privateText, path: privateText },
    signal: privateText, stdout: privateText, stderr: privateText.repeat(10000) });
  assert.match(diagnostic, /^exit=no-exit, process=unclassified, signal=unclassified, transport=unclassified, stderr_sha256=[0-9a-f]{64}$/);
  for (const value of ['SECRET', 'private', 'https:', 'Bearer', 'abc']) assert.ok(!diagnostic.includes(value));
  assert.ok(diagnostic.length < 1024);
});

test('transport diagnostics retain empty and unknown failures without inventing a cause', () => {
  assert.match(transportFailure({ status: 1, stderr: 'unknown remote condition' }),
    /^exit=1, process=none, signal=none, transport=unclassified, stderr_sha256=/);
  assert.match(transportFailure({ status: -1, error: {}, signal: 'SIGKILL', stderr: '' }),
    /^exit=-1, process=unclassified, signal=SIGKILL, transport=unclassified, stderr_sha256=/);
  assert.match(transportFailure({ status: Number.MAX_VALUE, stderr: '' }), /^exit=no-exit,/);
});

test('published missing asset cannot be repaired', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, draft: false, count: 2 });
  assert.throws(() => publishPrepared(prepared, gh.runner), /missing an asset/);
  assert.equal(gh.uploads.length + gh.writes.length, 0);
});

test('stable release and mismatched commit are rejected without writes', t => {
  const prepared = fixture(t);
  for (const change of [g => g.release.prerelease = false,
    g => g.tagCommit = 'b'.repeat(40), g => g.release.target_commitish = 'main']) {
    const gh = fakeGitHub(prepared, { existing: true, count: 3 });
    change(gh);
    assert.throws(() => publishPrepared(prepared, gh.runner));
    assert.equal(gh.uploads.length + gh.writes.length, 0);
  }
});

test('occupied tag with different commit does not create a release', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared);
  gh.tagCommit = 'b'.repeat(40);
  assert.throws(() => publishPrepared(prepared, gh.runner), /exact control commit/);
  assert.equal(gh.writes.length, 0);
});

test('draft with foreign, incomplete, duplicate or mismatched asset is never overwritten', t => {
  const prepared = fixture(t);
  for (const change of [g => g.assets[0].digest = null, g => g.assets[0].size++,
    g => g.assets[0].state = 'starter', g => g.assets[0].name = 'unexpected.json',
    g => g.assets.push({ ...g.assets[0] })]) {
    const gh = fakeGitHub(prepared, { existing: true, count: 1 });
    change(gh);
    assert.throws(() => publishPrepared(prepared, gh.runner));
    assert.equal(gh.uploads.length + gh.writes.length, 0);
  }
});

test('failed upload is not retried, overwritten, removed or published', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, failUpload: true });
  assert.throws(() => publishPrepared(prepared, gh.runner), /without retry/);
  assert.equal(gh.uploads.length, 1);
  assert.equal(gh.writes.length, 0);
  assert.equal(gh.release.draft, true);
});

test('asset mutation after an upload stops before publication', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true,
    hook: ({ kind }) => { if (kind === 'uploaded') fs.appendFileSync(prepared.snapshot.files[0].filename, 'changed'); } });
  assert.throws(() => publishPrepared(prepared, gh.runner), /Local inputs changed/);
  assert.equal(gh.uploads.length, 1);
  assert.equal(gh.writes.length, 0);
});

test('mutation between remote check and upload is detected before upload', t => {
  const prepared = fixture(t);
  let reads = 0;
  const gh = fakeGitHub(prepared, { existing: true, hook: ({ endpoint }) => {
    if (endpoint?.includes('/assets?') && ++reads === 2) fs.appendFileSync(prepared.snapshot.files[0].filename, 'changed');
  } });
  assert.throws(() => publishPrepared(prepared, gh.runner), /Local inputs changed/);
  assert.equal(gh.uploads.length, 0);
});

test('request changes and extra files invalidate the original snapshot', t => {
  const prepared = fixture(t);
  fs.appendFileSync(prepared.snapshot.request, ' ');
  assert.throws(() => assertUnchanged(prepared.snapshot));
  const another = fixture(t);
  fs.writeFileSync(path.join(another.snapshot.directory, 'extra'), 'x');
  assert.throws(() => assertUnchanged(another.snapshot), /exactly the three/);
});

test('verifier cannot substitute tag, commit format, archive, assets or unknown claims', t => {
  const prepared = fixture(t);
  for (const change of [v => v.tag += '-other', v => v.control_commit = 'main',
    v => v.archive_sha256 = 'b'.repeat(64), v => v.assets[0].sha256 = 'c'.repeat(64),
    v => v.authorized = true, v => v.assets[0].extra = true]) {
    const value = structuredClone(prepared.verification);
    change(value);
    assert.throws(() => validateVerification(value, prepared.snapshot));
  }
});

test('previously verified remote asset identity may not change during a draft upload', t => {
  const prepared = fixture(t), gh = fakeGitHub(prepared, { existing: true, count: 1,
    hook: ({ kind, state }) => { if (kind === 'uploaded') state.assets[0].id++; } });
  assert.throws(() => publishPrepared(prepared, gh.runner), /asset identity changed/);
  assert.equal(gh.writes.length, 0);
});

test('GitHub outage is not interpreted as a missing release', t => {
  const prepared = fixture(t);
  let calls = 0;
  assert.throws(() => publishPrepared(prepared, () => {
    calls++;
    return { status: 1, stdout: '', stderr: 'connection failed' };
  }), /stopped without retry/);
  assert.equal(calls, 1);
});

test('production runner refuses caller-supplied verifier claims before any remote operation', t => {
  assert.throws(() => publishPrepared(fixture(t)), /requires the unchanged result/);
});

test('child environment disables credential-bearing debug logs', () => {
  const source = { GH_DEBUG: 'api', GIT_TRACE: '1', GIT_TRACE_CURL: '1', GIT_CURL_VERBOSE: '1',
    DEBUG: '*', GH_HOST: 'wrong.example', GH_TOKEN: 'synthetic-secret', PATH: 'unchanged' };
  const env = childEnvironment(source);
  assert.equal(env.GH_HOST, 'github.com');
  assert.equal(env.GH_PROMPT_DISABLED, '1');
  assert.equal(env.GH_TOKEN, source.GH_TOKEN);
  for (const key of ['GH_DEBUG', 'GIT_TRACE', 'GIT_TRACE_CURL', 'GIT_CURL_VERBOSE', 'DEBUG']) assert.equal(env[key], undefined);
  assert.equal(source.GH_DEBUG, 'api');
});

test('verification diagnostics retain static code and stderr fingerprint without private text', () => {
  const error = verificationFailure({ status: 2, stderr: 'private path and token\nLOCAL_CANDIDATE_SOURCE_CHANGED\n' });
  assert.match(error, /exit=2/);
  assert.match(error, /LOCAL_CANDIDATE_SOURCE_CHANGED/);
  assert.match(error, /stderr_sha256=[a-f0-9]{16}/);
  assert.ok(!error.includes('private path'));
  assert.ok(!error.includes('token'));
});
