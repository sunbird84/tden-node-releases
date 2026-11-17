import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { ASSET_NAMES, REPOSITORY, captureInputs, assertUnchanged, validateVerification,
  publishPrepared, parseArguments, childEnvironment, verificationFailure } from './publish_local_preview.mjs';

// Synthetic verifier results exercise the transport boundary, not package trust.
// The CLI has no injected verifier or option to consume these test results.
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tden-preview-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'assets');
  fs.mkdirSync(directory);
  for (const name of ASSET_NAMES) fs.writeFileSync(path.join(directory, name), `synthetic ${name}\n`);
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

function fakeGitHub(prepared, { existing = false, draft = true, count = 0, hook, failUpload = false } = {}) {
  const v = prepared.verification;
  let serial = 20;
  const state = { calls: [], uploads: [], writes: [], tagCommit: existing ? v.control_commit : null,
    release: existing ? { id: 7, tag_name: v.tag, target_commitish: v.control_commit, draft, prerelease: true } : null,
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
    if (method === 'GET' && endpoint.startsWith('releases/tags/')) return state.release ? ok(state.release) : missing();
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
      assert.deepEqual(body, { draft: false, prerelease: true, make_latest: 'false' });
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
