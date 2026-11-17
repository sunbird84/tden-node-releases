import test from 'node:test';
import assert from 'node:assert/strict';
import { uploadWithWslCurl, WSL_UPLOAD_TIMEOUT_MS } from './local_preview_upload.mjs';

const TOKEN = 'gho_SYNTHETIC_private_credential_123456789';
const FILE = { filename: 'E:\\candidate artifacts\\tden-node-linux-amd64.tar.gz',
  name: 'tden-node-linux-amd64.tar.gz', bytes: 12345, sha256: 'a'.repeat(64) };
const PROTOCOL = 'tden:local-preview-curl-upload:v1';
const telemetry = { curl_exit: 0, stderr_sha256: 'b'.repeat(64), http_status: 201,
  uploaded_bytes: FILE.bytes, total_seconds: 1.25, tls_verify: 0, http_version: '2' };
const success = () => ({ protocol: PROTOCOL, ok: true, asset_id: 4321, name: FILE.name,
  bytes: FILE.bytes, sha256: FILE.sha256, ...telemetry });
const child = (value, status = 0) => ({ status, stdout: Buffer.from(JSON.stringify(value)), stderr: Buffer.from(TOKEN) });
function fake(reply = child(success())) {
  const calls = [], tokens = [];
  const auth = Buffer.from(`${TOKEN}\r\n`);
  const runner = (command, args, options) => {
    calls.push({ command, args, options });
    if (calls.length === 1) return { status: 0, stdout: auth, stderr: Buffer.from(TOKEN) };
    tokens.push(Buffer.from(options.input));
    return typeof reply === 'function' ? reply(command, args, options) : reply;
  };
  return { runner, calls, tokens, auth };
}
function noLeak(result) {
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
  assert.deepEqual(Object.keys(result).sort(), ['status', 'stderr', 'stdout']);
}

test('fixed Windows GH and WSL stdin transport, with asset-compatible response', () => {
  const f = fake();
  const result = uploadWithWslCurl(FILE, 9876, f.runner);
  assert.equal(result.status, 0); noLeak(result);
  assert.deepEqual(JSON.parse(result.stdout), { id: 4321, name: FILE.name, state: 'uploaded', size: FILE.bytes, digest: `sha256:${FILE.sha256}` });
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[0].command, 'C:\\Program Files\\GitHub CLI\\gh.exe');
  assert.deepEqual(f.calls[0].args, ['auth', 'token', '--hostname', 'github.com']);
  assert.equal(f.calls[1].command, 'C:\\Windows\\System32\\wsl.exe');
  assert.deepEqual(f.calls[1].args.slice(0, 8), ['-d', 'Ubuntu', '-u', 'root', '--exec', 'python3', '-I', '-B']);
  assert.match(f.calls[1].args[8], /^\/mnt\/[a-z]\/.*\/control\/scripts\/local_preview_upload\.py$/);
  assert.deepEqual(f.calls[1].args.slice(9), ['--release-id', '9876', '--file', '/mnt/e/candidate artifacts/tden-node-linux-amd64.tar.gz',
    '--name', FILE.name, '--bytes', String(FILE.bytes), '--sha256', FILE.sha256]);
  assert.equal(f.tokens[0].toString(), TOKEN);
  for (const call of f.calls) {
    assert.equal(JSON.stringify(call.args).includes(TOKEN), false);
    assert.equal(JSON.stringify(call.options.env).includes(TOKEN), false);
  }
  assert.equal(f.calls[1].options.timeout, WSL_UPLOAD_TIMEOUT_MS);
  assert.ok(WSL_UPLOAD_TIMEOUT_MS > 850000 && WSL_UPLOAD_TIMEOUT_MS <= 1800000);
  assert.ok(f.auth.every(byte => byte === 0));
  assert.ok(f.calls[1].options.input.every(byte => byte === 0));
});

test('GH authentication environment retained, WSL token and forwarding variables removed', () => {
  const values = { GH_TOKEN: 'existing-auth-only-for-gh', GITHUB_TOKEN: 'existing-other-token',
    GH_ENTERPRISE_TOKEN: 'enterprise-token', OTHER_SECRET: 'secret-value', WSLENV: 'GH_TOKEN/u:OTHER_SECRET/u',
    GH_DEBUG: 'api', GIT_TRACE_CURL: '1', GIT_TRACE2_EVENT: 'secret-log', CURL_VERBOSE: '1', SSLKEYLOGFILE: 'secret-log',
    RUST_LOG: 'trace', NODE_DEBUG: 'child_process', NODE_OPTIONS: '--trace-warnings', DEBUG: '*' };
  const saved = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  try {
    Object.assign(process.env, values);
    const f = fake(); assert.equal(uploadWithWslCurl(FILE, 1, f.runner).status, 0);
    assert.equal(f.calls[0].options.env.GH_TOKEN, values.GH_TOKEN);
    for (const key of Object.keys(values)) {
      assert.equal(key in f.calls[1].options.env, false, key);
      if (!['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'OTHER_SECRET'].includes(key))
        assert.equal(key in f.calls[0].options.env, false, key);
    }
  } finally { for (const [key, value] of Object.entries(saved)) value === undefined ? delete process.env[key] : process.env[key] = value; }
});

test('invalid target arguments never fetch authentication', () => {
  for (const [file, release] of [
    [{ ...FILE, name: 'other.tar.gz' }, 1], [{ ...FILE, filename: 'relative.tar.gz' }, 1],
    [{ ...FILE, filename: 'E:/x/../tden-node-linux-amd64.tar.gz' }, 1],
    [{ ...FILE, filename: '\\\\server\\share\\tden-node-linux-amd64.tar.gz' }, 1],
    [{ ...FILE, filename: 'E:/x/tden-node-linux-amd64.tar.gz:stream' }, 1],
    [{ ...FILE, bytes: 0 }, 1], [{ ...FILE, bytes: 1024 ** 3 + 1 }, 1],
    [{ ...FILE, sha256: 'A'.repeat(64) }, 1], [FILE, 0], [FILE, '1'], [FILE, Number.MAX_SAFE_INTEGER + 1],
  ]) {
    const f = fake(); const result = uploadWithWslCurl(file, release, f.runner);
    assert.equal(result.stderr, 'WSL_UPLOAD_INPUT'); assert.equal(f.calls.length, 0); noLeak(result);
  }
});

test('auth errors and malformed credentials never call WSL or disclose diagnostics', () => {
  for (const auth of [
    { status: 1, stdout: TOKEN, stderr: TOKEN }, { status: null, error: new Error(TOKEN), stdout: TOKEN },
    { status: 0, stdout: ` ${TOKEN}` }, { status: 0, stdout: `${TOKEN}\nheader=secret` },
    { status: 0, stdout: 'x'.repeat(4097) }, { status: 0, stdout: 'short' },
  ]) {
    let calls = 0;
    const result = uploadWithWslCurl(FILE, 1, () => { calls++; return auth; });
    assert.equal(result.stderr, 'WSL_UPLOAD_AUTH'); assert.equal(calls, 1); noLeak(result);
  }
});

test('well-formed transfer failure exposes only allowlisted numbers', () => {
  const f = fake(child({ protocol: PROTOCOL, ok: false, code: 'TRANSFER_FAILED', ...telemetry,
    curl_exit: 28, http_status: 0, uploaded_bytes: 1024 }, 1));
  const result = uploadWithWslCurl(FILE, 1, f.runner);
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'WSL_UPLOAD_TRANSFER_FAILED curl_exit=28 http_status=0 uploaded_bytes=1024 total_seconds=1.25 tls_verify=0');
  noLeak(result);
});

test('failure with absent curl status remains closed and safe', () => {
  const f = fake(child({ protocol: PROTOCOL, ok: false, code: 'TRANSFER_FAILED', curl_exit: -1, stderr_sha256: 'b'.repeat(64) }, 1));
  assert.equal(uploadWithWslCurl(FILE, 1, f.runner).stderr, 'WSL_UPLOAD_TRANSFER_FAILED curl_exit=-1');
});

test('zero HTTP-version failure diagnostics accepted but success requires HTTP1.1 or HTTP2', () => {
  const f = fake(child({ protocol: PROTOCOL, ok: false, code: 'TRANSFER_FAILED', ...telemetry,
    curl_exit: 28, http_status: 0, http_version: '0', uploaded_bytes: 0 }, 1));
  assert.equal(uploadWithWslCurl(FILE, 1, f.runner).stderr,
    'WSL_UPLOAD_TRANSFER_FAILED curl_exit=28 http_status=0 uploaded_bytes=0 total_seconds=1.25 tls_verify=0');
  for (const http_version of ['0', '1', '1.0', '3']) {
    const result = uploadWithWslCurl(FILE, 1, fake(child({ ...success(), http_version })).runner);
    assert.equal(result.stderr, 'WSL_UPLOAD_RESPONSE_BINDING'); noLeak(result);
  }
  assert.equal(uploadWithWslCurl(FILE, 1, fake(child({ ...success(), http_version: '1.1' })).runner).status, 0);
});

test('known Python local failure codes are static broker diagnostics', () => {
  for (const code of ['PROCESS_TIMEOUT', 'ASSET_CHANGED', 'ASSET_DIGEST_MISMATCH', 'RESPONSE_BINDING', 'LOCAL_IO_ERROR']) {
    const f = fake(child({ protocol: PROTOCOL, ok: false, code }, 1));
    const result = uploadWithWslCurl(FILE, 1, f.runner);
    assert.equal(result.stderr, `WSL_UPLOAD_${code}`); noLeak(result);
  }
});

test('malformed, extra, duplicate, secret and inconsistent responses are rejected', () => {
  const invalid = [
    child({ ...success(), extra: TOKEN }), child({ ...success(), sha256: 'c'.repeat(64) }),
    child({ ...success(), name: 'candidate-build.json' }), child({ ...success(), bytes: FILE.bytes + 1 }),
    child({ ...success(), asset_id: '4321' }), child({ ...success(), tls_verify: 1 }),
    child({ ...success(), curl_exit: 28 }), child({ ...success(), http_status: 302 }),
    child({ ...success(), total_seconds: TOKEN }), child({ ...success(), uploaded_bytes: -1 }),
    child({ ...success(), http_version: TOKEN }), child({ ...success(), stderr_sha256: TOKEN }),
    child({ ...success(), protocol: 'other' }), child(success(), 1),
    child({ protocol: PROTOCOL, ok: false, code: TOKEN }, 1),
    child({ protocol: PROTOCOL, ok: false, code: 'ASSET_CHANGED', diagnostic: TOKEN }, 1),
    child({ protocol: PROTOCOL, ok: false, code: 'PROCESS_TIMEOUT' }, 0),
    child({ protocol: PROTOCOL, ok: false, code: 'TRANSFER_FAILED', curl_exit: 28, stderr_sha256: 'b'.repeat(64), http_status: 0 }, 1),
    { status: 0, stdout: TOKEN, stderr: TOKEN },
    { status: 0, stdout: 'x'.repeat(16385), stderr: TOKEN },
    { status: 0, stdout: JSON.stringify(success()).replace('"ok":true', '"ok":false,"ok":true'), stderr: TOKEN },
  ];
  for (const reply of invalid) {
    const f = fake(reply); const result = uploadWithWslCurl(FILE, 1, f.runner);
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
    assert.match(result.stderr, /^WSL_UPLOAD_RESPONSE(?:_BINDING)?$/); noLeak(result);
  }
});

test('thrown exceptions and timeouts do not leak messages or retry', () => {
  for (const reply of [() => { throw new Error(TOKEN); },
    { status: null, error: Object.assign(new Error(TOKEN), { code: TOKEN }), stdout: TOKEN, stderr: TOKEN },
    { status: 0, signal: TOKEN, stdout: JSON.stringify(success()), stderr: TOKEN }]) {
    const f = fake(reply); const result = uploadWithWslCurl(FILE, 1, f.runner);
    assert.match(result.stderr, /^WSL_UPLOAD_(BROKER|PROCESS)$/);
    assert.equal(f.calls.length, 2); noLeak(result);
    assert.ok(f.calls[1].options.input.every(byte => byte === 0));
  }
});

test('broker timeout is reported statically without implying remote rollback', () => {
  const f = fake({ status: null, error: Object.assign(new Error(TOKEN), { code: 'ETIMEDOUT' }), stdout: TOKEN, stderr: TOKEN });
  const result = uploadWithWslCurl(FILE, 1, f.runner);
  assert.equal(result.stderr, 'WSL_UPLOAD_PROCESS_TIMEOUT'); assert.equal(f.calls.length, 2); noLeak(result);
});
