// Same-computer upload broker. Authentication is passed only through private stdin.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const GH = 'C:\\Program Files\\GitHub CLI\\gh.exe';
const WSL = 'C:\\Windows\\System32\\wsl.exe';
const PYTHON = fileURLToPath(new URL('./local_preview_upload.py', import.meta.url));
const PROTOCOL = 'tden:local-preview-curl-upload:v1';
const NAMES = new Set(['candidate-build.json', 'tden-node-linux-amd64.tar.gz', 'tden-node-linux-amd64.tar.gz.sha256']);
const HASH = /^[0-9a-f]{64}$/;
const CODES = new Set(['RELEASE_ID', 'ASSET_NAME', 'ASSET_PATH', 'ASSET_BYTES', 'ASSET_DIGEST',
  'AUTH_FORMAT', 'ASSET_FILE', 'ASSET_CHANGED', 'ASSET_DIGEST_MISMATCH', 'PROCESS_TIMEOUT',
  'TRANSFER_FAILED', 'TRANSFER_SIZE', 'RESPONSE_JSON', 'RESPONSE_BINDING', 'LOCAL_IO_ERROR']);
const TELEMETRY = ['http_status', 'uploaded_bytes', 'total_seconds', 'tls_verify', 'http_version'];
const NUMBERS = ['curl_exit', 'http_status', 'uploaded_bytes', 'total_seconds', 'tls_verify'];
export const WSL_UPLOAD_TIMEOUT_MS = 20 * 60 * 1000;
const WSL_ENV_KEYS = new Set(['systemroot', 'windir', 'temp', 'tmp', 'userprofile', 'appdata', 'localappdata',
  'path', 'comspec', 'pathext', 'processor_architecture', 'programfiles', 'programfiles(x86)', 'programdata',
  'number_of_processors', 'systemdrive']);
const LOG_ENV = /(?:^|_)(?:debug|trace|verbose|log|logfile|keylogfile)(?:_|$)|^GIT_TRACE|^(?:SSLKEYLOGFILE|SSLKEYLOG|NODE_OPTIONS|PYTHONINSPECT|PYTHONSTARTUP|PYTHONVERBOSE|BASH_ENV|ENV|PS4)$/i;

class GuardError extends Error {}
function need(ok, code) { if (!ok) throw new GuardError(code); }
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function keysAre(value, expected) {
  return isObject(value) && Object.keys(value).sort().join('|') === [...expected].sort().join('|');
}

function environment(wsl) {
  const result = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (LOG_ENV.test(key) || /^WSLENV$/i.test(key)) continue;
    if (wsl && (!WSL_ENV_KEYS.has(key.toLowerCase()) || /token|secret|password|passwd|credential/i.test(key))) continue;
    result[key] = value;
  }
  if (!wsl) Object.assign(result, { GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1', NO_COLOR: '1' });
  return result;
}

function wslPath(filename) {
  need(typeof filename === 'string' && /^[A-Za-z]:[\\/]/.test(filename)
    && !/[\x00-\x1f\x7f]/.test(filename), 'INPUT');
  const rest = filename.slice(3).replaceAll('\\', '/');
  need(rest.length > 0 && !rest.includes(':') && !rest.split('/').some(part => !part || part === '.' || part === '..'), 'INPUT');
  return `/mnt/${filename[0].toLowerCase()}/${rest}`;
}

export function productionRunner(command, args, options) {
  // Node's own child-process debug logger is initialized before child env filtering.
  // Refuse such a parent process before spawning anything that may handle a token.
  need(!Object.entries(process.env).some(([key, value]) => value && /^NODE_DEBUG(?:_NATIVE)?$/i.test(key))
    && !/--(?:inspect|debug|trace|tls-keylog)/i.test(process.env.NODE_OPTIONS ?? '')
    && !process.execArgv.some(value => /--(?:inspect|debug|trace|tls-keylog)/i.test(value)), 'PARENT_LOGGING');
  // No shell and no inherited stdio: a failed child cannot print credentials.
  return spawnSync(command, args, { ...options, shell: false, windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'], encoding: 'buffer', maxBuffer: 64 * 1024 });
}

function failure(code, diagnostics = null) {
  const fields = diagnostics === null ? [] : NUMBERS.filter(key => key in diagnostics)
    .map(key => `${key}=${diagnostics[key]}`);
  return { status: 1, stdout: '', stderr: [`WSL_UPLOAD_${code}`, ...fields].join(' ') };
}

function textBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  need(typeof value === 'string', 'RESPONSE');
  return Buffer.from(value, 'utf8');
}

function parseResponse(stdout) {
  const bytes = textBytes(stdout);
  need(bytes.length > 0 && bytes.length <= 16384, 'RESPONSE');
  const raw = bytes.toString('utf8');
  need(Buffer.from(raw, 'utf8').equals(bytes), 'RESPONSE');
  let value;
  try { value = JSON.parse(raw); } catch { throw new GuardError('RESPONSE'); }
  need(isObject(value), 'RESPONSE');
  // The protocol is flat. Reject duplicate/escaped duplicate keys as well as unknown fields.
  const writtenKeys = [...raw.matchAll(/"((?:\\.|[^"\\])*)"\s*:/g)].map(match => {
    try { return JSON.parse(`"${match[1]}"`); } catch { throw new GuardError('RESPONSE'); }
  });
  need(writtenKeys.length === Object.keys(value).length && new Set(writtenKeys).size === writtenKeys.length, 'RESPONSE');
  need(value.protocol === PROTOCOL && typeof value.ok === 'boolean', 'RESPONSE');
  return value;
}

function validateTelemetry(value, required) {
  const present = TELEMETRY.filter(key => key in value);
  need(required ? present.length === TELEMETRY.length : [0, TELEMETRY.length].includes(present.length), 'RESPONSE');
  need(integer(value.curl_exit, -1, 255) && typeof value.stderr_sha256 === 'string' && HASH.test(value.stderr_sha256), 'RESPONSE');
  if (present.length) need(integer(value.http_status, 0, 999) && integer(value.uploaded_bytes, 0, 999999999999)
    && typeof value.total_seconds === 'number' && Number.isFinite(value.total_seconds)
    && value.total_seconds >= 0 && value.total_seconds < 1000000
    && integer(value.tls_verify, 0, 9999999999) && ['0', '1', '1.0', '1.1', '2', '3'].includes(value.http_version), 'RESPONSE');
}

function validatedResult(result, file) {
  if (result?.error?.code === 'ETIMEDOUT') throw new GuardError('PROCESS_TIMEOUT');
  need(result && !result.error && result.signal == null, 'PROCESS');
  const value = parseResponse(result.stdout);
  if (value.ok) {
    need(result.status === 0 && keysAre(value, ['protocol', 'ok', 'asset_id', 'name', 'bytes', 'sha256',
      'curl_exit', 'stderr_sha256', ...TELEMETRY]), 'RESPONSE');
    validateTelemetry(value, true);
    need(integer(value.asset_id, 1, Number.MAX_SAFE_INTEGER) && value.name === file.name
      && value.bytes === file.bytes && value.sha256 === file.sha256 && value.curl_exit === 0
      && value.http_status === 201 && value.uploaded_bytes === file.bytes && value.tls_verify === 0
      && ['1.1', '2'].includes(value.http_version), 'RESPONSE_BINDING');
    // Return only the asset fields the existing GH caller understands, not raw Python output.
    return { status: 0, stdout: JSON.stringify({ id: value.asset_id, name: file.name,
      state: 'uploaded', size: file.bytes, digest: `sha256:${file.sha256}` }), stderr: '' };
  }
  need(result.status === 1 && CODES.has(value.code), 'RESPONSE');
  if (value.code === 'TRANSFER_FAILED') {
    need(keysAre(value, ['protocol', 'ok', 'code', 'curl_exit', 'stderr_sha256',
      ...TELEMETRY.filter(key => key in value)]), 'RESPONSE');
    validateTelemetry(value, false);
    return failure('TRANSFER_FAILED', value);
  }
  need(keysAre(value, ['protocol', 'ok', 'code']), 'RESPONSE');
  return failure(value.code);
}

export function uploadWithWslCurl(file, releaseId, runner = productionRunner) {
  let authOutput, token;
  try {
    need(runner !== productionRunner || process.platform === 'win32', 'PLATFORM');
    need(typeof runner === 'function' && isObject(file) && NAMES.has(file.name)
      && typeof file.sha256 === 'string' && HASH.test(file.sha256)
      && integer(file.bytes, 1, 1024 ** 3) && integer(releaseId, 1, Number.MAX_SAFE_INTEGER), 'INPUT');
    const filename = wslPath(file.filename);
    need(path.win32.basename(file.filename) === file.name, 'INPUT');
    const script = wslPath(PYTHON);
    const auth = runner(GH, ['auth', 'token', '--hostname', 'github.com'],
      { env: environment(false), timeout: 30000 });
    need(auth && !auth.error && auth.signal == null && auth.status === 0
      && (Buffer.isBuffer(auth.stdout) || typeof auth.stdout === 'string'), 'AUTH');
    authOutput = textBytes(auth.stdout);
    need(authOutput.length <= 4098, 'AUTH');
    let length = authOutput.length;
    while (length > 0 && (authOutput[length - 1] === 10 || authOutput[length - 1] === 13)) length--;
    token = Buffer.from(authOutput.subarray(0, length));
    need(token.length >= 20 && token.length <= 4096
      && token.every(byte => byte >= 65 && byte <= 90 || byte >= 97 && byte <= 122
        || byte >= 48 && byte <= 57 || byte === 95), 'AUTH');
    const result = runner(WSL, ['-d', 'Ubuntu', '-u', 'root', '--exec', 'python3', '-I', '-B', script,
      '--release-id', String(releaseId), '--file', filename, '--name', file.name,
      '--bytes', String(file.bytes), '--sha256', file.sha256],
    { input: token, env: environment(true), timeout: WSL_UPLOAD_TIMEOUT_MS });
    return validatedResult(result, file);
  } catch (error) {
    // Never use exception.message, child stderr or an arbitrary code in a public result.
    const code = error instanceof GuardError && ['INPUT', 'PLATFORM', 'AUTH', 'RESPONSE', 'RESPONSE_BINDING', 'PROCESS', 'PROCESS_TIMEOUT', 'PARENT_LOGGING'].includes(error.message)
      ? error.message : 'BROKER';
    return failure(code);
  } finally {
    if (Buffer.isBuffer(authOutput)) authOutput.fill(0);
    if (Buffer.isBuffer(token)) token.fill(0);
  }
}
