#!/usr/bin/env node
// Local TEST previews only. The CLI always runs the independent Python verifier.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { uploadWithWslCurl } from './local_preview_upload.mjs';

export const REPOSITORY = 'sunbird84/tden-node-releases';
export const ASSET_NAMES = Object.freeze([
  'candidate-build.json', 'tden-node-linux-amd64.tar.gz',
  'tden-node-linux-amd64.tar.gz.sha256',
]);
const VERIFICATION_PROTOCOL = 'tden:node-local-preview-verification:v1';
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const verifiedPreparations = new WeakMap();
const requireThat = (ok, message) => { if (!ok) throw new Error(message); };
const hex = (value, length) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const stamp = s => [s.dev, s.ino, s.size, s.mtimeNs, s.ctimeNs, s.mode, s.nlink].map(String);

function fingerprint(filename) {
  const initial = fs.lstatSync(filename, { bigint: true });
  requireThat(initial.isFile() && !initial.isSymbolicLink() && initial.nlink === 1n,
    'Inputs must be regular files with one link.');
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    requireThat(equal(stamp(initial), stamp(before)), 'Input changed before hashing.');
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      bytes += count;
      requireThat(Number.isSafeInteger(bytes), 'Input size is outside the supported range.');
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(filename, { bigint: true });
    requireThat(equal(stamp(before), stamp(after)) && equal(stamp(after), stamp(current))
      && BigInt(bytes) === after.size, 'Input changed during hashing.');
    return { bytes, sha256: hash.digest('hex'), stamp: stamp(after) };
  } finally { fs.closeSync(fd); }
}

export function captureInputs(requestPath, assetDirectory) {
  const directory = path.resolve(assetDirectory);
  const info = fs.lstatSync(directory);
  requireThat(info.isDirectory() && !info.isSymbolicLink(), 'Asset directory must be a real directory.');
  requireThat(equal(fs.readdirSync(directory).sort(), ASSET_NAMES), 'Asset directory must contain exactly the three preview assets.');
  const request = path.resolve(requestPath);
  const files = ASSET_NAMES.map(name => ({ name, filename: path.join(directory, name), ...fingerprint(path.join(directory, name)) }));
  return { directory, request, requestFingerprint: fingerprint(request), files };
}

export function assertUnchanged(snapshot) {
  requireThat(equal(captureInputs(snapshot.request, snapshot.directory), snapshot),
    'Local inputs changed; no automatic retry or overwrite is allowed.');
}

export function validateVerification(value, snapshot) {
  requireThat(value && equal(Object.keys(value).sort(),
    ['protocol', 'tag', 'control_commit', 'archive_sha256', 'version', 'assets'].sort()),
  'Independent verifier returned an unexpected schema.');
  requireThat(value.protocol === VERIFICATION_PROTOCOL && hex(value.control_commit, 40)
    && hex(value.archive_sha256, 64) && typeof value.version === 'string' && value.version.length <= 160,
  'Independent verification identity is invalid.');
  const slug = value.version.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  requireThat(slug && value.tag === `node-${slug}-local-${value.archive_sha256}`,
    'Preview tag does not bind its version and archive.');
  const expected = snapshot.files.map(({ name, bytes, sha256 }) => ({ name, bytes, sha256 }));
  requireThat(Array.isArray(value.assets) && value.assets.length === 3
    && value.assets.every(a => a && equal(Object.keys(a).sort(), ['bytes', 'name', 'sha256'])
      && Number.isSafeInteger(a.bytes) && a.bytes > 0 && hex(a.sha256, 64))
    && value.assets.every((asset, i) => asset.name === expected[i].name
      && asset.bytes === expected[i].bytes && asset.sha256 === expected[i].sha256)
    && value.archive_sha256 === expected.find(a => a.name.endsWith('.tar.gz')).sha256,
  'Independent verification does not match the actual three assets.');
  return value;
}

// Release-body contract shared with Native's API and Atom catalogs. These are
// discovery metadata only: publication does not authorize a node upgrade.
// The production caller has independently verified the entire descriptor; bind
// this read to those same bytes and serialize only fixed markers and typed data.
export function localPreviewReleaseBody({ snapshot, verification: v }) {
  validateVerification(v, snapshot);
  const asset = snapshot.files.find(file => file.name === 'candidate-build.json');
  requireThat(asset && asset.bytes <= 65536, 'Verified candidate descriptor is missing or oversized.');
  const bytes = fs.readFileSync(asset.filename);
  requireThat(bytes.length === asset.bytes && crypto.createHash('sha256').update(bytes).digest('hex') === asset.sha256,
    'Candidate descriptor changed after independent verification.');
  const descriptor = JSON.parse(bytes.toString('utf8'));
  const archive = v.assets.find(file => file.name === 'tden-node-linux-amd64.tar.gz');
  requireThat(descriptor.protocol === 'tden:node-candidate-build:v1' && descriptor.build_environment === 'local'
    && descriptor.version === v.version && descriptor.archive_sha256 === v.archive_sha256
    && Number.isSafeInteger(descriptor.archive_bytes) && descriptor.archive_bytes === archive.bytes
    && descriptor.local_build_provenance?.control_commit === v.control_commit
    && hex(descriptor.bootstrap_trust_template_sha256, 64) && hex(descriptor.tuf_root_sha256, 64),
  'Verified descriptor does not bind the local preview catalog metadata.');
  return 'Locally built TEST recovery preview. This is not a stable release, Core Team organization signature, public-node upgrade directive, TUF promotion, or deployment acceptance.\n\n'
    + `Control commit: ${v.control_commit}\nArchive SHA-256: ${v.archive_sha256}\n`
    + `Archive bytes: ${descriptor.archive_bytes}\nRelease channel: preview\n`
    + `Bootstrap trust template SHA-256: ${descriptor.bootstrap_trust_template_sha256}\n`
    + `TUF root SHA-256: ${descriptor.tuf_root_sha256}\n`;
}

export function childEnvironment(source = process.env) {
  const env = { ...source, GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1', NO_COLOR: '1' };
  for (const key of Object.keys(env)) {
    if (/^(GH_DEBUG|GH_FORCE_TTY|GIT_TRACE.*|GIT_CURL_VERBOSE|CURL_VERBOSE|DEBUG)$/i.test(key)) delete env[key];
  }
  return env;
}

function run(command, args, input) {
  return spawnSync(command, args, { input, encoding: 'utf8', windowsHide: true,
    timeout: 15 * 60 * 1000, maxBuffer: 4 * 1024 * 1024,
    env: childEnvironment() });
}

export function verificationFailure(result) {
  const stderr = String(result.stderr ?? '');
  const safeCode = stderr.match(/^LOCAL_CANDIDATE_[A-Z0-9_]+$/m)?.[0];
  const evidence = crypto.createHash('sha256').update(stderr).digest('hex').slice(0, 16);
  const exit = Number.isInteger(result.status) ? result.status : 'no-exit';
  const processCode = /^[A-Z0-9_]+$/.test(result.error?.code ?? '') ? `, process=${result.error.code}` : '';
  return `Independent local candidate verification failed (exit=${exit}${processCode}${safeCode ? `, code=${safeCode}` : ''}, stderr_sha256=${evidence}).`;
}

export function transportFailure(result) {
  const stderr = String(result.stderr ?? '');
  // Never copy a process field or a matched error substring into diagnostics.
  // Exact allowlists preserve useful causes without exposing URLs or credentials.
  const processCodes = new Set(['ETIMEDOUT', 'ENOBUFS', 'ENOENT', 'EACCES', 'EPERM', 'EPIPE',
    'ECONNRESET', 'ECONNABORTED', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH',
    'EAI_AGAIN', 'ENOTFOUND', 'ECANCELED', 'EINVAL']);
  const signals = new Set(['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGBREAK', 'SIGHUP',
    'SIGQUIT', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGFPE', 'SIGPIPE', 'SIGTRAP',
    'SIGSYS', 'SIGXCPU', 'SIGXFSZ']);
  const processCode = result.error == null ? 'none'
    : processCodes.has(result.error.code) ? result.error.code : 'unclassified';
  const signal = result.signal == null ? 'none'
    : signals.has(result.signal) ? result.signal : 'unclassified';
  const exit = Number.isInteger(result.status) && result.status >= -2147483648 && result.status <= 4294967295
    ? result.status : 'no-exit';
  const families = [
    ['SOCKET_IO', /\b(?:wsarecv|wsasend)\b/i],
    ['SOCKET_RESET', /\b(?:ECONNRESET|WSAECONNRESET)\b|\bconnection reset\b|\bforcibly closed\b/i],
    ['SOCKET_ABORT', /\b(?:ECONNABORTED|WSAECONNABORTED)\b|\bconnection (?:was |has been )?aborted\b|\bsoftware caused connection abort\b/i],
    ['SOCKET_TIMEOUT', /\b(?:ETIMEDOUT|WSAETIMEDOUT)\b|\bi\/o timeout\b|\bconnection timed out\b|\bconnected host has failed to respond\b/i],
    ['SOCKET_REFUSED', /\b(?:ECONNREFUSED|WSAECONNREFUSED)\b|\bconnection refused\b|\btarget machine actively refused\b/i],
    ['DNS', /\b(?:ENOTFOUND|EAI_AGAIN|WSAHOST_NOT_FOUND|WSATRY_AGAIN)\b|\bno such host\b|\btemporary failure in name resolution\b|\bcould(?: not|n't) resolve (?:host|proxy)\b/i],
    ['TLS_CERTIFICATE', /\bx509:|\bcertificate (?:verify failed|signed by unknown authority|has expired|is not yet valid)\b|\bCERT_(?:E_EXPIRED|E_UNTRUSTEDROOT|E_CN_NO_MATCH)\b/i],
    ['TLS_HANDSHAKE', /\bTLS handshake timeout\b|\btls: (?:handshake failure|first record does not look like a TLS handshake)\b|\bSSL connect error\b/i],
    ['CERT_REVOCATION_OFFLINE', /\bCRYPT_E_REVOCATION_OFFLINE\b|\b0x80092013\b/i],
    ['HTTP2', /\b(?:http2|HTTP\/2|REFUSED_STREAM|GOAWAY)\b|\bstream error: [^\r\n]{0,160}\b(?:INTERNAL_ERROR|PROTOCOL_ERROR|FLOW_CONTROL_ERROR)\b/i],
    ['REQUEST_TIMEOUT', /\bcontext deadline exceeded\b/i],
    ['UNEXPECTED_EOF', /\bunexpected EOF\b/i],
    ['BROKEN_PIPE', /\bbroken pipe\b|\bEPIPE\b/i],
  ];
  const classes = families.filter(([, pattern]) => pattern.test(stderr)).map(([label]) => label);
  if (!classes.includes('UNEXPECTED_EOF') && /\bEOF\b/i.test(stderr)) classes.push('EOF');
  const statuses = [...new Set([...stderr.matchAll(/\bHTTP(?:\/(?:1\.[01]|2(?:\.0)?))?[ \t]+([45][0-9]{2})\b/gi)]
    .map(match => Number(match[1])))].sort((a, b) => a - b);
  classes.push(...statuses.slice(0, 8).map(code => `HTTP ${code}`));
  if (statuses.length > 8) classes.push('HTTP_STATUS_LIMIT');
  return `exit=${exit}, process=${processCode}, signal=${signal}, transport=${classes.join('|') || 'unclassified'}, stderr_sha256=${crypto.createHash('sha256').update(stderr).digest('hex')}`;
}

function wslPath(filename) {
  requireThat(/^[A-Za-z]:[\\/]/.test(filename), 'The Windows CLI requires absolute drive paths.');
  return `/mnt/${filename[0].toLowerCase()}/${filename.slice(3).replaceAll('\\', '/')}`;
}

export function preparePreview(requestPath, assetDirectory) {
  requireThat(process.platform === 'win32', 'Production preparation requires the Windows Node runtime.');
  const snapshot = captureInputs(requestPath, assetDirectory);
  const result = run('C:\\Windows\\System32\\wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', 'python3', '-I', '-B',
    wslPath(path.join(scriptDirectory, 'local_candidate_metadata.py')), 'verify',
    '--request', wslPath(snapshot.request), '--asset-dir', wslPath(snapshot.directory)]);
  requireThat(!result.error && result.status === 0, verificationFailure(result));
  assertUnchanged(snapshot);
  let verification;
  try { verification = JSON.parse(result.stdout); } catch { throw new Error('Independent verifier returned invalid JSON.'); }
  validateVerification(verification, snapshot);
  const prepared = { snapshot, verification };
  verifiedPreparations.set(prepared, JSON.stringify(prepared));
  return prepared;
}

const productionGh = (args, input) => run('C:\\Program Files\\GitHub CLI\\gh.exe', args, input);
// Shared transport engine, exported for isolated tests. The production CLI can
// reach it only after preparePreview; no CLI flag accepts a verification result.
export function publishPrepared(prepared, gh = productionGh, uploadTransport = 'gh') {
  requireThat(uploadTransport === 'gh' || uploadTransport === 'wsl-curl', 'Unknown upload transport.');
  requireThat(gh !== productionGh || verifiedPreparations.get(prepared) === JSON.stringify(prepared),
    'Production publication requires the unchanged result of independent preparation.');
  const { snapshot, verification: v } = prepared;
  validateVerification(v, snapshot);
  assertUnchanged(snapshot);
  const releaseBody = localPreviewReleaseBody(prepared);
  const prefix = `repos/${REPOSITORY}`;
  const api = (method, endpoint, body, missing = false) => {
    const args = ['api', '--hostname', 'github.com', '--method', method, `${prefix}/${endpoint}`];
    if (body !== undefined) args.push('--input', '-');
    const result = gh(args, body === undefined ? undefined : JSON.stringify(body));
    if (!result.error && result.status === 1 && missing && /\(HTTP 404\)/.test(result.stderr ?? '')) return null;
    requireThat(!result.error && result.status === 0, `GitHub ${method} failed; stopped without retry or cleanup (${transportFailure(result)}).`);
    try { return JSON.parse(result.stdout); } catch { throw new Error('GitHub returned invalid JSON.'); }
  };
  const tagEndpoint = `git/ref/tags/${encodeURIComponent(v.tag)}`;
  function checkRef(optional = false) {
    let ref = api('GET', tagEndpoint, undefined, optional);
    if (ref === null) return false;
    requireThat(ref.ref === `refs/tags/${v.tag}`, 'GitHub returned a different tag reference.');
    let object = ref.object;
    for (let depth = 0; object?.type === 'tag' && depth < 4; depth++) {
      requireThat(hex(object.sha, 40), 'Invalid annotated tag identity.');
      object = api('GET', `git/tags/${object.sha}`).object;
    }
    requireThat(object?.type === 'commit' && object.sha === v.control_commit,
      'Existing tag does not resolve to the exact control commit.');
    return true;
  }
  function checkRelease(release, id, draft) {
    requireThat(release && Number.isSafeInteger(release.id) && release.id > 0
      && (!id || release.id === id) && release.tag_name === v.tag
      && release.target_commitish === v.control_commit && release.prerelease === true
      && typeof release.draft === 'boolean' && (draft === undefined || release.draft === draft),
    'Release identity, commit or preview state differs.');
    return release;
  }
  const knownIDs = new Map();
  function checkAssets(id, complete = false) {
    const assets = api('GET', `releases/${id}/assets?per_page=100`);
    requireThat(Array.isArray(assets) && assets.length <= 3, 'Unexpected GitHub asset set.');
    const seen = new Set();
    for (const asset of assets) {
      const expected = v.assets.find(a => a.name === asset.name);
      requireThat(expected && !seen.has(asset.name) && Number.isSafeInteger(asset.id) && asset.id > 0
        && asset.state === 'uploaded' && asset.size === expected.bytes
        && asset.digest === `sha256:${expected.sha256}`,
      'Existing GitHub asset is incomplete or differs; no replacement is allowed.');
      requireThat(!knownIDs.has(asset.name) || knownIDs.get(asset.name) === asset.id,
        'GitHub asset identity changed during publication.');
      seen.add(asset.name);
      knownIDs.set(asset.name, asset.id);
    }
    requireThat([...knownIDs.keys()].every(name => seen.has(name)), 'A previously verified GitHub asset disappeared.');
    requireThat(!complete || seen.size === 3, 'Published preview is missing an asset.');
    return seen;
  }

  let release = api('GET', `releases/tags/${encodeURIComponent(v.tag)}`, undefined, true);
  if (!release) {
    // The tag endpoint returns published releases only. Authorized listings include drafts.
    // https://docs.github.com/en/rest/releases/releases#list-releases
    const matches = [];
    let complete = false;
    for (let page = 1; page <= 10; page++) {
      const entries = api('GET', `releases?per_page=100&page=${page}`);
      requireThat(Array.isArray(entries) && entries.length <= 100
        && entries.every(entry => entry && typeof entry.tag_name === 'string'), 'Release listing is invalid.');
      matches.push(...entries.filter(entry => entry.tag_name === v.tag));
      requireThat(matches.length <= 1, 'Multiple releases use the candidate tag; stopped without mutation.');
      if (entries.length < 100) { complete = true; break; }
    }
    requireThat(complete, 'Release listing exceeds the bounded scan; stopped without mutation.');
    release = matches[0] ?? null;
  }
  if (release) {
    checkRelease(release);
    checkRef();
    checkAssets(release.id, !release.draft);
    if (!release.draft) {
      assertUnchanged(snapshot);
      requireThat(release.body === releaseBody, 'Published preview catalog metadata differs; no automatic repair is allowed.');
      return { protocol: 'tden:node-local-preview-publication:v1', result: 'already-published-verified',
        repository: REPOSITORY, tag: v.tag, control_commit: v.control_commit };
    }
  } else {
    const commit = api('GET', `commits/${v.control_commit}`);
    requireThat(commit.sha === v.control_commit, 'Control commit is unavailable in the fixed repository.');
    if (!checkRef(true)) {
      assertUnchanged(snapshot);
      api('POST', 'git/refs', { ref: `refs/tags/${v.tag}`, sha: v.control_commit });
      checkRef();
    }
    assertUnchanged(snapshot);
    release = api('POST', 'releases', {
      tag_name: v.tag, target_commitish: v.control_commit,
      name: `Local TEST recovery preview ${v.tag}`,
      body: releaseBody,
      draft: true, prerelease: true, make_latest: 'false',
    });
    checkRelease(release, undefined, true);
  }
  const id = release.id;
  for (const file of snapshot.files) {
    checkRelease(api('GET', `releases/${id}`), id, true);
    checkRef();
    const present = checkAssets(id);
    if (present.has(file.name)) continue;
    assertUnchanged(snapshot);
    const result = uploadTransport === 'wsl-curl'
      ? uploadWithWslCurl(file, id)
      : gh(['release', 'upload', v.tag, file.filename, '--repo', `github.com/${REPOSITORY}`]);
    requireThat(!result.error && result.status === 0, `GitHub upload failed; stopped without retry, overwrite or cleanup (${uploadTransport === 'wsl-curl' ? result.stderr : transportFailure(result)}).`);
    assertUnchanged(snapshot);
    requireThat(checkAssets(id).has(file.name), 'Uploaded asset could not be independently verified.');
  }
  checkRelease(api('GET', `releases/${id}`), id, true);
  checkRef();
  checkAssets(id, true);
  assertUnchanged(snapshot);
  api('PATCH', `releases/${id}`, { draft: false, prerelease: true, make_latest: 'false', body: releaseBody });
  const published = checkRelease(api('GET', `releases/${id}`), id, false);
  requireThat(published.body === releaseBody, 'Published preview catalog metadata was not preserved.');
  checkRef();
  checkAssets(id, true);
  assertUnchanged(snapshot);
  return { protocol: 'tden:node-local-preview-publication:v1', result: 'published-preview-verified',
    repository: REPOSITORY, tag: v.tag, control_commit: v.control_commit };
}

export function parseArguments(args) {
  const result = { publish: false, uploadTransport: 'gh' };
  let explicitTransport = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--publish') { requireThat(!result.publish, 'Repeated --publish.'); result.publish = true; }
    else if (arg === '--upload-transport') {
      requireThat(!explicitTransport && ['gh', 'wsl-curl'].includes(args[i + 1]), 'Missing, repeated or unknown upload transport.');
      result.uploadTransport = args[++i];
      explicitTransport = true;
    } else if (arg === '--request' || arg === '--asset-dir') {
      const key = arg === '--request' ? 'requestPath' : 'assetDirectory';
      requireThat(!result[key] && args[i + 1] && !args[i + 1].startsWith('--'), 'Missing or repeated path argument.');
      result[key] = args[++i];
    } else throw new Error('Only --request, --asset-dir, --upload-transport and explicit --publish are supported.');
  }
  requireThat(result.requestPath && result.assetDirectory,
    'Usage: node publish_local_preview.mjs --request <Windows JSON path> --asset-dir <Windows directory> [--publish] [--upload-transport gh|wsl-curl]');
  return result;
}

function main(args) {
  const options = parseArguments(args);
  const prepared = preparePreview(options.requestPath, options.assetDirectory);
  const result = options.publish ? publishPrepared(prepared, productionGh, options.uploadTransport) : {
    ...prepared.verification, protocol: 'tden:node-local-preview-publication:v1',
    result: 'dry-run-verified', repository: REPOSITORY,
  };
  console.log(JSON.stringify(result));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(`Local preview publication stopped: ${error.message}`); process.exitCode = 1; }
}
