'use strict';
// Separate transport for read-only reconciliation. Original network identity stays pinned.
const fs = require('node:fs'), path = require('node:path'), cp = require('node:child_process');
const F = require('./deployment-files');
const POLICY = 'ANCHORED_AUDIT_READ_RPC_PROFILE_V1';
const CONFIG = 'b1fb4596332921c0c68a66504098fb3b4ba988e36d6f79ab465d6b22fc7aba61';
const PUBLIC = 'fa0a2820a3732739d719cdead513f0929f1b458ae69a2cbc7766b62ae449ad1b';
const FILE_ENV = 'PPI_AUDIT_READ_RPC_PROFILE', SHA_ENV = 'PPI_AUDIT_READ_RPC_SHA256';
const repo = path.resolve(__dirname, '../..');
function enabled() {
    const file = process.env[FILE_ENV], sha = process.env[SHA_ENV];
    if (!file && !sha) return false;
    if (!file || !sha) throw new Error('Both read profile pins required');
    return true;
}
function rejected() {
    const e = new Error('Read RPC profile validation failed'); e.code = 'PPI_READ_PROFILE_FAILURE'; return e;
}
function check(condition) { if (!condition) throw rejected(); }
function privateFile(file) {
    check(typeof file === 'string' && path.isAbsolute(file));
    const p = F.safePath(file);
    check(p !== repo && !p.startsWith(repo + path.sep));
    F.privateDir(path.dirname(p));
    const s = fs.lstatSync(p);
    check(s.isFile() && s.uid === process.getuid() && s.nlink === 1 && !(s.mode & 0o077) && s.size <= 16384);
    const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
        const opened = fs.fstatSync(fd);
        check(opened.ino === s.ino && opened.dev === s.dev && opened.size === s.size);
        check(opened.uid === process.getuid() && opened.nlink === 1 && !(opened.mode & 0o077));
        return fs.readFileSync(fd);
    } finally { fs.closeSync(fd); }
}
function git() {
    const run = (...args) => cp.execFileSync('git', ['-C', repo, ...args],
        {encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']}).trim();
    check(run('branch', '--show-current') === 'feat/identity-resolution' && !run('status', '--porcelain'));
    return run('rev-parse', 'HEAD');
}
function candidate(url, provider) {
    check(typeof url === 'string' && url.length >= 1 && url.length <= 4096 && !/\s/.test(url));
    const u = new URL(url);
    check(u.protocol === 'https:' && !u.username && !u.password && !u.hash &&
        (!u.port || u.port === '443'));
    check(provider === 0 ? u.hostname.endsWith('.quiknode.pro') && !u.search && u.pathname !== '/' :
        u.hostname.endsWith('.alchemy.com'));
    return url;
}
function load() {
    check(enabled());
    const sha = process.env[SHA_ENV];
    check(/^[0-9a-f]{64}$/.test(sha));
    const bytes = privateFile(process.env[FILE_ENV]);
    check(F.digest(bytes.toString('utf8')) === sha);
    const p = JSON.parse(bytes.toString('utf8'));
    check(bytes.toString('utf8') === F.stable(p) + '\n');
    check(F.stable(Object.keys(p).sort()) === F.stable(['code_revision','original_config_file',
        'original_config_sha256','original_rpc_sha256','policy','public_payload_sha256','rpc_urls'].sort()));
    check(p.policy === POLICY && p.original_config_sha256 === CONFIG && p.public_payload_sha256 === PUBLIC &&
        /^[0-9a-f]{40}$/.test(p.code_revision));
    const original = JSON.parse(privateFile(p.original_config_file).toString('utf8'));
    check(F.digest(original) === CONFIG && Array.isArray(original.rpc_urls) && original.rpc_urls.length === 2);
    check(Array.isArray(p.original_rpc_sha256) && p.original_rpc_sha256.length === 2 &&
        p.original_rpc_sha256.every((h, i) => h === F.digest(original.rpc_urls[i])));
    check(Array.isArray(p.rpc_urls) && p.rpc_urls.length === 2 && p.rpc_urls[1] === original.rpc_urls[1]);
    p.rpc_urls.forEach(candidate);
    check(new URL(p.rpc_urls[0]).hostname !== new URL(p.rpc_urls[1]).hostname);
    return {p, sha, bytes};
}
function scope(p) {
    const executable = path.resolve(process.argv[1] || '');
    check(executable === path.join(__dirname, 'publish-research.js'));
    check(process.argv.length === 9 && process.argv[7] === 'RECONCILE' && process.argv[8] === p.code_revision);
    check(git() === p.code_revision);
}
function route(originalUrl) {
    if (!enabled()) return null;
    const selection = load(); scope(selection.p);
    const index = selection.p.original_rpc_sha256.indexOf(F.digest(originalUrl));
    check(index === 0 || index === 1);
    return {
        fetch(address, request, underlying, readMethods) {
            try {
                check(address === originalUrl);
                const now = load(); check(now.sha === selection.sha && now.bytes.equals(selection.bytes));
                const body = JSON.parse(request.body), entries = Array.isArray(body) ? body : [body];
                // Reject a write before ANY transport call. Do not fall back to the old endpoint.
                check(entries.length >= 1 && entries.length <= 10 && entries.every(e => readMethods.has(e.method)));
            } catch { throw rejected(); }
            return underlying(selection.p.rpc_urls[index], {...request, redirect: 'error'});
        }
    };
}
function attestation() {
    if (!enabled()) return {};
    const {p, sha} = load(); scope(p);
    return {read_verification: {policy: POLICY, profile_sha256: sha,
        original_config_sha256: CONFIG, code_revision: p.code_revision, providers: ['QUICKNODE','ALCHEMY']}};
}
module.exports = {enabled, route, attestation, POLICY};
