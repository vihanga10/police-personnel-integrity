'use strict';
// READ-ONLY live check of one officer's ORIGINAL anchor on both chains. Never signs or submits a transaction.
//   Fabric : the reader identity asks BOTH organizations' peers for ReadOfficer / ReadBatch (evaluate only).
//   Sepolia: eth_call on the contract's readOfficer / readBatch views, plus the node's own finalized block.
// Input: one JSON object on stdin (paths and public identifiers only). Output: one JSON line, no paths, no keys, no raw errors.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const HEX = /^[0-9a-f]{64}$/;
const ABI = ['function readOfficer(bytes32 batch, bytes32 handle) view returns (bytes32)',
    'function readBatch(bytes32 batch) view returns (bytes32[5], uint256, bool)'];

function privateFile(file, limit = 65536) {
    const p = path.resolve(file), s = fs.lstatSync(p);
    if (!s.isFile() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077) || s.size > limit) throw new Error('PRIVATE_FILE_REQUIRED');
    return fs.readFileSync(p);
}
function validate(job) {
    const need = (v, ok) => { if (!ok) throw new Error('JOB_INVALID'); };
    need(job, job && typeof job === 'object');
    for (const k of ['batch', 'handle', 'commitment', 'merkle_root']) need(k, HEX.test(job[k] || ''));
    need('contract', /^0x[0-9a-fA-F]{40}$/.test(job.contract || ''));
    need('chain', Number.isInteger(job.chain_id) && Number.isInteger(job.sealing_block) && job.sealing_block > 0 && Number.isInteger(job.officers) && job.officers > 0);
    for (const k of ['fabric_config', 'fabric_sha256', 'network_config', 'network_sha256']) need(k, typeof job[k] === 'string' && job[k].length > 0);
    need('hashes', HEX.test(job.fabric_sha256) && HEX.test(job.network_sha256));
    return job;
}
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
// Only a short upper-case code is ever reported; raw messages (which can contain paths) are never passed on.
const code = error => {
    const value = error && error.code !== undefined ? error.code : error && error.message;
    return /^[A-Z][A-Z0-9_]{2,59}$/.test(String(value)) ? String(value) : (Number.isInteger(value) ? 'CODE_' + value : 'ERROR');
};

async function sepolia(job, deps) {
    const raw = privateFile(job.network_config);
    if (sha(raw) !== job.network_sha256) return {status: 'UNAVAILABLE', reason: 'NETWORK_CONFIG_DIFFERS'};
    const urls = JSON.parse(raw.toString()).rpc_urls;
    let last = 'NO_RPC';
    for (const url of urls) {
        try {
            const request = new deps.ethers.FetchRequest(url);
            request.timeout = 20000;
            const provider = new deps.ethers.JsonRpcProvider(request, job.chain_id, {staticNetwork: true});
            const contract = new deps.ethers.Contract(job.contract, ABI, provider);
            const [officer, batch] = await Promise.all([contract.readOfficer('0x' + job.batch, '0x' + job.handle), contract.readBatch('0x' + job.batch)]);
            const finalized = await provider.getBlock('finalized');
            const metadata = batch[0].map(v => v.slice(2).toLowerCase());
            const result = {
                status: 'READ', rpc_host: new URL(url).host, finalized_block: finalized.number,
                officer_value_matches_commitment: officer.slice(2).toLowerCase() === job.commitment,
                batch_root_present: metadata.includes(job.merkle_root), batch_officer_count: Number(batch[1]), batch_sealed: batch[2] === true,
                officer_count_matches: Number(batch[1]) === job.officers, sealed_block_is_finalized: finalized.number >= job.sealing_block};
            result.passed = result.officer_value_matches_commitment && result.batch_root_present && result.batch_sealed && result.officer_count_matches && result.sealed_block_is_finalized;
            provider.destroy();
            return result;
        } catch (error) {
            last = code(error);
        }
    }
    return {status: 'UNAVAILABLE', reason: last};
}

async function fabric(job, deps) {
    let connection;
    try {
        if (sha(privateFile(job.fabric_config)) !== job.fabric_sha256) return {status: 'UNAVAILABLE', reason: 'GATEWAY_CONFIG_DIFFERS'};
        connection = deps.connections(job.fabric_config, true, 'officer-evidence-v1');
        await connection.verifyNetwork();
        const officer = await connection.driver.observe('ReadOfficer', [job.batch, job.handle]);
        const batch = await connection.driver.observe('ReadBatch', [job.batch]);
        const orgs = Object.keys(officer).sort();
        const per = Object.fromEntries(orgs.map(org => [org, officer[org].commitment === job.commitment && officer[org].publication_id === job.handle && officer[org].batch_publication_id === job.batch]));
        const canonical = value => JSON.stringify(value, Object.keys(value).sort());
        const records = Object.values(batch).map(b => b.metadata || {});
        const roots = records.map(m => m.merkle_root);
        const result = {status: 'READ', organizations: orgs, each_organization_matches: per, organizations_agree: orgs.length === 2 && canonical(officer[orgs[0]]) === canonical(officer[orgs[1]]),
            batch_root_matches: roots.length === 2 && roots.every(r => r === job.merkle_root),
            batch_officer_count_matches: records.length === 2 && records.every(m => m.officer_count === job.officers), network_identity_verified: true};
        result.passed = orgs.join() === 'Org1MSP,Org2MSP' && Object.values(per).every(Boolean) && result.organizations_agree && result.batch_root_matches && result.batch_officer_count_matches;
        return result;
    } catch (error) {
        return {status: 'UNAVAILABLE', reason: code(error)};
    } finally {
        if (connection) connection.close();
    }
}

async function run(job, deps) {
    validate(job);
    const [chainFabric, chainSepolia] = await Promise.all([fabric(job, deps), sepolia(job, deps)]);
    return {policy: 'ORIGINAL_ANCHOR_LIVE_CHECK_V1', read_only: true, transactions_submitted: 0, checked_at: new Date().toISOString(),
        fabric: chainFabric, sepolia: chainSepolia, passed: chainFabric.passed === true && chainSepolia.passed === true};
}

async function main() {
    const input = fs.readFileSync(0, 'utf8');
    try {
        const deps = {ethers: require('ethers'), connections: require('../fabric/client/gateway').connections};
        process.stdout.write(JSON.stringify(await run(JSON.parse(input), deps)) + '\n');
        return 0;
    } catch (error) {
        process.stdout.write(JSON.stringify({policy: 'ORIGINAL_ANCHOR_LIVE_CHECK_V1', read_only: true, transactions_submitted: 0, passed: false, error: code(error)}) + '\n');
        return 1;
    }
}
if (require.main === module) main().then(c => { process.exitCode = c; });
module.exports = {run, validate, sepolia, fabric};
