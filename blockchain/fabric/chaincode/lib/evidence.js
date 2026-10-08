'use strict';
// Dependency-free contract rules; the Fabric adapter supplies its authenticated context.
const crypto = require('node:crypto');
const POLICY = 'OFFICER_PROTECTED_COMMITMENT_V1';
const HEX = /^[0-9a-f]{64}$/;
const SIZE = 100, COUNT = 6596, CHUNKS = Math.ceil(COUNT / SIZE);
const metadataKeys = ['policy', 'commitment_version', 'key_version', 'batch_publication_id', 'shared_commitment',
    'coverage_commitment', 'batch_commitment', 'merkle_root', 'officer_count', 'public_payload_sha256'];
function check(condition, message) { if (!condition) throw new Error(message); }
function exact(value, keys) {
    check(value !== null && typeof value === 'object' && !Array.isArray(value) &&
        Object.keys(value).sort().join(',') === [...keys].sort().join(','), 'Unexpected payload fields');
}
function canonical(value) {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value !== null && typeof value === 'object') {
        return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
    }
    check(value === null || typeof value === 'string' || typeof value === 'boolean' || Number.isSafeInteger(value), 'Unsupported JSON type');
    return JSON.stringify(value);
}
function sha(value) { return crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex'); }
function tree(leaves) {
    let nodes = leaves.map(leaf => crypto.createHash('sha256').update(Buffer.from([0])).update(canonical(leaf), 'utf8').digest());
    check(nodes.length > 0, 'Empty tree');
    while (nodes.length > 1) {
        if (nodes.length % 2) nodes.push(nodes[nodes.length - 1]);
        const parents = [];
        for (let i = 0; i < nodes.length; i += 2) parents.push(crypto.createHash('sha256').update(Buffer.from([1])).update(nodes[i]).update(nodes[i+1]).digest());
        nodes = parents;
    }
    return nodes[0].toString('hex');
}
function validateMetadata(data) {
    exact(data, metadataKeys);
    check(data.policy === POLICY && data.commitment_version === 1 && data.key_version === 'commit-v1' && data.officer_count === COUNT, 'Unexpected batch policy');
    for (const name of ['batch_publication_id', 'shared_commitment', 'coverage_commitment', 'batch_commitment', 'merkle_root', 'public_payload_sha256']) {
        check(typeof data[name] === 'string' && HEX.test(data[name]), 'Invalid protected digest');
    }
    return data;
}
function validateRecords(rows) {
    check(Array.isArray(rows) && rows.length > 0 && rows.length <= SIZE, 'Invalid chunk size');
    let previous = '';
    for (const row of rows) {
        exact(row, ['publication_id', 'commitment_version', 'commitment']);
        check(row.commitment_version === 1 && typeof row.publication_id === 'string' && HEX.test(row.publication_id) &&
            typeof row.commitment === 'string' && HEX.test(row.commitment) && row.publication_id > previous, 'Invalid or unordered officer commitment');
        previous = row.publication_id;
    }
}
function writer(ctx) {
    check(ctx.clientIdentity.getMSPID() === 'Org1MSP' &&
        ctx.clientIdentity.assertAttributeValue('evidence.anchor', 'true'), 'Anchoring identity not authorized');
}
function reader(ctx) { check(['Org1MSP', 'Org2MSP'].includes(ctx.clientIdentity.getMSPID()), 'Reader MSP not authorized'); }
function id(batch) { check(typeof batch === 'string' && HEX.test(batch), 'Invalid batch handle'); return batch; }
const key = (kind, batch, suffix = '') => `evidence-v1:${kind}:${id(batch)}${suffix ? ':'+suffix : ''}`;
async function read(ctx, stateKey) {
    const bytes = await ctx.stub.getState(stateKey);
    return bytes.length ? JSON.parse(bytes.toString('utf8')) : null;
}
async function append(ctx, stateKey, value) {
    // A read-before-write gives Fabric an MVCC read dependency against competing inserts.
    check(await read(ctx, stateKey) === null, 'Immutable key already exists');
    await ctx.stub.putState(stateKey, Buffer.from(canonical(value), 'utf8'));
}
function transaction(ctx) { const tx = ctx.stub.getTxID(); check(HEX.test(tx), 'Invalid transaction ID'); return tx; }

class EvidenceRules {
    async CreateBatch(ctx, json) {
        writer(ctx); check(Buffer.byteLength(json, 'utf8') <= 4096, 'Batch input too large');
        const metadata = validateMetadata(JSON.parse(json)); const stateKey = key('batch', metadata.batch_publication_id);
        const existing = await read(ctx, stateKey);
        if (existing) { check(canonical(existing.metadata) === canonical(metadata), 'Conflicting immutable batch'); return existing; }
        const result = { metadata, transaction_id: transaction(ctx) };
        await append(ctx, stateKey, result); return result;
    }
    async AppendOfficers(ctx, batch, indexText, json) {
        writer(ctx); id(batch); check(/^(0|[1-9][0-9]*)$/.test(indexText), 'Invalid chunk index');
        const index = Number(indexText); check(index < CHUNKS && Buffer.byteLength(json, 'utf8') <= 32768, 'Chunk input too large');
        const rows = JSON.parse(json); validateRecords(rows);
        check(rows.length === (index === CHUNKS-1 ? COUNT-SIZE*index : SIZE), 'Incomplete officer chunk');
        const registered = await read(ctx, key('batch', batch)); check(registered !== null, 'Batch not registered');
        const chunkKey = key('chunk', batch, String(index).padStart(3, '0'));
        const fingerprint = sha(rows), prior = await read(ctx, chunkKey);
        if (prior) { check(prior.records_sha256 === fingerprint, 'Conflicting immutable chunk'); return prior; }
        check(await read(ctx, key('seal', batch)) === null, 'Batch already sealed');
        if (index > 0) {
            const previous = await read(ctx, key('chunk', batch, String(index-1).padStart(3, '0')));
            check(previous !== null && previous.publication_ids[previous.publication_ids.length-1] < rows[0].publication_id, 'Chunks must be sequential and ordered');
        }
        const tx = transaction(ctx);
        // Validate all keys before writes; a failed Fabric invocation discards its complete write set.
        for (const row of rows) check(await read(ctx, key('officer', batch, row.publication_id)) === null, 'Officer already committed');
        for (const row of rows) await append(ctx, key('officer', batch, row.publication_id), { batch_publication_id: batch, ...row, transaction_id: tx });
        const result = { index, records_sha256: fingerprint, publication_ids: rows.map(r => r.publication_id), transaction_id: tx };
        await append(ctx, chunkKey, result); return result;
    }
    async SealBatch(ctx, batch) {
        writer(ctx); id(batch);
        const registered = await read(ctx, key('batch', batch)); check(registered !== null, 'Batch not registered');
        const existing = await read(ctx, key('seal', batch)); if (existing) return existing;
        const rows = [];
        for (let index = 0; index < CHUNKS; index++) {
            const chunk = await read(ctx, key('chunk', batch, String(index).padStart(3, '0'))); check(chunk !== null, 'Batch coverage incomplete');
            const part = [];
            for (const handle of chunk.publication_ids) {
                const stored = await read(ctx, key('officer', batch, handle)); check(stored !== null && stored.transaction_id === chunk.transaction_id, 'Officer evidence missing');
                part.push({ publication_id: stored.publication_id, commitment_version: stored.commitment_version, commitment: stored.commitment });
            }
            validateRecords(part); check(sha(part) === chunk.records_sha256, 'Chunk content differs'); rows.push(...part);
        }
        check(rows.length === COUNT && new Set(rows.map(r => r.publication_id)).size === COUNT &&
            new Set(rows.map(r => r.commitment)).size === COUNT && rows.every((r, i) => i === 0 || rows[i-1].publication_id < r.publication_id), 'Officer coverage differs');
        const metadata = registered.metadata;
        const publication = Object.fromEntries(Object.entries(metadata).filter(([k]) => !['officer_count', 'public_payload_sha256'].includes(k)));
        publication.officers = rows;
        check(sha(publication) === metadata.public_payload_sha256, 'Publication payload differs');
        const leaves = rows.map(r => ({ kind: 'OFFICER', ...r }));
        leaves.push({ kind: 'BATCH', publication_id: batch, commitment: metadata.batch_commitment });
        check(tree(leaves) === metadata.merkle_root, 'Publication Merkle root differs');
        const result = { batch_publication_id: batch, public_payload_sha256: metadata.public_payload_sha256,
            officer_count: COUNT, merkle_root: metadata.merkle_root, transaction_id: transaction(ctx) };
        await append(ctx, key('seal', batch), result); return result;
    }
    async ReadBatch(ctx, batch) { reader(ctx); const result = await read(ctx, key('batch', batch)); check(result !== null, 'Batch absent'); return result; }
    async ReadOfficer(ctx, batch, handle) { reader(ctx); check(HEX.test(handle), 'Invalid officer handle'); const result = await read(ctx, key('officer', batch, handle)); check(result !== null, 'Officer absent'); return result; }
    async ReadChunk(ctx, batch, indexText) { reader(ctx); check(/^(0|[1-9][0-9]*)$/.test(indexText) && Number(indexText) < CHUNKS, 'Invalid chunk index'); const result = await read(ctx, key('chunk', batch, indexText.padStart(3, '0'))); check(result !== null, 'Chunk absent'); return result; }
    async ReadSeal(ctx, batch) { reader(ctx); const result = await read(ctx, key('seal', batch)); check(result !== null, 'Seal absent'); return result; }
}
module.exports = { EvidenceRules, canonical, sha, tree, validateMetadata, validateRecords, key, POLICY };
