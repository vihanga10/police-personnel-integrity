'use strict';
const fs = require('node:fs'), path = require('node:path');
const F = require('./deployment-files'), W = require('./sepolia-wallet'), R = require('./sepolia-rpc');
const { artifact } = require('./deployment-artifact');
const { run: verifyDeployment } = require('./deployment-engine');
const { authorize, recent } = require('./public-authorization');
const { run } = require('./publication-engine');
async function main(argv) {
    if (argv.length !== 7) throw new Error('Guarded Python launcher required');
    const [root, backup, ticketFile, directory, resultFile, mode, expectedRevision] = argv;
    const cp = require('node:child_process'), repo = path.resolve(__dirname, '../..');
    const git = (...args) => cp.execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    if (git('status', '--porcelain') || git('branch', '--show-current') !== 'feat/identity-resolution' || git('rev-parse', 'HEAD') !== expectedRevision) throw new Error('Committed launcher source differs');
    git('merge-base', '--is-ancestor', '94706a2', 'HEAD');
    const input = fs.readFileSync(0, 'utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(input)) throw new Error('Private session key required');
    const auth = authorize(F.read(ticketFile), Buffer.from(input, 'hex'), mode);
    const wallet = await W.load(root, backup), config = R.configuration(F.read(path.join(root, 'network.json')));
    const a = artifact(wallet.address), rpcs = config.urls.map(R.endpoint), deploymentRoot = path.join(root, 'deployment');
    const saved = F.read(path.join(deploymentRoot, 'PASSED.json'));
    if (saved.transaction_hash !== auth.payload.deployment_transaction || saved.contract_address !== '0x4Ae794040d9794cd3b50BB06Fd41eE540c2435a6') throw new Error('Original contract binding differs');
    // Read-only verification of the original deployed contract; no new deployment transaction.
    const verified = await verifyDeployment({ mode: 'VALIDATE', wallet, rpcs, config, artifact: a, directory: deploymentRoot });
    if (verified.status !== 'PASSED') throw new Error('Original deployment no longer reconciles');
    if (mode === 'RECONCILE') F.privateDir(directory);
    const result = await F.locked(directory, () => run({ mode, wallet, rpcs, config, artifact: a, deployment: saved,
        plan: auth.plan, digest: auth.payload.public_payload_sha256, directory,
        publicationBudget: auth.payload.publication_fee_budget_eth, guard: () => recent(auth.payload),
        receiptWaitMs: 45000, finalityWaitMs: 60000, pollIntervalMs: 3000,
        waitProgress: (phase, index) => console.log(`Public bounded wait: ${phase} | operation=${index}`),
        progress: n => console.log(`Public original receipts verified: ${n} / 68`),
        readProgress: n => console.log(`Public officer readback: ${n} / 6596`) }));
    F.write(resultFile, { ...result, code_revision: expectedRevision });
    console.log(`Guarded Sepolia publication ${mode}: ${result.status}`);
    // Do not print individual handles, full authorization, signed transactions or RPC credentials.
    const { transaction_hashes, ...summary } = result;
    console.log(JSON.stringify(summary));
    console.log('Original evidence and Fabric commitments preserved. Classification remains UNASSESSED; audit execution remains pending.');
}
if (require.main === module) main(process.argv.slice(2)).catch(error => {
    console.error('Public readback diagnostic:', JSON.stringify(R.safeFailure(error)));
    console.error('Public publication stopped. Private journals and original transactions preserved; rerun the guarded launcher with fresh evidence checks.');
    process.exitCode = 1;
});
module.exports = { main };
