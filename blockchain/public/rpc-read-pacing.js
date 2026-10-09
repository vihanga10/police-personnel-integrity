'use strict';
const { performance } = require('node:perf_hooks');
// Per-provider scheduling counts logical reads, not merely HTTP batches.
// A ten-read batch reserves 1 second at the conservative default 100 ms/read.
function readPacing({ sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
    clock = () => performance.now(), intervalMs = 100, cooldownMs = 5000 } = {}) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 1000 ||
        !Number.isSafeInteger(cooldownMs) || cooldownMs < 5000 || cooldownMs > 30000)
        throw new Error('Invalid RPC pacing bounds');
    let tail = Promise.resolve(), next = 0, cool = 0;
    function cooldown() { cool = Math.max(cool, clock() + cooldownMs); }
    function run(weight, action) {
        if (!Number.isSafeInteger(weight) || weight < 1 || weight > 10 || typeof action !== 'function')
            return Promise.reject(new Error('Invalid RPC read weight'));
        const task = tail.then(async () => {
            // Recheck after sleep: a concurrent response can impose a cooldown.
            while (clock() < Math.max(next, cool)) await sleep(Math.max(next, cool) - clock());
            next = clock() + weight * intervalMs;
            return action();
        });
        // Preserve each caller's failure while allowing later queued reads to run.
        tail = task.catch(() => {});
        return task;
    }
    return { run, cooldown };
}
module.exports = { readPacing };
