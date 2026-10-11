'use strict';
// No configured public RPC/wallet factory is provisioned. Never load a fixture,
// user module, environment endpoint or fallback from the production pipe entry.
async function loadConfiguredTransport(){
    throw new Error('Public runtime is not provisioned; live transport remains disabled');
}
module.exports={loadConfiguredTransport};
