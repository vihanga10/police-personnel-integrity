'use strict';
const {Contract} = require('fabric-contract-api');
const {AccountabilityRules} = require('./lib/accountability');
// Separate deployable package. No update, delete, initialization or evidence API.
class AccountabilityAnchor extends Contract {
    constructor() { super('AccountabilityAnchor'); this.rules = new AccountabilityRules(); }
    async AnchorAccountability(ctx,json) { return this.rules.AnchorAccountability(ctx,json); }
    async ReadAccountability(ctx,id) { return this.rules.ReadAccountability(ctx,id); }
}
module.exports.contracts = [AccountabilityAnchor];
