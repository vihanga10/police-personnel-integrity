'use strict';
const {Contract} = require('fabric-contract-api');
const {FindingsRules} = require('./lib/findings');
// Separate deployable package. No update, delete, initialization or evidence API.
class FindingsAnchor extends Contract {
    constructor() { super('FindingsAnchor'); this.rules = new FindingsRules(); }
    async AnchorFindings(ctx,json) { return this.rules.AnchorFindings(ctx,json); }
    async ReadFindings(ctx,id) { return this.rules.ReadFindings(ctx,id); }
}
module.exports.contracts = [FindingsAnchor];
