'use strict';
const {Contract} = require('fabric-contract-api');
const {IntakeRules} = require('./lib/intake');
// Separate deployable package. No update, delete, initialization or evidence API.
class IntakeAnchor extends Contract {
    constructor() { super('IntakeAnchor'); this.rules = new IntakeRules(); }
    async AnchorIntake(ctx,json) { return this.rules.AnchorIntake(ctx,json); }
    async ReadIntake(ctx,id) { return this.rules.ReadIntake(ctx,id); }
}
module.exports.contracts = [IntakeAnchor];
