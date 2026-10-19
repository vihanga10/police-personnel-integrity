'use strict';
const { Contract } = require('fabric-contract-api');
const { EvidenceRules } = require('./lib/evidence');
// Only these explicit transaction methods are exported; no update/delete/initialization API exists.
class OfficerEvidence extends Contract {
    constructor() { super('OfficerEvidence'); this.rules = new EvidenceRules(); }
    async CreateBatch(ctx, json) { return this.rules.CreateBatch(ctx, json); }
    async AppendOfficers(ctx, batch, index, json) { return this.rules.AppendOfficers(ctx, batch, index, json); }
    async SealBatch(ctx, batch) { return this.rules.SealBatch(ctx, batch); }
    async ReadBatch(ctx, batch) { return this.rules.ReadBatch(ctx, batch); }
    async ReadOfficer(ctx, batch, handle) { return this.rules.ReadOfficer(ctx, batch, handle); }
    async ReadChunk(ctx, batch, index) { return this.rules.ReadChunk(ctx, batch, index); }
    async ReadSeal(ctx, batch) { return this.rules.ReadSeal(ctx, batch); }
}
module.exports.contracts = [OfficerEvidence];
