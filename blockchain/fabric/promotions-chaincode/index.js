'use strict';
const {Contract} = require('fabric-contract-api');
const {PromotionsRules} = require('./lib/promotions');
// Separate deployable package. No update, delete, initialization or evidence API.
class PromotionsAnchor extends Contract {
    constructor() { super('PromotionsAnchor'); this.rules = new PromotionsRules(); }
    async AnchorPromotions(ctx,json) { return this.rules.AnchorPromotions(ctx,json); }
    async ReadPromotions(ctx,id) { return this.rules.ReadPromotions(ctx,id); }
}
module.exports.contracts = [PromotionsAnchor];
