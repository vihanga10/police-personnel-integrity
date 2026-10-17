'use strict';
// Pure schema/ABI preparation. Does not authenticate a receipt or submit a transaction.
const {encodeBytes32String}=require('ethers');
const {DATASETS}=require('../../fabric/intake-chaincode/lib/intake');
const POLICY='PERSONNEL_INTAKE_PUBLIC_ANCHOR_V1',NAMESPACE='personnel-intake-anchor-v1';
const METADATA=['public_sha256','merkle_root','fabric_destination_sha256','fabric_transaction_id','fabric_receipt_sha256'];
const FIELDS=['policy','namespace','dataset','publication_id',...METADATA];
function argumentsFor(payload){
    if(!payload||Object.getPrototypeOf(payload)!==Object.prototype||Reflect.ownKeys(payload).length!==FIELDS.length||
        !FIELDS.every(k=>Object.hasOwn(payload,k)))throw new Error('Exact public intake schema required');
    for(const k of FIELDS){const d=Object.getOwnPropertyDescriptor(payload,k);if(!d||!Object.hasOwn(d,'value'))throw new Error('Plain fields required');}
    if(payload.policy!==POLICY||payload.namespace!==NAMESPACE)throw new Error('Public intake policy/namespace differs');
    if(!DATASETS.includes(payload.dataset))throw new Error('Registered dataset code required');
    for(const k of ['publication_id',...METADATA]){
        if(typeof payload[k]!=='string'||! /^[0-9a-f]{64}$/.test(payload[k])||/^0{64}$/.test(payload[k]))throw new Error('Nonzero lowercase SHA-256 field required: '+k);
    }
    return ['0x'+payload.publication_id,encodeBytes32String(payload.dataset),METADATA.map(k=>'0x'+payload[k])];
}
module.exports={POLICY,NAMESPACE,METADATA,FIELDS,argumentsFor};
