'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {definitionHash,normalized}=require('../client/findings-definition');
const {observeRead,transient}=require('../client/findings-observation');
const base=Buffer.from('08011203312e301a04657363632204767363632a2e0a2c120c120a080212020800120208011a0d120b0a074f7267314d535010031a0d120b0a074f7267324d535010033200','hex');
const a=Buffer.from('420b0a074f7267314d53501001','hex'),b=Buffer.from('420b0a074f7267324d53501001','hex');
const golden=Buffer.concat([base,a,b]),reverse=Buffer.concat([base,b,a]);
test('actual Mac response vectors differ in bytes but keep all approvals and definition pins',()=>{
 assert.notDeepEqual(golden,reverse);assert.equal(definitionHash(golden),definitionHash(reverse));assert.deepEqual(normalized(golden),golden);
});
for(const [name,offset] of [['sequence',1],['version',6],['endorsement plugin',11],['validation plugin',17],['validation policy',35],['approval boolean',golden.length-1]])test('rejects changed pin: '+name,()=>{
 const changed=Buffer.from(golden);changed[offset]=name==='sequence'?2:changed[offset]^1;assert.notEqual(definitionHash(changed),definitionHash(golden));
});
test('collection configuration remains byte-exact',()=>{
 const changed=Buffer.concat([base.subarray(0,base.length-2),Buffer.from('32020a00','hex'),a,b]);assert.notEqual(definitionHash(changed),definitionHash(golden));
});
test('init-required value remains pinned',()=>assert.notEqual(definitionHash(Buffer.concat([base,Buffer.from([0x38,1]),a,b])),definitionHash(golden)));
test('approval removal remains pinned',()=>assert.notEqual(definitionHash(Buffer.concat([base,a])),definitionHash(golden)));
for(const [name,bytes] of [
 ['duplicate approval',Buffer.concat([golden,a])],['duplicate singleton',Buffer.concat([golden,Buffer.from([8,1])])],
 ['unknown field',Buffer.concat([golden,Buffer.from([0x48,1])])],['truncated',golden.subarray(0,golden.length-1)],
 ['overlong varint',Buffer.concat([Buffer.from([8,0x81,0]),golden.subarray(2)])],['invalid approval boolean',Buffer.concat([base,Buffer.from('420b0a074f7267314d53501002','hex'),b])],
 ['empty',Buffer.alloc(0)],['oversize',Buffer.alloc(1048577)]])test('malformed definition fails closed: '+name,()=>assert.throws(()=>definitionHash(bytes)));
const id='a'.repeat(64),missing=Object.assign(new Error('no such transaction ID ['+id+'] in index'),{code:2});
test('index lag retries original-ID reads only',async()=>{
 let calls=0,sleeps=0;const result=await observeRead(async()=>{if(++calls<3)throw missing;return 'original commit';},id,{sleep:async()=>{sleeps++;}});
 assert.equal(result,'original commit');assert.equal(calls,3);assert.equal(sleeps,2);
});
for(const code of [4,14])test('temporary transport code '+code+' retries read',async()=>{let n=0;assert.equal(await observeRead(async()=>{if(++n===1)throw Object.assign(new Error('temporary'),{code});return 1;},id,{sleep:async()=>{}}),1);});
for(const error of [new Error('Approved chaincode definition differs'),Object.assign(new Error('access denied'),{code:9}),Object.assign(new Error('chaincode response 500: forbidden'),{code:2}),Object.assign(new Error('no such transaction ID ['+'b'.repeat(64)+'] in index'),{code:2}),new Error('INVALID commit')])test('nontransient failure is not retried: '+error.message,async()=>{let calls=0;await assert.rejects(observeRead(async()=>{calls++;throw error;},id,{sleep:async()=>{}}),e=>e===error);assert.equal(calls,1);});
test('index exhaustion returns uncertainty, never ABSENT',async()=>{let calls=0;await assert.rejects(observeRead(async()=>{calls++;throw missing;},id,{attempts:3,sleep:async()=>{}}),e=>e===missing);assert.equal(calls,3);});
test('time budget stops further reads',async()=>{let calls=0,t=0;await assert.rejects(observeRead(async()=>{calls++;throw missing;},id,{now:()=>t,budget:10,sleep:async()=>{t+=10;}}));assert.equal(calls,2);});
test('invalid original ID rejected before reading',async()=>{let calls=0;await assert.rejects(observeRead(async()=>calls++,'bad'));assert.equal(calls,0);});
