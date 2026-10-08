'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {identity,verifyPeer}=require('../block-identity');
function v(n){const b=[];do{let x=n&127;n>>>=7;if(n)x|=128;b.push(x);}while(n);return Buffer.from(b);}
function f(n,value){return Buffer.concat([v(n*8+2),v(value.length),Buffer.from(value)]);}
function block({number=0,previous='',hash='a'.repeat(32),data='config',metadata='orderer'}={}){
    return Buffer.concat([f(1,Buffer.concat([Buffer.from([8,number]),f(2,previous),f(3,hash)])),f(2,f(1,data)),f(3,f(1,metadata))]);}
test('same header and contents despite different peer metadata',()=>{
 const captured=identity(block());assert.deepEqual(verifyPeer(captured,block({metadata:'peer validation flags'})),captured);
});
for(const change of [{hash:'b'.repeat(32)},{data:'changed config'},{number:1},{previous:'prior block'}])test('reject changed genesis '+JSON.stringify(change),()=>assert.throws(()=>verifyPeer(identity(block()),block(change))));
for(const bytes of [Buffer.from([10,255]),Buffer.concat([block(),f(1,'duplicate')]),Buffer.concat([block(),f(4,'unknown')]),Buffer.from([10,128,0]),Buffer.concat([f(1,f(3,'short')),f(2,f(1,'data')),f(3,Buffer.alloc(0))])])test('reject malformed or ambiguous protobuf '+bytes.length,()=>assert.throws(()=>identity(bytes)));
test('network descriptor preserves whole-file capture and adds content policy',()=>{
 const fs=require('node:fs');const source=fs.readFileSync(require.resolve('../gateway'),'utf8');
 assert.match(source,/Saved genesis file differs/);assert.match(source,/genesis_identity:genesisIdentity/);
});
