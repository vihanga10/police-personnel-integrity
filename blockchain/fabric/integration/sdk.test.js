'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const sdk=require('@hyperledger/fabric-gateway'),grpc=require('@grpc/grpc-js');
const {common}=require('@hyperledger/fabric-protos');const {prepared}=require('./sdk-fixture');
const B=require('../client/findings-block');
const payload=require('../findings-chaincode/test/commitment-vector.json').payload;
const dest={genesis_sha256:'a'.repeat(64),channel:'personnel',chaincode:'findings-anchor-v1',namespace:'findings-anchor-v1',organizations:['Org1MSP','Org2MSP']};
function connect(t){const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),client=new grpc.Client('127.0.0.1:1',grpc.credentials.createInsecure());
    const g=sdk.connect({client,identity:{mspId:'Org1MSP',credentials:Buffer.from('offline fixture identity')},signer:sdk.signers.newPrivateKeySigner(pair.privateKey),hash:sdk.hash.sha256});
    t.after(()=>{g.close();client.close();});return g;}
test('pinned genuine SDK/protobuf/grpc versions loaded',()=>{
    assert.equal(require('@hyperledger/fabric-gateway/package.json').version,'1.8.0');assert.equal(require('@grpc/grpc-js/package.json').version,'1.14.4');assert.equal(require('@hyperledger/fabric-protos/package.json').version,'0.3.7');
});
test('real SDK rehydrates official PreparedTransaction bytes/result/digest',t=>{
    const f=prepared(payload),tx=connect(t).newTransaction(f.bytes);assert.equal(tx.getTransactionId(),f.id);assert.deepEqual(Buffer.from(tx.getBytes()),f.bytes);
    assert.deepEqual(JSON.parse(Buffer.from(tx.getResult()).toString()),f.expected);assert.deepEqual(Buffer.from(tx.getDigest()),crypto.createHash('sha256').update(f.raw).digest());
});
test('bounded existing parser accepts full real-protobuf prepared transaction',()=>{
    const f=prepared(payload),r=B.prepared(f.bytes,payload,dest,f.certificate);assert.equal(r.id,f.id);assert.deepEqual(r.payload,f.raw);
});
test('genuine SDK creates and rehydrates proposal with exact method and independent nonce',t=>{
    const g=connect(t),c=g.getNetwork('personnel').getContract('findings-anchor-v1','FindingsAnchor');
    const a=c.newProposal('AnchorFindings',{arguments:[JSON.stringify(payload)],endorsingOrganizations:['Org1MSP','Org2MSP']});
    const restored=g.newProposal(a.getBytes());assert.equal(restored.getTransactionId(),a.getTransactionId());assert.deepEqual(Buffer.from(restored.getBytes()),Buffer.from(a.getBytes()));
    assert.notEqual(c.newProposal('AnchorFindings',{arguments:[JSON.stringify(payload)]}).getTransactionId(),a.getTransactionId());
});
test('existing block verifier accepts official protobuf block and rejects INVALID flag',()=>{
    const f=prepared(payload),envelope=new common.Envelope();envelope.setPayload(f.raw);envelope.setSignature(Buffer.from('artificial signature'));
    const eb=Buffer.from(envelope.serializeBinary()),h=new common.BlockHeader();h.setNumber(1);h.setPreviousHash(crypto.randomBytes(32));h.setDataHash(crypto.createHash('sha256').update(eb).digest());
    const data=new common.BlockData();data.setDataList([eb]);const meta=new common.BlockMetadata();meta.setMetadataList([Buffer.alloc(0),Buffer.alloc(0),Buffer.from([0])]);
    const b=new common.Block();b.setHeader(h);b.setData(data);b.setMetadata(meta);assert.equal(B.committed(b.serializeBinary(),f.raw,f.id,'personnel').block_number,'1');
    meta.setMetadataList([Buffer.alloc(0),Buffer.alloc(0),Buffer.from([11])]);assert.throws(()=>B.committed(b.serializeBinary(),f.raw,f.id,'personnel'),/not VALID/);
});
test('real SDK malformed transaction fails without RPC',t=>assert.throws(()=>connect(t).newTransaction(Buffer.from([0xff]))));
test('real fabric-contract-api instantiates dedicated wrapper without mocking',()=>{
    const Contract=require('../findings-chaincode').contracts[0],c=new Contract();assert.equal(c.getName(),'FindingsAnchor');assert.equal(typeof c.AnchorFindings,'function');assert.equal(typeof c.ReadFindings,'function');
});
test('real fabric-shim decodes the fixture X509 findings attribute and rejects evidence-only',t=>{
    const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{execFileSync}=require('node:child_process');
    const dir=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'findings-sdk-cert-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
    for(const kind of ['findings.anchor','evidence.anchor']){
        const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem'),cfg=path.join(dir,'config.cnf');
        const attrs=Buffer.from(JSON.stringify({attrs:{[kind]:'true'}})).toString('hex').match(/../g).join(':');
        fs.writeFileSync(cfg,'[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=fixture-client\nOU=client\n[ext]\n1.2.3.4.5.6.7.8.1=DER:'+attrs+'\n',{mode:0o600});
        execFileSync('openssl',['ecparam','-name','prime256v1','-genkey','-noout','-out',key]);
        execFileSync('openssl',['req','-new','-x509','-key',key,'-out',cert,'-days','1','-config',cfg],{stdio:'ignore'});
        const {ClientIdentity}=require('fabric-shim');const cid=new ClientIdentity({getChannelID:()=> 'personnel',getTxID:()=> 'fixture',getCreator:()=>({mspid:'Org1MSP',idBytes:fs.readFileSync(cert)})});
        assert.equal(cid.assertAttributeValue('findings.anchor','true'),kind==='findings.anchor');
    }
});
test('official lifecycle protobuf decodes reordered approvals with identical definition values',()=>{
    const {definitionHash,normalized}=require('../client/findings-definition');
    const T=require('@hyperledger/fabric-protos').peer.lifecycle.QueryChaincodeDefinitionResult;
    const base=Buffer.from('08011203312e301a04657363632204767363632a2e0a2c120c120a080212020800120208011a0d120b0a074f7267314d535010031a0d120b0a074f7267324d535010033200','hex');
    const a=Buffer.from('420b0a074f7267314d53501001','hex'),b=Buffer.from('420b0a074f7267324d53501001','hex');
    const left=Buffer.concat([base,a,b]),right=Buffer.concat([base,b,a]);
    const object=bytes=>{const o=T.deserializeBinary(bytes).toObject();o.approvalsMap.sort((a,b)=>a[0].localeCompare(b[0]));return o;};
    assert.deepEqual(object(left),object(right));assert.deepEqual(object(normalized(right)),object(left));
    assert.equal(definitionHash(left),definitionHash(right));assert.equal(object(left).sequence,1);
    assert.deepEqual(object(left).approvalsMap,[['Org1MSP',true],['Org2MSP',true]]);
});
