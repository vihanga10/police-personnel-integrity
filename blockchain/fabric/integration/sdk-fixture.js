'use strict';
// Real protocol classes, artificial messages. No peer or endorsement claim.
const {common,peer,msp,gateway}=require('@hyperledger/fabric-protos');
const crypto=require('node:crypto');
const {canonical,RECORD_POLICY}=require('../findings-chaincode/lib/findings');
function prepared(payload,certificate=Buffer.from('offline fixture identity')){
    const sid=new msp.SerializedIdentity();sid.setMspid('Org1MSP');sid.setIdBytes(certificate);
    const creator=Buffer.from(sid.serializeBinary()),nonce=crypto.randomBytes(24),id=crypto.createHash('sha256').update(Buffer.concat([nonce,creator])).digest('hex');
    const sh=new common.SignatureHeader();sh.setCreator(creator);sh.setNonce(nonce);
    const ch=new common.ChannelHeader();ch.setType(3);ch.setChannelId('personnel');ch.setTxId(id);
    const header=new common.Header();header.setChannelHeader(ch.serializeBinary());header.setSignatureHeader(sh.serializeBinary());
    const cc=new peer.ChaincodeID();cc.setName('findings-anchor-v1');
    const input=new peer.ChaincodeInput();input.setArgsList([Buffer.from('FindingsAnchor:AnchorFindings'),Buffer.from(canonical(payload))]);
    const spec=new peer.ChaincodeSpec();spec.setType(1);spec.setChaincodeId(cc);spec.setInput(input);
    const invoke=new peer.ChaincodeInvocationSpec();invoke.setChaincodeSpec(spec);
    const cpp=new peer.ChaincodeProposalPayload();cpp.setInput(invoke.serializeBinary());
    const expected={policy:RECORD_POLICY,payload,transaction_id:id};
    const response=new peer.Response();response.setStatus(200);response.setPayload(Buffer.from(canonical(expected)));
    const ca=new peer.ChaincodeAction();ca.setResponse(response);ca.setChaincodeId(cc);
    const prp=new peer.ProposalResponsePayload();prp.setProposalHash(crypto.randomBytes(32));prp.setExtension$(ca.serializeBinary());
    const ea=new peer.ChaincodeEndorsedAction();ea.setProposalResponsePayload(prp.serializeBinary());
    const cap=new peer.ChaincodeActionPayload();cap.setChaincodeProposalPayload(cpp.serializeBinary());cap.setAction(ea);
    const action=new peer.TransactionAction();action.setHeader(sh.serializeBinary());action.setPayload(cap.serializeBinary());
    const transaction=new peer.Transaction();transaction.setActionsList([action]);
    const body=new common.Payload();body.setHeader(header);body.setData(transaction.serializeBinary());
    const envelope=new common.Envelope();envelope.setPayload(body.serializeBinary());
    const prepared=new gateway.PreparedTransaction();prepared.setTransactionId(id);prepared.setEnvelope(envelope);
    return {bytes:Buffer.from(prepared.serializeBinary()),raw:Buffer.from(body.serializeBinary()),expected,id,certificate};
}
module.exports={prepared};
