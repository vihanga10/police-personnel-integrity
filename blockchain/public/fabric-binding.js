'use strict';
function requireEqual(value,expected,message){if(value!==expected)throw new Error(message);}
function bindCapturedReceipt(receipt,publication,digest){
    requireEqual(receipt.status,'PASSED','Saved workflow status differs');
    requireEqual(receipt.mode,'RECONCILE','Saved read-only reconciliation required');
    requireEqual(receipt.public_payload_sha256,digest,'Saved publication digest differs');
    const r=receipt.fabric_result;
    if(!r || !r.network || !r.network.genesis_identity) throw new Error('Saved Fabric result missing');
    requireEqual(r.status,'PASSED','Saved Fabric status differs');
    requireEqual(r.mode,'RECONCILE','Saved Fabric mode differs');
    requireEqual(r.public_payload_sha256,digest,'Saved Fabric digest differs');
    requireEqual(r.officers,6596,'Saved officer count differs');
    requireEqual(r.original_valid_transactions,68,'Saved receipt count differs');
    requireEqual(r.two_organization_readback,true,'Saved peer readback missing');
    requireEqual(r.batch_publication_id,publication.batch_publication_id,'Saved batch differs');
    requireEqual(r.merkle_root,publication.merkle_root,'Saved Merkle root differs');
    requireEqual(r.classification,'UNASSESSED','Saved classification differs');
    requireEqual(r.network.channel,'personnel','Saved channel differs');
    requireEqual(r.network.chaincode,'officer-evidence-v1','Saved chaincode differs');
    // Pin this research network's previously reconciled genesis, not a test namespace.
    requireEqual(r.network.genesis_sha256,'7e496158e847bd1ed07232f4790331f9ec9a6639e3419e2e98ea55a89948016e','Saved genesis capture differs');
    requireEqual(r.network.genesis_identity.policy,'FABRIC_GENESIS_HEADER_DATA_V1','Saved identity policy differs');
    requireEqual(r.network.genesis_identity.header_sha256,'b9ed551d2ce23b9ac765e6e9e9966ce498e7b09e85450fb98103e38354588cb6','Saved genesis header differs');
    requireEqual(r.network.genesis_identity.data_sha256,'2d4a456cfa91b90cbbd152d47ee960f07a42be2eba401d4a0bedddf42064d434','Saved genesis data differs');
    return true;
}
module.exports={bindCapturedReceipt};
