'use strict';
const fs=require('node:fs'),path=require('node:path'),solc=require('solc');
function compile() {
    if (!solc.version().startsWith('0.8.30+commit.73712a01.')) throw new Error('Pinned compiler differs');
    const input={language:'Solidity',sources:{'OfficerEvidence.sol':{content:fs.readFileSync(path.join(__dirname,'contracts/OfficerEvidence.sol'),'utf8')}},settings:{optimizer:{enabled:true,runs:200},viaIR:false,evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}};
    const output=JSON.parse(solc.compile(JSON.stringify(input)));
    const errors=(output.errors||[]).filter(e=>e.severity==='error');
    if(errors.length) throw new Error(errors.map(e=>e.formattedMessage).join('\n'));
    const contract=output.contracts['OfficerEvidence.sol'].OfficerEvidence;
    return {abi:contract.abi,bytecode:'0x'+contract.evm.bytecode.object,runtime:'0x'+contract.evm.deployedBytecode.object,compiler:solc.version(),settings:input.settings};
}
module.exports={compile};
