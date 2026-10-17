'use strict';
const fs=require('node:fs'),path=require('node:path'),solc=require('solc');
const SOURCE='PersonnelIntakeAnchor.sol';
function compile(){
    if(!solc.version().startsWith('0.8.30+commit.73712a01.'))throw new Error('Pinned compiler differs');
    const input={language:'Solidity',sources:{[SOURCE]:{content:fs.readFileSync(path.join(__dirname,'contracts',SOURCE),'utf8')}},
        settings:{optimizer:{enabled:true,runs:200},viaIR:false,evmVersion:'shanghai',
            outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}}};
    const output=JSON.parse(solc.compile(JSON.stringify(input)));
    const errors=(output.errors||[]).filter(e=>e.severity==='error');
    if(errors.length)throw new Error(errors.map(e=>e.formattedMessage).join('\n'));
    const c=output.contracts[SOURCE].PersonnelIntakeAnchor;
    return {abi:c.abi,bytecode:'0x'+c.evm.bytecode.object,runtimeTemplate:'0x'+c.evm.deployedBytecode.object,
        immutableReferences:c.evm.deployedBytecode.immutableReferences,compiler:solc.version(),settings:input.settings};
}
module.exports={compile,SOURCE};
