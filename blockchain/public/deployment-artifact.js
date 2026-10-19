'use strict';
const fs=require('node:fs'),path=require('node:path'),solc=require('solc');
const {getAddress}=require('ethers'),F=require('./deployment-files'),{compile}=require('./compile');
function artifact(writer){writer=getAddress(writer);const base=compile(),source=fs.readFileSync(path.join(__dirname,'contracts/OfficerEvidence.sol'),'utf8');
    const settings={...base.settings,outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences'],'':['ast']}}};
    const out=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'OfficerEvidence.sol':{content:source}},settings})));
    if((out.errors||[]).some(e=>e.severity==='error'))throw new Error('Compilation failed');
    const c=out.contracts['OfficerEvidence.sol'].OfficerEvidence;
    if('0x'+c.evm.bytecode.object!==base.bytecode||'0x'+c.evm.deployedBytecode.object!==base.runtime)throw new Error('Compiler outputs differ');
    const declarations=out.sources['OfficerEvidence.sol'].ast.nodes.filter(n=>n.nodeType==='ContractDefinition').flatMap(n=>n.nodes);
    const variable=declarations.find(n=>n.nodeType==='VariableDeclaration'&&n.name==='writer'&&n.mutability==='immutable');
    const refs=c.evm.deployedBytecode.immutableReferences;
    if(!variable||Object.keys(refs).length!==1||!refs[String(variable.id)]?.length)throw new Error('Writer immutable binding differs');
    const bytes=Buffer.from(c.evm.deployedBytecode.object,'hex'),address=Buffer.from(writer.slice(2).padStart(64,'0'),'hex');
    for(const r of refs[String(variable.id)]){if(r.length!==32||r.start<0||r.start+32>bytes.length)throw new Error('Immutable position differs');address.copy(bytes,r.start);}
    const runtime='0x'+bytes.toString('hex');
    return {abi:base.abi,bytecode:base.bytecode,runtime,source_sha256:F.digest(source),creation_sha256:F.digest(base.bytecode),runtime_sha256:F.digest(runtime),compiler:base.compiler,settings_sha256:F.digest(base.settings),writer};
}
module.exports={artifact};
