"""Disposable source-gate substitute around the ACTUAL backend service/worker.

TEST ONLY. Does not replay research evidence or establish an AlgorithmPermit.
No production library is changed. Requires the launcher's owned test marker.
"""
import ast
import base64
from copy import deepcopy
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import types

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def require(value,message):
    if not value:raise ValueError(message)


def encoded(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def main():
    root=Path(os.environ['PPI_TEST_ROOT']).resolve()
    require(json.loads((root/'ISOLATED-RUN.json').read_text())['policy']=='PPI_DISPOSABLE_FINDINGS_FABRIC_V1',
            'Owned disposable run required')
    file=Path(sys.argv[1]).resolve()
    require(file.is_relative_to(root) and not file.is_symlink(),'Private fixture request required')
    request=json.loads(file.read_text());job=request['fabric_job']
    require(request['policy']=='PPI_BACKEND_PIPELINE_FIXTURE_V1' and job['repo']=='/work/pipeline',
            'Disposable backend policy required')
    require(job['mode'] in ('EXECUTE','RECONCILE'),'Fixture mode required')
    for name in ('gatewayConfigFile','witnessConfigFile','directory','recoveryKeyFile'):
        require(Path(job[name]).resolve().is_relative_to(root),'Fixture paths must stay inside owned root')
    calls=[]
    phase=request['phase']
    require(phase in ('fabric','public-plan','public-run'),'Isolated pipeline phase required')
    class FindingsBackendGate:
        def __init__(self,mode):
            self.repo=Path('/work/pipeline');self.revision=job['selection']['code_revision'];self.mode=mode
            self._selection=deepcopy(job['selection'])
            stores=[]
            for name in ('commitment','registry','journal'):
                directory=file.parent/name;directory.mkdir(mode=0o700,exist_ok=True);stores.append(directory)
            self.directory=stores[0];self.findings=findings
        @property
        def selection(self):return deepcopy(self._selection)
        def check(self,action,selection,mode):
            require(selection==self._selection and mode==self.mode,'Fixture source selection differs')
            calls.append(['source',action,mode])
            require(not (phase=='fabric' and action==request.get('deny_action')),'FIXTURE_SOURCE_DENIED')
            require(not request.get('source_expired'),'FIXTURE_ORIGINAL_PERMIT_EXPIRED')
            return self.selection
        def check_recovery_key(self,value):
            require(type(value) is bytes and len(value)==32,'Fixture dedicated key required')
    findings=types.SimpleNamespace(registry=types.SimpleNamespace(root=file.parent/'registry',
        journal=types.SimpleNamespace(root=file.parent/'journal')))
    def private_root(value,repo):
        path=Path(value).resolve()
        require(path.is_relative_to(root) and path.is_dir() and path.stat().st_uid==os.getuid() and
            path.stat().st_mode&0o077==0,'Private owned fixture storage required')
        return path
    tree=ast.parse(Path('/work/pipeline/backend/app/identity/findings_backend_gate.py').read_text())
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_approval')
    space=dict(require=require,base64=base64,re=re,datetime=datetime,timezone=timezone,
        Ed25519PublicKey=Ed25519PublicKey,encoded=encoded,POLICY='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1')
    exec(compile(ast.Module(body=[function],type_ignores=[]),'committed-approval-function','exec'),space)
    for name in ('app','app.identity'):
        module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
    gate=types.ModuleType('app.identity.findings_backend_gate')
    gate.FindingsBackendGate=FindingsBackendGate;gate.verify_approval=space['verify_approval'];gate.POLICY=space['POLICY']
    commitment=types.ModuleType('app.identity.findings_commitments');commitment._root=private_root
    reconstruction=types.ModuleType('app.identity.historical_reconstruction');reconstruction.require=require
    protected=types.ModuleType('app.identity.protected_commitment');protected.encoded=encoded
    import hashlib
    protected.digest=lambda value:hashlib.sha256(encoded(value)).hexdigest()
    # Exact committed destination validation, with the same SHA shape primitive.
    dest_tree=ast.parse(Path('/work/pipeline/backend/app/identity/controlled_findings_anchoring.py').read_text())
    functions=[n for n in dest_tree.body if isinstance(n,ast.FunctionDef) and n.name in ('_exact','destinations')]
    def sha_shape(value):require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'SHA shape differs')
    dspace=dict(require=require,re=re,NAMESPACE='findings-anchor-v1',F=types.SimpleNamespace(_sha=sha_shape))
    exec(compile(ast.Module(body=functions,type_ignores=[]),'committed-destinations','exec'),dspace)
    dest=types.ModuleType('app.identity.controlled_findings_anchoring');dest.destinations=dspace['destinations']
    for module in (gate,commitment,reconstruction,protected,dest):sys.modules[module.__name__]=module
    def load(name):
        fullname='app.identity.'+name
        spec=importlib.util.spec_from_file_location(fullname,str(Path('/work/pipeline/backend/app/identity')/(name+'.py')))
        module=importlib.util.module_from_spec(spec);sys.modules[fullname]=module;spec.loader.exec_module(module)
        return module
    service=load('findings_backend_service')
    public_gate=load('findings_public_backend_gate');load('findings_public_backend_service')
    pipeline=load('findings_backend_pipeline')
    check=public_gate.FindingsPublicBackendGate.check
    def controlled(self,action,selection,mode):
        calls.append(['public',action,mode])
        require(not (phase=='public-run' and action==request.get('deny_action')),'FIXTURE_SOURCE_DENIED')
        return check(self,action,selection,mode)
    public_gate.FindingsPublicBackendGate.check=controlled
    from cryptography.hazmat.primitives.serialization import load_pem_public_key,Encoding,PublicFormat
    def trust(keys):return {k:load_pem_public_key(v.encode()).public_bytes(Encoding.Raw,PublicFormat.Raw) for k,v in keys.items()}
    try:
        source=FindingsBackendGate(request['mode']);read=FindingsBackendGate('RECONCILE')
        require(type(request['public_options']) is dict,'Isolated public options required')
        for name in ('network_config_file','witness_config_file','recovery_directory','recovery_key_file','runtime_config_file'):
            require(Path(request['public_options'][name]).resolve().is_relative_to(root),'Public fixture paths outside owned run')
        fopts=dict(node_binary='/usr/local/bin/node',gateway_config_file=job['gatewayConfigFile'],
            witness_config_file=job['witnessConfigFile'],witness_config_sha256=job['witnessConfigSha256'],
            recovery_directory=job['directory'],recovery_key_file=job['recoveryKeyFile'],timeout=120)
        p=pipeline.FindingsBackendPipeline(source,read,fabric_options=fopts,public_options=request['public_options'],
            fabric_trusted_keys=trust(job['trustedKeys']),public_trusted_keys=trust(request['public_trusted_keys']),
            public_config=request['public_config'],public_destination=request['public_destination'])
        if phase=='fabric':result=p.run_fabric(request['fabric_approval'])
        elif phase=='public-plan':result=p.public_selection(request['fabric_read_approval'])
        else:result=p.run_public(fabric_read_approval=request['fabric_read_approval'],public_approval=request['public_approval'],
            expected_selection=request['public_selection'])
        print(encoded(dict(ok=True,result=result,guards=calls,full_source_replay_simulated=True)).decode())
    except Exception as error:
        print(encoded(dict(ok=False,error_type=type(error).__name__,error_message=str(error)[:2000],guards=calls,
            full_source_replay_simulated=True)).decode())


if __name__=='__main__':main()
