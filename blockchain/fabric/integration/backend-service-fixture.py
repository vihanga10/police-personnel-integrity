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
    request=json.loads(file.read_text());job=request['job']
    require(request['policy']=='PPI_BACKEND_SERVICE_FIXTURE_V1' and job['repo']=='/work/fabric',
            'Disposable backend policy required')
    require(job['mode'] in ('EXECUTE','RECONCILE'),'Fixture mode required')
    for name in ('gatewayConfigFile','witnessConfigFile','directory','recoveryKeyFile'):
        require(Path(job[name]).resolve().is_relative_to(root),'Fixture paths must stay inside owned root')
    calls=[]
    class FindingsBackendGate:
        def __init__(self):
            self.repo=Path('/work/fabric');self.mode=job['mode'];self._selection=deepcopy(job['selection'])
            stores=[]
            for name in ('commitment','registry','journal'):
                directory=file.parent/name;directory.mkdir(mode=0o700,exist_ok=True);stores.append(directory)
            self.directory=stores[0]
            self.findings=types.SimpleNamespace(registry=types.SimpleNamespace(root=stores[1],journal=types.SimpleNamespace(root=stores[2])))
        @property
        def selection(self):return deepcopy(self._selection)
        def check(self,action,selection,mode):
            require(selection==self._selection and mode==self.mode,'Fixture source selection differs')
            calls.append(action)
            require(action!=request.get('deny_action'),'FIXTURE_SOURCE_REPLAY_DENIED')
            return self.selection
        def check_recovery_key(self,value):
            require(type(value) is bytes and len(value)==32,'Fixture recovery key required')
    def private_root(value,repo):
        path=Path(value).resolve()
        require(path.is_relative_to(root) and path.is_dir() and path.stat().st_uid==os.getuid() and
            path.stat().st_mode&0o077==0,'Private owned fixture storage required')
        return path
    # Compile the exact committed approval function, not a replacement verifier.
    tree=ast.parse(Path('/work/backend/app/identity/findings_backend_gate.py').read_text())
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_approval')
    space=dict(require=require,base64=base64,re=re,datetime=datetime,timezone=timezone,
        Ed25519PublicKey=Ed25519PublicKey,encoded=encoded,POLICY='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1')
    exec(compile(ast.Module(body=[function],type_ignores=[]),'committed-approval-function','exec'),space)
    # Only source replay and associated configuration are substituted. Import the
    # real service file, without reimplementing run_fabric or _exchange.
    for name in ('app','app.identity'):
        module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
    gate=types.ModuleType('app.identity.findings_backend_gate')
    gate.FindingsBackendGate=FindingsBackendGate;gate.verify_approval=space['verify_approval'];gate.POLICY=space['POLICY']
    commitment=types.ModuleType('app.identity.findings_commitments');commitment._root=private_root
    reconstruction=types.ModuleType('app.identity.historical_reconstruction');reconstruction.require=require
    protected=types.ModuleType('app.identity.protected_commitment');protected.encoded=encoded
    import hashlib
    protected.digest=lambda value:hashlib.sha256(encoded(value)).hexdigest()
    for module in (gate,commitment,reconstruction,protected):sys.modules[module.__name__]=module
    spec=importlib.util.spec_from_file_location('app.identity.findings_backend_service',str(Path('/work/backend/app/identity/findings_backend_service.py')))
    service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)
    from cryptography.hazmat.primitives.serialization import load_pem_public_key,Encoding,PublicFormat
    keys={name:load_pem_public_key(pem.encode()).public_bytes(Encoding.Raw,PublicFormat.Raw) for name,pem in job['trustedKeys'].items()}
    try:
        result=service.run_fabric(FindingsBackendGate(),approval=job['approval'],trusted_keys=keys,
            node_binary='/usr/local/bin/node',gateway_config_file=job['gatewayConfigFile'],
            witness_config_file=job['witnessConfigFile'],witness_config_sha256=job['witnessConfigSha256'],
            recovery_directory=job['directory'],recovery_key_file=job['recoveryKeyFile'],timeout=120)
        result['backend_gate']='SUBSTITUTED_SOURCE_REPLAY_FIXTURE'
        print(encoded(dict(ok=True,result=result,guards=calls,full_source_replay_simulated=True)).decode())
    except Exception as error:
        print(encoded(dict(ok=False,error_type=type(error).__name__,error_message=str(error)[:2000],guards=calls,full_source_replay_simulated=True)).decode())


if __name__=='__main__':main()
