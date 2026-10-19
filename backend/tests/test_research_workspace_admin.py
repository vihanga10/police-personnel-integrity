"""Private administrative tools: no default data and exact bounded signing."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import pytest
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from research_workspace_fixture import initialize,presentation,disclosure,identifier

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'

def run(name,*args):
    return subprocess.run([sys.executable,str(SCRIPTS/name),*map(str,args)],capture_output=True,text=True,timeout=20)

def test_private_presentation_sign_import_check_and_no_overwrite(tmp_path):
    store,key,config=initialize(tmp_path)
    draft=tmp_path/'presentation-draft.json';draft.write_text(json.dumps(presentation(key,generation=2)['payload']));draft.chmod(0o600)
    signing=tmp_path/'offline.key';signing.write_bytes(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()));signing.chmod(0o600)
    output=tmp_path/'signed.json'
    args=('--config',config,'--draft',draft,'--signing-key',signing,'--key-id','workspace-test','--output',output)
    result=run('sign_research_presentation.py',*args);assert result.returncode==0,result.stderr
    assert output.stat().st_mode&0o777==0o600 and store.get_packet(identifier(1))['generation']==1
    before=output.read_bytes();assert run('sign_research_presentation.py',*args).returncode!=0 and output.read_bytes()==before
    result=run('manage_research_workspace.py','presentation','--config',config,'--envelope',output)
    assert result.returncode==0 and store.get_packet(identifier(1))['generation']==2
    assert run('manage_research_workspace.py','check','--config',config).returncode==0

@pytest.mark.parametrize('change',['unknown-signer','wrong-domain','expired','unsafe-path'])
def test_signing_rejects_unapproved_or_stale_drafts(tmp_path,change):
    store,key,config=initialize(tmp_path);value=disclosure(key)['payload']
    if change=='wrong-domain':value['kind']='CHAIN_APPROVAL'
    if change=='expired':value['expires_at']=int(time.time())-1
    draft=tmp_path/'draft.json';draft.write_text(json.dumps(value));draft.chmod(0o644 if change=='unsafe-path' else 0o600)
    signing=tmp_path/'offline.key';signing.write_bytes(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()));signing.chmod(0o600)
    output=tmp_path/'signed.json'
    result=run('sign_research_presentation.py','--config',config,'--draft',draft,'--signing-key',signing,'--key-id',
        'unknown' if change=='unknown-signer' else 'workspace-test','--output',output)
    assert result.returncode!=0 and not output.exists()

def test_workspace_does_not_create_a_missing_configuration_or_fallback_account(tmp_path):
    missing=tmp_path/'absent.json'
    result=run('manage_research_workspace.py','init','--config',missing)
    assert result.returncode!=0 and not missing.exists()

def test_untrusted_envelope_cannot_be_imported(tmp_path):
    store,key,config=initialize(tmp_path);envelope=presentation(key,generation=2);envelope['payload']['source_public_sha256']='f'*64
    file=tmp_path/'unsigned-edit.json';file.write_text(json.dumps(envelope));file.chmod(0o600)
    result=run('manage_research_workspace.py','presentation','--config',config,'--envelope',file)
    assert result.returncode!=0 and store.get_packet(identifier(1))['generation']==1
