import json
from pathlib import Path
import subprocess
import sys
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from scoped_access_fixture import setup,grant

BACKEND=Path(__file__).resolve().parents[1]

def run(script,*args):
    return subprocess.run([sys.executable,str(BACKEND/'scripts'/script),*map(str,args)],
        cwd=BACKEND,capture_output=True,text=True,timeout=20)

def test_offline_signed_account_update_uses_exact_pinned_authority(tmp_path):
    store,key,config=setup(tmp_path)
    private=tmp_path/'authority.key';private.write_bytes(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()));private.chmod(0o600)
    payload=tmp_path/'payload.json';payload.write_text(json.dumps(grant(key)['payload']));payload.chmod(0o600)
    out=tmp_path/'signed.json'
    result=run('sign_access_grant.py','--config',config,'--authority-key',private,'--payload',payload,'--output',out,'--key-id','test-admin')
    assert result.returncode==0,result.stderr
    assert json.loads(out.read_text())['payload']['scope_id']=='S1' and out.stat().st_mode&0o077==0
    result=run('sign_access_grant.py','--config',config,'--authority-key',private,'--payload',payload,'--output',out,'--key-id','test-admin')
    assert result.returncode!=0 # Cannot replace a previously issued administrative grant.
    result=run('manage_scoped_access.py','status','--config',config)
    assert result.returncode==0 and 'Only the separate access store' in result.stdout


def test_no_initial_password_or_unsigned_enrollment_is_accepted(tmp_path):
    store,key,config=setup(tmp_path)
    file=tmp_path/'grant.json';file.write_text(json.dumps(grant(key)));file.chmod(0o600)
    result=run('manage_scoped_access.py','account','--config',config,'--envelope',file)
    assert result.returncode!=0 and 'no default account' in result.stderr
    unsigned=grant(key)['payload'];file.write_text(json.dumps(unsigned))
    result=run('manage_scoped_access.py','account','--config',config,'--envelope',file)
    assert result.returncode!=0


def test_init_is_explicit_and_refuses_existing_database(tmp_path):
    store,key,config=setup(tmp_path)
    before=store.path.read_bytes()
    result=run('manage_scoped_access.py','init','--config',config)
    assert result.returncode!=0 and store.path.read_bytes()==before
