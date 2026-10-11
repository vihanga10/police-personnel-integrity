"""Execute the isolated driver in a fresh interpreter, before any chain access."""
import base64
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import subprocess
import sys
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

ROOT=Path(__file__).resolve().parents[2]
DRIVER=ROOT/'blockchain/fabric/integration/backend-pipeline-fixture.py'


@pytest.mark.parametrize('expired',[False,True])
def test_actual_driver_rejects_invalid_approval_or_expired_source_before_workers(tmp_path,expired):
    root=tmp_path/'owned';root.mkdir(mode=0o700)
    (root/'ISOLATED-RUN.json').write_text(json.dumps({'policy':'PPI_DISPOSABLE_FINDINGS_FABRIC_V1'}))
    case=root/'case';case.mkdir(mode=0o700);recovery=case/'fabric';recovery.mkdir(mode=0o700)
    public=case/'public';public.mkdir(mode=0o700)
    key=case/'fabric.key';key.write_bytes(b'R'*32);key.chmod(0o600)
    signer=Ed25519PrivateKey.generate();pem=signer.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()
    s={'fixture':'opaque','code_revision':'1'*40};now=datetime.now(timezone.utc);fmt=lambda t:t.isoformat(timespec='milliseconds').replace('+00:00','Z')
    body=dict(policy='PROTECTED_FINDINGS_GATEWAY_BRIDGE_V1',key_id='test',mode='EXECUTE',selection=s,
        issued_at=fmt(now-timedelta(seconds=1)),expires_at=fmt(now+timedelta(seconds=60)))
    bad=dict(body=body,signature=base64.b64encode(b'X'*64).decode())
    job=dict(repo='/work/pipeline',mode='EXECUTE',selection=s,trustedKeys={'test':pem},
        gatewayConfigFile=str(case/'gateway.json'),witnessConfigFile=str(case/'witness.json'),witnessConfigSha256='f'*64,
        directory=str(recovery),recoveryKeyFile=str(key))
    options=dict(node_binary=sys.executable,network_config_file=str(case/'network.json'),witness_config_file=str(case/'public-witness.json'),
        witness_config_sha256='e'*64,recovery_directory=str(public),recovery_key_file=str(case/'public.key'),timeout=10,
        runtime_config_file=str(case/'runtime.json'),runtime_config_sha256='d'*64)
    config=dict(policy='FINDINGS_PUBLIC_NETWORK_FIXTURE_V1',rpc_urls=['https://one.example.invalid/','https://two.example.invalid/'],
        max_fee_gwei='2',priority_fee_gwei='1',max_total_fee_eth='0.005',confirmations=12)
    request=dict(policy='PPI_BACKEND_PIPELINE_FIXTURE_V1',phase='fabric',mode='EXECUTE',fabric_job=job,
        public_options=options,public_config=config,public_destination={},public_trusted_keys={'test':pem},
        fabric_approval=bad,source_expired=expired)
    file=case/'request.json';file.write_text(json.dumps(request))
    code="""import importlib.util,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('driver',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
repo=Path(sys.argv[2]);request=sys.argv[3];root=sys.argv[4]
def mapped(value):
 text=str(value)
 if text=='/work/pipeline':return repo
 if text.startswith('/work/pipeline/'):return repo/text.removeprefix('/work/pipeline/')
 return Path(value)
m.Path=mapped;os.environ['PPI_TEST_ROOT']=root;sys.argv=['driver',request];m.main()
"""
    p=subprocess.run([sys.executable,'-c',code,str(DRIVER),str(ROOT),str(file),str(root)],capture_output=True,text=True,timeout=15)
    assert p.returncode==0,p.stderr
    result=json.loads(p.stdout);assert result['ok'] is False and result['full_source_replay_simulated'] is True
    if expired:assert result['error_message']=='FIXTURE_ORIGINAL_PERMIT_EXPIRED'
    else:assert result['error_type']=='InvalidSignature'
    assert list(recovery.iterdir())==[] and list(public.iterdir())==[]
