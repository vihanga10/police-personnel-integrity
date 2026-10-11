"""Configured service selection tests; pipe results use declared doubles.

Actual Python/Node pipe, HTTPS and EVM execution is in the Node runtime suite.
"""
import hashlib
import os
from pathlib import Path
import pytest
from app.identity import findings_public_backend_service as S
from app.identity.protected_commitment import encoded
from test_findings_public_backend_service import service
from test_findings_public_backend_gate import public_fixture,grant,gate_fixture,build,prepared,prepare,recovered,key_data,witnessed_findings,registered,journal,output,witnessed,setup,verified,keys


@pytest.fixture
def configured(service,tmp_path):
    t,g,kw,r=service
    worker=g.repo/'blockchain/public/findings/configured-public-backend-worker.js'
    worker.write_text('// fixed test worker')
    wallet=tmp_path/'wallet.key';wallet.write_bytes(os.urandom(32));wallet.chmod(0o600)
    cfg=dict(policy='FINDINGS_CONFIGURED_LOCAL_HTTPS_RUNTIME_V1',network_config_sha256=g.selection['network_config_sha256'],
        writer=g.selection['destination']['writer'],wallet_file=str(wallet),wallet_sha256=hashlib.sha256(wallet.read_bytes()).hexdigest(),
        timeout_ms=2000,providers=[])
    file=tmp_path/'runtime.json';file.write_bytes(encoded(cfg));file.chmod(0o600)
    kw.update(runtime_config_file=file,runtime_config_sha256=hashlib.sha256(file.read_bytes()).hexdigest())
    return t,g,kw,r,cfg,wallet


def test_fixed_configured_worker_uses_administrative_args_and_guards(configured,monkeypatch):
    _,g,kw,r,_,wallet=configured
    def exchange(command,job,guard,timeout):
        assert command[1]==str(g.repo/'blockchain/public/findings/configured-public-backend-worker.js')
        assert command[2:]==[str(kw['runtime_config_file']),kw['runtime_config_sha256']]
        assert 'runtimeConfigFile' not in job and wallet.read_bytes().hex() not in str(job)
        guard('SIGN',job['selection'],job['mode']);return r
    monkeypatch.setattr(S,'_exchange',exchange)
    assert S.run_public(g,**kw)['live_research_ready'] is False


@pytest.mark.parametrize('fault',['pair','pin','policy','selection','writer','wallet-pin','wallet-reuse','mode','hardlink','symlink'])
def test_configured_runtime_refused_before_worker(configured,monkeypatch,fault,tmp_path):
    _,g,kw,_,c,wallet=configured
    if fault=='pair':kw['runtime_config_sha256']=None
    elif fault=='pin':kw['runtime_config_sha256']='0'*64
    elif fault=='policy':c['policy']='LIVE'
    elif fault=='selection':c['network_config_sha256']='0'*64
    elif fault=='writer':c['writer']='0x'+'1'*40
    elif fault=='wallet-pin':c['wallet_sha256']='0'*64
    elif fault=='wallet-reuse':wallet.write_bytes(Path(kw['recovery_key_file']).read_bytes());c['wallet_sha256']=hashlib.sha256(wallet.read_bytes()).hexdigest()
    elif fault=='mode':wallet.chmod(0o644)
    elif fault=='hardlink':os.link(wallet,tmp_path/'linked')
    elif fault=='symlink':wallet.rename(tmp_path/'original');wallet.symlink_to(tmp_path/'original')
    if fault not in ('pair','pin'):
        kw['runtime_config_file'].write_bytes(encoded(c));kw['runtime_config_sha256']=hashlib.sha256(encoded(c)).hexdigest()
    monkeypatch.setattr(S,'_exchange',lambda *a,**k:pytest.fail('Worker must not start'))
    with pytest.raises(ValueError):S.run_public(g,**kw)


@pytest.mark.parametrize('file',['runtime','wallet'])
def test_runtime_drift_during_guard_stops_before_return(configured,monkeypatch,file):
    _,g,kw,r,_,wallet=configured
    def exchange(command,job,guard,timeout):
        p=kw['runtime_config_file'] if file=='runtime' else wallet
        with p.open('ab') as out:out.write(b'x')
        guard('SIGN',job['selection'],job['mode']);return r
    monkeypatch.setattr(S,'_exchange',exchange)
    with pytest.raises(ValueError,match='runtime changed'):S.run_public(g,**kw)
