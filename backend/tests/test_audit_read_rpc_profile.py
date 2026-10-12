"""Private fixture Git/profile tests only; no actual custody, keys or RPC access."""
from argparse import Namespace
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import pytest
from app.identity import audit_read_rpc_profile as P
from app.identity.check_audit_gate_read_rpc import command

@pytest.fixture
def fixture(tmp_path, monkeypatch):
    repo = tmp_path / 'repo'; repo.mkdir()
    subprocess.run(['git','init','-q','-b','feat/identity-resolution',str(repo)],check=True)
    subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit','-q','--allow-empty','-m','Fixture'],check=True)
    wallet = tmp_path / 'wallet'; wallet.mkdir(mode=0o700)
    config = {'rpc_urls':['https://fixture.publicnode.com','https://fixture.alchemy.com/v2/FIXTURE'], 'policy':'FIXTURE'}
    (wallet/'network.json').write_text(P.canonical(config)+'\n'); (wallet/'network.json').chmod(0o600)
    # Explicit fixture pin substitution: never done by the production scripts.
    monkeypatch.setattr(P,'CONFIG',P.sha(P.canonical(config)))
    file = tmp_path/'read-profile'/'profile.json'
    url = 'https://fixture.ethereum-sepolia.quiknode.pro/FIXTURE_TOKEN/'
    digest = P.prepare(wallet,file,url,repo)
    return repo,wallet,file,url,digest

def rewrite(file, value):
    file.write_text(P.canonical(value)+'\n')
    return P.sha(file.read_bytes())

def test_profile_preserves_original_and_is_exclusive(fixture):
    repo,wallet,file,url,digest = fixture
    before = (wallet/'network.json').read_bytes()
    p = P.load(file,digest,wallet,repo)
    assert p['rpc_urls'][0] == url and p['rpc_urls'][1].endswith('/FIXTURE')
    assert file.stat().st_mode & 0o777 == 0o600
    assert file.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(Exception): P.prepare(wallet,file,url,repo)
    assert (wallet/'network.json').read_bytes() == before and P.sha(file.read_bytes()) == digest

@pytest.mark.parametrize('field,value',[
 ('policy','OTHER'),('code_revision','0'*40),('original_config_sha256','0'*64),
 ('public_payload_sha256','0'*64),('original_rpc_sha256',['0'*64,'1'*64]),
 ('rpc_urls',['https://fixture.quiknode.pro/FIXTURE','https://other.alchemy.com/FIXTURE']),
 ('rpc_urls',['https://fixture.quiknode.pro.attacker.invalid/FIXTURE','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['http://fixture.quiknode.pro/FIXTURE','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['https://fixture.quiknode.pro/FIXTURE?extra=1','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['https://fixture.quiknode.pro/FIXTURE#secret','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['https://user:password@fixture.quiknode.pro/FIXTURE','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['https://fixture.quiknode.pro/','https://fixture.alchemy.com/v2/FIXTURE']),
 ('rpc_urls',['https://fixture.quiknode.pro/FIXTURE']),('unexpected',True)])
def test_recomputed_hash_does_not_bypass_bindings(fixture,field,value):
    repo,wallet,file,url,digest = fixture
    p = json.loads(file.read_text()); p[field] = value
    digest = rewrite(file,p)
    with pytest.raises(Exception): P.load(file,digest,wallet,repo)

@pytest.mark.parametrize('fault',['wrong_hash','private_mode','parent_mode','hardlink','symlink','pretty_json','duplicate_json','dirty_git','changed_original','wrong_branch'])
def test_private_and_current_inputs_required(fixture,fault):
    repo,wallet,file,url,digest = fixture
    if fault == 'wrong_hash': digest = '0'*64
    elif fault == 'private_mode': file.chmod(0o644)
    elif fault == 'parent_mode': file.parent.chmod(0o755)
    elif fault == 'hardlink': os.link(file,file.parent/'linked.json')
    elif fault == 'symlink':
        actual=file.parent/'actual.json'; file.rename(actual); file.symlink_to(actual)
    elif fault == 'pretty_json': file.write_text(json.dumps(json.loads(file.read_text()),indent=2)); digest=P.sha(file.read_bytes())
    elif fault == 'duplicate_json':
        file.write_text(file.read_text().replace('{','{"policy":"OTHER",',1)); digest=P.sha(file.read_bytes())
    elif fault == 'dirty_git': (repo/'unreviewed').write_text('Fixture')
    elif fault == 'changed_original': (wallet/'network.json').write_text('{}\n')
    elif fault == 'wrong_branch': subprocess.run(['git','-C',str(repo),'checkout','-q','-b','main'],check=True)
    with pytest.raises(Exception): P.load(file,digest,wallet,repo)

def test_prepare_rejects_unsafe_destination_before_writing(fixture):
    repo,wallet,file,url,digest = fixture
    with pytest.raises(Exception): P.prepare(wallet,repo/'profile.json',url,repo)
    with pytest.raises(Exception): P.prepare(wallet,file.parent/'..'/'profile2.json',url,repo)
    assert not (repo/'profile.json').exists()

def test_wrapper_command_has_no_execute_or_skip_gate(fixture):
    from app.identity.check_audit_gate import INHERITED
    values={n.replace('-','_'):Path('/fixture')/n for n in (*INHERITED,'output-root')}
    values.update(publication_fee_budget_eth='2.30',read_profile=Path('/private/profile.json'),expected_read_profile_sha256='a'*64)
    argv=command(Namespace(**values))
    assert argv[1:4]==['-u','-m','app.identity.check_audit_gate']
    assert '--execute' not in argv and '--read-profile' not in argv and '--expected-read-profile-sha256' not in argv
    assert argv[-2:]==['--publication-fee-budget-eth','2.30']

def test_permit_digest_includes_transport_attestation():
    from app.identity.audit_gate import verify_inputs
    from test_audit_gate import verified
    # Reuse existing fully invented verified fixture and its explicit public pin substitution.
    patch=pytest.MonkeyPatch()
    try:
        p,l,f,r,c,now = verified.__wrapped__(patch)
        before=verify_inputs(p,l,f,r,c,now=now)
        r=deepcopy(r)
        r['public_result']['read_verification']={'policy':P.POLICY,'profile_sha256':'d'*64,
            'providers':['QUICKNODE','ALCHEMY'],'original_config_sha256':P.CONFIG,'code_revision':c['code_revision']}
        after=verify_inputs(p,l,f,r,c,now=now)
        assert before['public_result_sha256'] != after['public_result_sha256']
        assert before['expires_at'] == after['expires_at']
        assert after['context'] == c
    finally: patch.undo()
