"""Archived loader checks actual keys/AEAD with controlled capture boundaries."""
import base64
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import pytest
import app.identity.saved_algorithm_snapshot as L
from app.identity.evidence_bundle_v2 import seal_artifact
from app.identity.protected_commitment import digest
from test_anchor_gate import public_fixture
from test_protected_commitment import identity_crypto,key_data


@pytest.fixture
def archived(tmp_path,monkeypatch):
    crypto=identity_crypto(tmp_path)
    def write(path,value):
        path.write_text(json.dumps(value));path.chmod(0o600)
    backup=tmp_path/'identity-backup.json';backup.write_bytes((tmp_path/'identity.json').read_bytes());backup.chmod(0o600)
    keys=tmp_path/'commitment-keys.json';key_backup=tmp_path/'commitment-backup.json'
    write(keys,key_data());write(key_backup,key_data())
    roots={name:tmp_path/name for name in ('bundle','binding','commitment')}
    for p in roots.values():p.mkdir(mode=0o700)
    public=public_fixture();monkeypatch.setattr(L,'PUBLIC_SHA',digest(public))
    write(roots['commitment']/'public-commitments.json',public)
    write(roots['binding']/'destination-bindings.encrypted.json',{'fixture':'artifact'})
    sha=hashlib.sha256((roots['binding']/'destination-bindings.encrypted.json').read_bytes()).hexdigest()
    saved=seal_artifact(crypto,crypto,{'context':{'generator_revision':'a'*40}}, {'fixture':'original'})
    write(roots['commitment']/'commitments.encrypted.json',saved)
    manifest={'snapshot':{'collection_started_at':datetime.now(timezone.utc).isoformat()}}
    monkeypatch.setattr(L,'load_attempt',lambda *a:(manifest,{}))
    monkeypatch.setattr(L,'load_binding',lambda *a:({},sha))
    monkeypatch.setattr(L,'generate',lambda *a,**kw:(public,{}))
    checks=[];monkeypatch.setattr(L,'verify_saved',lambda *a:checks.append(a))
    args=SimpleNamespace(key_file=tmp_path/'identity.json',backup_key_file=backup,
        commitment_key_file=keys,backup_commitment_key_file=key_backup,bundle_attempt=roots['bundle'],
        binding_attempt=roots['binding'],commitment_attempt=roots['commitment'])
    return args,roots,public,checks


def test_archived_loader_does_not_require_an_audit_permit(archived,tmp_path):
    args,_,public,checks=archived
    result=L.load_saved_snapshot(args,tmp_path/'repo')
    assert result['public']==public and 'envelope' not in result
    assert len(checks)==1 and checks[0][-1]['code_revision']=='a'*40


@pytest.mark.parametrize('failure',['snapshot','binding','ciphertext','recovery','key_reuse','same_file'])
def test_archived_integrity_and_key_failures_block_replay(archived,tmp_path,monkeypatch,failure):
    args,roots,public,checks=archived
    if failure=='snapshot':
        altered=deepcopy(public);altered['officers'][0]['commitment']='f'*64
        monkeypatch.setattr(L,'generate',lambda *a,**kw:(altered,{}))
    elif failure=='binding':monkeypatch.setattr(L,'load_binding',lambda *a:({},'f'*64))
    elif failure=='ciphertext':
        p=roots['commitment']/'commitments.encrypted.json';value=json.loads(p.read_text());value['ciphertext']='AAAA'+value['ciphertext'][4:];p.write_text(json.dumps(value))
    elif failure=='recovery':
        p=args.backup_key_file;value=json.loads(p.read_text());value['encryption_keys']['enc']=base64.b64encode(b'Z'*32).decode();p.write_text(json.dumps(value))
    elif failure=='key_reuse':
        value=key_data();value['content_key']=base64.b64encode(b'E'*32).decode()
        args.commitment_key_file.write_text(json.dumps(value));args.backup_commitment_key_file.write_text(json.dumps(value))
    else:args.backup_key_file=args.key_file
    with pytest.raises(Exception):L.load_saved_snapshot(args,tmp_path/'repo')
    assert not checks
