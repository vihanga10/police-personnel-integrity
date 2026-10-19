"""Large encrypted-source watch regression; fixtures never establish real readiness."""
from copy import deepcopy
from pathlib import Path
import hashlib
import os
import pytest
from app.access import research_connection as C
from app.identity import audit_gate as A
from app.identity.evidence_bundle_v2 import open_artifact
from research_connection_fixture import connected, setup, verified, keys, write


def test_large_binding_is_fully_streamed_pinned_and_rechecked_before_any_loader(connected,monkeypatch):
    t=connected;path=Path(t['config']['source']['binding_attempt'])/'destination-bindings.encrypted.json'
    # Local precondition check pins bytes; the production loader still decrypts
    # and verifies all originals before any operational export/import.
    data=b'fixture-large-binding-byte-sequence'*600000
    assert len(data)>C.CONFIG_MAX_BYTES
    write(path,data);snapshot=t['snapshot']
    old_context=deepcopy(snapshot['context'])
    permit=open_artifact(snapshot['crypto'],snapshot['envelope'],A.binding(old_context))
    snapshot['context']['binding_artifact_sha256']=hashlib.sha256(data).hexdigest()
    permit['context']=deepcopy(snapshot['context'])
    snapshot['envelope']=A.seal_permit(snapshot['crypto'],snapshot['backup'],permit)
    write(Path(t['config']['source']['audit_gate_attempt'])/'audit-permit.encrypted.json',snapshot['envelope'])
    original=Path.read_bytes
    def no_whole_binding(file):
        if file==path:raise AssertionError('Large bindings must not use read_bytes')
        return original(file)
    monkeypatch.setattr(Path,'read_bytes',no_whole_binding)
    connection=C.Connection(t['configfile']);result=connection.check([])
    assert result['status']=='LOCAL_PRECONDITIONS_VERIFIED' and not result['source_replay_verified']
    assert connection.pins[path]==hashlib.sha256(data).hexdigest()
    assert connection.bounds[path]==C.SOURCE_ARTIFACT_MAX_BYTES and t['calls']==[]
    connection.unchanged([])
    with path.open('r+b') as file:file.seek(len(data)//2);file.write(b'changed')
    with pytest.raises(ValueError,match='Connection input changed'):connection.unchanged([])


def test_actual_reported_binding_size_fits_only_source_artifact_bound():
    assert C.CONFIG_MAX_BYTES < 567784998 < C.SOURCE_ARTIFACT_MAX_BYTES
    assert C.HASH_CHUNK_BYTES==1024*1024


def test_large_configuration_still_denied_before_loader(connected):
    t=connected;path=t['configfile']
    with path.open('ab') as file:file.write(b' '*(C.CONFIG_MAX_BYTES+1))
    with pytest.raises(ValueError):C.Connection(path)
    assert t['calls']==[]


def test_large_mode_cannot_be_applied_to_other_private_files(connected):
    t=connected;connection=C.Connection(t['configfile'])
    with pytest.raises(ValueError,match='reserved'):connection._watch(t['authorization_file'],source_artifact=True)


def test_stream_digest_retains_small_byte_changes_and_matches_sha256(tmp_path):
    repo=tmp_path/'repo';repo.mkdir();path=write(tmp_path/'private-file',os.urandom(3*C.HASH_CHUNK_BYTES+19))
    expected=hashlib.sha256(path.read_bytes()).hexdigest()
    assert C.file_digest(path,repo,C.CONFIG_MAX_BYTES)==expected
    with path.open('r+b') as file:file.seek(C.HASH_CHUNK_BYTES);file.write(b'changed')
    assert C.file_digest(path,repo,C.CONFIG_MAX_BYTES)!=expected


@pytest.mark.parametrize('fault',['symlink','public_mode','hardlink','oversize'])
def test_stream_digest_rejects_unsafe_inputs_before_read(tmp_path,fault):
    repo=tmp_path/'repo';repo.mkdir();path=write(tmp_path/'private-file',b'fixture bytes')
    if fault=='symlink':
        linked=tmp_path/'linked';linked.symlink_to(path);path=linked
    elif fault=='public_mode':path.chmod(0o644)
    elif fault=='hardlink':os.link(path,tmp_path/'second-link')
    else:
        with path.open('ab') as file:file.truncate(C.SOURCE_ARTIFACT_MAX_BYTES+1)
    with pytest.raises(ValueError):C.file_digest(path,repo,C.SOURCE_ARTIFACT_MAX_BYTES)


def test_reported_568mb_size_hashes_complete_tail_in_bounded_chunks(tmp_path,monkeypatch):
    repo=tmp_path/'repo';repo.mkdir();path=tmp_path/'binding-fixture'
    size=567784998;tail=b'fixed-generated-fixture-tail'
    with path.open('xb') as file:
        os.fchmod(file.fileno(),0o600);file.truncate(size)
        file.seek(size-len(tail));file.write(tail)
    expected=hashlib.sha256();zeros=b'\0'*(256*1024)
    remaining=size-len(tail)
    while remaining:
        amount=min(remaining,len(zeros));expected.update(zeros[:amount]);remaining-=amount
    expected.update(tail)
    original=Path.read_bytes
    def deny_whole_read(file):
        if file==path:raise AssertionError('The reported-size artifact must be streamed')
        return original(file)
    monkeypatch.setattr(Path,'read_bytes',deny_whole_read)
    assert C.file_digest(path,repo,C.SOURCE_ARTIFACT_MAX_BYTES)==expected.hexdigest()
    with pytest.raises(ValueError,match='Bounded configuration input required'):
        C.file_digest(path,repo,C.CONFIG_MAX_BYTES)
