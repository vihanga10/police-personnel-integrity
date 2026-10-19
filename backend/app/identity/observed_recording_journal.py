"""Encrypted append-only observation journal, starting at a new baseline.

Trusted backend only. Observation times are recorder knowledge times, not old
intake/SQL commit times. Checkpoints cover this journal, not all source changes.
No CLI, receipt-authority issuer, database hook or live research runner is added.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4
import base64
import fcntl
import json
import os
import tempfile
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.exceptions import InvalidSignature

from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.authenticated_recording_history import _claim, _time, _hash, _text
from app.identity.bitemporal_reconstruction import RecordingHistory, EvidenceVersion, query
from app.identity.evidence_bundle_v2 import canonical, seal_artifact, open_artifact
from app.identity.historical_reconstruction import DIMENSIONS, require
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.protected_commitment import digest

POLICY = 'OBSERVED_RECORDING_JOURNAL_V1'
AUTH_POLICY = 'COMMITTED_CLAIM_OBSERVATION_AUTHORIZATION_V1'
BASE_FIELDS = {'policy','kind','journal_id','observed_at','scope','source_context',
    'original_publication_sha256','source_registry_sha256','claims','semantics'}
EVENT_FIELDS = {'policy','kind','event_id','journal_anchor','sequence','previous_receipt_sha256',
    'observed_at','version_id','claim','source_key','supersedes','withdrawn',
    'authorization','semantics'}
CHECK_FIELDS = {'policy','kind','checkpoint_id','journal_anchor','observed_through',
    'issued_at','event_inventory','completeness_statement'}
AUTH_FIELDS = {'policy','kind','journal_anchor','claim','source_key','supersedes','withdrawn',
    'evidence_epoch_sha256','readiness_reference','issued_at','expires_at','status'}


def _now():
    return datetime.now(timezone.utc)


def _public(key):
    require(isinstance(key, Ed25519PrivateKey), 'Recorder signing key required.')
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _recorder(key,key_id,keys,crypto,backup):
    require(keys.get(key_id)==_public(key), 'Recorder does not match pinned key.')
    seed=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    for recovery in (crypto,backup):
        require(seed not in recovery.encryption_keys.values() and seed not in recovery.lookup_keys.values(),
            'Recorder signing key must be separate from identity encryption and lookup keys.')


def _sign(value, key, key_id, policy=POLICY):
    _text(key_id)
    signature = key.sign(canonical([policy,key_id,value]).encode())
    return dict(key_id=key_id,payload=value,signature=base64.b64encode(signature).decode())


def _verify(receipt, keys, fields, kind, policy=POLICY):
    require(type(receipt) is dict and set(receipt)=={'key_id','payload','signature'},
        'Observation receipt shape differs.')
    key_id=receipt['key_id']; _text(key_id)
    require(key_id in keys, 'Observation signer is not authorized.')
    key=keys[key_id]
    require(type(key) is bytes and len(key)==32, 'Pinned observation public key required.')
    value=receipt['payload']
    require(type(value) is dict and set(value)==fields and value['policy']==policy and
        value['kind']==kind, 'Observation receipt policy or schema differs.')
    try:
        signature=base64.b64decode(receipt['signature'],validate=True)
        Ed25519PublicKey.from_public_bytes(key).verify(signature,
            canonical([policy,key_id,value]).encode())
    except (InvalidSignature,ValueError,TypeError):
        raise ValueError('Observation signature verification failed.') from None
    return value


def _private_root(root,repo):
    root=Path(root).expanduser().absolute(); repo=Path(repo).expanduser().resolve()
    require(not root.is_relative_to(repo), 'Observation journal must be outside repository.')
    require(not any(p.is_symlink() for p in (root,*root.parents)), 'Journal symlink refused.')
    require(root.is_dir() and root.stat().st_uid==os.getuid() and
        root.stat().st_mode & 0o077==0, 'Existing owner-only journal directory required.')
    return root


def _binding(kind,anchor=None):
    return dict(artifact='OBSERVED_RECORDING_'+kind,policy=POLICY,journal_anchor=anchor)


def _read(path,crypto,backup,binding):
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
        path.stat().st_mode & 0o077==0, 'Private observation artifact required.')
    data=path.read_bytes(); envelope=json.loads(data)
    primary=open_artifact(crypto,envelope,binding)
    require(open_artifact(backup,envelope,binding)==primary, 'Observation recovery differs.')
    return sha256(data).hexdigest(),primary


def _publish(path,receipt,crypto,backup,binding,check):
    envelope=seal_artifact(crypto,backup,receipt,binding)
    require(open_artifact(crypto,envelope,binding)==receipt and
        open_artifact(backup,envelope,binding)==receipt, 'Observation output recovery differs.')
    temporary=None
    data=(canonical(envelope)+'\n').encode()
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.observation-',delete=False) as stream:
            temporary=Path(stream.name); os.fchmod(stream.fileno(),0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        check()  # Recheck after staging, immediately before non-overwriting publication.
        os.link(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)
    return sha256(data).hexdigest()


def _wire(claim):
    value=asdict(claim)
    for name in ('start','end'):
        if value[name] is not None:value[name]=value[name].isoformat()
    value['issues']=list(value['issues'])
    return value


def create_baseline(args,repo,revision,officer_uid,root,signer,key_id,recorder_keys):
    """Public backend entry: reproduce anchored snapshot and require fresh gate."""
    from app.identity.algorithm_snapshot import load_verified_snapshot
    snapshot=load_verified_snapshot(args,repo,revision)
    return create_loaded_baseline(snapshot,repo,officer_uid,root,signer,key_id,recorder_keys)


def create_loaded_baseline(snapshot,repo,officer_uid,root,signer,key_id,recorder_keys):
    """Internal boundary; snapshot MUST be the existing full replay loader result."""
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    _recorder(signer,key_id,recorder_keys,snapshot['crypto'],snapshot['backup'])
    root=_private_root(root,repo)
    # Directory fd also serves as the advisory lock; no plaintext lock metadata.
    fd=os.open(root,os.O_RDONLY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        require(not list(root.iterdir()), 'New empty observation journal required.')
        from uuid import UUID
        require(str(UUID(officer_uid))==officer_uid and any(
            link['officer_uid']==officer_uid and link['role']=='officer_nic_no'
            for item in snapshot['catalog'].values() for link in item['candidate_links']),
            'Baseline officer outside captured candidate evidence.')
        catalog=deepcopy(snapshot['catalog']); bindings=deepcopy(snapshot['bindings']['raw_bindings'])
        source_sha=digest(dict(catalog=catalog,bindings=bindings))
        claims=source_claims(officer_uid,catalog,bindings)
        entries=[dict(claim=_wire(c),source_key=json.loads(c.source_reference)['filename']) for c in claims]
        require(len({c.claim_id for c in claims})==len(claims), 'Duplicate baseline claim.')
        # Assigned after authenticated extraction; never copied from a CSV/SQL date.
        observed=_now().isoformat()
        base=dict(policy=POLICY,kind='BASELINE',journal_id=str(uuid4()),observed_at=observed,
            scope=dict(officer_uid=officer_uid,source_keys=sorted(HEADERS),dimensions=sorted(DIMENSIONS)),
            source_context=deepcopy(snapshot['context']),original_publication_sha256=digest(snapshot['public']),
            source_registry_sha256=digest({k:sorted(v) for k,v in HEADERS.items()}),claims=entries,
            semantics='RECORDER_OBSERVED_ARCHIVED_BASELINE')
        def check():
            permit.check(snapshot)
            require(digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings']))==source_sha,
                'Baseline source changed during recording.')
        anchor=_publish(root/'baseline.encrypted.json',_sign(base,signer,key_id),
            snapshot['crypto'],snapshot['backup'],_binding('BASELINE'),check)
        checkpoint=_checkpoint(anchor,[],observed,signer,key_id)
        name='checkpoint-'+checkpoint['payload']['checkpoint_id']+'.encrypted.json'
        pin=_publish(root/name,checkpoint,snapshot['crypto'],snapshot['backup'],_binding('CHECKPOINT',anchor),check)
        return dict(journal_anchor=anchor,checkpoint_file=name,checkpoint_sha256=pin,
            observed_at=observed,earlier_knowledge_supported=False)
    finally:
        os.close(fd)


def _checkpoint(anchor,inventory,end,signer,key_id):
    issued=_now().isoformat()
    require(_time(end)<=_time(issued), 'Recorder clock moved backwards.')
    return _sign(dict(policy=POLICY,kind='CHECKPOINT',checkpoint_id=str(uuid4()),
        journal_anchor=anchor,observed_through=end,issued_at=issued,event_inventory=inventory,
        completeness_statement='ALL_DURABLY_RECORDED_OBSERVATIONS_IN_THIS_JOURNAL'),signer,key_id)


def load_checkpoint(root,repo,crypto,backup,recorder_keys,observation_keys,*,
        expected_anchor,checkpoint_file,expected_checkpoint_digest):
    """Independently supplied latest pins prevent undetected checkpoint rollback.

    Returned history covers journal observations only, not database/source change
    completeness. Never expose it as a full system-history coverage guarantee.
    """
    root=_private_root(root,repo);_hash(expected_anchor);_hash(expected_checkpoint_digest)
    require(isinstance(checkpoint_file,str) and Path(checkpoint_file).name==checkpoint_file and
        checkpoint_file.startswith('checkpoint-') and checkpoint_file.endswith('.encrypted.json'),
        'Checkpoint filename differs.')
    artifact_sha,signed=_read(root/'baseline.encrypted.json',crypto,backup,_binding('BASELINE'))
    require(artifact_sha==expected_anchor, 'Independent baseline pin differs.')
    base=_verify(signed,recorder_keys,BASE_FIELDS,'BASELINE')
    require(base['semantics']=='RECORDER_OBSERVED_ARCHIVED_BASELINE', 'Baseline time semantics differ.')
    start=_time(base['observed_at']);require(start<=_now(), 'Future baseline observation refused.')
    from app.identity.authenticated_recording_history import _scope
    _scope(base['scope']);_hash(base['source_registry_sha256']);_hash(base['original_publication_sha256'])
    artifact_sha,receipt=_read(root/checkpoint_file,crypto,backup,_binding('CHECKPOINT',expected_anchor))
    require(artifact_sha==expected_checkpoint_digest, 'Independent checkpoint pin differs.')
    checkpoint=_verify(receipt,recorder_keys,CHECK_FIELDS,'CHECKPOINT')
    require(checkpoint['journal_anchor']==expected_anchor and
        checkpoint['completeness_statement']=='ALL_DURABLY_RECORDED_OBSERVATIONS_IN_THIS_JOURNAL',
        'Observation checkpoint scope differs.')
    end=_time(checkpoint['observed_through']);issued=_time(checkpoint['issued_at'])
    require(start<=end<=issued<=_now(), 'Observation coverage time order differs.')
    inventory=checkpoint['event_inventory']
    require(type(inventory) is list, 'Observation event inventory required.')
    versions=[];ids=set();previous=digest(signed);last=start
    require(type(base['claims']) is list, 'Baseline claim inventory required.')
    for entry in base['claims']:
        require(type(entry) is dict and set(entry)=={'claim','source_key'}, 'Baseline entry differs.')
        claim=_claim(entry['claim']);source=entry['source_key']
        require(source in base['scope']['source_keys'] and claim.claim_id not in ids,
            'Baseline source or claim differs.')
        ids.add(claim.claim_id)
        identifier='baseline:'+digest(entry)
        versions.append(EvidenceVersion(identifier,claim,source,start,base['journal_id'],expected_anchor))
    for index,item in enumerate(inventory,1):
        name=f'event-{index:08d}.encrypted.json'
        require(type(item) is dict and set(item)=={'file','sha256'} and item['file']==name,
            'Ordered observation inventory required.')
        _hash(item['sha256'])
        artifact_sha,receipt=_read(root/name,crypto,backup,_binding('EVENT',expected_anchor))
        require(artifact_sha==item['sha256'], 'Observation artifact changed.')
        event=_verify(receipt,recorder_keys,EVENT_FIELDS,'EVENT')
        require(event['journal_anchor']==expected_anchor and type(event['sequence']) is int and
            event['sequence']==index and event['previous_receipt_sha256']==previous and
            event['semantics']=='RECORDER_OBSERVED_AUTHORIZED_COMMITTED_VERSION',
            'Observation chain or semantics differs.')
        observed=_time(event['observed_at'])
        require(last<observed<=end, 'Observation clock order differs.')
        authorization=_verify(event['authorization'],observation_keys,AUTH_FIELDS,'OBSERVATION',AUTH_POLICY)
        _authorization(authorization,base,expected_anchor,observed,recorder_keys,observation_keys)
        for field in ('claim','source_key','supersedes','withdrawn'):
            require(event[field]==authorization[field], 'Observation differs from authorized committed evidence.')
        claim=_claim(event['claim'])
        versions.append(EvidenceVersion(event['version_id'],claim,event['source_key'],observed,
            event['event_id'],item['sha256'],event['supersedes'],event['withdrawn']))
        previous,last=digest(receipt),observed
    history=RecordingHistory(base['scope']['officer_uid'],start,end,checkpoint['checkpoint_id'],
        expected_checkpoint_digest,tuple(versions))
    return dict(history=history,baseline=base,checkpoint=checkpoint,last_receipt_sha256=previous,
        earlier_knowledge_supported=False,source_change_completeness_established=False,
        coverage_semantics='JOURNAL_OBSERVATIONS_ONLY')


def _authorization(value,base,anchor,observed,recorder_keys,observation_keys):
    require(not set(recorder_keys.values()) & set(observation_keys.values()),
        'Recorder and committed-evidence authority keys must be separate.')
    require(value['journal_anchor']==anchor and value['status']=='COMMITTED_VERSION_VERIFIED',
        'Committed evidence authorization differs.')
    _hash(value['evidence_epoch_sha256']);_text(value['readiness_reference'])
    issued,expires=_time(value['issued_at']),_time(value['expires_at'])
    require(issued<=observed<expires and expires==issued+timedelta(seconds=600),
        'Committed evidence authorization expired or time differs.')
    claim=_claim(value['claim'])
    require(claim.officer_uid==base['scope']['officer_uid'] and
        value['source_key'] in base['scope']['source_keys'], 'Committed observation outside journal scope.')
    require(type(value['withdrawn']) is bool, 'Explicit observation withdrawal required.')


def append_observation(root,repo,crypto,backup,signer,key_id,recorder_keys,observation_keys,
        authorization,*,expected_anchor,checkpoint_file,expected_checkpoint_digest):
    """Append only separately authorized committed evidence, with no backdate input.

    The external trusted authority must check the actual committed version and
    its evidence epoch before signing. This package does not issue its approvals.
    This authorization is not a research audit permit or source-truth finding.
    """
    root=_private_root(root,repo)
    # Freeze request material before authentication; do not retain caller payload aliases.
    authorization=deepcopy(authorization)
    _recorder(signer,key_id,recorder_keys,crypto,backup)
    fd=os.open(root,os.O_RDONLY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        state=load_checkpoint(root,repo,crypto,backup,recorder_keys,observation_keys,
            expected_anchor=expected_anchor,checkpoint_file=checkpoint_file,
            expected_checkpoint_digest=expected_checkpoint_digest)
        inventory=state['checkpoint']['event_inventory']
        require({p.name for p in root.glob('event-*.encrypted.json')}=={i['file'] for i in inventory},
            'Uncheckpointed observations or stale append checkpoint; recovery required.')
        approved=_verify(authorization,observation_keys,AUTH_FIELDS,'OBSERVATION',AUTH_POLICY)
        observed=_now();base=state['baseline']
        _authorization(approved,base,expected_anchor,observed,recorder_keys,observation_keys)
        require(observed>state['history'].coverage_end, 'Recorder clock did not advance beyond checkpoint.')
        sequence=len(inventory)+1;version_id=str(uuid4());event_id=str(uuid4())
        claim=_claim(approved['claim'])
        version=EvidenceVersion(version_id,claim,approved['source_key'],observed,event_id,
            digest(authorization),approved['supersedes'],approved['withdrawn'])
        # Fail lineage validation before any publication.
        RecordingHistory(state['history'].officer_uid,state['history'].coverage_start,observed,
            'pending-checkpoint','0'*64,(*state['history'].versions,version))
        event=dict(policy=POLICY,kind='EVENT',event_id=event_id,journal_anchor=expected_anchor,
            sequence=sequence,previous_receipt_sha256=state['last_receipt_sha256'],
            observed_at=observed.isoformat(),version_id=version_id,claim=approved['claim'],
            source_key=approved['source_key'],supersedes=approved['supersedes'],
            withdrawn=approved['withdrawn'],authorization=deepcopy(authorization),
            semantics='RECORDER_OBSERVED_AUTHORIZED_COMMITTED_VERSION')
        def check():
            current=_now();require(current>=observed, 'Recorder clock moved backwards.')
            _authorization(approved,base,expected_anchor,current,recorder_keys,observation_keys)
        name=f'event-{sequence:08d}.encrypted.json'
        sha=_publish(root/name,_sign(event,signer,key_id),crypto,backup,_binding('EVENT',expected_anchor),check)
        inventory=[*inventory,dict(file=name,sha256=sha)]
        checkpoint=_checkpoint(expected_anchor,inventory,observed.isoformat(),signer,key_id)
        name='checkpoint-'+checkpoint['payload']['checkpoint_id']+'.encrypted.json'
        pin=_publish(root/name,checkpoint,crypto,backup,_binding('CHECKPOINT',expected_anchor),check)
        return dict(journal_anchor=expected_anchor,checkpoint_file=name,checkpoint_sha256=pin,
            observed_at=observed.isoformat(),version_id=version_id,earlier_knowledge_supported=False)
    finally:
        os.close(fd)


def query_observed_journal(state,*,effective_on,known_at):
    require(state['coverage_semantics']=='JOURNAL_OBSERVATIONS_ONLY' and
        state['source_change_completeness_established'] is False,
        'Explicit observation-only history boundary required.')
    return dict(result=query(state['history'],effective_on=effective_on,known_at=known_at),
        coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',earlier_knowledge_supported=False,
        source_change_completeness_established=False,accepted_state=None)
