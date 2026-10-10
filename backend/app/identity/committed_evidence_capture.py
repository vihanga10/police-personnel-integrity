"""Encrypted committed-version outbox and trusted journal capture bridge.

The outbox is a new evidence store, not proof of updates to existing HR/PF/SRB
destinations. No automatic schema installation, intake hook or request endpoint.
Loaded APIs require full anchored replay and trusted intake configuration.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import json
from uuid import UUID

from sqlalchemy import Table, Column, MetaData, String, Text, DateTime, UniqueConstraint, select, text, func
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from app.identity import observed_recording_journal as J
from app.identity import recording_tip_witness as W
from app.identity import recording_checkpoint_registry as R
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.bitemporal_reconstruction import EvidenceVersion, RecordingHistory
from app.identity.historical_reconstruction import require
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.evidence_bundle_v2 import canonical, seal_artifact, open_artifact
from app.identity.protected_commitment import digest
from app.identity.witness_secure_transport import HTTPSWitnessTransport

POLICY = 'COMMITTED_ENCRYPTED_EVIDENCE_CAPTURE_V1'
metadata = MetaData()
OUTBOX = Table('recording_evidence_outbox', metadata,
    Column('operation_id', String(36), primary_key=True),
    Column('journal_anchor', String(64), nullable=False),
    Column('intent_sha256', String(64), nullable=False),
    Column('envelope_sha256', String(64), nullable=False),
    Column('envelope_json', Text, nullable=False),
    Column('database_reported_created_at', DateTime(timezone=True), nullable=False, server_default=func.now()),
    UniqueConstraint('journal_anchor','intent_sha256',name='uq_recording_evidence_intent'),
    schema='identity')


def _engine(engine, *, production=False):
    require(isinstance(engine, Engine), 'Separate committed database Engine required.')
    require(engine.dialect.name == 'postgresql' or
        (not production and engine.dialect.name == 'sqlite'), 'PostgreSQL engine required.')
    if engine.dialect.name == 'postgresql':
        with engine.connect() as connection:
            flags=connection.execute(text("SELECT has_table_privilege(current_user, "
                "'identity.recording_evidence_outbox', 'UPDATE'), "
                "has_any_column_privilege(current_user, 'identity.recording_evidence_outbox', 'UPDATE'), "
                "has_table_privilege(current_user, 'identity.recording_evidence_outbox', 'DELETE'), "
                "has_table_privilege(current_user, 'identity.recording_evidence_outbox', 'TRUNCATE'), "
                "has_table_privilege(current_user, 'identity.recording_evidence_outbox', 'TRIGGER')")).one()
            require(not any(flags), 'Outbox runtime role must be append-only.')
            require(connection.execute(text("SELECT current_setting('fsync') = 'on', "
                "NOT pg_is_in_recovery()")).one()==(True,True),
                'Primary PostgreSQL with fsync enabled required.')


def _snapshot(args, repo, revision, engine, adapter):
    _engine(engine, production=True)
    require(type(adapter) is W.WitnessedCheckpointRegistry and
        type(adapter.client) is W.WitnessClient and
        type(adapter.client.exchange) is HTTPSWitnessTransport,
        'Configured mutual-TLS witness transport required.')
    transport=adapter.client.exchange
    require(Path(transport.repo).expanduser().resolve()==Path(repo).expanduser().resolve() and
        Path(adapter.registry.repo).expanduser().resolve()==Path(repo).expanduser().resolve() and
        all(transport.profile[k]==adapter.client.scope[k] for k in W.SCOPE) and
        transport.writer_key_id==adapter.client.key_id and
        transport.profile['writer_keys_sha256']==W._key_digest(adapter.client.writer_keys) and
        transport.profile['witness_keys_sha256']==W._key_digest(adapter.client.witness_keys),
        'Secure capture transport pins differ.')
    from app.identity.algorithm_snapshot import load_verified_snapshot
    return load_verified_snapshot(args,repo,revision)


def commit_evidence_version(args, repo, revision, engine, adapter, **submission):
    """Trusted intake calls this after validation; it commits only the new outbox."""
    return commit_loaded_version(_snapshot(args,repo,revision,engine,adapter),engine,adapter,**submission)


def capture_evidence_version(args, repo, revision, engine, adapter, *, operation_id,
        authority_signer, authority_key_id, recorder_signer, recorder_key_id):
    snapshot=_snapshot(args,repo,revision,engine,adapter)
    return capture_loaded_version(snapshot,engine,adapter,operation_id=operation_id,
        authority_signer=authority_signer,authority_key_id=authority_key_id,
        recorder_signer=recorder_signer,recorder_key_id=recorder_key_id)


def _id(value):
    require(isinstance(value,str) and str(UUID(value))==value,'Canonical operation UUID required.')
    return value


def _selection(snapshot,adapter,permit):
    require(type(adapter) is W.WitnessedCheckpointRegistry and type(adapter.registry) is R.CheckpointRegistry
        and type(adapter.client) is W.WitnessClient,'Trusted witnessed registry required.')
    W.WitnessedCheckpointRegistry(adapter.registry,adapter.client)
    permit.check(snapshot)
    selected=adapter.select();base=selected['state']['baseline']
    context=dict(snapshot['context']);recorded=dict(base['source_context'])
    context.pop('code_revision',None);recorded.pop('code_revision',None)
    expected=[dict(claim=J._wire(c),source_key=json.loads(c.source_reference)['filename'])
        for c in source_claims(base['scope']['officer_uid'],snapshot['catalog'],snapshot['bindings']['raw_bindings'])]
    require(context==recorded and base['original_publication_sha256']==digest(snapshot['public']) and
        base['source_registry_sha256']==digest({k:sorted(v) for k,v in HEADERS.items()}) and
        sorted(map(canonical,expected))==sorted(map(canonical,base['claims'])),
        'Capture baseline differs from anchored source replay.')
    permit.check(snapshot)
    return selected


def _binding(operation_id,anchor):
    return dict(artifact='COMMITTED_EVIDENCE_OUTBOX',policy=POLICY,operation_id=operation_id,journal_anchor=anchor)


def _read(engine,snapshot,operation_id,anchor):
    """A new connection checks commit visibility; caller transactions are refused."""
    _id(operation_id)
    with engine.connect() as connection:
        row=connection.execute(select(OUTBOX).where(OUTBOX.c.operation_id==operation_id)).mappings().one_or_none()
    if row is None:return None
    require(row['journal_anchor']==anchor,'Committed outbox journal differs.')
    envelope=json.loads(row['envelope_json'])
    require(digest(envelope)==row['envelope_sha256'],'Committed outbox bytes differ.')
    binding=_binding(operation_id,anchor)
    body=open_artifact(snapshot['crypto'],envelope,binding)
    require(open_artifact(snapshot['backup'],envelope,binding)==body and
        body['policy']==POLICY and body['operation_id']==operation_id and body['journal_anchor']==anchor and
        digest(body['intent'])==row['intent_sha256'], 'Committed outbox recovery or identity differs.')
    return dict(body=body,epoch=row['envelope_sha256'])


def _proposed(state,intent,operation_id):
    history=state['history'];versions=history.versions
    predecessor=next((v for v in versions if v.version_id==intent['supersedes']),None)
    if intent['supersedes'] is not None:
        require(predecessor is not None,'Correction predecessor missing.')
        head=max((v for v in versions if v.claim.claim_id==predecessor.claim.claim_id),
            key=lambda v:v.recorded_at)
        require(head.version_id==predecessor.version_id,'Correction must reference latest claim version.')
    if intent['withdrawn']:
        require(predecessor is not None and intent['source_row'] is None and
            intent['source_claim_id'] is None and isinstance(intent['withdrawal_reason'],str) and
            bool(intent['withdrawal_reason'].strip()),'Withdrawal requires predecessor and explanation.')
        claim=predecessor.claim;source=predecessor.source_key
    else:
        require(intent['withdrawal_reason'] is None,'Withdrawal explanation only applies to withdrawals.')
        item=intent['source_row'];require(type(item) is dict,'Validated intake source row required.')
        raw=item['raw_record_id'];source=item['filename'];require(source in HEADERS,'Unsupported temporal source.')
        # Bind to evidence bytes actually stored in this outbox, not caller-asserted
        # PostgreSQL/Mongo destination fingerprints.
        own_binding=[dict(table=OUTBOX.fullname,operation_id=operation_id,source_sha256=digest(item))]
        claims=source_claims(history.officer_uid,{raw:item},{raw:own_binding})
        matches=[c for c in claims if c.claim_id==intent['source_claim_id']]
        require(len(matches)==1,'Exact extracted source claim required.')
        claim=matches[0]
        if predecessor:
            require(source==predecessor.source_key and claim.dimension==predecessor.claim.dimension and
                claim.claim_id.split(':',1)[1]==predecessor.claim.claim_id.split(':',1)[1],
                'Correction cannot change source or logical claim slot.')
            claim=replace(claim,claim_id=predecessor.claim.claim_id)
    now=J._now()
    require(now>history.coverage_end,'Capture clock must advance beyond existing history.')
    version=EvidenceVersion(operation_id,claim,source,now,operation_id,'0'*64,
        intent['supersedes'],intent['withdrawn'])
    RecordingHistory(history.officer_uid,history.coverage_start,now,'pending','0'*64,(*versions,version))
    return dict(claim=J._wire(claim),source_key=source,supersedes=intent['supersedes'],withdrawn=intent['withdrawn'])


def commit_loaded_version(snapshot,engine,adapter,*,operation_id,source_row=None,
        source_claim_id=None,supersedes=None,withdrawn=False,withdrawal_reason=None):
    """INTERNAL trusted intake boundary. No caller-provided observation timestamp.

    Caller validation establishes delivery completeness and subject association;
    neither source truth nor independent capture is established here.
    """
    _engine(engine);_id(operation_id);require(type(withdrawn) is bool,'Explicit withdrawal flag required.')
    intent=deepcopy(dict(source_row=source_row,source_claim_id=source_claim_id,
        supersedes=supersedes,withdrawn=withdrawn,withdrawal_reason=withdrawal_reason))
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    anchor=adapter.registry.anchor
    existing=_read(engine,snapshot,operation_id,anchor)
    if existing:
        require(existing['body']['intent']==intent,'Operation ID reused for different evidence.')
        _selection(snapshot,adapter,permit)
        return dict(policy=POLICY,status='ALREADY_COMMITTED',operation_id=operation_id)
    selected=_selection(snapshot,adapter,permit)
    approved=_proposed(selected['state'],intent,operation_id)
    body=dict(policy=POLICY,operation_id=operation_id,journal_anchor=anchor,intent=intent,
        proposed=approved,original_publication_sha256=digest(snapshot['public']),
        source_context=deepcopy(snapshot['context']),
        storage_semantics='NEW_ENCRYPTED_OUTBOX_EVIDENCE_VERSION',accepted_state=None)
    envelope=seal_artifact(snapshot['crypto'],snapshot['backup'],body,_binding(operation_id,anchor))
    require(open_artifact(snapshot['backup'],envelope,envelope['binding'])==body,'Outbox backup recovery differs.')
    permit.check(snapshot)
    require(_selection(snapshot,adapter,permit)==selected,'Witnessed selection changed before evidence commit.')
    try:
        with engine.begin() as connection:
            if engine.dialect.name=='postgresql':connection.execute(text("SET LOCAL synchronous_commit = 'on'"))
            connection.execute(OUTBOX.insert().values(operation_id=operation_id,journal_anchor=anchor,
                intent_sha256=digest(intent),envelope_sha256=digest(envelope),envelope_json=canonical(envelope)))
            permit.check(snapshot)
    except IntegrityError:
        duplicate=_read(engine,snapshot,operation_id,anchor)
        require(duplicate is not None and duplicate['body']['intent']==intent,
            'Concurrent or repeated evidence intent has a different operation ID.')
    saved=_read(engine,snapshot,operation_id,anchor)
    require(saved is not None and saved['body']['intent']==intent,'Post-commit evidence readback differs.')
    permit.check(snapshot)
    return dict(policy=POLICY,status='COMMITTED',operation_id=operation_id)


def capture_loaded_version(snapshot,engine,adapter,*,operation_id,authority_signer,
        authority_key_id,recorder_signer,recorder_key_id):
    """Read committed evidence, sign at current observation time, append and witness.

    Pending journal/registry writes require the existing separately authorized
    recovery workflow. No distributed-transaction or automatic-repair claim.
    """
    _engine(engine);_id(operation_id);permit=AlgorithmPermit(snapshot)
    selected=_selection(snapshot,adapter,permit);registry=adapter.registry
    saved=_read(engine,snapshot,operation_id,registry.anchor)
    require(saved is not None,'Evidence version is not visible as committed.')
    body=saved['body'];state=selected['state']
    require(body['original_publication_sha256']==digest(snapshot['public']) and
        body['storage_semantics']=='NEW_ENCRYPTED_OUTBOX_EVIDENCE_VERSION' and body['accepted_state'] is None,
        'Committed evidence epoch differs.')
    old_context=dict(body['source_context']);current_context=dict(snapshot['context'])
    old_context.pop('code_revision',None);current_context.pop('code_revision',None)
    require(old_context==current_context,'Committed evidence source context differs.')
    # Authenticate both signer configurations even on idempotent retries.
    J._recorder(authority_signer,authority_key_id,registry.observation_keys,snapshot['crypto'],snapshot['backup'])
    J._recorder(recorder_signer,recorder_key_id,registry.recorder_keys,registry.journal_crypto,registry.journal_backup)
    found=[]
    for item in state['checkpoint']['event_inventory']:
        _,receipt=J._read(registry.journal_root/item['file'],registry.journal_crypto,
            registry.journal_backup,J._binding('EVENT',registry.anchor))
        if receipt['payload']['authorization']['payload']['evidence_epoch_sha256']==saved['epoch']:
            found.append(receipt['payload'])
    require(len(found)<=1,'Evidence epoch was captured repeatedly.')
    if found:
        event=found[0]
        require(all(event[k]==body['proposed'][k] for k in ('claim','source_key','supersedes','withdrawn')),
            'Previously captured epoch differs.')
        permit.check(snapshot)
        require(adapter.select()==selected,'Witness advanced during capture retry.')
        return dict(policy=POLICY,status='ALREADY_CAPTURED',operation_id=operation_id,
            source_change_completeness_established=False)
    proposed=_proposed(state,body['intent'],operation_id)
    require(proposed==body['proposed'],'Committed proposal no longer matches current lineage.')
    issued=J._now()
    value=dict(policy=J.AUTH_POLICY,kind='OBSERVATION',journal_anchor=registry.anchor,
        **proposed,evidence_epoch_sha256=saved['epoch'],
        readiness_reference='COMMITTED_ENCRYPTED_OUTBOX:'+operation_id,
        issued_at=issued.isoformat(),expires_at=(issued+timedelta(seconds=600)).isoformat(),
        status='COMMITTED_VERSION_VERIFIED')
    authorization=J._sign(value,authority_signer,authority_key_id,J.AUTH_POLICY)
    J._authorization(value,state['baseline'],registry.anchor,issued,registry.recorder_keys,registry.observation_keys)
    permit.check(snapshot)
    require(_read(engine,snapshot,operation_id,registry.anchor)==saved,'Committed epoch changed before recording.')
    require(_selection(snapshot,adapter,permit)==selected,'Witnessed history changed before recording.')
    outcome=J.append_observation(registry.journal_root,registry.repo,registry.journal_crypto,
        registry.journal_backup,recorder_signer,recorder_key_id,registry.recorder_keys,
        registry.observation_keys,authorization,expected_anchor=registry.anchor,
        checkpoint_file=selected['checkpoint_file'],expected_checkpoint_digest=selected['checkpoint_sha256'])
    adapter.register(checkpoint_file=outcome['checkpoint_file'],checkpoint_sha256=outcome['checkpoint_sha256'])
    permit.check(snapshot)
    latest=adapter.select()
    require(any(v.version_id==outcome['version_id'] for v in latest['state']['history'].versions),
        'Witnessed capture readback differs.')
    return dict(policy=POLICY,status='CAPTURED',operation_id=operation_id,
        source_change_completeness_established=False)
