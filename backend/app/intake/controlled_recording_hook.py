"""Opt-in, signed routing of committed staging rows into observed history.

Trusted backend only. Existing intake registration is not modified or enabled.
Routing approves candidate membership, not source truth or accepted identity.
"""
from dataclasses import dataclass, asdict
from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid5

from sqlalchemy import select, func, text
from sqlalchemy.engine import Engine
from app.staging.models import IntakeBatch, IntakeFile, RawRecord
from app.intake.staging_store import stored_row
from app.intake.staging_rows import open_row
from app.identity import committed_evidence_capture as C
from app.identity import observed_recording_journal as J
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.destination_binding import row_binding
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require

POLICY='CONTROLLED_STAGED_RECORDING_ROUTE_V1'
FIELDS={'policy','kind','journal_anchor','officer_uid','scope','raw_record_id','stage_sha256',
    'source_claim_id','supersedes','operation_id','issued_at','expires_at'}
NAMESPACE=UUID('b7319977-124f-4c86-86c8-e3057e28f6c4')


@dataclass(frozen=True)
class StageScope:
    """Pinned backend registration expectations, never request-selected paths."""
    batch_id: str
    archive_sha256: str
    receipt_sha256: str
    import_file_id: str
    filename: str
    file_sha256: str
    expected_rows: int
    source_system_code: str

    def __post_init__(self):
        for value in (self.archive_sha256,self.receipt_sha256,self.file_sha256):J._hash(value)
        require(str(UUID(self.import_file_id))==self.import_file_id,'Pinned import UUID differs.')
        require(self.filename in HEADERS and type(self.expected_rows) is int and self.expected_rows>0,
            'Supported nonempty temporal staging file required.')
        J._text(self.batch_id);J._text(self.source_system_code)


def _stage_engine(engine):
    require(isinstance(engine,Engine),'Committed staging Engine required.')
    require(engine.dialect.name in ('postgresql','sqlite'),'Supported staging engine required.')
    if engine.dialect.name=='postgresql':
        with engine.connect() as connection:
            for table in (IntakeBatch.__table__,IntakeFile.__table__,RawRecord.__table__):
                flags=connection.execute(text("SELECT has_any_column_privilege(current_user,:table,'INSERT'), "
                    "has_any_column_privilege(current_user,:table,'UPDATE'), "
                    "has_table_privilege(current_user,:table,'DELETE'), "
                    "has_table_privilege(current_user,:table,'TRUNCATE'), "
                    "has_table_privilege(current_user,:table,'TRIGGER')"),{'table':table.fullname}).one()
                require(not any(flags),'Hook staging role must be read-only.')


def read_committed_stage(engine,snapshot,scope,raw_record_id):
    require(type(scope) is StageScope,'Pinned staging scope required.')
    J._hash(raw_record_id);_stage_engine(engine)
    B,F,R=IntakeBatch.__table__,IntakeFile.__table__,RawRecord.__table__
    with engine.connect() as connection:
        if engine.dialect.name=='postgresql':
            connection.execute(text('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'))
        batch=connection.execute(select(B).where(B.c.batch_id==scope.batch_id)).mappings().one_or_none()
        file=connection.execute(select(F).where(F.c.import_file_id==UUID(scope.import_file_id))).mappings().one_or_none()
        row=connection.execute(select(R).where(R.c.raw_record_id==raw_record_id)).mappings().one_or_none()
        require(batch is not None and file is not None and row is not None,'Committed staging registration missing.')
        count,first,last,distinct=connection.execute(select(func.count(),func.min(R.c.source_row_number),
            func.max(R.c.source_row_number),func.count(func.distinct(R.c.source_row_number))).where(
            R.c.import_file_id==UUID(scope.import_file_id))).one()
    require(batch['archive_sha256']==scope.archive_sha256 and
        batch['registration_receipt_sha256']==scope.receipt_sha256 and batch['schema_version']=='1.0' and
        file['batch_id']==row['batch_id']==scope.batch_id and
        str(row['import_file_id'])==scope.import_file_id and
        file['source_file_sha256']==row['source_file_sha256']==scope.file_sha256 and
        file['archive_path']==row['archive_path'] and
        file['archive_path'].split('/')[-1]==scope.filename and
        file['expected_row_count']==count==distinct==scope.expected_rows and first==1 and last==count and
        1<=row['source_row_number']<=count and file['column_count']==len(file['columns']) and
        set(file['columns'])==HEADERS[scope.filename] and file['delimiter']==',' and
        file['declared_encoding'] in ('UTF-8','UTF-8-BOM'), 'Pinned staging registration differs.')
    sealed=stored_row(row)
    primary=open_row(snapshot['crypto'],sealed);backup=open_row(snapshot['backup'],sealed)
    require(primary==backup and primary['columns']==file['columns'],'Staging recovery/header differs.')
    fingerprint=digest([row_binding(B.fullname,('batch_id',),batch),
        row_binding(F.fullname,('import_file_id',),file),row_binding(R.fullname,('raw_record_id',),row)])
    return dict(original=dict(columns=primary['columns'],values=primary['values']),stage_sha256=fingerprint,
        source_row_number=row['source_row_number'],archive_path=row['archive_path'])


def _catalog(stage,scope,raw,officer):
    # These are staging candidate records, not invented identity.source_assertion rows.
    return dict(raw_record_id=raw,filename=scope.filename,original=deepcopy(stage['original']),
        classification='UNASSESSED',delivery=dict(complete=True,scope='PINNED_STAGING_FILE_ONLY'),
        candidate_links=[dict(officer_uid=officer,role='officer_nic_no',state='CANDIDATE_NOT_ACCEPTED')],
        provenance=dict(staging_scope=asdict(scope),stage_sha256=stage['stage_sha256'],
            source_row_number=stage['source_row_number'],archive_path=stage['archive_path'],
            source_assignment_semantics='BACKEND_REPORTED_SOURCE_NOT_AUTHENTICATED'),
        assertion=dict(policy=POLICY,semantics='STAGED_CANDIDATE_NOT_IDENTITY_ASSERTION'))


def _material(stage,scope,raw,officer,claim_id,supersedes,anchor):
    item=_catalog(stage,scope,raw,officer)
    claims=source_claims(officer,{raw:item},{raw:[{'stage_sha256':stage['stage_sha256']}]})
    require(sum(c.claim_id==claim_id for c in claims)==1,'Exact staged temporal claim selector required.')
    require(supersedes is None or isinstance(supersedes,str) and bool(supersedes),
        'Explicit predecessor version required for correction.')
    identity=dict(journal_anchor=anchor,officer_uid=officer,scope=asdict(scope),raw_record_id=raw,
        stage_sha256=stage['stage_sha256'],source_claim_id=claim_id,supersedes=supersedes)
    operation=str(uuid5(NAMESPACE,digest(identity)))
    return identity,dict(operation_id=operation,source_row=item,source_claim_id=claim_id,supersedes=supersedes)


def issue_loaded_route(snapshot,stage_engine,adapter,scope,*,raw_record_id,source_claim_id,
        supersedes=None,authority_signer,authority_key_id):
    """INTERNAL authorized routing boundary; no caller-supplied source cells."""
    permit=AlgorithmPermit(snapshot);selected=C._selection(snapshot,adapter,permit)
    registry=adapter.registry;officer=selected['state']['history'].officer_uid
    J._recorder(authority_signer,authority_key_id,registry.observation_keys,snapshot['crypto'],snapshot['backup'])
    stage=read_committed_stage(stage_engine,snapshot,scope,raw_record_id)
    identity,submission=_material(stage,scope,raw_record_id,officer,source_claim_id,supersedes,registry.anchor)
    now=J._now();value=dict(policy=POLICY,kind='ROUTE',**identity,operation_id=submission['operation_id'],
        issued_at=now.isoformat(),expires_at=(now+timedelta(seconds=600)).isoformat())
    permit.check(snapshot)
    require(C._selection(snapshot,adapter,permit)==selected,'Witnessed routing selection changed.')
    require(read_committed_stage(stage_engine,snapshot,scope,raw_record_id)==stage,'Staged route changed.')
    return J._sign(value,authority_signer,authority_key_id,POLICY)


def process_loaded_route(snapshot,stage_engine,outbox_engine,adapter,receipt,*,authority_signer,
        authority_key_id,recorder_signer,recorder_key_id):
    """INTERNAL opt-in post-commit hook; use existing authorized recovery on interruption.

    Refreshed routes have the same deterministic operation ID and immutable intent.
    No successful batch-completeness or exact database commit-time claim is made.
    """
    permit=AlgorithmPermit(snapshot);selected=C._selection(snapshot,adapter,permit);registry=adapter.registry
    value=J._verify(deepcopy(receipt),registry.observation_keys,FIELDS,'ROUTE',POLICY)
    now=J._now();issued=J._time(value['issued_at']);expires=J._time(value['expires_at'])
    require(issued<=now<expires and expires==issued+timedelta(seconds=600), 'Staged route expired or time differs.')
    require(value['journal_anchor']==registry.anchor and
        value['officer_uid']==selected['state']['history'].officer_uid,'Staged routing scope differs.')
    require(type(value['scope']) is dict and set(value['scope'])==set(StageScope.__dataclass_fields__),
        'Pinned routing scope fields differ.')
    scope=StageScope(**value['scope']);stage=read_committed_stage(stage_engine,snapshot,scope,value['raw_record_id'])
    identity,submission=_material(stage,scope,value['raw_record_id'],value['officer_uid'],
        value['source_claim_id'],value['supersedes'],registry.anchor)
    require(all(value[k]==v for k,v in identity.items()) and value['operation_id']==submission['operation_id'],
        'Signed staging bytes or operation identity differ.')
    # Validate capture signers before the outbox transaction, so a bad key cannot
    # leave a new row committed merely because the later capture was refused.
    J._recorder(authority_signer,authority_key_id,registry.observation_keys,snapshot['crypto'],snapshot['backup'])
    J._recorder(recorder_signer,recorder_key_id,registry.recorder_keys,registry.journal_crypto,registry.journal_backup)
    permit.check(snapshot)
    C.commit_loaded_version(snapshot,outbox_engine,adapter,**submission)
    result=C.capture_loaded_version(snapshot,outbox_engine,adapter,operation_id=submission['operation_id'],
        authority_signer=authority_signer,authority_key_id=authority_key_id,
        recorder_signer=recorder_signer,recorder_key_id=recorder_key_id)
    return dict(policy=POLICY,status=result['status'],operation_id=submission['operation_id'],
        coverage_semantics='JOURNAL_OBSERVATIONS_ONLY',source_change_completeness_established=False)


def process_registered_route(args,repo,revision,stage_engine,outbox_engine,adapter,receipt,**signers):
    """Public backend entry; configured PostgreSQL/mTLS and full replay required."""
    require(isinstance(stage_engine,Engine) and stage_engine.dialect.name=='postgresql',
        'Configured PostgreSQL staging reader required.')
    snapshot=C._snapshot(args,repo,revision,outbox_engine,adapter)
    return process_loaded_route(snapshot,stage_engine,outbox_engine,adapter,receipt,**signers)


def issue_registered_route(args,repo,revision,stage_engine,outbox_engine,adapter,scope,**routing):
    """Authorized backend routing entry; same full replay and live-readiness gate."""
    require(isinstance(stage_engine,Engine) and stage_engine.dialect.name=='postgresql',
        'Configured PostgreSQL staging reader required.')
    snapshot=C._snapshot(args,repo,revision,outbox_engine,adapter)
    return issue_loaded_route(snapshot,stage_engine,adapter,scope,**routing)
