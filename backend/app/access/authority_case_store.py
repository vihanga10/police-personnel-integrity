"""Immutable encrypted explicit research assessments; no police authorization issuer."""
import base64
import hashlib
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.access.policy import encoded,require,uid
from app.access import research_policy as P
from app.access import operational_authority as A

POLICY='GENERATED_AUTHORITY_ASSESSMENT_RECORD_V1'
FIELDS={'policy','kind','record_origin','officer_uid','action_reference','workspace_sha256','source_public_sha256',
    'assessment','actor_packets','recorded_at','version','supersedes','operation_id','review_reference'}

def validate(envelope,store):
    require(type(envelope) is dict and set(envelope)=={'key_id','payload','signature'})
    keys=getattr(store,'workflow_keys',{});require(envelope['key_id'] in keys,'Unconfigured research assessor')
    p=envelope['payload'];require(type(p) is dict and set(p)==FIELDS)
    require(p['policy']==POLICY and p['kind']=='AUTHORITY_ASSESSMENT' and p['record_origin']=='GENERATED_RESEARCH_RECORDS')
    Ed25519PublicKey.from_public_bytes(keys[envelope['key_id']]).verify(base64.b64decode(envelope['signature'],validate=True),encoded(p))
    uid(p['officer_uid']);uid(p['operation_id']);P.sha(p['action_reference']);P.sha(p['workspace_sha256']);P.sha(p['source_public_sha256'])
    require(P.instant(p['recorded_at'])<=datetime.fromtimestamp(store.clock(),timezone.utc) and type(p['version']) is int and p['version']>0)
    P.text(p['review_reference'],200);typed=A.assessment(p['assessment']);A.evidence_references(typed)
    require(type(p['actor_packets']) is dict and len(p['actor_packets'])<=128)
    for officer,pin in p['actor_packets'].items():uid(officer);P.sha(pin)
    if p['supersedes'] is not None:P.sha(p['supersedes'])
    return p

def rows(store,officer):
    with store.transaction() as database:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE name='authority_assessments'").fetchone():return []
        values=database.execute('SELECT id,value FROM authority_assessments WHERE officer=? ORDER BY seq',
            (store.index('ASSESSMENT_OFFICER',officer),)).fetchall()
    result=[];heads={};operations=set()
    for ident,blob in values:
        envelope=store.open('AUTHORITY_ASSESSMENT',ident,blob);p=validate(envelope,store)
        require(p['officer_uid']==officer and P.fingerprint(envelope)==ident and p['operation_id'] not in operations)
        operations.add(p['operation_id']);previous=heads.get(p['action_reference'])
        require(p['version']==(previous[0]+1 if previous else 1) and p['supersedes']==(previous[1] if previous else None),
            'Assessment correction lineage differs')
        if previous:require(P.instant(p['recorded_at'])>previous[2],'Assessment correction must advance actual recorded time')
        heads[p['action_reference']]=(p['version'],ident,P.instant(p['recorded_at']));result.append(envelope)
        with store.transaction() as database:
            for reference,expected in p['assessment']['evidence_digests']:
                key=store.index('AUTHORITY_EVIDENCE',p['operation_id'],reference)
                evidence=database.execute('SELECT value FROM authority_assessment_evidence WHERE id=?',(key,)).fetchone()
                require(evidence is not None,'Missing retained assessment evidence')
                value=store.open('AUTHORITY_EVIDENCE',key,evidence[0])
                data=base64.b64decode(value['data'],validate=True)
                require(value['reference']==reference and value['operation_id']==p['operation_id'] and
                    hashlib.sha256(data).hexdigest()==expected,'Retained assessment evidence differs')
    return result

def append(store,envelope,check,*,evidence):
    p=validate(envelope,store);ident=P.fingerprint(envelope);previous=rows(store,p['officer_uid'])
    require(type(evidence) is dict and 0<len(evidence)<=128 and all(type(v) is bytes and v for v in evidence.values()))
    require(sum(map(len,evidence.values()))<=8*1024*1024 and
        {ref:hashlib.sha256(data).hexdigest() for ref,data in evidence.items()}==dict(p['assessment']['evidence_digests']),
        'Exact assessment evidence bytes required')
    replay=next((e for e in previous if e['payload']['operation_id']==p['operation_id']),None)
    if replay:require(replay==envelope,'Assessment operation conflict');return ident
    head=next((e for e in reversed(previous) if e['payload']['action_reference']==p['action_reference']),None)
    require(p['version']==(head['payload']['version']+1 if head else 1) and p['supersedes']==(P.fingerprint(head) if head else None))
    if head:require(P.instant(p['recorded_at'])>P.instant(head['payload']['recorded_at']))
    check()
    with store.transaction() as database:
        database.execute('CREATE TABLE IF NOT EXISTS authority_assessments(seq INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,officer TEXT NOT NULL,value BLOB NOT NULL)')
        database.execute('CREATE TABLE IF NOT EXISTS authority_assessment_evidence(id TEXT PRIMARY KEY,value BLOB NOT NULL)')
        for table in ('authority_assessments','authority_assessment_evidence'):
            for operation in ('UPDATE','DELETE'):
                database.execute(f"CREATE TRIGGER IF NOT EXISTS no_{table}_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable research assessment'); END")
        count=database.execute('SELECT COUNT(*) FROM authority_assessments WHERE officer=?',(store.index('ASSESSMENT_OFFICER',p['officer_uid']),)).fetchone()[0]
        require(count==len(previous),'Assessment inventory advanced concurrently')
        require(count<2000,'Assessment inventory bound')
        database.execute('INSERT INTO authority_assessments(id,officer,value) VALUES(?,?,?)',
            (ident,store.index('ASSESSMENT_OFFICER',p['officer_uid']),store.seal('AUTHORITY_ASSESSMENT',ident,envelope)))
        for reference,data in evidence.items():
            key=store.index('AUTHORITY_EVIDENCE',p['operation_id'],reference)
            database.execute('INSERT INTO authority_assessment_evidence VALUES(?,?)',(key,store.seal('AUTHORITY_EVIDENCE',key,
                dict(operation_id=p['operation_id'],reference=reference,data=base64.b64encode(data).decode()))))
        store.event(database,dict(kind='AUTHORITY_RESEARCH_ASSESSMENT_RECORDED',officer_uid=p['officer_uid'],assessment_sha256=ident,version=p['version']))
        check(database)
    return ident
