"""Retained, encrypted operator observations for application finding prefixes.

No HTTP receipt import or publication. A receipt is a past verified observation,
not an assertion that the chain is being checked on every page load.
"""
from app.access import application_findings_commitments as A, review_workflow as W, research_policy as P
from app.access.policy import require, uid

def initialize(store):
    with store.transaction() as c:
        c.execute('CREATE TABLE IF NOT EXISTS application_anchor_observations (seq INTEGER PRIMARY KEY, officer TEXT NOT NULL, value TEXT NOT NULL)')
        for action in ('UPDATE','DELETE'):
            c.execute(f"CREATE TRIGGER IF NOT EXISTS application_anchor_observations_{action} BEFORE {action} ON application_anchor_observations BEGIN SELECT RAISE(ABORT,'immutable anchor observation'); END")

def validate(result,public,destination):
    require(type(result) is dict and set(result)=={'status','fabric','public','scope','independent_witness_deployment_verified'})
    require(result['scope']=='APPLICATION_FINDINGS_PREFIX_ONLY' and result['independent_witness_deployment_verified'] is False)
    fabric=result['fabric'];chain=result['public'];require(type(fabric) is dict and set(fabric)=={'status','destination','payload','transaction_id','verification'})
    require(fabric['status']=='FINAL' and fabric['payload']==A.fabric_payload(public));P.sha(fabric['transaction_id'])
    d=fabric['destination'];require(set(d)=={'genesis_sha256','channel','chaincode','namespace','organizations'} and d['channel']=='personnel' and d['chaincode']==d['namespace']=='findings-anchor-v1' and d['organizations']==['Org1MSP','Org2MSP']);P.sha(d['genesis_sha256'])
    v=fabric['verification'];require(set(v)=={'validation_code','organizations','block_sha256'} and v['validation_code']=='VALID' and v['organizations']==d['organizations']);P.sha(v['block_sha256'])
    require(type(chain) is dict);transaction=chain.get('transaction_id');require(type(transaction) is str and transaction.startswith('0x'));P.sha(transaction[2:])
    if chain.get('status')=='PENDING':
        require(set(chain)=={'status','reason','transaction_id'} and chain['reason'] in ('BOTH_ORIGINAL_RECEIPTS_REQUIRED','FINALITY_AND_CONFIRMATIONS_REQUIRED') and result['status']=='PENDING')
    else:
        require(set(chain)=={'status','destination','payload','transaction_id','verification'} and chain['status']=='FINAL' and result['status']=='BOTH_CHAINS_VERIFIED' and chain['destination']==destination)
        payload=dict(policy='FINDINGS_PUBLIC_ANCHOR_V1',namespace='findings-anchor-v1',publication_id=public['publication_id'],public_sha256=P.fingerprint(public),merkle_root=public['merkle_root'],fabric_destination_sha256=P.fingerprint(d),fabric_transaction_id=fabric['transaction_id'],fabric_receipt_sha256=P.fingerprint(fabric))
        require(chain['payload']==payload)
        v=chain['verification'];require(set(v)=={'execution_status','finalized','independent_readback','block_sha256'} and type(v['execution_status']) is int and v['execution_status']==1 and v['finalized'] is True and v['independent_readback'] is True);P.sha(v['block_sha256'])
    return result

def record(store,selection,public,result,destination):
    validate(result,public,destination);initialize(store);uid(selection['officer_uid'])
    require(A.select(store,selection['officer_uid'])==selection,'Changed finding prefix')
    with store.transaction() as c:
        current=[e for e in W.entries(store,c) if e['input']['officer_uid']==selection['officer_uid']]
        require(current==selection['entries'],'Changed finding prefix')
        seq=c.execute('SELECT count(*) FROM application_anchor_observations').fetchone()[0]+1;require(seq<=20000)
        value=dict(policy='APPLICATION_ANCHOR_OBSERVATION_V1',officer_uid=selection['officer_uid'],entry_references=[P.fingerprint(e) for e in current],publication_id=public['publication_id'],observed_at=store.clock(),result=result)
        c.execute('INSERT INTO application_anchor_observations VALUES(?,?,?)',(seq,store.index('OFFICER',selection['officer_uid']),store.seal('APPLICATION_ANCHOR_OBSERVATION',seq,value)))
        store.event(c,dict(kind='APPLICATION_ANCHOR_OBSERVATION',sequence=seq,reference=P.fingerprint(value)))
        return value

def status(service,token,officer):
    service.authorized(token,officer);store=service.store;initialize(store);W.initialize(store)
    with store.transaction() as c:
        entries=[e for e in W.entries(store,c) if e['input']['officer_uid']==officer]
        row=c.execute('SELECT seq,value FROM application_anchor_observations WHERE officer=? ORDER BY seq DESC LIMIT 1',(store.index('OFFICER',officer),)).fetchone()
        observation=store.open('APPLICATION_ANCHOR_OBSERVATION',row[0],row[1]) if row else None
        if observation:
            require(observation['officer_uid']==officer and observation['policy']=='APPLICATION_ANCHOR_OBSERVATION_V1')
            require(any(e.get('kind')=='APPLICATION_ANCHOR_OBSERVATION' and e['sequence']==row[0] and e['reference']==P.fingerprint(observation) for e in store._events(c)),'Observation event differs')
    service.authorized(token,officer,charge=False)
    base=dict(scope='APPLICATION_FINDINGS_PREFIX_ONLY',entry_count=len(entries),fresh_chain_verification=False,independent_witness_deployment_verified=False)
    if not observation:return dict(base,status='NOT_OBSERVED',both_chains_anchored=False)
    current=observation['entry_references']==[P.fingerprint(e) for e in entries]
    result=observation['result'];verified=result['status']=='BOTH_CHAINS_VERIFIED'
    return dict(base,status=result['status'] if current else 'NEW_FINDINGS_NOT_ANCHORED',both_chains_anchored=verified and current,
        observed_at=observation['observed_at'],publication_id=observation['publication_id'],covered_entry_count=len(observation['entry_references']),
        fabric_transaction_id=result['fabric']['transaction_id'],public_transaction_id=result['public']['transaction_id'])
