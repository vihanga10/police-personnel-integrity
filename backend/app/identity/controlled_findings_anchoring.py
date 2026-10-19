"""Isolated dual-chain coordinator. No operational adapter or network entry point.

Adapters are trusted test boundaries, not proof supplied by a request. An adapter
must reserve immutable transaction bytes before broadcast and reconcile that
same transaction after ambiguity. This module deliberately accepts fixtures only.
"""
from copy import deepcopy
from datetime import timezone
import base64
import fcntl
import os
import re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.identity import findings_commitments as C
from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest, encoded

POLICY='ISOLATED_CONTROLLED_FINDINGS_ANCHOR_V1'
NAMESPACE='findings-anchor-v1'
APPROVAL_FIELDS={'policy','key_id','mode','issued_at','expires_at','selection'}
SELECTION_FIELDS={'private_sha256','public_sha256','history_sha256','code_revision','destinations'}


def _exact(value,fields):
    require(type(value) is dict and set(value)==set(fields),'Exact anchoring schema required.')


def destinations(value):
    _exact(value,('fabric','public'))
    a,b=value['fabric'],value['public']
    _exact(a,('genesis_sha256','channel','chaincode','namespace','organizations'))
    _exact(b,('chain_id','contract','runtime_sha256','writer','namespace','finality'))
    F._sha(a['genesis_sha256']);F._sha(b['runtime_sha256'])
    require(a['namespace']==b['namespace']==NAMESPACE and a['chaincode']!='officer-evidence-v1',
        'Dedicated findings destination required.')
    require(all(type(a[k]) is str and re.fullmatch('[a-zA-Z0-9_.-]{1,128}',a[k]) for k in ('channel','chaincode')),
        'Fabric destination differs.')
    require(a['organizations']==['Org1MSP','Org2MSP'],'Two organization findings readback required.')
    require(type(b['chain_id']) is int and b['chain_id']==11155111 and b['finality']=='FINALIZED',
        'Sepolia finalized findings destination required.')
    for k in ('contract','writer'):
        require(type(b[k]) is str and re.fullmatch('0x[0-9a-f]{40}',b[k]) and b[k]!='0x'+'0'*40,
            'Nonzero lowercase EVM address required.')
    return value


def verify_approval(approval,trusted_keys,selection,mode):
    """Backend-selected approver keys; callers cannot nominate their own trust."""
    _exact(approval,('body','signature'));body=approval['body'];_exact(body,APPROVAL_FIELDS)
    require(body['policy']==POLICY and body['mode']==mode and mode in ('EXECUTE','RECONCILE'),
        'Anchoring approval mode differs.')
    _exact(body['selection'],SELECTION_FIELDS)
    require(body['selection']==selection,'Approved findings selection differs.')
    require(body['key_id'] in trusted_keys,'Anchoring approver is not trusted.')
    key=trusted_keys[body['key_id']]
    require(type(key) is bytes and len(key)==32,'Pinned approver public key required.')
    signature=base64.b64decode(approval['signature'],validate=True)
    require(len(signature)==64,'Ed25519 anchoring signature required.')
    Ed25519PublicKey.from_public_bytes(key).verify(signature,encoded(body))
    issued,expires=F._time(body['issued_at']),F._time(body['expires_at'])
    now=J._now().astimezone(timezone.utc)
    require(issued<=now<expires and 0<(expires-issued).total_seconds()<=600,
        'Fresh bounded anchoring approval required.')


def _receipt(receipt,stage,payload,destination,plan):
    _exact(receipt,('status','destination','payload','transaction_id','verification'))
    require(receipt['status']=='FINAL' and receipt['destination']==destination and receipt['payload']==payload and
        receipt['transaction_id']==plan['transaction_id'],'Final findings receipt binding differs.')
    F._sha(receipt['transaction_id'])
    v=receipt['verification']
    if stage=='fabric':
        _exact(v,('validation_code','organizations','block_sha256'))
        require(v['validation_code']=='VALID' and v['organizations']==destination['organizations'],
            'Valid two organization Fabric readback required.')
    else:
        _exact(v,('execution_status','finalized','independent_readback','block_sha256'))
        require(type(v['execution_status']) is int and v['execution_status']==1 and v['finalized'] is True and
            v['independent_readback'] is True,'Finalized independent public readback required.')
    F._sha(v['block_sha256'])


def run_isolated(snapshot,repo,findings,keys,backup_keys,*,commitment_directory,
        expected_private_sha256,expected_public_sha256,approval,trusted_keys,
        fabric,public,directory,mode='EXECUTE'):
    """Internal full-loader fixture boundary. Never expose as a request API.

    No real network transport is implemented. Both fixture adapters MUST provide:
    inspect(destination), prepare(operation,payload,destination),
    observe(plan,payload,destination), submit(plan,payload,destination).
    prepare has no chain side effects; submit uses the EXACT durable plan.
    observe returns ABSENT/PENDING or an independently verified FINAL receipt.
    """
    require(getattr(fabric,'fixture_transport',None) is True and getattr(public,'fixture_transport',None) is True,
        'This step supports isolated adapters only; live adapters are pending.')
    require(mode in ('EXECUTE','RECONCILE'),'Unsupported findings anchoring mode.')
    root=C._root(directory,repo);source=C._root(commitment_directory,repo)
    stores=(source,findings.registry.root,findings.registry.journal.root)
    require(all(not root.is_relative_to(p) and not p.is_relative_to(root) for p in stores),
        'Dedicated anchoring recovery directory required.')
    allowed={'intent.encrypted.json','fabric-plan.encrypted.json','fabric-final.encrypted.json',
        'public-plan.encrypted.json','public-final.encrypted.json'}
    require({p.name for p in root.iterdir()}<=allowed,'Unexpected recovery artifacts; inspect interruption.')
    fd=os.open(root,os.O_RDONLY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        return _run(snapshot,repo,findings,keys,backup_keys,source,expected_private_sha256,
            expected_public_sha256,deepcopy(approval),deepcopy(trusted_keys),fabric,public,root,mode)
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def _run(snapshot,repo,findings,keys,backup_keys,source,private_pin,public_pin,
        approval,trusted_keys,fabric,public,root,mode):
    F._sha(private_pin);F._sha(public_pin)
    crypto,backup=snapshot['crypto'],snapshot['backup']
    verified=C.verify_prepared(source,repo,keys,backup_keys,crypto,backup,expected_private_sha256=private_pin)
    require(verified['public_sha256']==public_pin,'Approved public commitment digest differs.')
    _,private=C._read(source,repo,crypto,backup,private_pin)
    p=private['public'];history=private['history']
    require(private['context']['source_context']==snapshot['context'] and
        private['context']['original_publication_sha256']==digest(snapshot['public']),
        'Anchoring original source context differs.')
    revision=snapshot['context']['code_revision']
    require(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'Committed anchoring source required.')
    dest=destinations(deepcopy(approval['body']['selection']['destinations']))
    selection=dict(private_sha256=private_pin,public_sha256=public_pin,history_sha256=digest(history),
        code_revision=revision,destinations=dest)
    verify_approval(approval,trusted_keys,selection,mode)
    permit=AlgorithmPermit(snapshot);permit.check(snapshot)
    source_pin=digest(dict(manifest=snapshot['manifest'],catalog=snapshot['catalog'],bindings=snapshot['bindings']))
    key_pin=C._key_pin(keys);pins=deepcopy(findings.registry.key_pins);scope=deepcopy(findings.scope)
    require(findings.registry.journal.officer_uid==history['entries'][0]['entry']['officer_uid'] and
        findings.registry.journal.officer_uid in {b['officer_uid'] for b in snapshot['manifest']['bundles']},
        'Findings anchoring subject differs.')
    operation=digest(dict(policy=POLICY,selection=selection))
    binding=dict(artifact='ISOLATED_FINDINGS_ANCHOR',policy=POLICY,operation=operation)
    def check():
        permit.check(snapshot);C._root(root,repo)
        verify_approval(approval,trusted_keys,selection,mode)
        require(C._key_pin(keys)==C._key_pin(backup_keys)==key_pin and findings.registry.key_pins==pins and
            findings.scope==scope and snapshot['context']==private['context']['source_context'] and
            digest(snapshot['public'])==private['context']['original_publication_sha256'] and
            digest(dict(manifest=snapshot['manifest'],catalog=snapshot['catalog'],bindings=snapshot['bindings']))==source_pin,
            'Anchoring source or configuration changed.')
        require(C.verify_prepared(source,repo,keys,backup_keys,crypto,backup,expected_private_sha256=private_pin)==verified,
            'Anchoring commitment artifact changed.')
        # Reconciling a signed old publication is read-only and does not claim latestness.
        if mode=='EXECUTE':require(findings.select()==history,'Latest witnessed findings changed; execution blocked.')
        for adapter,name in ((fabric,'fabric'),(public,'public')):
            require(adapter.fixture_transport is True and adapter.inspect(deepcopy(dest[name]))==dest[name],
                'Pinned findings destination changed.')
        permit.check(snapshot)
    def read(name):
        path=root/name
        if not path.exists():return None
        return J._read(path,crypto,backup,dict(binding,stage=name))[1]
    def save(name,value):
        existing=read(name)
        if existing is None:
            require(mode=='EXECUTE','Read-only reconciliation cannot create recovery state.')
            J._publish(root/name,value,crypto,backup,dict(binding,stage=name),check)
        else:require(existing==value,'Immutable recovery stage differs.')
    check()
    intent=read('intent.encrypted.json')
    if intent is None:
        save('intent.encrypted.json',dict(policy=POLICY,selection=selection,operation=operation,initial_approval=approval))
    else:
        _exact(intent,('policy','selection','operation','initial_approval'))
        require(intent['policy']==POLICY and intent['selection']==selection and intent['operation']==operation,
            'Original anchoring intent differs.')
        original=intent['initial_approval'];_exact(original,('body','signature'));_exact(original['body'],APPROVAL_FIELDS)
        require(original['body']['policy']==POLICY and original['body']['mode']=='EXECUTE' and
            original['body']['selection']==selection and original['body']['key_id'] in trusted_keys,
            'Original approval audit binding differs.')
        Ed25519PublicKey.from_public_bytes(trusted_keys[original['body']['key_id']]).verify(
            base64.b64decode(original['signature'],validate=True),encoded(original['body']))
    first=dict(policy='FINDINGS_FABRIC_ANCHOR_V1',namespace=NAMESPACE,publication_id=p['publication_id'],
        public_sha256=public_pin,merkle_root=p['merkle_root'],publication_commitment=p['publication_commitment'])
    def stage(name,adapter,payload):
        check();plan_name=name+'-plan.encrypted.json';final_name=name+'-final.encrypted.json'
        plan=read(plan_name)
        if plan is None:
            require(mode=='EXECUTE','Original durable transaction plan required for reconciliation.')
            plan=adapter.prepare(operation,deepcopy(payload),deepcopy(dest[name]))
            _exact(plan,('operation','payload_sha256','destination','transaction_id','transaction'))
            require(plan['operation']==operation and plan['payload_sha256']==digest(payload) and plan['destination']==dest[name],
                'Prepared transaction scope differs.')
            F._sha(plan['transaction_id'])
            require(type(plan['transaction']) is str and 0<len(plan['transaction'])<=200000,
                'Bounded immutable transaction envelope required.')
            save(plan_name,plan)
        _exact(plan,('operation','payload_sha256','destination','transaction_id','transaction'))
        require(plan['operation']==operation and plan['payload_sha256']==digest(payload) and plan['destination']==dest[name],
            'Saved transaction plan differs.')
        F._sha(plan['transaction_id'])
        require(type(plan['transaction']) is str and 0<len(plan['transaction'])<=200000,
            'Saved immutable transaction envelope differs.')
        check();observed=adapter.observe(deepcopy(plan),deepcopy(payload),deepcopy(dest[name]))
        if type(observed) is dict and observed=={'status':'ABSENT'}:
            require(mode=='EXECUTE' and read(final_name) is None,'Previously finalized transaction missing or read-only mode.')
            check();adapter.submit(deepcopy(plan),deepcopy(payload),deepcopy(dest[name]))
            check();observed=adapter.observe(deepcopy(plan),deepcopy(payload),deepcopy(dest[name]))
        # PENDING and unknown/errors stop. Never create another transaction identity.
        _receipt(observed,name,payload,dest[name],plan)
        if mode=='EXECUTE':save(final_name,observed)
        else:require(read(final_name)==observed,'Original final receipt required for reconciliation.')
        check();return observed
    private_receipt=stage('fabric',fabric,first)
    second=dict(policy='FINDINGS_PUBLIC_ANCHOR_V1',namespace=NAMESPACE,publication_id=p['publication_id'],
        public_sha256=public_pin,merkle_root=p['merkle_root'],fabric_destination_sha256=digest(dest['fabric']),
        fabric_transaction_id=private_receipt['transaction_id'],fabric_receipt_sha256=digest(private_receipt))
    stage('public',public,second)
    # Re-read the private ledger AFTER public finality; a stale receipt is insufficient.
    plan=read('fabric-plan.encrypted.json');check()
    again=fabric.observe(deepcopy(plan),deepcopy(first),deepcopy(dest['fabric']))
    _receipt(again,'fabric',first,dest['fabric'],plan)
    require(again==private_receipt,'Private chain changed after public anchoring.')
    check()
    return dict(policy=POLICY,status='ISOLATED_BOTH_VERIFIED',mode=mode,operation=operation,
        public_sha256=public_pin,merkle_root=p['merkle_root'],findings_anchored=False,accepted_state=None,
        latest_history_checked=mode=='EXECUTE',live_chain_verification=False)
