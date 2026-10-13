"""Bounded recording of the existing per-officer journal format.

Compile subject claims once from a fully authenticated replay. No caller-supplied
loader, historical clock, permit renewal or transport bypass is accepted here.
"""
from copy import deepcopy
from pathlib import Path
from uuid import uuid4
import json
import re
import os
import tempfile
from datetime import datetime, timezone, timedelta
from app.identity.audit_gate import binding
from app.identity.evidence_bundle_v2 import open_artifact
from app.identity import observed_recording_journal as J
from app.identity.algorithm_permit import AlgorithmPermit
from app.identity.historical_source_claims import source_claims, HEADERS
from app.identity.historical_reconstruction import DIMENSIONS
from app.identity.protected_commitment import digest
from app.access.policy import uid
from app.access.store import private

POLICY='BULK_RECORDED_HISTORY_CONTROL_V1'
DESC_FIELDS={'policy','kind','officer_uid','source_sha256','journal_anchor','checkpoint_file','checkpoint_sha256'}

def publish_control(path, receipt, check=lambda:None):
    """Durable non-overwriting publication, including control receipts."""
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.bulk-history-',delete=False) as stream:
            temporary=Path(stream.name);os.fchmod(stream.fileno(),0o600)
            stream.write((J.canonical(receipt)+'\n').encode());stream.flush();os.fsync(stream.fileno())
        check();os.link(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)

def unique(pairs):
    result={}
    for name,value in pairs:
        J.require(name not in result,'Duplicate bulk control field');result[name]=value
    return result

class VerifiedBaselineBatch:
    def __init__(self,snapshot,officers,signer,key_id,recorder_keys):
        self.snapshot=snapshot;self.permit=AlgorithmPermit(snapshot);self.permit.check(snapshot)
        J._recorder(signer,key_id,recorder_keys,snapshot['crypto'],snapshot['backup'])
        self.signer,self.key_id,self.recorder_keys=signer,key_id,dict(recorder_keys)
        self.context=deepcopy(snapshot['context']);self.public_sha=digest(snapshot['public'])
        self._permit=J.canonical(self.permit.check(snapshot))
        self.source_sha=digest(dict(catalog=snapshot['catalog'],bindings=snapshot['bindings']['raw_bindings']))
        self.registry_sha=digest({k:sorted(v) for k,v in HEADERS.items()})
        officers=set(officers);J.require(0<len(officers)<=10000,'Bounded complete officer set required')
        self._compiled={}
        index={officer:{} for officer in officers}
        for raw,item in snapshot['catalog'].items():
            if item['filename'] not in HEADERS:continue
            subject=[v for v in item['candidate_links'] if v['role']=='officer_nic_no']
            if not subject:continue
            J.require(len(subject)==1 and subject[0]['officer_uid'] in index,'Historical subject membership differs')
            index[subject[0]['officer_uid']][raw]=item
        for officer in sorted(officers):
            uid(officer)
            claims=source_claims(officer,index[officer],snapshot['bindings']['raw_bindings'])
            J.require(len({c.claim_id for c in claims})==len(claims),'Duplicate recorded claim')
            entries=[dict(claim=J._wire(c),source_key=json.loads(c.source_reference)['filename']) for c in claims]
            # Freeze the extraction as canonical strings. Later caller mutation cannot
            # change a recorded claim, and final verification checks the whole input.
            self._compiled[officer]=J.canonical(entries)
        self.check(full=True)

    def check(self,*,full=False):
        self.permit.check(self.snapshot)
        J.require(self.snapshot['context']==self.context and digest(self.snapshot['public'])==self.public_sha,
                  'Recorded history context or publication changed')
        if full:J.require(digest(dict(catalog=self.snapshot['catalog'],bindings=self.snapshot['bindings']['raw_bindings']))==self.source_sha,
                          'Recorded history source changed')

    def deadline(self):
        """Authenticate both permit keys before each durable write.

        Compiled claims/context/publication digests are frozen. The complete
        mutable input is checked at batch boundaries and before UI publication;
        a changed input can leave private artifacts, never a published UI set.
        This check does not issue or extend a permit.
        """
        now=datetime.now(timezone.utc)
        primary=open_artifact(self.snapshot['crypto'],self.snapshot['envelope'],binding(self.context))
        backup=open_artifact(self.snapshot['backup'],self.snapshot['envelope'],binding(self.context))
        J.require(J.canonical(primary)==J.canonical(backup)==self._permit,'Bulk permit or recovery changed')
        checked,issued,expires=(datetime.fromisoformat(primary[k]) for k in ('checked_at','issued_at','expires_at'))
        J.require(checked<=issued<=now<expires and expires==checked+timedelta(seconds=600),'Bulk audit permit expired')

    def entries(self,officer):return json.loads(self._compiled[officer])

    def _base(self,root,repo,officer):
        file=private(Path(root)/'baseline.encrypted.json',repo=repo)
        anchor,receipt=J._read(file,self.snapshot['crypto'],self.snapshot['backup'],J._binding('BASELINE'))
        base=J._verify(receipt,self.recorder_keys,J.BASE_FIELDS,'BASELINE')
        J.require(base['scope']==dict(officer_uid=officer,source_keys=sorted(HEADERS),dimensions=sorted(DIMENSIONS)) and
            base['source_context']==self.context and base['original_publication_sha256']==self.public_sha and
            base['source_registry_sha256']==self.registry_sha and base['claims']==self.entries(officer) and
            base['semantics']=='RECORDER_OBSERVED_ARCHIVED_BASELINE','Archived baseline differs from authenticated replay')
        J.require(J._time(base['observed_at'])<=J._now(),'Future observation refused')
        return anchor,base

    def record(self,root,repo,officer):
        self.deadline();root=J._private_root(root,repo);uid(officer)
        J.require(officer in self._compiled,'Officer not in authenticated source')
        names={p.name for p in root.iterdir()}
        J.require(all(n in {'baseline.encrypted.json','record.json'} or
                      re.fullmatch(r'checkpoint-[0-9a-f-]{36}\.encrypted\.json',n) for n in names),
                  'Unexpected journal artifact; preserve and investigate')
        descriptor=root/'record.json'
        if descriptor.exists():
            file=private(descriptor,repo=repo)
            J.require(file.stat().st_size<=16384,'Bounded baseline descriptor required')
            receipt=json.loads(file.read_bytes(),object_pairs_hook=unique)
            pin=J._verify(receipt,self.recorder_keys,DESC_FIELDS,'RECORDED_BASELINE',POLICY)
            J.require(pin['officer_uid']==officer and pin['source_sha256']==self.source_sha,'Recorded baseline descriptor differs')
            self._base(root,repo,officer)
            state=self.load(root,repo,pin)
            return pin,state
        if not (root/'baseline.encrypted.json').exists():
            J.require(not names,'A checkpoint cannot precede its baseline')
            observed=J._now().isoformat()
            base=dict(policy=J.POLICY,kind='BASELINE',journal_id=str(uuid4()),observed_at=observed,
                scope=dict(officer_uid=officer,source_keys=sorted(HEADERS),dimensions=sorted(DIMENSIONS)),
                source_context=deepcopy(self.context),original_publication_sha256=self.public_sha,
                source_registry_sha256=self.registry_sha,claims=self.entries(officer),semantics='RECORDER_OBSERVED_ARCHIVED_BASELINE')
            J._publish(root/'baseline.encrypted.json',J._sign(base,self.signer,self.key_id),
                self.snapshot['crypto'],self.snapshot['backup'],J._binding('BASELINE'),self.deadline)
        anchor,base=self._base(root,repo,officer)
        checkpoints=list(root.glob('checkpoint-*.encrypted.json'))
        J.require(len(checkpoints)<=1,'Ambiguous unpublished checkpoints; recovery approval required')
        if not checkpoints:
            checkpoint=J._checkpoint(anchor,[],base['observed_at'],self.signer,self.key_id)
            name='checkpoint-'+checkpoint['payload']['checkpoint_id']+'.encrypted.json'
            J._publish(root/name,checkpoint,self.snapshot['crypto'],self.snapshot['backup'],J._binding('CHECKPOINT',anchor),self.deadline)
            checkpoints=[root/name]
        file=private(checkpoints[0],repo=repo)
        checkpoint_sha,_=J._read(file,self.snapshot['crypto'],self.snapshot['backup'],J._binding('CHECKPOINT',anchor))
        pin=dict(policy=POLICY,kind='RECORDED_BASELINE',officer_uid=officer,source_sha256=self.source_sha,
                 journal_anchor=anchor,checkpoint_file=file.name,checkpoint_sha256=checkpoint_sha)
        state=self.load(root,repo,pin)
        J.require(state['checkpoint']['event_inventory']==[], 'Initial bulk enrollment cannot discard observations')
        publish_control(descriptor,J._sign(pin,self.signer,self.key_id,POLICY),self.deadline)
        return pin,state

    def load(self,root,repo,pin):
        state=J.load_checkpoint(root,repo,self.snapshot['crypto'],self.snapshot['backup'],self.recorder_keys,{},
            expected_anchor=pin['journal_anchor'],checkpoint_file=pin['checkpoint_file'],expected_checkpoint_digest=pin['checkpoint_sha256'])
        J.require(state['history'].officer_uid==pin['officer_uid'],'Recorded history officer differs')
        return state
