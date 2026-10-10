"""Separate encrypted findings tips and explicitly authorized interrupted-write recovery.

Trusted backend configuration only. Independently retained latest registry pins
remain mandatory; two local directories cannot detect simultaneous rollback.
"""
from copy import deepcopy
from contextlib import contextmanager
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import fcntl
import os
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption

from app.identity import encrypted_findings_journal as F
from app.identity import observed_recording_journal as J
from app.identity.recording_checkpoint_registry import _publish
from app.identity.protected_commitment import digest
from app.identity.historical_reconstruction import require

POLICY='INDEPENDENT_FINDINGS_TIP_REGISTRY_V1'
RECOVERY_POLICY='FINDINGS_TIP_RECOVERY_AUTHORIZATION_V1'
FIELDS={'policy','kind','registry_id','ledger_id','sequence','previous_sha256','journal_tip',
    'operation_id','registered_at','key_pins','recovery'}
AUTH_FIELDS={'policy','kind','registry_id','ledger_id','registry_tip','journal_tip','pending_registry_tip',
    'operation_id','registry_inventory','journal_inventory','key_pins','issued_at','expires_at'}


def _tip(value,identity_field,identity):
    require(type(value) is dict and set(value)=={identity_field,'sequence','entry_sha256'} and
        value[identity_field]==identity and type(value['sequence']) is int and value['sequence']>=0,
        'Trusted findings tip shape differs.')
    F._sha(value['entry_sha256'])
    require(value['sequence']!=0 or value['entry_sha256']=='0'*64,'Empty findings tip digest differs.')


def _secrets(crypto,backup):
    return set(crypto.encryption_keys.values())|set(crypto.lookup_keys.values())|set(backup.encryption_keys.values())|set(backup.lookup_keys.values())


class FindingsTipRegistry:
    """One separate registry per findings ledger; no implicit latest-tip selection."""
    def __init__(self,*,root,journal,registry_id,crypto,backup,signer,key_id,registry_keys,recovery_keys):
        require(type(journal) is F.FindingsJournal,'Configured findings journal required.')
        self.journal=journal;self.root=J._private_root(root,journal.repo);self.registry_id=F._uuid(registry_id)
        require(not self.root.is_relative_to(journal.root) and not journal.root.is_relative_to(self.root),
            'Findings registry must be separate from journal.')
        self.crypto=crypto;self.backup=backup;self.signer=signer;self.key_id=key_id
        self.registry_keys=deepcopy(registry_keys);self.recovery_keys=deepcopy(recovery_keys)
        require(self.registry_keys and self.recovery_keys,'Registry and recovery key pins required.')
        groups=[set(m.values()) for m in (registry_keys,recovery_keys,journal.writer_keys,journal.reviewer_keys)]
        require(all(not a&b for i,a in enumerate(groups) for b in groups[i+1:]),
            'Registry, recovery, findings writer and reviewer keys must be separate.')
        J._recorder(signer,key_id,self.registry_keys,crypto,backup)
        seed=signer.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
        require(not _secrets(crypto,backup)&_secrets(journal.crypto,journal.backup) and
            seed not in _secrets(journal.crypto,journal.backup),'Registry secrets must be separate from findings secrets.')
        self.key_pins=self._pins()

    def _pins(self):
        self.journal._authority_config()
        result={name:digest({k:v.hex() for k,v in sorted(mapping.items())}) for name,mapping in
            (('registry',self.registry_keys),('recovery',self.recovery_keys),
             ('writer',self.journal.writer_keys),('reviewer',self.journal.reviewer_keys))}
        if self.journal.authority_keys:
            require(not set(self.journal.authority_keys.values())&(set(self.registry_keys.values())|set(self.recovery_keys.values())),
                'Review assessor keys must be separate from registry and recovery keys.')
            result['review_authority']=digest(dict(keys={k:v.hex() for k,v in sorted(self.journal.authority_keys.items())},
                identities=self.journal.reviewer_identities,scopes=self.journal.authority_scopes))
        return result

    def _config(self):
        require(self._pins()==self.key_pins,'Findings registry key pins changed.')
        J._private_root(self.root,self.journal.repo);J._private_root(self.journal.root,self.journal.repo)
        require(not self.root.is_relative_to(self.journal.root) and not self.journal.root.is_relative_to(self.root),
            'Findings registry paths overlap.')
        J._recorder(self.signer,self.key_id,self.registry_keys,self.crypto,self.backup)

    @contextmanager
    def _locked(self):
        # Registry then journal. Journal methods acquire their own lock only when
        # the caller is not already holding it; internal _replay does not relock.
        self._config();fd=os.open(self.root,os.O_RDONLY)
        try:fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def _tip(self,sequence,sha):return dict(registry_id=self.registry_id,sequence=sequence,entry_sha256=sha)
    def empty_tip(self):return self._tip(0,'0'*64)

    def _binding(self,sequence):
        return dict(artifact='INDEPENDENT_FINDINGS_TIP',policy=POLICY,registry_id=self.registry_id,
            ledger_id=self.journal.ledger_id,sequence=sequence)

    def _entries(self,tip,staging=None,pending=None):
        _tip(tip,'registry_id',self.registry_id)
        names={p.name for p in self.root.iterdir() if p!=staging and p!=pending}
        require(names=={f'entry-{i:08d}.encrypted.json' for i in range(1,tip['sequence']+1)},
            'Findings registry tip is stale, missing or rolled back; recovery required.')
        entries=[];previous='0'*64;prior=self.journal.empty_tip();last=None
        for index in range(1,tip['sequence']+1):
            fingerprint,receipt=J._read(self.root/f'entry-{index:08d}.encrypted.json',self.crypto,self.backup,self._binding(index))
            value=J._verify(receipt,self.registry_keys,FIELDS,'TIP_ENTRY',POLICY)
            require(value['registry_id']==self.registry_id and value['ledger_id']==self.journal.ledger_id and
                type(value['sequence']) is int and value['sequence']==index and value['previous_sha256']==previous and
                value['key_pins']==self.key_pins,'Findings registry scope, chain or keys differ.')
            _tip(value['journal_tip'],'ledger_id',self.journal.ledger_id);F._uuid(value['operation_id'])
            require(value['journal_tip']['sequence']==prior['sequence']+1,'Findings registry cannot skip journal entries.')
            now=F._time(value['registered_at'])
            require(now<=J._now() and (last is None or now>=last),'Findings registry clock differs.')
            if value['recovery'] is not None:
                auth=self._authorization(value['recovery'],now)
                require(auth['registry_tip']==self._tip(index-1,previous) and auth['journal_tip']==value['journal_tip'] and
                    auth['operation_id']==value['operation_id'] and auth['pending_registry_tip'] is None,
                    'Recorded findings recovery differs.')
            entries.append(dict(sha=fingerprint,value=value));previous=fingerprint;prior=value['journal_tip'];last=now
        require(tip==self._tip(len(entries),previous),'Independent findings registry pin differs.')
        return entries

    def _journal_tip(self,entries):return deepcopy(entries[-1]['value']['journal_tip'] if entries else self.journal.empty_tip())

    def _history(self,entries,new_tip=None,operation=None):
        tip=new_tip or self._journal_tip(entries);history,_=self.journal._replay(tip)
        for record in entries:
            journal_tip=record['value']['journal_tip'];item=history[journal_tip['sequence']-1]
            require(item['entry_sha256']==journal_tip['entry_sha256'] and
                item['entry']['operation_id']==record['value']['operation_id'] and
                F._time(item['entry']['recorded_at'])<=F._time(record['value']['registered_at']),
                'Registered findings history differs.')
        if new_tip is not None:
            prior=self._journal_tip(entries)
            require(new_tip['sequence']==prior['sequence']+1 and history[-1]['entry']['previous_sha256']==prior['entry_sha256'] and
                history[-1]['entry']['operation_id']==operation,'Pending finding operation or predecessor differs.')
        return history

    def select(self,expected_registry_tip):
        """Sensitive plaintext backend selection; no console/UI disclosure."""
        with self._locked(),self.journal._lock():
            entries=self._entries(expected_registry_tip);history=self._history(entries)
            return dict(registry_tip=deepcopy(expected_registry_tip),journal_tip=self._journal_tip(entries),entries=deepcopy(history))

    def _advance(self,registry_tip,journal_tip,operation,recovery=None):
        # Caller holds registry lock. Journal lock covers validation/publication.
        with self.journal._lock():
            entries=self._entries(registry_tip);pending_history=self._history(entries,journal_tip,operation)
            now=J._now();require(now>=F._time(pending_history[-1]['entry']['recorded_at']),
                'Registry clock precedes pending finding.')
            require(not entries or now>=F._time(entries[-1]['value']['registered_at']),'Registry clock moved backwards.')
            value=dict(policy=POLICY,kind='TIP_ENTRY',registry_id=self.registry_id,ledger_id=self.journal.ledger_id,
                sequence=registry_tip['sequence']+1,previous_sha256=registry_tip['entry_sha256'],journal_tip=deepcopy(journal_tip),
                operation_id=operation,registered_at=now.isoformat(),key_pins=deepcopy(self.key_pins),recovery=deepcopy(recovery))
            def check(staging):
                self._config();require(J._now()>=now,'Registry clock moved backwards.')
                current=self._entries(registry_tip,staging=staging);self._history(current,journal_tip,operation)
                if recovery is not None:
                    auth=self._authorization(recovery,J._now());self._inventories(auth,staging=staging)
            path=self.root/f"entry-{value['sequence']:08d}.encrypted.json"
            sha=_publish(path,J._sign(value,self.signer,self.key_id,POLICY),self.crypto,self.backup,self._binding(value['sequence']),check)
            tip=self._tip(value['sequence'],sha);self._history(self._entries(tip))
            return dict(status='REGISTERED',registry_tip=tip,journal_tip=deepcopy(journal_tip),findings_anchored=False,accepted_state=None)

    def append_receipt(self,*,expected_registry_tip,**kwargs):
        with self._locked():
            entries=self._entries(expected_registry_tip);journal_tip=self._journal_tip(entries)
            with self.journal._lock():self._history(entries)
            result=self.journal.append_receipt(expected_tip=journal_tip,**kwargs)
            if result['status']=='ALREADY_RECORDED':return self._unchanged(expected_registry_tip,journal_tip)
            return self._advance(expected_registry_tip,result['tip'],kwargs['operation_id'])

    def append_review(self,*,expected_registry_tip,intent,before_publish=None):
        with self._locked():
            entries=self._entries(expected_registry_tip);journal_tip=self._journal_tip(entries)
            with self.journal._lock():self._history(entries)
            result=self.journal.append_review(expected_tip=journal_tip,intent=intent,before_publish=before_publish)
            if result['status']=='ALREADY_RECORDED':return self._unchanged(expected_registry_tip,journal_tip)
            return self._advance(expected_registry_tip,result['tip'],intent['payload']['operation_id'])

    @staticmethod
    def _unchanged(registry_tip,journal_tip):
        return dict(status='ALREADY_REGISTERED',registry_tip=deepcopy(registry_tip),journal_tip=deepcopy(journal_tip),
            findings_anchored=False,accepted_state=None)

    def _inventory(self,root,staging=None):
        result={}
        for path in root.iterdir():
            if path==staging:continue
            require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
                path.stat().st_mode&0o077==0,'Private findings recovery inventory required.')
            result[path.name]=sha256(path.read_bytes()).hexdigest()
        return result

    def _inventories(self,auth,staging=None):
        require(auth['registry_inventory']==self._inventory(self.root,staging) and
            auth['journal_inventory']==self._inventory(self.journal.root),'Findings recovery inventory changed.')

    def _authorization(self,receipt,at):
        value=J._verify(receipt,self.recovery_keys,AUTH_FIELDS,'RECOVERY',RECOVERY_POLICY)
        require(value['registry_id']==self.registry_id and value['ledger_id']==self.journal.ledger_id and
            value['key_pins']==self.key_pins,'Findings recovery scope or key pins differ.')
        _tip(value['registry_tip'],'registry_id',self.registry_id);_tip(value['journal_tip'],'ledger_id',self.journal.ledger_id)
        if value['pending_registry_tip'] is not None:_tip(value['pending_registry_tip'],'registry_id',self.registry_id)
        F._uuid(value['operation_id']);start=F._time(value['issued_at']);end=F._time(value['expires_at'])
        require(start<=at<=end and start<end<=start+timedelta(seconds=600),'Findings recovery authorization expired or future.')
        for inventory in (value['registry_inventory'],value['journal_inventory']):
            require(type(inventory) is dict,'Findings recovery inventory required.')
            for name,sha in inventory.items():
                require(type(name) is str and Path(name).name==name and name not in ('.','..'),'Recovery inventory filename differs.')
                F._sha(sha)
        return value

    def _pending(self,auth):
        old=auth['registry_tip'];new=auth['pending_registry_tip'];pending=None
        if new is not None:
            require(new['sequence']==old['sequence']+1,'Pending registry must advance once.')
            pending=self.root/f"entry-{new['sequence']:08d}.encrypted.json"
        entries=self._entries(old,pending=pending)
        self._history(entries,auth['journal_tip'],auth['operation_id'])
        if new is not None:
            full=self._entries(new);require(full[-1]['value']['previous_sha256']==old['entry_sha256'] and
                full[-1]['value']['journal_tip']==auth['journal_tip'] and full[-1]['value']['operation_id']==auth['operation_id'],
                'Pending registry operation differs.')
            self._history(full)
        return entries

    def authorize_recovery(self,*,signer,key_id,expected_registry_tip,journal_tip,operation_id,
            issued_at,expires_at,pending_registry_tip=None):
        """Trusted recovery issuer; no action-date role authorization is claimed."""
        J._recorder(signer,key_id,self.recovery_keys,self.crypto,self.backup)
        seed=signer.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
        require(seed not in _secrets(self.journal.crypto,self.journal.backup),'Recovery signing secret overlaps findings keys.')
        with self._locked(),self.journal._lock():
            value=dict(policy=RECOVERY_POLICY,kind='RECOVERY',registry_id=self.registry_id,ledger_id=self.journal.ledger_id,
                registry_tip=deepcopy(expected_registry_tip),journal_tip=deepcopy(journal_tip),pending_registry_tip=deepcopy(pending_registry_tip),
                operation_id=operation_id,key_pins=deepcopy(self.key_pins),issued_at=issued_at,expires_at=expires_at,
                registry_inventory=self._inventory(self.root),journal_inventory=self._inventory(self.journal.root))
            receipt=J._sign(value,signer,key_id,RECOVERY_POLICY)
            self._authorization(receipt,J._now());self._pending(value)
            return receipt

    def recover(self,authorization):
        # Pin exact inventories before deciding whether a registry entry already
        # survived; no latest-file scan, deletion, replacement or expiry waiver.
        authorization=deepcopy(authorization)
        with self._locked():
            with self.journal._lock():
                auth=self._authorization(authorization,J._now());self._inventories(auth);self._pending(auth)
                if auth['pending_registry_tip'] is not None:
                    return dict(status='RECOVERED',registry_tip=deepcopy(auth['pending_registry_tip']),
                        journal_tip=deepcopy(auth['journal_tip']),findings_anchored=False,accepted_state=None)
            result=self._advance(auth['registry_tip'],auth['journal_tip'],auth['operation_id'],authorization)
            result['status']='RECOVERED';return result
