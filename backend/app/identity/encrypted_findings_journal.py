"""Trusted-backend signed, encrypted findings storage; no endpoint or live hook.

Expected tips must come from independent trusted storage. This module does not
provide that service or action-date reviewer authority verification.
"""
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
import fcntl
import hashlib
import json
import os
import re

from app.identity import observed_recording_journal as J
from app.identity import protected_contradiction_runner as P
from app.identity import bitemporal_contradictions as D
from app.identity.evidence_bundle_v2 import canonical, open_artifact
from app.identity.historical_reconstruction import require
from app.identity.protected_commitment import digest

POLICY='ENCRYPTED_FINDINGS_JOURNAL_V1'
REVIEW_POLICY='FINDINGS_REVIEW_INTENT_V1'
DECISIONS=('NEEDS_MORE_EVIDENCE','REPORTED_DISAGREEMENT_SUPPORTED','REPORTED_DISAGREEMENT_NOT_SUPPORTED')
FIELDS={'policy','kind','ledger_id','officer_uid','sequence','previous_sha256','operation_id',
    'recorded_at','finding_id','supersedes','receipt_sha256','finding','review','reason'}
REVIEW_FIELDS={'policy','kind','ledger_id','officer_uid','finding_id','target_entry_sha256',
    'operation_id','decision','reason','evidence_references','issued_at','expires_at'}


def _uuid(value):
    require(type(value) is str and str(UUID(value))==value,'Canonical UUID required.')
    return value


def _sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,'SHA256 pin required.')
    return value


def _text(value):
    require(type(value) is str and bool(value.strip()),'Nonempty finding explanation required.')


def _time(value):
    try: result=datetime.fromisoformat(value)
    except (ValueError,TypeError):raise ValueError('Aware finding recording time required.') from None
    require(result.tzinfo is not None and result.utcoffset() is not None,'Aware finding recording time required.')
    return result.astimezone(timezone.utc)


def _json(data):
    def unique(pairs):
        result={}
        for k,v in pairs:
            require(k not in result,'Duplicate finding artifact field.');result[k]=v
        return result
    return json.loads(data,object_pairs_hook=unique)


def _finding(value,officer):
    require(type(value) is dict and value.get('policy')==P.POLICY and value.get('officer_uid')==officer,
        'Protected finding scope or policy differs.')
    require(value.get('accepted_state') is None and value.get('accepted_contradiction') is False and
        value.get('findings_anchored') is False and value.get('authenticated_journal_replay') is True and
        value.get('coverage_semantics')=='JOURNAL_OBSERVATIONS_ONLY' and
        value.get('source_change_completeness_established') is False,'Reported finding semantics differ.')
    comparison=value['comparison'];query=value['query']
    require(comparison['policy']==D.POLICY and comparison['query_digest']==query['query_digest'] and
        comparison['accepted_state'] is None and comparison['receipt_authenticity_claim'] is False,
        'Finding comparison policy differs.')
    for pair in comparison['comparisons']:
        require(pair['status'] in D.STATUSES and pair['accepted_contradiction'] is False and
            len(pair['claim_ids'])==len(pair['version_ids'])==len(pair['source_references'])==
            len(pair['receipt_digests'])==len(pair['destination_digests'])==2 and
            bool(pair['reasons']),'Finding provenance or explanation differs.')
    return value


def read_comparison_receipt(path,repo,crypto,backup,officer_uid):
    """Recover existing runner receipt; does not redo live readiness or latestness."""
    path=Path(path).expanduser().absolute();J._private_root(path.parent,repo)
    require(not path.is_symlink() and path.is_file() and path.stat().st_uid==os.getuid() and
        path.stat().st_mode&0o077==0,'Private comparison receipt required.')
    data=path.read_bytes();envelope=_json(data);binding=envelope['binding']
    require(binding['artifact']=='PROTECTED_OBSERVED_CONTRADICTIONS' and binding['policy']==P.POLICY,
        'Protected comparison receipt binding differs.')
    finding=open_artifact(crypto,envelope,binding)
    require(open_artifact(backup,envelope,binding)==finding and digest(finding)==binding['result_sha256'],
        'Comparison receipt recovery or digest differs.')
    return hashlib.sha256(data).hexdigest(),deepcopy(_finding(finding,officer_uid))


def issue_review_intent(*,signer,key_id,reviewer_keys,crypto,backup,ledger_id,officer_uid,finding_id,
        target_entry_sha256,operation_id,decision,reason,evidence_references,issued_at,expires_at):
    """Trusted review backend only; key allowlist is not action-date role authority."""
    _uuid(ledger_id);_uuid(officer_uid);_uuid(finding_id);_uuid(operation_id);_sha(target_entry_sha256)
    _text(reason);require(decision in DECISIONS,'Reported review decision required.')
    require(type(evidence_references) is list and all(type(x) is str and x.strip() for x in evidence_references),
        'Review evidence reference list required.')
    require(_time(expires_at)>_time(issued_at),'Review expiry must follow issuance.')
    J._recorder(signer,key_id,reviewer_keys,crypto,backup)
    value=dict(policy=REVIEW_POLICY,kind='REVIEW',ledger_id=ledger_id,officer_uid=officer_uid,
        finding_id=finding_id,target_entry_sha256=target_entry_sha256,operation_id=operation_id,
        decision=decision,reason=reason,evidence_references=deepcopy(evidence_references),
        issued_at=issued_at,expires_at=expires_at)
    return J._sign(value,signer,key_id,REVIEW_POLICY)


class FindingsJournal:
    """Private filesystem foundation. Backend-configured objects only.

    Append-only API and signed replay detect modification against external pins.
    A filesystem owner can delete/rollback files: independent tip durability and
    witness integration are required before operational use.
    """
    def __init__(self,*,root,repo,ledger_id,officer_uid,crypto,backup,signer,key_id,writer_keys,reviewer_keys):
        self.repo=Path(repo).expanduser().resolve();self.root=J._private_root(root,self.repo)
        self.ledger_id=_uuid(ledger_id);self.officer_uid=_uuid(officer_uid)
        self.crypto=crypto;self.backup=backup;self.signer=signer;self.key_id=key_id
        self.writer_keys=deepcopy(writer_keys);self.reviewer_keys=deepcopy(reviewer_keys)
        require(self.writer_keys and self.reviewer_keys and
            not (set(self.writer_keys.values())&set(self.reviewer_keys.values())),
            'Separate writer and reviewer public keys required.')
        J._recorder(signer,key_id,self.writer_keys,crypto,backup)

    @contextmanager
    def _lock(self):
        J._private_root(self.root,self.repo)
        fd=os.open(self.root,os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX);yield
        finally:os.close(fd)

    def _binding(self,sequence):
        return dict(artifact='ENCRYPTED_FINDINGS_ENTRY',policy=POLICY,ledger_id=self.ledger_id,
            sequence=sequence)

    def _tip(self,sequence,sha):
        return dict(ledger_id=self.ledger_id,sequence=sequence,entry_sha256=sha)

    def empty_tip(self):
        return self._tip(0,'0'*64)

    def _replay(self,expected_tip):
        require(type(expected_tip) is dict and set(expected_tip)=={'ledger_id','sequence','entry_sha256'} and
            expected_tip['ledger_id']==self.ledger_id and type(expected_tip['sequence']) is int and
            expected_tip['sequence']>=0,'Independent findings tip required.')
        _sha(expected_tip['entry_sha256'])
        names={p.name for p in self.root.iterdir() if not p.name.startswith('.observation-')}
        require(names=={f'entry-{i:08d}.encrypted.json' for i in range(1,expected_tip['sequence']+1)},
            'Findings inventory differs from independent tip; recovery required.')
        previous='0'*64;entries=[];heads={};operations=set();last=None
        for sequence in range(1,expected_tip['sequence']+1):
            path=self.root/f'entry-{sequence:08d}.encrypted.json'
            sha,receipt=J._read(path,self.crypto,self.backup,self._binding(sequence))
            value=J._verify(receipt,self.writer_keys,FIELDS,receipt['payload']['kind'],POLICY)
            require(value['ledger_id']==self.ledger_id and value['officer_uid']==self.officer_uid and
                type(value['sequence']) is int and value['sequence']==sequence and value['previous_sha256']==previous,
                'Findings sequence or scope differs.')
            now=_time(value['recorded_at']);require(last is None or now>last,'Finding clock did not advance.')
            op=_uuid(value['operation_id']);require(op not in operations,'Repeated finding operation.')
            operations.add(op);self._validate(value,heads,now)
            entries.append(dict(entry_sha256=sha,entry=deepcopy(value)))
            if value['kind'] in ('FINDING','CORRECTION'):heads[value['finding_id']]=dict(sha=sha,entry=value)
            previous=sha;last=now
        require(expected_tip==self._tip(len(entries),previous),'Findings tip digest differs.')
        return entries,heads

    def _validate(self,v,heads,now):
        _uuid(v['finding_id'])
        if v['kind'] in ('FINDING','CORRECTION'):
            _sha(v['receipt_sha256']);_finding(v['finding'],self.officer_uid)
            require(v['review'] is None,'Finding cannot carry review authority.')
            if v['kind']=='FINDING':
                require(v['finding_id'] not in heads and v['supersedes'] is None and v['reason'] is None,
                    'Original finding already exists or has correction metadata.')
            else:
                _text(v['reason']);require(v['finding_id'] in heads and
                    v['supersedes']==heads[v['finding_id']]['sha'],'Correction must link to current finding head.')
        else:
            require(v['kind']=='REVIEW' and v['finding'] is None and v['receipt_sha256'] is None and
                v['supersedes'] is None and v['reason'] is None,'Finding entry kind differs.')
            review=J._verify(v['review'],self.reviewer_keys,REVIEW_FIELDS,'REVIEW',REVIEW_POLICY)
            require(review['ledger_id']==self.ledger_id and review['officer_uid']==self.officer_uid and
                review['finding_id']==v['finding_id'] and review['operation_id']==v['operation_id'] and
                v['finding_id'] in heads and review['target_entry_sha256']==heads[v['finding_id']]['sha'],
                'Review must name current finding head and ledger scope.')
            require(_time(review['issued_at'])<=now<=_time(review['expires_at']),'Review intent outside validity window.')
            _text(review['reason']);require(review['decision'] in DECISIONS,'Reported review decision required.')
            require(type(review['evidence_references']) is list and all(type(x) is str and x.strip()
                for x in review['evidence_references']),'Review evidence reference list required.')

    def read(self,expected_tip):
        """Returns sensitive plaintext to authorized backend only, never console/UI."""
        with self._lock():return deepcopy(self._replay(expected_tip)[0])

    def recover_pending(self,*,expected_tip,operation_id,approved_entry_sha256):
        """Explicit trusted recovery of exactly one signed entry after interruption.

        The approved digest is supplied by independent recovery authorization;
        this method never advances an external tip or chooses a local latest tip.
        """
        _uuid(operation_id);_sha(approved_entry_sha256)
        with self._lock():
            require(type(expected_tip) is dict and type(expected_tip.get('sequence')) is int and
                expected_tip['sequence']>=0,'Independent recovery tip required.')
            new_tip=self._tip(expected_tip['sequence']+1,approved_entry_sha256)
            entries,_=self._replay(new_tip)
            pending=entries[-1]['entry']
            require(expected_tip==self._tip(len(entries)-1,pending['previous_sha256']) and
                pending['operation_id']==operation_id,'Pending findings recovery authorization differs.')
            return dict(status='RECOVERED',tip=new_tip,accepted_state=None,findings_anchored=False)

    def append_receipt(self,*,expected_tip,operation_id,finding_id,receipt_path,supersedes=None,reason=None,before_publish=None):
        sha,finding=read_comparison_receipt(receipt_path,self.repo,self.crypto,self.backup,self.officer_uid)
        return self._append(expected_tip,operation_id,finding_id,'CORRECTION' if supersedes is not None else 'FINDING',
            supersedes,sha,finding,None,reason,before_publish)

    def append_review(self,*,expected_tip,intent):
        value=J._verify(intent,self.reviewer_keys,REVIEW_FIELDS,'REVIEW',REVIEW_POLICY)
        return self._append(expected_tip,value['operation_id'],value['finding_id'],'REVIEW',None,None,None,intent,None)

    def _append(self,tip,operation,finding_id,kind,supersedes,receipt_sha,finding,review,reason,before_publish=None):
        _uuid(operation);_uuid(finding_id)
        require(before_publish is None or callable(before_publish),
            'Trusted findings publication validator required.')
        # Freeze caller data so a mutation cannot change what is validated/signed.
        proposed=deepcopy(dict(kind=kind,operation_id=operation,finding_id=finding_id,supersedes=supersedes,
            receipt_sha256=receipt_sha,finding=finding,review=review,reason=reason))
        with self._lock():
            entries,heads=self._replay(tip)
            for entry in entries:
                old=entry['entry']
                if old['operation_id']==operation:
                    require(all(old[k]==v for k,v in proposed.items()),'Finding retry content differs.')
                    return dict(status='ALREADY_RECORDED',tip=deepcopy(tip),accepted_state=None,findings_anchored=False)
            now=J._now().astimezone(timezone.utc)
            value=dict(policy=POLICY,ledger_id=self.ledger_id,officer_uid=self.officer_uid,
                sequence=len(entries)+1,previous_sha256=tip['entry_sha256'],recorded_at=now.isoformat(),**proposed)
            if entries:require(now>_time(entries[-1]['entry']['recorded_at']),'Finding clock did not advance.')
            self._validate(value,heads,now)
            path=self.root/f"entry-{value['sequence']:08d}.encrypted.json"
            def check():
                require(J._now().astimezone(timezone.utc)>=now,'Finding clock moved backwards.')
                self._replay(tip);self._validate(value,heads,J._now().astimezone(timezone.utc))
                if before_publish is not None:before_publish()
            sha=J._publish(path,J._sign(value,self.signer,self.key_id,POLICY),self.crypto,self.backup,
                self._binding(value['sequence']),check)
            new_tip=self._tip(value['sequence'],sha)
            self._replay(new_tip)
            return dict(status='RECORDED',tip=new_tip,accepted_state=None,findings_anchored=False)
